use std::collections::BTreeMap;
use std::sync::Mutex;

use http::HeaderMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use tracing::debug;
use url::Url;

use super::{QuarantinedPackage, QuarantinedVersion, Registry, RegistryStats, ResponseAction};
use crate::rule::Rules;

pub struct NpmRegistry {
    cutoff: Timestamp,
    state: Mutex<NpmState>,
}

#[cfg(test)]
impl NpmRegistry {
    pub fn test_cutoff(&self) -> Timestamp {
        self.cutoff
    }
}

struct NpmState {
    packages_checked: usize,
    quarantined: Vec<QuarantinedPackage>,
}

#[derive(Deserialize, Serialize)]
struct NpmMetadata {
    name: String,
    #[serde(rename = "dist-tags")]
    dist_tags: BTreeMap<String, String>,
    time: BTreeMap<String, String>,
    versions: Map<String, serde_json::Value>,
    #[serde(flatten)]
    extra: Map<String, serde_json::Value>,
}

const KNOWN_HOSTS: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

impl NpmRegistry {
    pub fn new(rules: Rules) -> Self {
        let cutoff = Timestamp::now() - jiff::Span::new().hours(rules.min_age_hours() as i64);
        NpmRegistry {
            cutoff,
            state: Mutex::new(NpmState {
                packages_checked: 0,
                quarantined: Vec::new(),
            }),
        }
    }

    fn is_metadata_url(&self, url: &Url) -> bool {
        let path = url.path().split('?').next().unwrap_or("");
        !path.ends_with(".tgz") && !path.contains("/-/")
    }

    fn check_version(&self, _name: &str, _version: &str, published_at: Option<Timestamp>) -> bool {
        matches!(published_at, Some(t) if t <= self.cutoff)
    }
}

impl Registry for NpmRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn prepare_request(&self, url: &Url, headers: &mut HeaderMap) {
        if !self.is_metadata_url(url) {
            return;
        }
        headers.insert("accept", "application/json".parse().unwrap());
        headers.remove("accept-encoding");
    }

    fn handle_response(
        &self,
        url: &Url,
        _status: u16,
        response_headers: &HeaderMap,
        body: &[u8],
    ) -> ResponseAction {
        if !self.is_metadata_url(url) {
            return ResponseAction::Passthrough;
        }

        let content_encoding = response_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");

        if content_encoding != "none" && content_encoding != "identity" {
            debug!("compressed npm metadata response, blocking");
            return ResponseAction::Block;
        }

        let mut meta: NpmMetadata = match serde_json::from_slice(body) {
            Ok(m) => m,
            Err(_) => return ResponseAction::Passthrough,
        };

        let mut to_remove = Vec::new();
        let mut quarantined_versions = Vec::new();

        for (version, ts_str) in &meta.time {
            if version == "created" || version == "modified" {
                continue;
            }
            let published_at: Option<Timestamp> = ts_str.parse().ok();
            if !self.check_version(&meta.name, version, published_at) {
                to_remove.push(version.clone());
                quarantined_versions.push(QuarantinedVersion {
                    version: version.clone(),
                    published_at,
                });
            }
        }

        let mut state = self.state.lock().unwrap();
        state.packages_checked += 1;

        if to_remove.is_empty() {
            return ResponseAction::Passthrough;
        }

        for v in &to_remove {
            meta.time.remove(v);
            meta.versions.remove(v);
            meta.dist_tags.retain(|_, tag_ver| tag_ver != v);
        }

        if !meta.dist_tags.contains_key("latest")
            && let Some(latest) = recalculate_latest(&meta.time)
        {
            meta.dist_tags.insert("latest".into(), latest);
        }

        state.quarantined.push(QuarantinedPackage {
            name: meta.name.clone(),
            quarantined_versions,
        });

        match serde_json::to_vec(&meta) {
            Ok(new_body) => ResponseAction::Rewrite { body: new_body },
            Err(_) => ResponseAction::Passthrough,
        }
    }

    fn stats(&self) -> RegistryStats {
        let state = self.state.lock().unwrap();
        RegistryStats {
            packages_checked: state.packages_checked,
            packages_quarantined: state.quarantined.clone(),
            ..Default::default()
        }
    }
}

fn recalculate_latest(time: &BTreeMap<String, String>) -> Option<String> {
    time.iter()
        .filter(|(ver, _)| *ver != "created" && *ver != "modified" && !ver.contains('-'))
        .max_by_key(|(_, ts)| ts.as_str())
        .map(|(ver, _)| ver.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture() -> Vec<u8> {
        std::fs::read("tests/data/npmjs/express.json").expect("fixture missing")
    }

    #[test]
    fn npm_rewrite_against_real_metadata() {
        let registry = NpmRegistry::new(Rules::new(365 * 24));
        let cutoff = registry.test_cutoff();

        let body = load_fixture();
        let headers = HeaderMap::new();
        let url = Url::parse("https://registry.npmjs.org/express").unwrap();

        let action = registry.handle_response(&url, 200, &headers, &body);

        let new_body = match action {
            ResponseAction::Rewrite { body } => body,
            _ => panic!("expected rewrite, got {:?}", action),
        };

        let meta: NpmMetadata = serde_json::from_slice(&new_body).unwrap();

        for (version, ts_str) in &meta.time {
            if version == "created" || version == "modified" {
                continue;
            }
            let ts: Timestamp = ts_str.parse().unwrap();
            assert!(
                ts <= cutoff,
                "remaining version {version} ({ts}) is newer than cutoff ({cutoff})"
            );
        }

        let original: NpmMetadata = serde_json::from_slice(&body).unwrap();
        assert!(
            meta.versions.len() < original.versions.len(),
            "should have stripped some versions ({} vs {})",
            meta.versions.len(),
            original.versions.len(),
        );
        assert!(
            meta.extra.contains_key("readme"),
            "extra fields like 'readme' should be preserved through round-trip"
        );

        let stats = registry.stats();
        assert_eq!(stats.packages_checked, 1);
        assert!(!stats.packages_quarantined.is_empty());
    }

    #[test]
    fn npm_passthrough_for_tarball() {
        let registry = NpmRegistry::new(Rules::new(48));
        let url = Url::parse("https://registry.npmjs.org/express/-/express-4.18.2.tgz").unwrap();
        let action = registry.handle_response(&url, 200, &HeaderMap::new(), b"data");
        assert!(matches!(action, ResponseAction::Passthrough));
    }

    #[test]
    fn npm_blocks_compressed_metadata() {
        let registry = NpmRegistry::new(Rules::new(48));
        let url = Url::parse("https://registry.npmjs.org/express").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        let action = registry.handle_response(&url, 200, &headers, b"compressed data");
        assert!(matches!(action, ResponseAction::Block));
    }
}
