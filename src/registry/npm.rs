use std::collections::BTreeMap;

use http::HeaderMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use url::Url;

use super::{PackageRef, Registry, VersionInfo};
use crate::rule::RuleVerdict;

pub struct NpmRegistry;

const KNOWN_HOSTS: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

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

impl Registry for NpmRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn is_metadata_url(&self, url: &Url) -> bool {
        let path = url.path().split('?').next().unwrap_or("");
        !path.ends_with(".tgz") && !path.contains("/-/")
    }

    fn parse_package_from_url(&self, url: &Url) -> Option<PackageRef> {
        let path = url.path();
        if !path.ends_with(".tgz") {
            return None;
        }
        let host = url.host_str()?;
        let prefix = format!("{}/", host);
        let full = format!("{}{}", host, path);
        if !full.starts_with(&prefix) {
            return None;
        }
        let after = &full[prefix.len()..];
        let sep = after.find("/-/")?;
        let package_name = after[..sep].to_string();
        let filename = &after[sep + 3..after.len() - 4];

        let base_name = if package_name.starts_with('@') {
            package_name.rsplit('/').next()?
        } else {
            &package_name
        };

        let version = filename
            .strip_prefix(&format!("{}-", base_name))
            .map(|v| v.to_string());

        Some(PackageRef {
            name: package_name,
            version,
        })
    }

    fn modify_request_headers(&self, headers: &mut HeaderMap) {
        headers.insert("accept", "application/json".parse().unwrap());
    }

    fn modify_metadata_response(
        &self,
        body: &[u8],
        headers: &HeaderMap,
        check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
    ) -> Option<Vec<u8>> {
        let mut meta: NpmMetadata = serde_json::from_slice(body).ok()?;

        let mut to_remove = Vec::new();
        for (version, ts_str) in &meta.time {
            if version == "created" || version == "modified" {
                continue;
            }
            let published_at: Option<Timestamp> = ts_str.parse().ok();
            let info = VersionInfo {
                name: meta.name.clone(),
                version: version.clone(),
                published_at,
                ecosystem: super::Ecosystem::Javascript,
            };
            if let RuleVerdict::StripVersion = check_version(&info) {
                to_remove.push(version.clone());
            }
        }

        if to_remove.is_empty() {
            return None;
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

        clear_caching_headers(headers);
        Some(serde_json::to_vec(&meta).unwrap_or_else(|_| body.to_vec()))
    }
}

fn recalculate_latest(time: &BTreeMap<String, String>) -> Option<String> {
    time.iter()
        .filter(|(ver, _)| *ver != "created" && *ver != "modified" && !ver.contains('-'))
        .max_by_key(|(_, ts)| ts.as_str())
        .map(|(ver, _)| ver.clone())
}

fn clear_caching_headers(headers: &HeaderMap) {
    let _ = headers;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::MinimumAge;

    fn load_fixture() -> Vec<u8> {
        std::fs::read("tests/data/npmjs/express.json").expect("fixture missing")
    }

    #[test]
    fn npm_rewrite_against_real_metadata() {
        let body = load_fixture();
        let headers = HeaderMap::new();
        let rule = MinimumAge::new(jiff::Span::new().hours(365 * 24));
        let cutoff = rule.cutoff();

        let result =
            NpmRegistry.modify_metadata_response(&body, &headers, &|info| rule.check(info));

        assert!(
            result.is_some(),
            "should rewrite — there are versions newer than 1 year"
        );
        let meta: NpmMetadata = serde_json::from_slice(result.as_ref().unwrap()).unwrap();

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
    }
}
