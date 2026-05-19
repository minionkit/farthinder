use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Map;
use url::Url;

use super::{reject_compressed, InterceptDecision, CutoffChecker, QuarantinedPackage, Registry, RegistryState, RegistryStats, ResponseAction, ToolName};
use crate::rule::Rules;

const JS_INSTALL_SUBCOMMANDS: &[&str] = &["install", "i", "ci", "add", "update", "upgrade"];

pub fn decide(tool: ToolName, args: Vec<String>) -> InterceptDecision {
    match tool {
        ToolName::Npx | ToolName::Bunx => InterceptDecision::Intercept(args),
        ToolName::Npm | ToolName::Bun | ToolName::Yarn | ToolName::Pnpm => {
            let subcmd = args.first().map(|s| s.as_str()).unwrap_or("");
            if subcmd.is_empty() && matches!(tool, ToolName::Yarn | ToolName::Pnpm) {
                return InterceptDecision::Intercept(args);
            }
            if JS_INSTALL_SUBCOMMANDS.contains(&subcmd) {
                InterceptDecision::Intercept(args)
            } else {
                InterceptDecision::Passthrough(args)
            }
        }
        _ => InterceptDecision::Passthrough(args),
    }
}

pub struct NpmRegistry {
    checker: CutoffChecker,
    state: Mutex<RegistryState>,
}

#[cfg(test)]
impl NpmRegistry {
    pub fn test_cutoff(&self) -> jiff::Timestamp {
        self.checker.cutoff()
    }
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
        NpmRegistry {
            checker: CutoffChecker::new(rules.min_age_hours()),
            state: Mutex::new(RegistryState::default()),
        }
    }

    fn is_metadata_url(url: &Url) -> bool {
        let path = url.path().split('?').next().unwrap_or("");
        !path.ends_with(".tgz") && !path.contains("/-/")
    }
}

impl Registry for NpmRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn prepare_request(&self, url: &Url, headers: &mut http::HeaderMap) {
        if !Self::is_metadata_url(url) {
            return;
        }
        headers.insert("accept", "application/json".parse().unwrap());
        headers.remove("accept-encoding");
    }

    fn handle_response(
        &self,
        url: &Url,
        _status: u16,
        response_headers: &http::HeaderMap,
        body: &[u8],
    ) -> ResponseAction {
        if !Self::is_metadata_url(url) {
            return ResponseAction::Passthrough;
        }

        if let Some(action) = reject_compressed(response_headers) {
            return action;
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
            let published_at = ts_str.parse::<jiff::Timestamp>().ok();
            if !self.checker.is_old_enough(published_at) {
                to_remove.push(version.clone());
                quarantined_versions.push(version.clone());
            }
        }

        {
            let mut state = self.state.lock().expect("npm state lock");
            state.packages_checked += 1;
        }

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

        {
            let mut state = self.state.lock().expect("npm state lock");
            state.quarantined.push(QuarantinedPackage {
                name: meta.name.clone(),
                quarantined_versions,
            });
        }

        match serde_json::to_vec(&meta) {
            Ok(new_body) => ResponseAction::Rewrite { body: new_body },
            Err(_) => ResponseAction::Block,
        }
    }

    fn stats(&self) -> RegistryStats {
        let state = self.state.lock().expect("npm state lock");
        RegistryStats {
            packages_checked: state.packages_checked,
            packages_quarantined: state.quarantined.clone(),
            ..Default::default()
        }
    }

    fn proxy_env_vars(&self, proxy_url: &str, ca_cert_path: &std::path::Path) -> Vec<(String, String)> {
        vec![
            ("npm_config_proxy".to_string(), proxy_url.to_string()),
            ("npm_config_https_proxy".to_string(), proxy_url.to_string()),
            ("HTTP_PROXY".to_string(), proxy_url.to_string()),
            ("HTTPS_PROXY".to_string(), proxy_url.to_string()),
            ("NODE_EXTRA_CA_CERTS".to_string(), ca_cert_path.to_string_lossy().to_string()),
        ]
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
        let headers = http::HeaderMap::new();
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
            let ts: jiff::Timestamp = ts_str.parse().unwrap();
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
        let action = registry.handle_response(&url, 200, &http::HeaderMap::new(), b"data");
        assert!(matches!(action, ResponseAction::Passthrough));
    }

    #[test]
    fn npm_blocks_compressed_metadata() {
        let registry = NpmRegistry::new(Rules::new(48));
        let url = Url::parse("https://registry.npmjs.org/express").unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        let action = registry.handle_response(&url, 200, &headers, b"compressed data");
        assert!(matches!(action, ResponseAction::Block));
    }
}

#[cfg(test)]
mod decide_tests {
    use test_case::test_case;
    use crate::registry::{Ecosystem, InterceptDecision, ToolName};

    fn decide(tool: &str, args: &[&str]) -> InterceptDecision {
        let tool: ToolName = tool.parse().unwrap();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Ecosystem::Javascript.decide(tool, args)
    }

    #[test_case("npx",  &["create-react-app", "my-app"] => true)]
    #[test_case("npm",  &["install", "--save-dev", "jest"] => true)]
    #[test_case("yarn", &[] => true)]
    #[test_case("npm",  &[] => false)]
    #[test_case("bun",  &["run", "dev"] => false)]
    fn js_intercepts(tool: &str, args: &[&str]) -> bool {
        matches!(decide(tool, args), InterceptDecision::Intercept(_))
    }
}
