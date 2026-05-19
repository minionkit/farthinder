use std::collections::BTreeMap;
use std::sync::Mutex;

use http::HeaderMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use url::Url;

use super::{reject_compressed, InterceptDecision, CutoffChecker, QuarantinedPackage, Registry, RegistryState, RegistryStats, ResponseAction, ToolName};
use crate::rule::Rules;

const PIPX_INSTALL_SUBCOMMANDS: &[&str] = &[
    "install", "run", "upgrade", "upgrade-all", "inject", "reinstall", "reinstall-all",
];
const POETRY_INSTALL_SUBCOMMANDS: &[&str] = &["install", "add", "update", "lock"];

pub fn decide(tool: ToolName, args: Vec<String>) -> InterceptDecision {
    match tool {
        ToolName::Uvx => InterceptDecision::Intercept(args),
        ToolName::Pip | ToolName::Pip3 => {
            let subcmd = args.first().map(|s| s.as_str()).unwrap_or("");
            if subcmd == "install" {
                InterceptDecision::Intercept(args)
            } else {
                InterceptDecision::Passthrough(args)
            }
        }
        ToolName::Uv => {
            let first = args.first().map(|s| s.as_str()).unwrap_or("");
            match first {
                "sync" | "lock" | "add" => InterceptDecision::Intercept(args),
                "run" => {
                    let mut hardened = vec!["--frozen".to_string()];
                    hardened.extend(args);
                    InterceptDecision::Intercept(hardened)
                }
                "pip" => {
                    let second = args.get(1).map(|s| s.as_str()).unwrap_or("");
                    if second == "install" {
                        InterceptDecision::Intercept(args)
                    } else {
                        InterceptDecision::Passthrough(args)
                    }
                }
                _ => InterceptDecision::Passthrough(args),
            }
        }
        ToolName::Pipx => {
            let subcmd = args.first().map(|s| s.as_str()).unwrap_or("");
            if PIPX_INSTALL_SUBCOMMANDS.contains(&subcmd) {
                InterceptDecision::Intercept(args)
            } else {
                InterceptDecision::Passthrough(args)
            }
        }
        ToolName::Poetry => {
            let subcmd = args.first().map(|s| s.as_str()).unwrap_or("");
            if POETRY_INSTALL_SUBCOMMANDS.contains(&subcmd) {
                InterceptDecision::Intercept(args)
            } else {
                InterceptDecision::Passthrough(args)
            }
        }
        _ => InterceptDecision::Passthrough(args),
    }
}

pub struct PyPIRegistry {
    checker: CutoffChecker,
    state: Mutex<RegistryState>,
}

const KNOWN_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "pythonhosted.org",
];

#[derive(Deserialize, Serialize)]
struct PyPIFile {
    filename: String,
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    digests: Option<Digests>,
    md5_digest: Option<String>,
    #[serde(default)]
    yanked: bool,
    yanked_reason: Option<String>,
    packagetype: String,
    size: Option<i64>,
    requires_python: Option<String>,
    #[serde(flatten)]
    extra: Map<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
struct Digests {
    sha256: Option<String>,
    md5: Option<String>,
    blake2b_256: Option<String>,
    #[serde(flatten)]
    extra: Map<String, serde_json::Value>,
}

impl PyPIRegistry {
    pub fn new(rules: Rules) -> Self {
        PyPIRegistry {
            checker: CutoffChecker::new(rules.min_age_hours()),
            state: Mutex::new(RegistryState::default()),
        }
    }

    fn is_metadata_url(url: &Url) -> bool {
        let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        if segments.len() >= 2 && segments[0] == "simple" {
            return true;
        }
        segments.len() >= 3
            && segments[0] == "pypi"
            && segments.last() == Some(&"json")
    }

    fn version_timestamp(files: &[PyPIFile]) -> Option<Timestamp> {
        files
            .iter()
            .filter_map(|f| f.upload_time_iso_8601.as_ref())
            .filter_map(|ts| ts.parse::<Timestamp>().ok())
            .max()
    }

    fn parse_version_from_url(url: &Url) -> Option<String> {
        let raw = url.path_segments()?.next_back()?;
        let filename = urlencoding::decode(raw).map(|s| s.to_string()).unwrap_or_default();

        if let Some(stripped) = filename.strip_suffix(".whl.metadata") {
            return parse_wheel_version(stripped);
        }
        if let Some(stripped) = filename.strip_suffix(".whl") {
            return parse_wheel_version(stripped);
        }

        for ext in &[
            ".tar.gz.metadata",
            ".zip.metadata",
            ".tar.bz2.metadata",
            ".tar.xz.metadata",
            ".tar.gz",
            ".zip",
            ".tar.bz2",
            ".tar.xz",
        ] {
            if let Some(stripped) = filename.strip_suffix(ext) {
                let last_dash = stripped.rfind('-')?;
                let version = &stripped[last_dash + 1..];
                if version == "latest" || version.is_empty() {
                    return None;
                }
                return Some(version.to_string());
            }
        }

        None
    }
}

impl Registry for PyPIRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn prepare_request(&self, url: &Url, headers: &mut HeaderMap) {
        if !Self::is_metadata_url(url) {
            return;
        }
        headers.remove("if-none-match");
        headers.remove("if-modified-since");
        headers.remove("accept-encoding");
    }

    fn handle_response(
        &self,
        url: &Url,
        _status: u16,
        response_headers: &HeaderMap,
        body: &[u8],
    ) -> ResponseAction {
        if !Self::is_metadata_url(url) {
            return ResponseAction::Passthrough;
        }

        if let Some(action) = reject_compressed(response_headers) {
            return action;
        }

        let content_type = response_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("html") {
            return ResponseAction::Block;
        }
        if content_type.contains("json") {
            return self.handle_json_response(body);
        }

        ResponseAction::Block
    }

    fn stats(&self) -> RegistryStats {
        let state = self.state.lock().expect("pypi state lock");
        RegistryStats {
            packages_checked: state.packages_checked,
            packages_quarantined: state.quarantined.clone(),
            ..Default::default()
        }
    }

    fn proxy_env_vars(&self, proxy_url: &str, ca_cert_path: &std::path::Path) -> Vec<(String, String)> {
        vec![
            ("HTTP_PROXY".to_string(), proxy_url.to_string()),
            ("HTTPS_PROXY".to_string(), proxy_url.to_string()),
            ("http_proxy".to_string(), proxy_url.to_string()),
            ("https_proxy".to_string(), proxy_url.to_string()),
            ("REQUESTS_CA_BUNDLE".to_string(), ca_cert_path.to_string_lossy().to_string()),
            ("SSL_CERT_FILE".to_string(), ca_cert_path.to_string_lossy().to_string()),
            ("PIP_CERT".to_string(), ca_cert_path.to_string_lossy().to_string()),
        ]
    }
}

impl PyPIRegistry {
    fn handle_json_response(&self, body: &[u8]) -> ResponseAction {
        let mut json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return ResponseAction::Block,
        };

        let mut quarantined_versions = Vec::new();

        let parsed_releases: BTreeMap<String, Vec<PyPIFile>> = match json.get("releases") {
            Some(r) => match serde_json::from_value::<BTreeMap<String, Vec<PyPIFile>>>(r.clone()) {
                Ok(r) => r,
                Err(_) => return ResponseAction::Block,
            },
            None => return ResponseAction::Passthrough,
        };

        let mut to_remove = Vec::new();
        for (version, files) in &parsed_releases {
            if files.is_empty() {
                continue;
            }
            let ts = Self::version_timestamp(files);
            if !self.checker.is_old_enough(ts) {
                to_remove.push(version.clone());
                quarantined_versions.push(version.clone());
            }
        }

        {
            let mut state = self.state.lock().expect("pypi state lock");
            state.packages_checked += 1;
        }

        if !to_remove.is_empty()
            && let Some(releases) = json.get_mut("releases").and_then(|r| r.as_object_mut())
        {
            for version in &to_remove {
                releases.remove(version);
            }
        }

        if let Some(urls) = json.get_mut("urls").and_then(|u| u.as_array_mut()) {
            urls.retain(|entry| {
                let filename = entry.get("filename").and_then(|f| f.as_str()).unwrap_or("");
                let fake_url = format!("https://files.pythonhosted.org/packages/{}", filename);
                let Ok(url) = Url::parse(&fake_url) else {
                    return true;
                };
                let Some(version) = Self::parse_version_from_url(&url) else {
                    return true;
                };
                !to_remove.contains(&version)
            });
        }

        if !to_remove.is_empty() {
            {
                let mut state = self.state.lock().expect("pypi state lock");
                state.quarantined.push(QuarantinedPackage {
                    name: json
                        .get("info")
                        .and_then(|i| i.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    quarantined_versions,
                });
            }
            match serde_json::to_vec(&json) {
                Ok(new_body) => ResponseAction::Rewrite { body: new_body },
                Err(_) => ResponseAction::Block,
            }
        } else {
            ResponseAction::Passthrough
        }
    }
}

fn parse_wheel_version(base: &str) -> Option<String> {
    let first_dash = base.find('-')?;
    let rest = &base[first_dash + 1..];
    let second_dash = rest.find('-').unwrap_or(rest.len());
    let version = &rest[..second_dash];
    if version == "latest" || version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn load_json_fixture() -> Vec<u8> {
        std::fs::read("tests/data/pypi/requests.json").expect("fixture missing")
    }

    #[test]
    fn pypi_rewrite_json_against_real_metadata() {
        let registry = PyPIRegistry::new(Rules::new(365 * 24));

        let body = load_json_fixture();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let url = Url::parse("https://pypi.org/pypi/requests/json").unwrap();

        let original: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let original_count = original["releases"].as_object().unwrap().len();

        let action = registry.handle_response(&url, 200, &headers, &body);

        let new_body = match action {
            ResponseAction::Rewrite { body } => body,
            _ => panic!("expected rewrite, got {:?}", action),
        };

        let result: serde_json::Value = serde_json::from_slice(&new_body).unwrap();
        let result_count = result["releases"].as_object().map(|o| o.len()).unwrap_or(0);

        assert!(
            result_count < original_count,
            "should have stripped some versions ({} vs {})",
            result_count,
            original_count,
        );

        assert_eq!(
            result["info"]["name"].as_str(),
            Some("requests"),
            "package info should be preserved",
        );

        let stats = registry.stats();
        assert_eq!(stats.packages_checked, 1);
    }

    #[test]
    fn pypi_passthrough_for_tarball() {
        let registry = PyPIRegistry::new(Rules::new(48));
        let url = Url::parse("https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz").unwrap();
        let action = registry.handle_response(&url, 200, &HeaderMap::new(), b"data");
        assert!(matches!(action, ResponseAction::Passthrough));
    }

    #[test]
    fn pypi_blocks_compressed_metadata() {
        let registry = PyPIRegistry::new(Rules::new(48));
        let url = Url::parse("https://pypi.org/pypi/requests/json").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("content-encoding", "gzip".parse().unwrap());
        let action = registry.handle_response(&url, 200, &headers, b"compressed data");
        assert!(matches!(action, ResponseAction::Block));
    }

    #[test]
    fn pypi_blocks_html_simple_index() {
        let registry = PyPIRegistry::new(Rules::new(48));
        let url = Url::parse("https://pypi.org/simple/requests/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        let action = registry.handle_response(&url, 200, &headers, b"<html><body><a href=\"foo.tar.gz\">foo</a></body></html>");
        assert!(matches!(action, ResponseAction::Block));
    }

    #[test]
    fn pypi_blocks_unknown_content_type() {
        let registry = PyPIRegistry::new(Rules::new(48));
        let url = Url::parse("https://pypi.org/pypi/requests/json").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        let action = registry.handle_response(&url, 200, &headers, b"some text");
        assert!(matches!(action, ResponseAction::Block));
    }

    #[test]
    fn version_timestamp_uses_latest_file() {
        let files = vec![
            PyPIFile {
                filename: "pkg-1.0.tar.gz".to_string(),
                upload_time_iso_8601: Some("2020-01-01T00:00:00Z".to_string()),
                digests: None,
                md5_digest: None,
                yanked: false,
                yanked_reason: None,
                packagetype: "sdist".to_string(),
                size: None,
                requires_python: None,
                extra: Map::new(),
            },
            PyPIFile {
                filename: "pkg-1.0-py3-none-any.whl".to_string(),
                upload_time_iso_8601: Some("2025-06-01T00:00:00Z".to_string()),
                digests: None,
                md5_digest: None,
                yanked: false,
                yanked_reason: None,
                packagetype: "bdist_wheel".to_string(),
                size: None,
                requires_python: None,
                extra: Map::new(),
            },
        ];
        let ts = PyPIRegistry::version_timestamp(&files).unwrap();
        assert_eq!(ts, "2025-06-01T00:00:00Z".parse::<Timestamp>().unwrap());
    }
}

#[cfg(test)]
mod decide_tests {
    use test_case::test_case;
    use crate::registry::{Ecosystem, InterceptDecision, ToolName};

    fn decide(tool: &str, args: &[&str]) -> InterceptDecision {
        let tool: ToolName = tool.parse().unwrap();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Ecosystem::Python.decide(tool, args)
    }

    #[test_case("uv", &["run", "python", "script.py"] => true)]
    #[test_case("uv", &["pip", "install", "requests"] => true)]
    #[test_case("uv", &["sync"] => true)]
    #[test_case("uv", &["pip", "list"] => false)]
    #[test_case("pip", &["install", "requests"] => true)]
    #[test_case("pip", &["list"] => false)]
    #[test_case("poetry", &["build"] => false)]
    fn python_intercepts(tool: &str, args: &[&str]) -> bool {
        matches!(decide(tool, args), InterceptDecision::Intercept(_))
    }

    #[test_case("uv", &["run", "python", "script.py"], &["--frozen", "run", "python", "script.py"])]
    #[test_case("uv", &["pip", "install", "requests"], &["pip", "install", "requests"])]
    fn python_intercepted_args(tool: &str, args: &[&str], expected: &[&str]) {
        let InterceptDecision::Intercept(got) = decide(tool, args) else {
            panic!("{tool} {args:?}: expected Intercept");
        };
        assert_eq!(got, expected.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }
}
