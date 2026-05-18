use std::sync::Mutex;

use http::HeaderMap;
use serde_json::Value;
use tracing::debug;
use url::Url;

use super::{BlockedItem, Registry, RegistryStats, ResponseAction};
use crate::rule::Rules;

pub struct PyPIRegistry {
    cutoff: jiff::Timestamp,
    state: Mutex<PyPIState>,
}

struct PyPIState {
    packages_checked: usize,
    quarantined: Vec<String>,
    blocked: Vec<BlockedItem>,
}

const KNOWN_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "pythonhosted.org",
];

impl PyPIRegistry {
    pub fn new(rules: Rules) -> Self {
        let cutoff = jiff::Timestamp::now() - jiff::Span::new().hours(rules.min_age_hours() as i64);
        PyPIRegistry {
            cutoff,
            state: Mutex::new(PyPIState {
                packages_checked: 0,
                quarantined: Vec::new(),
                blocked: Vec::new(),
            }),
        }
    }

    fn is_metadata_url(&self, url: &Url) -> bool {
        let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        if segments.len() >= 2 && segments[0] == "simple" {
            return true;
        }
        segments.len() >= 3
            && segments[0] == "pypi"
            && segments.last() == Some(&"json")
    }

    fn check_version(&self, _version: &str, published_at: Option<jiff::Timestamp>) -> bool {
        matches!(published_at, Some(t) if t <= self.cutoff)
    }

    fn parse_package_from_url(&self, url: &Url) -> Option<PackageRef> {
        let raw = url.path_segments()?.next_back()?;
        let filename = percent_decode_str(raw);

        if let Some(stripped) = filename.strip_suffix(".whl.metadata") {
            return parse_wheel(stripped);
        }
        if let Some(stripped) = filename.strip_suffix(".whl") {
            return parse_wheel(stripped);
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
                let name = &stripped[..last_dash];
                let version = &stripped[last_dash + 1..];
                if version == "latest" || name.is_empty() || version.is_empty() {
                    return None;
                }
                return Some(PackageRef {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                });
            }
        }

        None
    }
}

struct PackageRef {
    #[allow(dead_code)]
    name: String,
    version: Option<String>,
}

impl Registry for PyPIRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn prepare_request(&self, url: &Url, headers: &mut HeaderMap) {
        if !self.is_metadata_url(url) {
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
        if !self.is_metadata_url(url) {
            return ResponseAction::Passthrough;
        }

        let content_encoding = response_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");

        if content_encoding != "none" && content_encoding != "identity" {
            debug!("compressed pypi metadata response, blocking");
            return ResponseAction::Block;
        }

        let content_type = response_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("html") {
            return self.handle_html_response(body);
        }
        if content_type.contains("json") {
            return self.handle_json_response(body);
        }

        ResponseAction::Passthrough
    }

    fn stats(&self) -> RegistryStats {
        let state = self.state.lock().unwrap();
        RegistryStats {
            packages_checked: state.packages_checked,
            downloads_blocked: state.blocked.clone(),
            ..Default::default()
        }
    }
}

impl PyPIRegistry {
    fn handle_html_response(&self, body: &[u8]) -> ResponseAction {
        let html = String::from_utf8_lossy(body);
        let mut modified = false;
        let mut result = String::new();
        let mut remaining = html.as_ref();

        while let Some(anchor_start) = remaining.find("<a ") {
            result.push_str(&remaining[..anchor_start]);
            remaining = &remaining[anchor_start..];
            let anchor_end = match remaining.find("</a>") {
                Some(pos) => pos,
                None => break,
            };
            let anchor = &remaining[..anchor_end + 4];

            if let Some(href) = extract_href(anchor)
                && let Ok(url) = Url::parse(&format!("https://files.pythonhosted.org{}", href))
                && let Some(pkg) = self.parse_package_from_url(&url)
                && let Some(version) = &pkg.version
                && !self.check_version(version, None)
            {
                modified = true;
                self.state.lock().unwrap().quarantined.push(version.clone());
                remaining = &remaining[anchor_end + 4..];
                continue;
            }

            result.push_str(anchor);
            remaining = &remaining[anchor_end + 4..];
        }
        result.push_str(remaining);

        if modified {
            self.state.lock().unwrap().packages_checked += 1;
            ResponseAction::Rewrite {
                body: result.into_bytes(),
            }
        } else {
            ResponseAction::Passthrough
        }
    }

    fn handle_json_response(&self, body: &[u8]) -> ResponseAction {
        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return ResponseAction::Passthrough,
        };
        let mut modified = false;

        if let Some(files) = json.get_mut("files").and_then(|f| f.as_array_mut()) {
            let this = self;
            files.retain(|entry| {
                let filename = entry.get("filename").and_then(|f| f.as_str()).unwrap_or("");
                let fake_url = format!("https://files.pythonhosted.org/packages/{}", filename);
                if let Ok(url) = Url::parse(&fake_url)
                    && let Some(pkg) = this.parse_package_from_url(&url)
                    && let Some(version) = pkg.version
                    && !this.check_version(&version, None)
                {
                    modified = true;
                    return false;
                }
                true
            });
        }

        if let Some(releases) = json.get_mut("releases").and_then(|r| r.as_object_mut()) {
            let keys: Vec<String> = releases.keys().cloned().collect();
            for version in keys {
                if !self.check_version(&version, None) {
                    releases.remove(&version);
                    modified = true;
                }
            }
        }

        if modified {
            self.state.lock().unwrap().packages_checked += 1;
            match serde_json::to_vec(&json) {
                Ok(new_body) => ResponseAction::Rewrite { body: new_body },
                Err(_) => ResponseAction::Passthrough,
            }
        } else {
            ResponseAction::Passthrough
        }
    }
}

fn parse_wheel(base: &str) -> Option<PackageRef> {
    let first_dash = base.find('-')?;
    let name = &base[..first_dash];
    let rest = &base[first_dash + 1..];
    let second_dash = rest.find('-').unwrap_or(rest.len());
    let version = &rest[..second_dash];
    if version == "latest" || name.is_empty() || version.is_empty() {
        return None;
    }
    Some(PackageRef {
        name: name.to_string(),
        version: Some(version.to_string()),
    })
}

fn percent_decode_str(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16)
        {
            result.push(byte);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

fn extract_href(anchor: &str) -> Option<String> {
    let href_start = anchor.find("href=\"")? + 6;
    let href_end = anchor[href_start..].find('"')?;
    Some(anchor[href_start..href_start + href_end].to_string())
}
