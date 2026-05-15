use http::HeaderMap;
use serde_json::Value;
use url::Url;

use super::{PackageRef, Registry, VersionInfo};
use crate::rule::RuleVerdict;

pub struct PyPIRegistry;

const KNOWN_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "pythonhosted.org",
];

impl Registry for PyPIRegistry {
    fn known_hosts(&self) -> &[&str] {
        KNOWN_HOSTS
    }

    fn is_metadata_url(&self, url: &Url) -> bool {
        let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        if segments.len() >= 2 && segments[0] == "simple" {
            return true;
        }
        segments.len() >= 3
            && segments[0] == "pypi"
            && segments.last().map_or(false, |s| *s == "json")
    }

    fn parse_package_from_url(&self, url: &Url) -> Option<PackageRef> {
        let raw = url.path_segments()?.last()?;
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

    fn modify_request_headers(&self, headers: &mut HeaderMap) {
        headers.remove("if-none-match");
        headers.remove("if-modified-since");
    }

    fn modify_metadata_response(
        &self,
        body: &[u8],
        headers: &HeaderMap,
        check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
    ) -> Option<Vec<u8>> {
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("html") {
            return modify_html_response(body, headers, check_version);
        }
        if content_type.contains("json") {
            return modify_json_response(body, headers, check_version);
        }
        None
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
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

fn modify_html_response(
    body: &[u8],
    headers: &HeaderMap,
    check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
) -> Option<Vec<u8>> {
    let html = String::from_utf8_lossy(body);
    let mut modified = false;
    let mut result = String::new();
    let mut remaining = html.as_ref();

    while let Some(anchor_start) = remaining.find("<a ") {
        result.push_str(&remaining[..anchor_start]);
        remaining = &remaining[anchor_start..];
        let anchor_end = remaining.find("</a>")?;
        let anchor = &remaining[..anchor_end + 4];

        if let Some(href) = extract_href(anchor) {
            let fake_url = format!("https://files.pythonhosted.org{}", href);
            if let Ok(url) = Url::parse(&fake_url) {
                if let Some(pkg) = PyPIRegistry.parse_package_from_url(&url) {
                    if let Some(version) = &pkg.version {
                        let info = VersionInfo {
                            name: pkg.name.clone(),
                            version: version.clone(),
                            published_at: None,
                            ecosystem: super::Ecosystem::Python,
                        };
                        if let RuleVerdict::StripVersion = check_version(&info) {
                            modified = true;
                            remaining = &remaining[anchor_end + 4..];
                            continue;
                        }
                    }
                }
            }
        }

        result.push_str(anchor);
        remaining = &remaining[anchor_end + 4..];
    }
    result.push_str(remaining);

    if modified {
        clear_caching_headers(headers);
        Some(result.into_bytes())
    } else {
        None
    }
}

fn extract_href(anchor: &str) -> Option<String> {
    let href_start = anchor.find("href=\"")? + 6;
    let href_end = anchor[href_start..].find('"')?;
    Some(anchor[href_start..href_start + href_end].to_string())
}

fn modify_json_response(
    body: &[u8],
    headers: &HeaderMap,
    check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
) -> Option<Vec<u8>> {
    let mut json: Value = serde_json::from_slice(body).ok()?;
    let mut modified = false;

    if let Some(files) = json.get_mut("files").and_then(|f| f.as_array_mut()) {
        files.retain(|entry| {
            let filename = entry.get("filename").and_then(|f| f.as_str()).unwrap_or("");
            let fake_url = format!("https://files.pythonhosted.org/packages/{}", filename);
            if let Ok(url) = Url::parse(&fake_url) {
                if let Some(pkg) = PyPIRegistry.parse_package_from_url(&url) {
                    if let Some(version) = pkg.version {
                        let info = VersionInfo {
                            name: pkg.name.clone(),
                            version,
                            published_at: None,
                            ecosystem: super::Ecosystem::Python,
                        };
                        if let RuleVerdict::StripVersion = check_version(&info) {
                            modified = true;
                            return false;
                        }
                    }
                }
            }
            true
        });
    }

    if let Some(releases) = json.get_mut("releases").and_then(|r| r.as_object_mut()) {
        let keys: Vec<String> = releases.keys().cloned().collect();
        for version in keys {
            let info = VersionInfo {
                name: String::new(),
                version: version.clone(),
                published_at: None,
                ecosystem: super::Ecosystem::Python,
            };
            if let RuleVerdict::StripVersion = check_version(&info) {
                releases.remove(&version);
                modified = true;
            }
        }
    }

    if modified {
        clear_caching_headers(headers);
        Some(serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec()))
    } else {
        None
    }
}

fn clear_caching_headers(headers: &HeaderMap) {
    let _ = headers;
}
