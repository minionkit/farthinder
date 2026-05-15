use http::HeaderMap;
use jiff::Timestamp;
use serde_json::Value;
use url::Url;

use super::{PackageRef, Registry, VersionInfo};
use crate::rule::RuleVerdict;

pub struct NpmRegistry;

const KNOWN_HOSTS: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];

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
        if let Some(accept) = headers.get("accept") {
            if accept
                .to_str()
                .unwrap_or("")
                .contains("application/vnd.npm.install-v1+json")
            {
                headers.insert("accept", "application/json".parse().unwrap());
            }
        }
    }

    fn modify_metadata_response(
        &self,
        body: &[u8],
        headers: &HeaderMap,
        check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
    ) -> Option<Vec<u8>> {
        let mut json: Value = serde_json::from_slice(body).ok()?;
        let time_map = json.get("time")?.as_object()?.clone();
        let name = json.get("name")?.as_str()?.to_string();

        let mut modified = false;
        let mut versions_to_remove = Vec::new();

        for (version, ts_val) in &time_map {
            if version == "created" || version == "modified" {
                continue;
            }
            let ts_str = ts_val.as_str()?;
            let published_at: Option<Timestamp> = ts_str.parse().ok();
            let info = VersionInfo {
                name: name.clone(),
                version: version.clone(),
                published_at,
                ecosystem: super::Ecosystem::Javascript,
            };
            if let RuleVerdict::StripVersion = check_version(&info) {
                versions_to_remove.push(version.clone());
                modified = true;
            }
        }

        for version in &versions_to_remove {
            if let Some(time) = json.get_mut("time").and_then(|t| t.as_object_mut()) {
                time.remove(version);
            }
            if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_object_mut()) {
                versions.remove(version);
            }
            if let Some(tags) = json.get_mut("dist-tags").and_then(|t| t.as_object_mut()) {
                tags.retain(|_, v| v.as_str().map_or(true, |tag_ver| tag_ver != version));
            }
        }

        let had_latest = json
            .get("dist-tags")
            .and_then(|t| t.get("latest"))
            .is_some();
        if had_latest && json.get("dist-tags").and_then(|t| t.get("latest")).is_none() {
            if let Some(latest) = recalculate_latest(&json) {
                json["dist-tags"]["latest"] = Value::String(latest);
            }
        }

        if modified {
            clear_caching_headers(headers);
            Some(serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec()))
        } else {
            None
        }
    }
}

fn recalculate_latest(json: &Value) -> Option<String> {
    let time = json.get("time")?.as_object()?;
    let mut best: Option<(String, String)> = None;
    for (ver, ts) in time {
        if ver == "created" || ver == "modified" || ver.contains('-') {
            continue;
        }
        let ts_str = ts.as_str()?;
        if best
            .as_ref()
            .map_or(true, |(_, best_ts)| ts_str > best_ts.as_str())
        {
            best = Some((ver.clone(), ts_str.to_string()));
        }
    }
    best.map(|(v, _)| v)
}

fn clear_caching_headers(headers: &HeaderMap) {
    // TODO: remove etag, last-modified, content-length when rewriting response
    let _ = headers;
}
