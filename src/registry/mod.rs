pub mod npm;
pub mod pypi;

use http::HeaderMap;
use jiff::Timestamp;
use url::Url;

use crate::rule::RuleVerdict;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ecosystem {
    Javascript,
    Python,
}

pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
}

pub struct VersionInfo {
    pub name: String,
    pub version: String,
    pub published_at: Option<Timestamp>,
    pub ecosystem: Ecosystem,
}

pub trait Registry: Send + Sync {
    fn known_hosts(&self) -> &[&str];
    fn is_metadata_url(&self, url: &Url) -> bool;
    fn parse_package_from_url(&self, url: &Url) -> Option<PackageRef>;
    fn modify_request_headers(&self, headers: &mut HeaderMap);
    fn modify_metadata_response(
        &self,
        body: &[u8],
        headers: &HeaderMap,
        check_version: &dyn Fn(&VersionInfo) -> RuleVerdict,
    ) -> Option<Vec<u8>>;
}

impl Ecosystem {
    pub fn registry(&self) -> Box<dyn Registry> {
        match self {
            Ecosystem::Javascript => Box::new(npm::NpmRegistry),
            Ecosystem::Python => Box::new(pypi::PyPIRegistry),
        }
    }

    pub fn matches_host(&self, host: &str) -> bool {
        self.registry().known_hosts().iter().any(|h| host == *h)
    }
}
