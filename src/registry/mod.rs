pub mod npm;
pub mod pypi;

use http::HeaderMap;
use jiff::Timestamp;
use url::Url;

use crate::rule::Rules;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ecosystem {
    Javascript,
    Python,
}

#[derive(Debug, Clone)]
pub enum ResponseAction {
    Passthrough,
    Rewrite { body: Vec<u8> },
    Block,
}

#[derive(Debug, Clone, Default)]
pub struct RegistryStats {
    pub connections_tunneled: usize,
    pub packages_checked: usize,
    pub packages_quarantined: Vec<QuarantinedPackage>,
    pub downloads_blocked: Vec<BlockedItem>,
}

impl RegistryStats {
    pub fn active(&self) -> bool {
        self.packages_checked > 0 || self.connections_tunneled > 0
    }
}

#[derive(Debug, Clone)]
pub struct QuarantinedPackage {
    pub name: String,
    pub quarantined_versions: Vec<QuarantinedVersion>,
}

#[derive(Debug, Clone)]
pub struct QuarantinedVersion {
    pub version: String,
    #[allow(dead_code)]
    pub published_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct BlockedItem {
    pub package: String,
    pub version: String,
}

pub trait Registry: Send + Sync {
    fn known_hosts(&self) -> &[&str];
    fn prepare_request(&self, url: &Url, headers: &mut HeaderMap);
    fn handle_response(
        &self,
        url: &Url,
        status: u16,
        response_headers: &HeaderMap,
        body: &[u8],
    ) -> ResponseAction;
    fn stats(&self) -> RegistryStats;
}

impl Ecosystem {
    pub fn registry(&self, rules: Rules) -> Box<dyn Registry> {
        match self {
            Ecosystem::Javascript => Box::new(npm::NpmRegistry::new(rules)),
            Ecosystem::Python => Box::new(pypi::PyPIRegistry::new(rules)),
        }
    }
}
