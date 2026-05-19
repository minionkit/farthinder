pub mod npm;
pub mod pypi;

use std::path::Path;

use http::HeaderMap;
use jiff::Timestamp;
use strum::{EnumString, Display, EnumIter};
use tracing::debug;
use url::Url;

use crate::rule::Rules;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ecosystem {
    Javascript,
    Python,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display, EnumIter)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum ToolName {
    Bun,
    Bunx,
    Npm,
    Npx,
    Pnpm,
    Yarn,
    Pip,
    Pip3,
    Uv,
    Uvx,
    Pipx,
    Poetry,
}

impl ToolName {
    pub fn ecosystem(&self) -> Option<Ecosystem> {
        match self {
            ToolName::Bun
            | ToolName::Bunx
            | ToolName::Npm
            | ToolName::Npx
            | ToolName::Pnpm
            | ToolName::Yarn => Some(Ecosystem::Javascript),
            ToolName::Pip
            | ToolName::Pip3
            | ToolName::Uv
            | ToolName::Uvx
            | ToolName::Pipx
            | ToolName::Poetry => Some(Ecosystem::Python),
        }
    }
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
    pub quarantined_versions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BlockedItem {
    pub package: String,
    pub version: String,
}

pub enum InterceptDecision {
    Passthrough(Vec<String>),
    Intercept(Vec<String>),
}

impl Ecosystem {
    pub fn decide(&self, tool: ToolName, args: Vec<String>) -> InterceptDecision {
        match self {
            Ecosystem::Javascript => npm::decide(tool, args),
            Ecosystem::Python => pypi::decide(tool, args),
        }
    }

    pub fn registry(&self, rules: Rules) -> Box<dyn Registry> {
        match self {
            Ecosystem::Javascript => Box::new(npm::NpmRegistry::new(rules)),
            Ecosystem::Python => Box::new(pypi::PyPIRegistry::new(rules)),
        }
    }
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
    fn proxy_env_vars(&self, proxy_url: &str, ca_cert_path: &Path) -> Vec<(String, String)>;
}

pub(crate) struct CutoffChecker {
    cutoff: Timestamp,
}

impl CutoffChecker {
    pub fn new(min_age_hours: u32) -> Self {
        Self {
            cutoff: Timestamp::now() - jiff::Span::new().hours(min_age_hours as i64),
        }
    }

    pub fn is_old_enough(&self, ts: Option<Timestamp>) -> bool {
        matches!(ts, Some(t) if t <= self.cutoff)
    }

    #[cfg(test)]
    pub fn cutoff(&self) -> Timestamp {
        self.cutoff
    }
}

#[derive(Debug, Default)]
pub(crate) struct RegistryState {
    pub packages_checked: usize,
    pub quarantined: Vec<QuarantinedPackage>,
}

fn reject_compressed(response_headers: &HeaderMap) -> Option<ResponseAction> {
    let content_encoding = response_headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");

    if content_encoding != "none" && content_encoding != "identity" {
        debug!("compressed metadata response, blocking");
        return Some(ResponseAction::Block);
    }
    None
}
