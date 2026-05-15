use registry::VersionInfo;
use jiff::Timestamp;

use crate::registry;

#[derive(Debug, PartialEq)]
pub enum RuleVerdict {
    Allow,
    Block(String),
    StripVersion,
}

pub struct MinimumAge {
    cutoff: Timestamp,
}

impl MinimumAge {
    pub fn new(minimum_age: jiff::Span) -> Self {
        Self {
            cutoff: Timestamp::now() - minimum_age,
        }
    }

    pub fn check(&self, info: &VersionInfo) -> RuleVerdict {
        match info.published_at {
            Some(t) if t > self.cutoff => RuleVerdict::StripVersion,
            _ => RuleVerdict::Allow,
        }
    }
}
