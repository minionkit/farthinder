use jiff::Timestamp;

use crate::registry::VersionInfo;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleVerdict {
    Allow,
    Block(String),
    StripVersion,
}

#[derive(Debug, Clone, Copy)]
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
            Some(t) if t <= self.cutoff => RuleVerdict::Allow,
            _ => RuleVerdict::StripVersion,
        }
    }

    #[cfg(test)]
    pub fn cutoff(&self) -> Timestamp {
        self.cutoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Ecosystem;

    fn info(name: &str, version: &str, published_at: Option<&str>) -> VersionInfo {
        VersionInfo {
            name: name.to_string(),
            version: version.to_string(),
            published_at: published_at.map(|s| s.parse().unwrap()),
            ecosystem: Ecosystem::Javascript,
        }
    }

    #[test]
    fn missing_timestamp_stripped() {
        let rule = MinimumAge::new(jiff::Span::new().hours(48));
        let info = info("sketchy", "1.0.0", None);
        assert_eq!(rule.check(&info), RuleVerdict::StripVersion);
    }
}
