//! DNS domain filter interface
//!
//! This module provides the DNS filtering trait interface.
//! The actual filtering is implemented by:
//! - RuleEngine (Phase 3) - Domain/IP-based rules
//! - ParentalController (Phase 6) - Device-specific blocklists and schedules

/// DNS filter trait - implemented by RuleEngine and ParentalController
pub trait DnsFilterTrait: Send + Sync {
    /// Check if a domain should be blocked
    fn is_blocked(&self, domain: &str) -> bool;
}

/// No-op filter that allows everything (used when parental control is disabled)
pub struct AllowAllFilter;

impl DnsFilterTrait for AllowAllFilter {
    fn is_blocked(&self, _domain: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_all_filter() {
        let filter = AllowAllFilter;
        assert!(!filter.is_blocked("anything.com"));
        assert!(!filter.is_blocked("blocked.com"));
    }
}
