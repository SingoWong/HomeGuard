//! DNS domain filter interface
//!
//! This module provides a simple interface for DNS filtering.
//! The actual rule matching logic (Trie, Aho-Corasick) will be
//! implemented in Phase 3 (Rule Engine) and Phase 6 (Parental Control).
//!
//! Phase 2 provides only a basic HashSet implementation for testing.

use std::collections::HashSet;

/// DNS filter trait - will be implemented by Rule Engine in Phase 3
pub trait DnsFilterTrait: Send + Sync {
    /// Check if a domain should be blocked
    fn is_blocked(&self, domain: &str) -> bool;
}

/// Simple DNS filter using exact match only
///
/// This is a temporary implementation for Phase 2 testing.
/// The full implementation with Trie and Aho-Corasick will be in Phase 3.
pub struct SimpleDnsFilter {
    /// Exact domain blocklist
    blocklist: HashSet<String>,
}

impl SimpleDnsFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self {
            blocklist: HashSet::new(),
        }
    }

    /// Add a domain to blocklist (exact match only)
    pub fn add_blocked_domain(&mut self, domain: &str) {
        self.blocklist.insert(domain.to_lowercase());
    }

    /// Get number of blocked domains
    pub fn len(&self) -> usize {
        self.blocklist.len()
    }

    /// Check if filter is empty
    pub fn is_empty(&self) -> bool {
        self.blocklist.is_empty()
    }
}

impl Default for SimpleDnsFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsFilterTrait for SimpleDnsFilter {
    fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let domain = domain.trim_end_matches('.');
        self.blocklist.contains(domain)
    }
}

/// No-op filter that allows everything
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
    fn test_simple_filter() {
        let mut filter = SimpleDnsFilter::new();
        filter.add_blocked_domain("blocked.com");
        filter.add_blocked_domain("bad.org");

        assert!(filter.is_blocked("blocked.com"));
        assert!(filter.is_blocked("BLOCKED.COM")); // Case insensitive
        assert!(filter.is_blocked("blocked.com.")); // Trailing dot
        assert!(filter.is_blocked("bad.org"));
        assert!(!filter.is_blocked("allowed.com"));
        assert!(!filter.is_blocked("www.blocked.com")); // No suffix match in simple filter
    }

    #[test]
    fn test_allow_all_filter() {
        let filter = AllowAllFilter;
        assert!(!filter.is_blocked("anything.com"));
        assert!(!filter.is_blocked("blocked.com"));
    }
}
