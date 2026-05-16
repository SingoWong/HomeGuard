//! IP CIDR matcher
//!
//! Provides IPv4 and IPv6 CIDR matching.
//! Uses linear scan for simplicity - suitable for home use with small rule sets.
//! For large rule sets, consider using a Patricia trie.

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP CIDR matcher
pub struct IpMatcher {
    /// IPv4 CIDR rules: (network, rule_index)
    ipv4_cidrs: Vec<(Ipv4Net, usize)>,

    /// IPv6 CIDR rules: (network, rule_index)
    ipv6_cidrs: Vec<(Ipv6Net, usize)>,
}

impl IpMatcher {
    /// Create a new empty IP matcher
    pub fn new() -> Self {
        Self {
            ipv4_cidrs: Vec::new(),
            ipv6_cidrs: Vec::new(),
        }
    }

    /// Build IP matcher from CIDR rules
    pub fn build(ipv4_rules: Vec<(Ipv4Net, usize)>, ipv6_rules: Vec<(Ipv6Net, usize)>) -> Self {
        Self {
            ipv4_cidrs: ipv4_rules,
            ipv6_cidrs: ipv6_rules,
        }
    }

    /// Add an IPv4 CIDR rule
    pub fn add_ipv4(&mut self, cidr: Ipv4Net, rule_index: usize) {
        self.ipv4_cidrs.push((cidr, rule_index));
    }

    /// Add an IPv6 CIDR rule
    pub fn add_ipv6(&mut self, cidr: Ipv6Net, rule_index: usize) {
        self.ipv6_cidrs.push((cidr, rule_index));
    }

    /// Match an IPv4 address
    ///
    /// Returns the first matching rule index (rules are checked in order)
    pub fn match_ipv4(&self, ip: Ipv4Addr) -> Option<usize> {
        for (cidr, index) in &self.ipv4_cidrs {
            if cidr.contains(&ip) {
                return Some(*index);
            }
        }
        None
    }

    /// Match an IPv6 address
    ///
    /// Returns the first matching rule index (rules are checked in order)
    pub fn match_ipv6(&self, ip: Ipv6Addr) -> Option<usize> {
        for (cidr, index) in &self.ipv6_cidrs {
            if cidr.contains(&ip) {
                return Some(*index);
            }
        }
        None
    }

    /// Match any IP address (IPv4 or IPv6)
    pub fn match_ip(&self, ip: IpAddr) -> Option<usize> {
        match ip {
            IpAddr::V4(ipv4) => self.match_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.match_ipv6(ipv6),
        }
    }

    /// Get all matching rule indices for an IPv4 address
    pub fn match_all_ipv4(&self, ip: Ipv4Addr) -> Vec<usize> {
        self.ipv4_cidrs
            .iter()
            .filter(|(cidr, _)| cidr.contains(&ip))
            .map(|(_, index)| *index)
            .collect()
    }

    /// Get all matching rule indices for an IPv6 address
    pub fn match_all_ipv6(&self, ip: Ipv6Addr) -> Vec<usize> {
        self.ipv6_cidrs
            .iter()
            .filter(|(cidr, _)| cidr.contains(&ip))
            .map(|(_, index)| *index)
            .collect()
    }

    /// Get all matching rule indices for any IP address
    pub fn match_all(&self, ip: IpAddr) -> Vec<usize> {
        match ip {
            IpAddr::V4(ipv4) => self.match_all_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.match_all_ipv6(ipv6),
        }
    }

    /// Get the number of IPv4 CIDR rules
    pub fn ipv4_count(&self) -> usize {
        self.ipv4_cidrs.len()
    }

    /// Get the number of IPv6 CIDR rules
    pub fn ipv6_count(&self) -> usize {
        self.ipv6_cidrs.len()
    }

    /// Get the total number of rules
    pub fn count(&self) -> usize {
        self.ipv4_cidrs.len() + self.ipv6_cidrs.len()
    }

    /// Check if the matcher is empty
    pub fn is_empty(&self) -> bool {
        self.ipv4_cidrs.is_empty() && self.ipv6_cidrs.is_empty()
    }
}

impl Default for IpMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr_match() {
        let matcher = IpMatcher::build(
            vec![
                ("192.168.0.0/16".parse().unwrap(), 0),
                ("10.0.0.0/8".parse().unwrap(), 1),
                ("172.16.0.0/12".parse().unwrap(), 2),
            ],
            vec![],
        );

        // 192.168.x.x should match rule 0
        assert_eq!(
            matcher.match_ipv4("192.168.1.1".parse().unwrap()),
            Some(0)
        );
        assert_eq!(
            matcher.match_ipv4("192.168.255.255".parse().unwrap()),
            Some(0)
        );

        // 10.x.x.x should match rule 1
        assert_eq!(matcher.match_ipv4("10.0.0.1".parse().unwrap()), Some(1));
        assert_eq!(
            matcher.match_ipv4("10.255.255.255".parse().unwrap()),
            Some(1)
        );

        // 172.16.x.x - 172.31.x.x should match rule 2
        assert_eq!(
            matcher.match_ipv4("172.16.0.1".parse().unwrap()),
            Some(2)
        );
        assert_eq!(
            matcher.match_ipv4("172.31.255.255".parse().unwrap()),
            Some(2)
        );

        // Public IPs should not match
        assert_eq!(matcher.match_ipv4("8.8.8.8".parse().unwrap()), None);
        assert_eq!(matcher.match_ipv4("1.1.1.1".parse().unwrap()), None);
    }

    #[test]
    fn test_ipv4_single_ip() {
        let matcher = IpMatcher::build(
            vec![("8.8.8.8/32".parse().unwrap(), 0)],
            vec![],
        );

        assert_eq!(matcher.match_ipv4("8.8.8.8".parse().unwrap()), Some(0));
        assert_eq!(matcher.match_ipv4("8.8.8.9".parse().unwrap()), None);
    }

    #[test]
    fn test_ipv6_cidr_match() {
        let matcher = IpMatcher::build(
            vec![],
            vec![
                ("2001:db8::/32".parse().unwrap(), 0),
                ("fe80::/10".parse().unwrap(), 1),
            ],
        );

        // 2001:db8:: prefix should match rule 0
        assert_eq!(
            matcher.match_ipv6("2001:db8::1".parse().unwrap()),
            Some(0)
        );
        assert_eq!(
            matcher.match_ipv6("2001:db8:1234:5678::1".parse().unwrap()),
            Some(0)
        );

        // Link-local should match rule 1
        assert_eq!(
            matcher.match_ipv6("fe80::1".parse().unwrap()),
            Some(1)
        );

        // Other addresses should not match
        assert_eq!(
            matcher.match_ipv6("2001:4860:4860::8888".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_mixed_ip_match() {
        let matcher = IpMatcher::build(
            vec![("192.168.0.0/16".parse().unwrap(), 0)],
            vec![("2001:db8::/32".parse().unwrap(), 1)],
        );

        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(matcher.match_ip(ipv4), Some(0));
        assert_eq!(matcher.match_ip(ipv6), Some(1));
    }

    #[test]
    fn test_match_order() {
        // First matching rule should win
        let matcher = IpMatcher::build(
            vec![
                ("192.168.1.0/24".parse().unwrap(), 0), // More specific
                ("192.168.0.0/16".parse().unwrap(), 1), // Less specific
            ],
            vec![],
        );

        // 192.168.1.1 matches both, but rule 0 comes first
        assert_eq!(
            matcher.match_ipv4("192.168.1.1".parse().unwrap()),
            Some(0)
        );

        // 192.168.2.1 only matches rule 1
        assert_eq!(
            matcher.match_ipv4("192.168.2.1".parse().unwrap()),
            Some(1)
        );
    }

    #[test]
    fn test_match_all() {
        let matcher = IpMatcher::build(
            vec![
                ("192.168.1.0/24".parse().unwrap(), 0),
                ("192.168.0.0/16".parse().unwrap(), 1),
                ("192.0.0.0/8".parse().unwrap(), 2),
            ],
            vec![],
        );

        let matches = matcher.match_all_ipv4("192.168.1.1".parse().unwrap());
        assert_eq!(matches, vec![0, 1, 2]);

        let matches = matcher.match_all_ipv4("192.168.2.1".parse().unwrap());
        assert_eq!(matches, vec![1, 2]);

        let matches = matcher.match_all_ipv4("192.1.1.1".parse().unwrap());
        assert_eq!(matches, vec![2]);
    }

    #[test]
    fn test_empty_matcher() {
        let matcher = IpMatcher::new();
        assert!(matcher.is_empty());
        assert_eq!(matcher.match_ipv4("192.168.1.1".parse().unwrap()), None);
        assert_eq!(
            matcher.match_ipv6("2001:db8::1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_count() {
        let mut matcher = IpMatcher::new();
        assert_eq!(matcher.count(), 0);

        matcher.add_ipv4("192.168.0.0/16".parse().unwrap(), 0);
        matcher.add_ipv4("10.0.0.0/8".parse().unwrap(), 1);
        matcher.add_ipv6("2001:db8::/32".parse().unwrap(), 2);

        assert_eq!(matcher.ipv4_count(), 2);
        assert_eq!(matcher.ipv6_count(), 1);
        assert_eq!(matcher.count(), 3);
    }
}
