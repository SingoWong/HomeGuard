//! Rule Engine
//!
//! Coordinates all matchers to provide unified rule matching.
//!
//! Matching order:
//! 1. Domain rules (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD)
//! 2. IP rules (IP-CIDR, IP-CIDR6)
//! 3. GeoIP rules
//! 4. FINAL rule
//!
//! Rules are matched in their original order. First match wins.

use std::net::IpAddr;
use std::path::Path;

use super::matcher::{DomainMatcher, GeoIpMatcher, IpMatcher};
use super::types::{MatchResult, Policy, Rule, RuleType};
use crate::dns::DnsFilterTrait;
use crate::error::Result;

/// Rule engine for matching domains and IPs
pub struct RuleEngine {
    /// All rules in original order
    rules: Vec<Rule>,

    /// Domain matcher (exact, suffix, keyword)
    domain_matcher: DomainMatcher,

    /// IP CIDR matcher
    ip_matcher: IpMatcher,

    /// GeoIP matcher
    geoip_matcher: GeoIpMatcher,

    /// FINAL rule policy (default if no rule matches)
    final_policy: Policy,

    /// Index of FINAL rule
    final_index: usize,
}

impl RuleEngine {
    /// Create a new rule engine from rules
    ///
    /// # Arguments
    /// * `rules` - List of rules in priority order
    /// * `geoip_db` - Optional path to MaxMind GeoIP database
    pub fn new(rules: Vec<Rule>, geoip_db: Option<&Path>) -> Result<Self> {
        let mut exact_domains = Vec::new();
        let mut suffix_domains = Vec::new();
        let mut keywords = Vec::new();
        let mut ipv4_cidrs = Vec::new();
        let mut ipv6_cidrs = Vec::new();
        let mut country_rules = Vec::new();
        let mut final_policy = Policy::Direct;
        let mut final_index = rules.len();

        // Categorize rules by type
        for (index, rule) in rules.iter().enumerate() {
            match &rule.rule_type {
                RuleType::Domain(domain) => {
                    exact_domains.push((domain.clone(), index));
                }
                RuleType::DomainSuffix(suffix) => {
                    suffix_domains.push((suffix.clone(), index));
                }
                RuleType::DomainKeyword(keyword) => {
                    keywords.push((keyword.clone(), index));
                }
                RuleType::IpCidr(cidr) => {
                    ipv4_cidrs.push((*cidr, index));
                }
                RuleType::IpCidr6(cidr) => {
                    ipv6_cidrs.push((*cidr, index));
                }
                RuleType::GeoIp(country) => {
                    country_rules.push((country.clone(), index));
                }
                RuleType::Final => {
                    final_policy = rule.policy.clone();
                    final_index = index;
                }
            }
        }

        // Build matchers
        let domain_matcher = DomainMatcher::build(exact_domains, suffix_domains, keywords);
        let ip_matcher = IpMatcher::build(ipv4_cidrs, ipv6_cidrs);
        let geoip_matcher = GeoIpMatcher::build(geoip_db, country_rules)?;

        Ok(Self {
            rules,
            domain_matcher,
            ip_matcher,
            geoip_matcher,
            final_policy,
            final_index,
        })
    }

    /// Match a domain name
    ///
    /// Only checks domain-based rules (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD)
    pub fn match_domain(&self, domain: &str) -> MatchResult {
        // Get all matching domain rule indices
        let matches = self.domain_matcher.match_all(domain);

        // Return the match with lowest index (highest priority)
        if let Some(&index) = matches.iter().min() {
            return self.create_match_result(index);
        }

        // No domain match, return FINAL
        self.final_result()
    }

    /// Match an IP address
    ///
    /// Only checks IP-based rules (IP-CIDR, IP-CIDR6, GEOIP)
    pub fn match_ip(&self, ip: IpAddr) -> MatchResult {
        // Collect all IP matches
        let mut matches = self.ip_matcher.match_all(ip);

        // Add GeoIP matches
        matches.extend(self.geoip_matcher.match_all(ip));

        // Return the match with lowest index (highest priority)
        if let Some(&index) = matches.iter().min() {
            return self.create_match_result(index);
        }

        // No IP match, return FINAL
        self.final_result()
    }

    /// Match a request with optional domain and IP
    ///
    /// This is the main matching function that:
    /// 1. Tries domain matching if domain is provided
    /// 2. Tries IP matching if IP is provided (respecting no-resolve option)
    /// 3. Returns the highest priority match or FINAL
    pub fn match_request(&self, domain: Option<&str>, ip: Option<IpAddr>) -> MatchResult {
        let mut candidates: Vec<usize> = Vec::new();

        // Domain matching
        if let Some(d) = domain {
            candidates.extend(self.domain_matcher.match_all(d));
        }

        // IP matching (for rules without no-resolve, or when we already have IP)
        if let Some(addr) = ip {
            // IP-CIDR matches
            for index in self.ip_matcher.match_all(addr) {
                if !self.rules[index].options.no_resolve || domain.is_none() {
                    candidates.push(index);
                }
            }

            // GeoIP matches
            for index in self.geoip_matcher.match_all(addr) {
                if !self.rules[index].options.no_resolve || domain.is_none() {
                    candidates.push(index);
                }
            }
        }

        // Return the highest priority match (lowest index)
        if let Some(&index) = candidates.iter().min() {
            return self.create_match_result(index);
        }

        // No match, return FINAL
        self.final_result()
    }

    /// Check if a domain should be blocked (policy == REJECT)
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.match_domain(domain).policy.is_reject()
    }

    /// Check if a domain should be proxied
    pub fn should_proxy(&self, domain: &str) -> bool {
        self.match_domain(domain).policy.is_proxy()
    }

    /// Get all rules
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the default (FINAL) policy
    pub fn final_policy(&self) -> &Policy {
        &self.final_policy
    }

    /// Create a match result from rule index
    fn create_match_result(&self, index: usize) -> MatchResult {
        let rule = &self.rules[index];
        MatchResult::new(rule.policy.clone(), index, rule.to_string())
    }

    /// Create FINAL match result
    fn final_result(&self) -> MatchResult {
        MatchResult::final_rule(self.final_policy.clone(), self.final_index)
    }
}

/// Implement DnsFilterTrait so RuleEngine can be used as DNS filter
impl DnsFilterTrait for RuleEngine {
    fn is_blocked(&self, domain: &str) -> bool {
        // Remove trailing dot if present
        let domain = domain.trim_end_matches('.');
        self.match_domain(domain).policy.is_reject()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleParser;

    fn create_test_rules() -> Vec<Rule> {
        let rule_strings = vec![
            "DOMAIN,blocked.com,REJECT",
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-KEYWORD,facebook,Proxy",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "FINAL,DIRECT",
        ];

        RuleParser::parse_rules(&rule_strings.iter().map(|s| *s).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn test_domain_exact_match() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_domain("blocked.com");
        assert_eq!(result.policy, Policy::Reject);
        assert_eq!(result.rule_index, 0);
    }

    #[test]
    fn test_domain_suffix_match() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_domain("www.google.com");
        assert_eq!(result.policy, Policy::Proxy("PROXY".to_string()));
        assert_eq!(result.rule_index, 1);

        let result = engine.match_domain("mail.google.com");
        assert_eq!(result.policy, Policy::Proxy("PROXY".to_string()));
    }

    #[test]
    fn test_domain_keyword_match() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_domain("www.facebook.com");
        assert_eq!(result.policy, Policy::Proxy("PROXY".to_string()));
        assert_eq!(result.rule_index, 2);
    }

    #[test]
    fn test_ip_cidr_match() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_ip("192.168.1.1".parse().unwrap());
        assert_eq!(result.policy, Policy::Direct);
        assert_eq!(result.rule_index, 3);

        let result = engine.match_ip("10.0.0.1".parse().unwrap());
        assert_eq!(result.policy, Policy::Direct);
        assert_eq!(result.rule_index, 4);
    }

    #[test]
    fn test_no_match_returns_final() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_domain("unknown.org");
        assert_eq!(result.policy, Policy::Direct);
        assert!(result.matched_rule.contains("FINAL"));
    }

    #[test]
    fn test_is_blocked() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        assert!(engine.is_blocked("blocked.com"));
        assert!(!engine.is_blocked("google.com"));
    }

    #[test]
    fn test_should_proxy() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        assert!(engine.should_proxy("www.google.com"));
        assert!(engine.should_proxy("facebook.net"));
        assert!(!engine.should_proxy("blocked.com"));
        assert!(!engine.should_proxy("unknown.org"));
    }

    #[test]
    fn test_match_request_domain_only() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_request(Some("www.google.com"), None);
        assert_eq!(result.policy, Policy::Proxy("PROXY".to_string()));
    }

    #[test]
    fn test_match_request_ip_only() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        let result = engine.match_request(None, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(result.policy, Policy::Direct);
    }

    #[test]
    fn test_match_request_domain_and_ip() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules, None).unwrap();

        // Domain match should take priority (index 1) over IP match (index 3)
        let result = engine.match_request(
            Some("www.google.com"),
            Some("192.168.1.1".parse().unwrap()),
        );
        assert_eq!(result.policy, Policy::Proxy("PROXY".to_string()));
        assert_eq!(result.rule_index, 1);
    }

    #[test]
    fn test_rule_priority() {
        // Test that lower index rules take priority
        let rule_strings = vec![
            "DOMAIN-SUFFIX,example.com,REJECT",  // index 0
            "DOMAIN,www.example.com,DIRECT",     // index 1 - more specific but lower priority
            "FINAL,Proxy",
        ];
        let rules = RuleParser::parse_rules(&rule_strings.iter().map(|s| *s).collect::<Vec<_>>()).unwrap();
        let engine = RuleEngine::new(rules, None).unwrap();

        // suffix rule (index 0) should win over exact rule (index 1)
        let result = engine.match_domain("www.example.com");
        assert_eq!(result.policy, Policy::Reject);
        assert_eq!(result.rule_index, 0);
    }

    #[test]
    fn test_no_resolve_option() {
        let rule_strings = vec![
            "IP-CIDR,192.168.0.0/16,REJECT,no-resolve",
            "FINAL,DIRECT",
        ];
        let rules = RuleParser::parse_rules(&rule_strings.iter().map(|s| *s).collect::<Vec<_>>()).unwrap();
        let engine = RuleEngine::new(rules, None).unwrap();

        // With domain, no-resolve rule should be skipped
        let result = engine.match_request(
            Some("example.com"),
            Some("192.168.1.1".parse().unwrap()),
        );
        assert_eq!(result.policy, Policy::Direct); // FINAL

        // Without domain, no-resolve rule should apply
        let result = engine.match_request(None, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(result.policy, Policy::Reject);
    }

    #[test]
    fn test_empty_rules() {
        let engine = RuleEngine::new(vec![], None).unwrap();
        let result = engine.match_domain("anything.com");
        assert_eq!(result.policy, Policy::Direct);
    }

    #[test]
    fn test_rule_count() {
        let rules = create_test_rules();
        let engine = RuleEngine::new(rules.clone(), None).unwrap();
        assert_eq!(engine.rule_count(), rules.len());
    }
}
