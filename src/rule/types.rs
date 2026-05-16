//! Rule type definitions
//!
//! Defines the core types for the rule engine:
//! - RuleType: Different matching methods (DOMAIN, IP-CIDR, etc.)
//! - Policy: Action to take (DIRECT, REJECT, Proxy)
//! - Rule: Complete rule with type, policy, and options

use ipnet::{Ipv4Net, Ipv6Net};
use std::fmt;

/// Rule type - defines how to match
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    /// Exact domain match (e.g., DOMAIN,example.com,DIRECT)
    Domain(String),

    /// Domain suffix match (e.g., DOMAIN-SUFFIX,google.com matches *.google.com)
    DomainSuffix(String),

    /// Domain keyword match (e.g., DOMAIN-KEYWORD,facebook matches anything containing "facebook")
    DomainKeyword(String),

    /// IPv4 CIDR match (e.g., IP-CIDR,192.168.0.0/16,DIRECT)
    IpCidr(Ipv4Net),

    /// IPv6 CIDR match (e.g., IP-CIDR6,2001:db8::/32,DIRECT)
    IpCidr6(Ipv6Net),

    /// GeoIP country code match (e.g., GEOIP,CN,DIRECT)
    GeoIp(String),

    /// Default/fallback rule (e.g., FINAL,DIRECT)
    Final,
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleType::Domain(d) => write!(f, "DOMAIN,{}", d),
            RuleType::DomainSuffix(d) => write!(f, "DOMAIN-SUFFIX,{}", d),
            RuleType::DomainKeyword(k) => write!(f, "DOMAIN-KEYWORD,{}", k),
            RuleType::IpCidr(cidr) => write!(f, "IP-CIDR,{}", cidr),
            RuleType::IpCidr6(cidr) => write!(f, "IP-CIDR6,{}", cidr),
            RuleType::GeoIp(cc) => write!(f, "GEOIP,{}", cc),
            RuleType::Final => write!(f, "FINAL"),
        }
    }
}

/// Policy - action to take when rule matches
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Policy {
    /// Direct connection (no proxy)
    Direct,

    /// Reject connection (return NXDOMAIN for DNS, RST for TCP)
    Reject,

    /// Use specified proxy group
    Proxy(String),
}

impl Default for Policy {
    fn default() -> Self {
        Policy::Direct
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Policy::Direct => write!(f, "DIRECT"),
            Policy::Reject => write!(f, "REJECT"),
            Policy::Proxy(name) => write!(f, "{}", name),
        }
    }
}

impl Policy {
    /// Parse policy from string
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DIRECT" => Policy::Direct,
            "REJECT" => Policy::Reject,
            name => Policy::Proxy(name.to_string()),
        }
    }

    /// Check if this policy is reject
    pub fn is_reject(&self) -> bool {
        matches!(self, Policy::Reject)
    }

    /// Check if this policy is direct
    pub fn is_direct(&self) -> bool {
        matches!(self, Policy::Direct)
    }

    /// Check if this policy uses a proxy
    pub fn is_proxy(&self) -> bool {
        matches!(self, Policy::Proxy(_))
    }
}

/// Rule options - modifiers for rule behavior
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOptions {
    /// Don't resolve domain to IP for IP-based rules
    /// When set, IP-CIDR/GEOIP rules will only match if IP is already known
    pub no_resolve: bool,
}

impl RuleOptions {
    /// Create new options with no-resolve flag
    pub fn with_no_resolve(no_resolve: bool) -> Self {
        Self { no_resolve }
    }

    /// Parse options from string slice
    pub fn parse(options: &[&str]) -> Self {
        let mut opts = Self::default();
        for opt in options {
            if opt.eq_ignore_ascii_case("no-resolve") {
                opts.no_resolve = true;
            }
        }
        opts
    }
}

/// Complete rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule matching type
    pub rule_type: RuleType,

    /// Policy to apply when matched
    pub policy: Policy,

    /// Rule options
    pub options: RuleOptions,
}

impl Rule {
    /// Create a new rule
    pub fn new(rule_type: RuleType, policy: Policy) -> Self {
        Self {
            rule_type,
            policy,
            options: RuleOptions::default(),
        }
    }

    /// Create a new rule with options
    pub fn with_options(rule_type: RuleType, policy: Policy, options: RuleOptions) -> Self {
        Self {
            rule_type,
            policy,
            options,
        }
    }

    /// Check if this rule requires domain matching
    pub fn is_domain_rule(&self) -> bool {
        matches!(
            self.rule_type,
            RuleType::Domain(_) | RuleType::DomainSuffix(_) | RuleType::DomainKeyword(_)
        )
    }

    /// Check if this rule requires IP matching
    pub fn is_ip_rule(&self) -> bool {
        matches!(
            self.rule_type,
            RuleType::IpCidr(_) | RuleType::IpCidr6(_) | RuleType::GeoIp(_)
        )
    }

    /// Check if this is the final/default rule
    pub fn is_final(&self) -> bool {
        matches!(self.rule_type, RuleType::Final)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.rule_type, self.policy)?;
        if self.options.no_resolve {
            write!(f, ",no-resolve")?;
        }
        Ok(())
    }
}

/// Result of rule matching
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Policy to apply
    pub policy: Policy,

    /// Index of the matched rule in the rule list
    pub rule_index: usize,

    /// String representation of the matched rule
    pub matched_rule: String,
}

impl MatchResult {
    /// Create a new match result
    pub fn new(policy: Policy, rule_index: usize, matched_rule: String) -> Self {
        Self {
            policy,
            rule_index,
            matched_rule,
        }
    }

    /// Create a match result for FINAL rule
    pub fn final_rule(policy: Policy, rule_index: usize) -> Self {
        Self {
            policy,
            rule_index,
            matched_rule: "FINAL".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_from_str() {
        assert_eq!(Policy::from_str("DIRECT"), Policy::Direct);
        assert_eq!(Policy::from_str("direct"), Policy::Direct);
        assert_eq!(Policy::from_str("REJECT"), Policy::Reject);
        assert_eq!(Policy::from_str("Proxy"), Policy::Proxy("PROXY".to_string()));
        assert_eq!(
            Policy::from_str("MyProxy"),
            Policy::Proxy("MYPROXY".to_string())
        );
    }

    #[test]
    fn test_policy_checks() {
        assert!(Policy::Direct.is_direct());
        assert!(!Policy::Direct.is_reject());
        assert!(!Policy::Direct.is_proxy());

        assert!(Policy::Reject.is_reject());
        assert!(!Policy::Reject.is_direct());

        assert!(Policy::Proxy("test".to_string()).is_proxy());
    }

    #[test]
    fn test_rule_options_parse() {
        let opts = RuleOptions::parse(&["no-resolve"]);
        assert!(opts.no_resolve);

        let opts = RuleOptions::parse(&["NO-RESOLVE"]);
        assert!(opts.no_resolve);

        let opts = RuleOptions::parse(&[]);
        assert!(!opts.no_resolve);
    }

    #[test]
    fn test_rule_type_display() {
        assert_eq!(
            RuleType::Domain("example.com".to_string()).to_string(),
            "DOMAIN,example.com"
        );
        assert_eq!(
            RuleType::DomainSuffix("google.com".to_string()).to_string(),
            "DOMAIN-SUFFIX,google.com"
        );
        assert_eq!(
            RuleType::DomainKeyword("facebook".to_string()).to_string(),
            "DOMAIN-KEYWORD,facebook"
        );
        assert_eq!(RuleType::Final.to_string(), "FINAL");
    }

    #[test]
    fn test_rule_display() {
        let rule = Rule::new(
            RuleType::Domain("example.com".to_string()),
            Policy::Direct,
        );
        assert_eq!(rule.to_string(), "DOMAIN,example.com,DIRECT");

        let rule = Rule::with_options(
            RuleType::IpCidr("192.168.0.0/16".parse().unwrap()),
            Policy::Direct,
            RuleOptions::with_no_resolve(true),
        );
        assert_eq!(rule.to_string(), "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve");
    }

    #[test]
    fn test_rule_type_checks() {
        let domain_rule = Rule::new(
            RuleType::Domain("example.com".to_string()),
            Policy::Direct,
        );
        assert!(domain_rule.is_domain_rule());
        assert!(!domain_rule.is_ip_rule());
        assert!(!domain_rule.is_final());

        let ip_rule = Rule::new(
            RuleType::IpCidr("192.168.0.0/16".parse().unwrap()),
            Policy::Direct,
        );
        assert!(!ip_rule.is_domain_rule());
        assert!(ip_rule.is_ip_rule());

        let final_rule = Rule::new(RuleType::Final, Policy::Direct);
        assert!(final_rule.is_final());
    }
}
