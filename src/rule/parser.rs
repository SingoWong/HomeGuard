//! Rule parser
//!
//! Parses Surge-style rule strings into Rule structs.
//!
//! Supported formats:
//! - DOMAIN,example.com,DIRECT
//! - DOMAIN-SUFFIX,google.com,Proxy
//! - DOMAIN-KEYWORD,facebook,REJECT
//! - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
//! - IP-CIDR6,2001:db8::/32,Proxy
//! - GEOIP,CN,DIRECT
//! - FINAL,DIRECT

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::error::{HomeGuardError, Result};

use super::types::{Policy, Rule, RuleOptions, RuleType};

/// Rule parser
pub struct RuleParser;

impl RuleParser {
    /// Parse a single rule line
    ///
    /// # Format
    /// ```text
    /// RULE-TYPE,PATTERN,POLICY[,options...]
    /// ```
    ///
    /// # Examples
    /// ```text
    /// DOMAIN,example.com,DIRECT
    /// DOMAIN-SUFFIX,google.com,Proxy
    /// IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
    /// FINAL,DIRECT
    /// ```
    pub fn parse_rule(line: &str) -> Result<Rule> {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            return Err(HomeGuardError::InvalidConfig("Empty or comment line".to_string()));
        }

        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

        if parts.is_empty() {
            return Err(HomeGuardError::InvalidConfig(format!(
                "Invalid rule format: {}",
                line
            )));
        }

        let rule_type_str = parts[0].to_uppercase();

        // Handle FINAL rule (only 2 parts: FINAL,POLICY)
        if rule_type_str == "FINAL" {
            if parts.len() < 2 {
                return Err(HomeGuardError::InvalidConfig(format!(
                    "FINAL rule requires policy: {}",
                    line
                )));
            }
            let policy = Policy::from_str(parts[1]);
            return Ok(Rule::new(RuleType::Final, policy));
        }

        // Other rules need at least 3 parts: TYPE,PATTERN,POLICY
        if parts.len() < 3 {
            return Err(HomeGuardError::InvalidConfig(format!(
                "Rule requires at least TYPE,PATTERN,POLICY: {}",
                line
            )));
        }

        let pattern = parts[1];
        let policy = Policy::from_str(parts[2]);

        // Parse options (everything after policy)
        let options = if parts.len() > 3 {
            RuleOptions::parse(&parts[3..])
        } else {
            RuleOptions::default()
        };

        let rule_type = match rule_type_str.as_str() {
            "DOMAIN" => RuleType::Domain(pattern.to_lowercase()),

            "DOMAIN-SUFFIX" => RuleType::DomainSuffix(pattern.to_lowercase()),

            "DOMAIN-KEYWORD" => RuleType::DomainKeyword(pattern.to_lowercase()),

            "IP-CIDR" => {
                let cidr = pattern.parse().map_err(|e| {
                    HomeGuardError::InvalidConfig(format!(
                        "Invalid IPv4 CIDR '{}': {}",
                        pattern, e
                    ))
                })?;
                RuleType::IpCidr(cidr)
            }

            "IP-CIDR6" => {
                let cidr = pattern.parse().map_err(|e| {
                    HomeGuardError::InvalidConfig(format!(
                        "Invalid IPv6 CIDR '{}': {}",
                        pattern, e
                    ))
                })?;
                RuleType::IpCidr6(cidr)
            }

            "GEOIP" => RuleType::GeoIp(pattern.to_uppercase()),

            _ => {
                return Err(HomeGuardError::InvalidConfig(format!(
                    "Unknown rule type '{}': {}",
                    rule_type_str, line
                )));
            }
        };

        Ok(Rule::with_options(rule_type, policy, options))
    }

    /// Parse multiple rule lines
    pub fn parse_rules(lines: &[&str]) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            match Self::parse_rule(line) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    return Err(HomeGuardError::InvalidConfig(format!(
                        "Error parsing rule at line {}: {}",
                        line_num + 1,
                        e
                    )));
                }
            }
        }

        Ok(rules)
    }

    /// Load rules from a file
    pub fn load_ruleset(path: &Path) -> Result<Vec<Rule>> {
        let file = File::open(path).map_err(|e| {
            HomeGuardError::InvalidConfig(format!(
                "Failed to open rule file '{}': {}",
                path.display(),
                e
            ))
        })?;

        let reader = BufReader::new(file);
        let mut rules = Vec::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                HomeGuardError::InvalidConfig(format!(
                    "Failed to read line {} in '{}': {}",
                    line_num + 1,
                    path.display(),
                    e
                ))
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            match Self::parse_rule(line) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    return Err(HomeGuardError::InvalidConfig(format!(
                        "Error parsing rule at {}:{}: {}",
                        path.display(),
                        line_num + 1,
                        e
                    )));
                }
            }
        }

        Ok(rules)
    }

    /// Parse rules from configuration strings
    ///
    /// This handles the rule_list from config file which may contain:
    /// - Direct rules: "DOMAIN,example.com,DIRECT"
    /// - Rule set references: "RULE-SET,path/to/rules.txt,POLICY"
    pub fn load_rules(rule_strings: &[String], base_path: Option<&Path>) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        for rule_str in rule_strings {
            let rule_str = rule_str.trim();

            // Skip empty lines and comments
            if rule_str.is_empty() || rule_str.starts_with('#') || rule_str.starts_with("//") {
                continue;
            }

            // Check for RULE-SET reference
            if rule_str.to_uppercase().starts_with("RULE-SET,") {
                let parts: Vec<&str> = rule_str.splitn(3, ',').collect();
                if parts.len() < 3 {
                    return Err(HomeGuardError::InvalidConfig(format!(
                        "RULE-SET requires path and policy: {}",
                        rule_str
                    )));
                }

                let rule_path = parts[1].trim();
                let policy_str = parts[2].trim();

                // Handle options in policy (e.g., "REJECT,schedule=school_hours")
                let policy_parts: Vec<&str> = policy_str.split(',').collect();
                let policy = Policy::from_str(policy_parts[0]);

                // Resolve path relative to base_path if provided
                let full_path = if let Some(base) = base_path {
                    base.join(rule_path)
                } else {
                    std::path::PathBuf::from(rule_path)
                };

                // Load rules from file and apply policy
                let file_rules = Self::load_ruleset(&full_path)?;
                for mut rule in file_rules {
                    // Override policy with the one specified in RULE-SET
                    rule.policy = policy.clone();
                    rules.push(rule);
                }
            } else {
                // Direct rule
                match Self::parse_rule(rule_str) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => {
                        return Err(HomeGuardError::InvalidConfig(format!(
                            "Error parsing rule '{}': {}",
                            rule_str, e
                        )));
                    }
                }
            }
        }

        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::{Ipv4Net, Ipv6Net};

    #[test]
    fn test_parse_domain_rule() {
        let rule = RuleParser::parse_rule("DOMAIN,example.com,DIRECT").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::Domain("example.com".to_string())
        );
        assert_eq!(rule.policy, Policy::Direct);
    }

    #[test]
    fn test_parse_domain_suffix_rule() {
        let rule = RuleParser::parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::DomainSuffix("google.com".to_string())
        );
        assert_eq!(rule.policy, Policy::Proxy("PROXY".to_string()));
    }

    #[test]
    fn test_parse_domain_keyword_rule() {
        let rule = RuleParser::parse_rule("DOMAIN-KEYWORD,facebook,REJECT").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::DomainKeyword("facebook".to_string())
        );
        assert_eq!(rule.policy, Policy::Reject);
    }

    #[test]
    fn test_parse_ip_cidr_rule() {
        let rule = RuleParser::parse_rule("IP-CIDR,192.168.0.0/16,DIRECT").unwrap();
        let expected_cidr: Ipv4Net = "192.168.0.0/16".parse().unwrap();
        assert_eq!(rule.rule_type, RuleType::IpCidr(expected_cidr));
        assert_eq!(rule.policy, Policy::Direct);
    }

    #[test]
    fn test_parse_ip_cidr_with_no_resolve() {
        let rule = RuleParser::parse_rule("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
        let expected_cidr: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        assert_eq!(rule.rule_type, RuleType::IpCidr(expected_cidr));
        assert!(rule.options.no_resolve);
    }

    #[test]
    fn test_parse_ip_cidr6_rule() {
        let rule = RuleParser::parse_rule("IP-CIDR6,2001:db8::/32,Proxy").unwrap();
        let expected_cidr: Ipv6Net = "2001:db8::/32".parse().unwrap();
        assert_eq!(rule.rule_type, RuleType::IpCidr6(expected_cidr));
    }

    #[test]
    fn test_parse_geoip_rule() {
        let rule = RuleParser::parse_rule("GEOIP,CN,DIRECT").unwrap();
        assert_eq!(rule.rule_type, RuleType::GeoIp("CN".to_string()));
        assert_eq!(rule.policy, Policy::Direct);
    }

    #[test]
    fn test_parse_geoip_lowercase() {
        let rule = RuleParser::parse_rule("GEOIP,cn,DIRECT").unwrap();
        assert_eq!(rule.rule_type, RuleType::GeoIp("CN".to_string()));
    }

    #[test]
    fn test_parse_final_rule() {
        let rule = RuleParser::parse_rule("FINAL,DIRECT").unwrap();
        assert_eq!(rule.rule_type, RuleType::Final);
        assert_eq!(rule.policy, Policy::Direct);
    }

    #[test]
    fn test_parse_with_whitespace() {
        let rule = RuleParser::parse_rule("  DOMAIN , example.com , DIRECT  ").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::Domain("example.com".to_string())
        );
    }

    #[test]
    fn test_parse_case_insensitive_type() {
        let rule = RuleParser::parse_rule("domain,example.com,DIRECT").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::Domain("example.com".to_string())
        );

        let rule = RuleParser::parse_rule("Domain-Suffix,google.com,DIRECT").unwrap();
        assert_eq!(
            rule.rule_type,
            RuleType::DomainSuffix("google.com".to_string())
        );
    }

    #[test]
    fn test_parse_invalid_rule() {
        assert!(RuleParser::parse_rule("INVALID,test,DIRECT").is_err());
        assert!(RuleParser::parse_rule("DOMAIN,example.com").is_err()); // Missing policy
        assert!(RuleParser::parse_rule("FINAL").is_err()); // Missing policy
        assert!(RuleParser::parse_rule("IP-CIDR,invalid,DIRECT").is_err()); // Invalid CIDR
    }

    #[test]
    fn test_parse_comment() {
        assert!(RuleParser::parse_rule("# This is a comment").is_err());
        assert!(RuleParser::parse_rule("// This is also a comment").is_err());
        assert!(RuleParser::parse_rule("").is_err());
    }

    #[test]
    fn test_parse_rules() {
        let lines = vec![
            "# Comment",
            "DOMAIN,example.com,DIRECT",
            "",
            "DOMAIN-SUFFIX,google.com,Proxy",
            "FINAL,DIRECT",
        ];

        let rules = RuleParser::parse_rules(&lines).unwrap();
        assert_eq!(rules.len(), 3);
        assert!(matches!(rules[0].rule_type, RuleType::Domain(_)));
        assert!(matches!(rules[1].rule_type, RuleType::DomainSuffix(_)));
        assert!(matches!(rules[2].rule_type, RuleType::Final));
    }

    #[test]
    fn test_parse_proxy_policy() {
        let rule = RuleParser::parse_rule("DOMAIN,example.com,MyProxy").unwrap();
        assert_eq!(rule.policy, Policy::Proxy("MYPROXY".to_string()));
    }
}
