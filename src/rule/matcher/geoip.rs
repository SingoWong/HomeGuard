//! GeoIP matcher
//!
//! Provides IP to country code matching using MaxMind GeoLite2 database.

use maxminddb::{geoip2, Reader};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::error::{HomeGuardError, Result};

/// GeoIP matcher using MaxMind database
pub struct GeoIpMatcher {
    /// MaxMind DB reader (optional - GeoIP matching disabled if None)
    reader: Option<Reader<Vec<u8>>>,

    /// Country code to rule index mapping
    /// Multiple rules can reference the same country code
    country_rules: HashMap<String, Vec<usize>>,
}

impl GeoIpMatcher {
    /// Create a new empty GeoIP matcher (no database loaded)
    pub fn new() -> Self {
        Self {
            reader: None,
            country_rules: HashMap::new(),
        }
    }

    /// Load GeoIP database from file
    pub fn load(path: &Path) -> Result<Self> {
        let reader = Reader::open_readfile(path).map_err(|e| {
            HomeGuardError::InvalidConfig(format!(
                "Failed to load GeoIP database '{}': {}",
                path.display(),
                e
            ))
        })?;

        Ok(Self {
            reader: Some(reader),
            country_rules: HashMap::new(),
        })
    }

    /// Build GeoIP matcher from database and country rules
    pub fn build(db_path: Option<&Path>, country_rules: Vec<(String, usize)>) -> Result<Self> {
        let reader = if let Some(path) = db_path {
            Some(Reader::open_readfile(path).map_err(|e| {
                HomeGuardError::InvalidConfig(format!(
                    "Failed to load GeoIP database '{}': {}",
                    path.display(),
                    e
                ))
            })?)
        } else {
            None
        };

        let mut rules_map: HashMap<String, Vec<usize>> = HashMap::new();
        for (country, index) in country_rules {
            rules_map
                .entry(country.to_uppercase())
                .or_default()
                .push(index);
        }

        Ok(Self {
            reader,
            country_rules: rules_map,
        })
    }

    /// Add a country code rule
    pub fn add_country(&mut self, country: &str, rule_index: usize) {
        self.country_rules
            .entry(country.to_uppercase())
            .or_default()
            .push(rule_index);
    }

    /// Look up country code for an IP address
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;

        let country: geoip2::Country = reader.lookup(ip).ok()?;
        let iso_code = country.country?.iso_code?;

        Some(iso_code.to_uppercase())
    }

    /// Match an IP address against GeoIP rules
    ///
    /// Returns the first matching rule index
    pub fn match_ip(&self, ip: IpAddr) -> Option<usize> {
        let country = self.lookup_country(ip)?;
        self.country_rules
            .get(&country)
            .and_then(|indices| indices.first().copied())
    }

    /// Match an IP address and return all matching rule indices
    pub fn match_all(&self, ip: IpAddr) -> Vec<usize> {
        if let Some(country) = self.lookup_country(ip) {
            self.country_rules
                .get(&country)
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Check if a country code matches any rule
    pub fn match_country(&self, country: &str) -> Option<usize> {
        self.country_rules
            .get(&country.to_uppercase())
            .and_then(|indices| indices.first().copied())
    }

    /// Check if the GeoIP database is loaded
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }

    /// Get the number of country rules
    pub fn country_count(&self) -> usize {
        self.country_rules.len()
    }

    /// Check if there are any country rules
    pub fn is_empty(&self) -> bool {
        self.country_rules.is_empty()
    }

    /// Get all configured country codes
    pub fn countries(&self) -> Vec<&String> {
        self.country_rules.keys().collect()
    }
}

impl Default for GeoIpMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty_matcher() {
        let matcher = GeoIpMatcher::new();
        assert!(!matcher.is_loaded());
        assert!(matcher.is_empty());
    }

    #[test]
    fn test_add_country_rules() {
        let mut matcher = GeoIpMatcher::new();
        matcher.add_country("CN", 0);
        matcher.add_country("US", 1);
        matcher.add_country("cn", 2); // Same country, different case

        assert_eq!(matcher.country_count(), 2); // CN and US
        assert!(!matcher.is_empty());

        // CN should have two rule indices
        assert_eq!(matcher.match_country("CN"), Some(0));
        assert_eq!(matcher.match_country("cn"), Some(0));
        assert_eq!(matcher.match_country("US"), Some(1));
        assert_eq!(matcher.match_country("JP"), None);
    }

    #[test]
    fn test_countries_list() {
        let mut matcher = GeoIpMatcher::new();
        matcher.add_country("CN", 0);
        matcher.add_country("US", 1);
        matcher.add_country("JP", 2);

        let countries = matcher.countries();
        assert_eq!(countries.len(), 3);
        assert!(countries.contains(&&"CN".to_string()));
        assert!(countries.contains(&&"US".to_string()));
        assert!(countries.contains(&&"JP".to_string()));
    }

    #[test]
    fn test_match_without_db() {
        let mut matcher = GeoIpMatcher::new();
        matcher.add_country("CN", 0);

        // Without DB, IP lookup should return None
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
        assert!(matcher.match_all(ip).is_empty());
    }

    // Note: Testing with actual GeoIP database requires having the database file
    // These tests would be integration tests with a test database

    #[test]
    fn test_build_without_db() {
        let rules = vec![
            ("CN".to_string(), 0),
            ("US".to_string(), 1),
        ];

        let matcher = GeoIpMatcher::build(None, rules).unwrap();
        assert!(!matcher.is_loaded());
        assert_eq!(matcher.country_count(), 2);
    }
}
