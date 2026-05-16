//! Domain matcher
//!
//! Provides efficient domain matching using:
//! - HashMap for exact domain matching: O(1)
//! - Reverse Trie for suffix matching: O(m) where m = domain parts count
//! - Aho-Corasick for keyword matching: O(n + matches)

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::HashMap;

/// Domain matcher with multiple matching strategies
pub struct DomainMatcher {
    /// Exact domain match: domain -> rule_index
    exact: HashMap<String, usize>,

    /// Suffix match using reversed domain parts
    /// e.g., "google.com" stored as "com.google"
    /// Uses a simple trie structure via nested HashMap
    suffix_trie: SuffixTrie,

    /// Keyword match using Aho-Corasick
    keyword_ac: Option<AhoCorasick>,

    /// Keyword to rule index mapping
    keyword_indices: Vec<usize>,
}

/// Simple trie for domain suffix matching
/// Stores domains in reverse order for efficient suffix lookup
struct SuffixTrie {
    children: HashMap<String, SuffixTrie>,
    /// Rule index if this node is a complete suffix pattern
    rule_index: Option<usize>,
}

impl SuffixTrie {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            rule_index: None,
        }
    }

    /// Insert a domain suffix pattern
    /// Domain is stored in reverse order: "google.com" -> ["com", "google"]
    fn insert(&mut self, domain: &str, rule_index: usize) {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut current = self;

        for part in parts {
            current = current
                .children
                .entry(part.to_lowercase())
                .or_insert_with(SuffixTrie::new);
        }
        current.rule_index = Some(rule_index);
    }

    /// Match a domain against suffix patterns
    /// Returns the rule index of the longest matching suffix
    fn match_domain(&self, domain: &str) -> Option<usize> {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut current = self;
        let mut last_match = None;

        for part in parts {
            let part_lower = part.to_lowercase();
            match current.children.get(&part_lower) {
                Some(child) => {
                    current = child;
                    // Update last match if this node has a rule
                    if current.rule_index.is_some() {
                        last_match = current.rule_index;
                    }
                }
                None => break,
            }
        }

        last_match
    }

    /// Check if the trie is empty
    fn is_empty(&self) -> bool {
        self.children.is_empty() && self.rule_index.is_none()
    }
}

impl DomainMatcher {
    /// Create a new empty domain matcher
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            suffix_trie: SuffixTrie::new(),
            keyword_ac: None,
            keyword_indices: Vec::new(),
        }
    }

    /// Build domain matcher from rule data
    ///
    /// # Arguments
    /// * `exact_domains` - (domain, rule_index) pairs for exact matching
    /// * `suffix_domains` - (domain_suffix, rule_index) pairs for suffix matching
    /// * `keywords` - (keyword, rule_index) pairs for keyword matching
    pub fn build(
        exact_domains: Vec<(String, usize)>,
        suffix_domains: Vec<(String, usize)>,
        keywords: Vec<(String, usize)>,
    ) -> Self {
        let mut matcher = Self::new();

        // Add exact domains
        for (domain, index) in exact_domains {
            matcher.add_exact(&domain, index);
        }

        // Add suffix domains
        for (domain, index) in suffix_domains {
            matcher.add_suffix(&domain, index);
        }

        // Build keyword matcher
        if !keywords.is_empty() {
            let patterns: Vec<&str> = keywords.iter().map(|(k, _)| k.as_str()).collect();
            let indices: Vec<usize> = keywords.iter().map(|(_, i)| *i).collect();

            if let Ok(ac) = AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostFirst)
                .ascii_case_insensitive(true)
                .build(&patterns)
            {
                matcher.keyword_ac = Some(ac);
                matcher.keyword_indices = indices;
            }
        }

        matcher
    }

    /// Add an exact domain match
    pub fn add_exact(&mut self, domain: &str, rule_index: usize) {
        self.exact.insert(domain.to_lowercase(), rule_index);
    }

    /// Add a suffix domain match
    pub fn add_suffix(&mut self, domain: &str, rule_index: usize) {
        self.suffix_trie.insert(domain, rule_index);
    }

    /// Match a domain and return the rule index
    ///
    /// Matching priority:
    /// 1. Exact match
    /// 2. Suffix match (longest match wins)
    /// 3. Keyword match (first match wins)
    pub fn match_domain(&self, domain: &str) -> Option<usize> {
        let domain_lower = domain.to_lowercase();

        // 1. Exact match
        if let Some(&index) = self.exact.get(&domain_lower) {
            return Some(index);
        }

        // 2. Suffix match
        if let Some(index) = self.suffix_trie.match_domain(&domain_lower) {
            return Some(index);
        }

        // 3. Keyword match
        if let Some(ref ac) = self.keyword_ac {
            if let Some(mat) = ac.find(&domain_lower) {
                return Some(self.keyword_indices[mat.pattern().as_usize()]);
            }
        }

        None
    }

    /// Match domain and return all matching rule indices
    /// Used when we need to check rule priority order
    pub fn match_all(&self, domain: &str) -> Vec<usize> {
        let domain_lower = domain.to_lowercase();
        let mut matches = Vec::new();

        // Exact match
        if let Some(&index) = self.exact.get(&domain_lower) {
            matches.push(index);
        }

        // Suffix match
        if let Some(index) = self.suffix_trie.match_domain(&domain_lower) {
            if !matches.contains(&index) {
                matches.push(index);
            }
        }

        // Keyword matches
        if let Some(ref ac) = self.keyword_ac {
            for mat in ac.find_iter(&domain_lower) {
                let index = self.keyword_indices[mat.pattern().as_usize()];
                if !matches.contains(&index) {
                    matches.push(index);
                }
            }
        }

        matches
    }

    /// Check if domain matches any exact rule
    pub fn match_exact(&self, domain: &str) -> Option<usize> {
        self.exact.get(&domain.to_lowercase()).copied()
    }

    /// Check if domain matches any suffix rule
    pub fn match_suffix(&self, domain: &str) -> Option<usize> {
        self.suffix_trie.match_domain(&domain.to_lowercase())
    }

    /// Check if domain matches any keyword rule
    pub fn match_keyword(&self, domain: &str) -> Option<usize> {
        if let Some(ref ac) = self.keyword_ac {
            if let Some(mat) = ac.find(&domain.to_lowercase()) {
                return Some(self.keyword_indices[mat.pattern().as_usize()]);
            }
        }
        None
    }

    /// Get the number of exact rules
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// Get the number of keyword rules
    pub fn keyword_count(&self) -> usize {
        self.keyword_indices.len()
    }

    /// Check if the matcher has any rules
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix_trie.is_empty() && self.keyword_indices.is_empty()
    }
}

impl Default for DomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = DomainMatcher::build(
            vec![
                ("example.com".to_string(), 0),
                ("test.org".to_string(), 1),
            ],
            vec![],
            vec![],
        );

        assert_eq!(matcher.match_domain("example.com"), Some(0));
        assert_eq!(matcher.match_domain("EXAMPLE.COM"), Some(0));
        assert_eq!(matcher.match_domain("test.org"), Some(1));
        assert_eq!(matcher.match_domain("other.com"), None);
        assert_eq!(matcher.match_domain("sub.example.com"), None);
    }

    #[test]
    fn test_suffix_match() {
        let matcher = DomainMatcher::build(
            vec![],
            vec![
                ("google.com".to_string(), 0),
                ("apple.com".to_string(), 1),
                ("icloud.apple.com".to_string(), 2),
            ],
            vec![],
        );

        // Direct suffix match
        assert_eq!(matcher.match_domain("google.com"), Some(0));
        assert_eq!(matcher.match_domain("www.google.com"), Some(0));
        assert_eq!(matcher.match_domain("mail.google.com"), Some(0));
        assert_eq!(matcher.match_domain("sub.www.google.com"), Some(0));

        // apple.com suffix
        assert_eq!(matcher.match_domain("apple.com"), Some(1));
        assert_eq!(matcher.match_domain("www.apple.com"), Some(1));

        // Longer suffix should match (icloud.apple.com)
        assert_eq!(matcher.match_domain("icloud.apple.com"), Some(2));
        assert_eq!(matcher.match_domain("www.icloud.apple.com"), Some(2));

        // No match
        assert_eq!(matcher.match_domain("notgoogle.com"), None);
        assert_eq!(matcher.match_domain("google.org"), None);
    }

    #[test]
    fn test_keyword_match() {
        let matcher = DomainMatcher::build(
            vec![],
            vec![],
            vec![
                ("facebook".to_string(), 0),
                ("twitter".to_string(), 1),
            ],
        );

        assert_eq!(matcher.match_domain("www.facebook.com"), Some(0));
        assert_eq!(matcher.match_domain("facebook.net"), Some(0));
        assert_eq!(matcher.match_domain("m.facebook.com"), Some(0));
        assert_eq!(matcher.match_domain("twitter.com"), Some(1));
        assert_eq!(matcher.match_domain("mobile.twitter.com"), Some(1));
        assert_eq!(matcher.match_domain("google.com"), None);
    }

    #[test]
    fn test_match_priority() {
        // Exact match should take priority over suffix and keyword
        let matcher = DomainMatcher::build(
            vec![("www.google.com".to_string(), 0)],
            vec![("google.com".to_string(), 1)],
            vec![("google".to_string(), 2)],
        );

        // Exact match wins
        assert_eq!(matcher.match_domain("www.google.com"), Some(0));

        // Suffix match for subdomain not in exact
        assert_eq!(matcher.match_domain("mail.google.com"), Some(1));

        // Base domain matches suffix
        assert_eq!(matcher.match_domain("google.com"), Some(1));
    }

    #[test]
    fn test_case_insensitive() {
        let matcher = DomainMatcher::build(
            vec![("Example.COM".to_string(), 0)],
            vec![("Google.Com".to_string(), 1)],
            vec![("FACEBOOK".to_string(), 2)],
        );

        assert_eq!(matcher.match_domain("example.com"), Some(0));
        assert_eq!(matcher.match_domain("EXAMPLE.COM"), Some(0));
        assert_eq!(matcher.match_domain("www.google.com"), Some(1));
        assert_eq!(matcher.match_domain("WWW.GOOGLE.COM"), Some(1));
        assert_eq!(matcher.match_domain("www.facebook.com"), Some(2));
    }

    #[test]
    fn test_match_all() {
        let matcher = DomainMatcher::build(
            vec![("www.google.com".to_string(), 0)],
            vec![("google.com".to_string(), 1)],
            vec![("google".to_string(), 2)],
        );

        let matches = matcher.match_all("www.google.com");
        assert!(matches.contains(&0)); // exact
        assert!(matches.contains(&1)); // suffix
        assert!(matches.contains(&2)); // keyword
    }

    #[test]
    fn test_empty_matcher() {
        let matcher = DomainMatcher::new();
        assert!(matcher.is_empty());
        assert_eq!(matcher.match_domain("anything.com"), None);
    }

    #[test]
    fn test_suffix_trie_edge_cases() {
        let matcher = DomainMatcher::build(
            vec![],
            vec![
                ("com".to_string(), 0),
                ("co.uk".to_string(), 1),
            ],
            vec![],
        );

        // .com suffix should match many domains
        assert_eq!(matcher.match_domain("example.com"), Some(0));
        assert_eq!(matcher.match_domain("google.com"), Some(0));

        // .co.uk suffix
        assert_eq!(matcher.match_domain("example.co.uk"), Some(1));
        assert_eq!(matcher.match_domain("www.bbc.co.uk"), Some(1));

        // .org should not match
        assert_eq!(matcher.match_domain("example.org"), None);
    }
}
