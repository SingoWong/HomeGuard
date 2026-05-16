//! Blocklist Manager
//!
//! Manages domain blocklists from multiple sources with category support.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::{HomeGuardError, Result};

/// Manages domain blocklists
pub struct BlocklistManager {
    /// Global domains (blocked for ALL devices)
    global_domains: HashSet<String>,

    /// Domain suffixes for global blocking
    global_suffixes: HashSet<String>,

    /// Category-based blocklists (category -> domains)
    category_domains: HashMap<String, HashSet<String>>,

    /// Category-based suffixes (category -> suffixes)
    category_suffixes: HashMap<String, HashSet<String>>,
}

impl BlocklistManager {
    /// Create empty manager
    pub fn new() -> Self {
        Self {
            global_domains: HashSet::new(),
            global_suffixes: HashSet::new(),
            category_domains: HashMap::new(),
            category_suffixes: HashMap::new(),
        }
    }

    /// Load blocklist from file
    ///
    /// File format:
    /// - One domain per line
    /// - Lines starting with # are comments
    /// - Lines starting with *. are treated as suffix rules
    /// - Empty lines are ignored
    ///
    /// Returns the number of domains loaded.
    pub fn load_file(&mut self, path: &Path, category: Option<&str>) -> Result<usize> {
        let file = File::open(path).map_err(|e| {
            HomeGuardError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to open blocklist file '{}': {}", path.display(), e),
            ))
        })?;

        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line.map_err(|e| {
                HomeGuardError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read line from '{}': {}", path.display(), e),
                ))
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse the domain
            let (domain, is_suffix) = if line.starts_with("*.") {
                // Wildcard suffix: *.example.com -> matches all subdomains
                (line[2..].to_lowercase(), true)
            } else if line.starts_with('.') {
                // Dot prefix: .example.com -> also suffix
                (line[1..].to_lowercase(), true)
            } else {
                (line.to_lowercase(), false)
            };

            // Add to appropriate set
            match category {
                Some(cat) => {
                    if is_suffix {
                        self.category_suffixes
                            .entry(cat.to_string())
                            .or_default()
                            .insert(domain);
                    } else {
                        self.category_domains
                            .entry(cat.to_string())
                            .or_default()
                            .insert(domain);
                    }
                }
                None => {
                    if is_suffix {
                        self.global_suffixes.insert(domain);
                    } else {
                        self.global_domains.insert(domain);
                    }
                }
            }

            count += 1;
        }

        debug!(
            "Loaded {} domains from {} (category: {:?})",
            count,
            path.display(),
            category
        );

        Ok(count)
    }

    /// Load all blocklists from a directory
    ///
    /// Directory structure:
    /// - global/*.txt -> global blocklists
    /// - categories/<name>.txt -> category blocklists
    /// - *.txt at root -> global blocklists
    pub fn load_directory(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            warn!("Blocklist directory does not exist: {}", dir.display());
            return Ok(());
        }

        let mut total_global = 0;
        let mut total_categories = 0;

        // Load global blocklists (root level .txt files)
        for entry in std::fs::read_dir(dir).map_err(|e| {
            HomeGuardError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory '{}': {}", dir.display(), e),
            ))
        })? {
            let entry = entry.map_err(|e| HomeGuardError::Io(e))?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "txt") {
                match self.load_file(&path, None) {
                    Ok(count) => total_global += count,
                    Err(e) => warn!("Failed to load blocklist '{}': {}", path.display(), e),
                }
            }
        }

        // Load global/ subdirectory
        let global_dir = dir.join("global");
        if global_dir.exists() && global_dir.is_dir() {
            for entry in std::fs::read_dir(&global_dir).map_err(|e| HomeGuardError::Io(e))? {
                let entry = entry.map_err(|e| HomeGuardError::Io(e))?;
                let path = entry.path();

                if path.is_file() && path.extension().map_or(false, |ext| ext == "txt") {
                    match self.load_file(&path, None) {
                        Ok(count) => total_global += count,
                        Err(e) => warn!("Failed to load blocklist '{}': {}", path.display(), e),
                    }
                }
            }
        }

        // Load categories/ subdirectory
        let categories_dir = dir.join("categories");
        if categories_dir.exists() && categories_dir.is_dir() {
            for entry in std::fs::read_dir(&categories_dir).map_err(|e| HomeGuardError::Io(e))? {
                let entry = entry.map_err(|e| HomeGuardError::Io(e))?;
                let path = entry.path();

                if path.is_file() && path.extension().map_or(false, |ext| ext == "txt") {
                    // Category name is filename without extension
                    let category = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown");

                    match self.load_file(&path, Some(category)) {
                        Ok(count) => total_categories += count,
                        Err(e) => warn!("Failed to load blocklist '{}': {}", path.display(), e),
                    }
                }
            }
        }

        info!(
            "Loaded {} global domains and {} category domains from {}",
            total_global,
            total_categories,
            dir.display()
        );

        Ok(())
    }

    /// Check if domain is in global blocklist
    pub fn is_blocked_globally(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();

        // Check exact match
        if self.global_domains.contains(&domain) {
            return true;
        }

        // Check suffix match
        self.matches_suffix(&domain, &self.global_suffixes)
    }

    /// Check if domain is in specific category
    pub fn is_in_category(&self, domain: &str, category: &str) -> bool {
        let domain = domain.to_lowercase();

        // Check exact match
        if let Some(domains) = self.category_domains.get(category) {
            if domains.contains(&domain) {
                return true;
            }
        }

        // Check suffix match
        if let Some(suffixes) = self.category_suffixes.get(category) {
            if self.matches_suffix(&domain, suffixes) {
                return true;
            }
        }

        false
    }

    /// Check if domain is in ANY of the given categories
    pub fn is_in_any_category(&self, domain: &str, categories: &[String]) -> bool {
        categories.iter().any(|cat| self.is_in_category(domain, cat))
    }

    /// Check if domain matches any suffix in the set
    fn matches_suffix(&self, domain: &str, suffixes: &HashSet<String>) -> bool {
        // Check if domain itself is a suffix
        if suffixes.contains(domain) {
            return true;
        }

        // Check if any parent domain is a suffix
        // e.g., for "www.example.com", check "example.com" and "com"
        let mut parts: Vec<&str> = domain.split('.').collect();

        while parts.len() > 1 {
            parts.remove(0);
            let parent = parts.join(".");

            if suffixes.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Add a domain to the global blocklist
    pub fn add_global(&mut self, domain: &str) {
        self.global_domains.insert(domain.to_lowercase());
    }

    /// Add a domain to a category blocklist
    pub fn add_to_category(&mut self, domain: &str, category: &str) {
        self.category_domains
            .entry(category.to_string())
            .or_default()
            .insert(domain.to_lowercase());
    }

    /// Get global domain count
    pub fn global_count(&self) -> usize {
        self.global_domains.len() + self.global_suffixes.len()
    }

    /// Get category count
    pub fn category_count(&self) -> usize {
        self.category_domains.len()
    }

    /// Get domain count in a category
    pub fn category_domain_count(&self, category: &str) -> usize {
        let domains = self.category_domains.get(category).map_or(0, |d| d.len());
        let suffixes = self.category_suffixes.get(category).map_or(0, |s| s.len());
        domains + suffixes
    }

    /// Get all category names
    pub fn categories(&self) -> Vec<&str> {
        let mut cats: HashSet<&str> = HashSet::new();

        for key in self.category_domains.keys() {
            cats.insert(key.as_str());
        }
        for key in self.category_suffixes.keys() {
            cats.insert(key.as_str());
        }

        cats.into_iter().collect()
    }
}

impl Default for BlocklistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_blocklist_file(dir: &Path, filename: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(filename);
        let mut file = File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_blocklist_manager_new() {
        let manager = BlocklistManager::new();
        assert_eq!(manager.global_count(), 0);
        assert_eq!(manager.category_count(), 0);
    }

    #[test]
    fn test_load_simple_blocklist() {
        let temp_dir = TempDir::new().unwrap();

        let content = r#"
# This is a comment
example.com
blocked.org

another.com
"#;

        let path = create_test_blocklist_file(temp_dir.path(), "test.txt", content);

        let mut manager = BlocklistManager::new();
        let count = manager.load_file(&path, None).unwrap();

        assert_eq!(count, 3);
        assert!(manager.is_blocked_globally("example.com"));
        assert!(manager.is_blocked_globally("blocked.org"));
        assert!(manager.is_blocked_globally("another.com"));
        assert!(!manager.is_blocked_globally("notblocked.com"));
    }

    #[test]
    fn test_load_blocklist_with_wildcards() {
        let temp_dir = TempDir::new().unwrap();

        let content = r#"
# Wildcard suffix
*.adult-content.com
.gambling.net
exact-match.org
"#;

        let path = create_test_blocklist_file(temp_dir.path(), "test.txt", content);

        let mut manager = BlocklistManager::new();
        manager.load_file(&path, None).unwrap();

        // Exact match
        assert!(manager.is_blocked_globally("exact-match.org"));

        // Suffix matches
        assert!(manager.is_blocked_globally("www.adult-content.com"));
        assert!(manager.is_blocked_globally("sub.domain.adult-content.com"));
        assert!(manager.is_blocked_globally("adult-content.com"));

        assert!(manager.is_blocked_globally("www.gambling.net"));
        assert!(manager.is_blocked_globally("gambling.net"));

        // Non-matches
        assert!(!manager.is_blocked_globally("adult-content.org"));
        assert!(!manager.is_blocked_globally("not-adult-content.com"));
    }

    #[test]
    fn test_load_category_blocklist() {
        let temp_dir = TempDir::new().unwrap();

        let content = r#"
game1.com
game2.org
*.gaming.net
"#;

        let path = create_test_blocklist_file(temp_dir.path(), "games.txt", content);

        let mut manager = BlocklistManager::new();
        manager.load_file(&path, Some("games")).unwrap();

        // Should be in category
        assert!(manager.is_in_category("game1.com", "games"));
        assert!(manager.is_in_category("game2.org", "games"));
        assert!(manager.is_in_category("www.gaming.net", "games"));

        // Should NOT be in global
        assert!(!manager.is_blocked_globally("game1.com"));

        // Should NOT be in other categories
        assert!(!manager.is_in_category("game1.com", "social"));
    }

    #[test]
    fn test_is_in_any_category() {
        let mut manager = BlocklistManager::new();

        manager.add_to_category("game.com", "games");
        manager.add_to_category("facebook.com", "social");

        let categories = vec!["games".to_string(), "social".to_string()];

        assert!(manager.is_in_any_category("game.com", &categories));
        assert!(manager.is_in_any_category("facebook.com", &categories));
        assert!(!manager.is_in_any_category("other.com", &categories));
    }

    #[test]
    fn test_case_insensitivity() {
        let mut manager = BlocklistManager::new();
        manager.add_global("Example.COM");

        assert!(manager.is_blocked_globally("example.com"));
        assert!(manager.is_blocked_globally("EXAMPLE.COM"));
        assert!(manager.is_blocked_globally("Example.Com"));
    }

    #[test]
    fn test_load_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        // Create directory structure
        std::fs::create_dir_all(base.join("global")).unwrap();
        std::fs::create_dir_all(base.join("categories")).unwrap();

        // Global blocklist at root
        create_test_blocklist_file(base, "ads.txt", "ad.com\ntracker.org");

        // Global blocklist in global/
        create_test_blocklist_file(&base.join("global"), "malware.txt", "malware.com");

        // Category blocklists
        create_test_blocklist_file(&base.join("categories"), "games.txt", "game1.com\ngame2.com");
        create_test_blocklist_file(&base.join("categories"), "social.txt", "social1.com");

        let mut manager = BlocklistManager::new();
        manager.load_directory(base).unwrap();

        // Check global
        assert!(manager.is_blocked_globally("ad.com"));
        assert!(manager.is_blocked_globally("tracker.org"));
        assert!(manager.is_blocked_globally("malware.com"));

        // Check categories
        assert!(manager.is_in_category("game1.com", "games"));
        assert!(manager.is_in_category("game2.com", "games"));
        assert!(manager.is_in_category("social1.com", "social"));

        // Cross-check
        assert!(!manager.is_in_category("ad.com", "games"));
        assert!(!manager.is_blocked_globally("game1.com"));
    }

    #[test]
    fn test_suffix_matching() {
        let mut manager = BlocklistManager::new();

        // Add a suffix rule
        manager.global_suffixes.insert("badsite.com".to_string());

        // Should match
        assert!(manager.is_blocked_globally("badsite.com"));
        assert!(manager.is_blocked_globally("www.badsite.com"));
        assert!(manager.is_blocked_globally("sub.domain.badsite.com"));

        // Should not match
        assert!(!manager.is_blocked_globally("notbadsite.com"));
        assert!(!manager.is_blocked_globally("badsite.org"));
    }

    #[test]
    fn test_categories_list() {
        let mut manager = BlocklistManager::new();

        manager.add_to_category("game.com", "games");
        manager.add_to_category("social.com", "social");
        manager.add_to_category("porn.com", "porn");

        let cats = manager.categories();
        assert_eq!(cats.len(), 3);
        assert!(cats.contains(&"games"));
        assert!(cats.contains(&"social"));
        assert!(cats.contains(&"porn"));
    }

    #[test]
    fn test_nonexistent_file() {
        let mut manager = BlocklistManager::new();
        let result = manager.load_file(Path::new("/nonexistent/file.txt"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonexistent_directory() {
        let mut manager = BlocklistManager::new();
        // Should not error, just log warning
        let result = manager.load_directory(Path::new("/nonexistent/directory"));
        assert!(result.is_ok());
    }
}
