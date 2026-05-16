//! Fallback proxy group
//!
//! Uses the first available proxy in the list.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::io::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::no_available_proxy_error;
use crate::outbound::{Address, AsyncStream, Outbound};

/// Fallback proxy group
///
/// Uses the first available proxy in the list. Periodically checks
/// availability and falls back to the next proxy if the current one fails.
pub struct FallbackGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    test_url: String,
    test_interval: Duration,
    test_timeout: Duration,
    /// Availability status for each proxy
    available: RwLock<Vec<bool>>,
    /// Last check time
    last_check: RwLock<Option<Instant>>,
}

impl FallbackGroup {
    /// Create a new fallback group
    pub fn new(
        name: impl Into<String>,
        proxies: Vec<Arc<dyn Outbound>>,
        test_url: impl Into<String>,
        test_interval: Duration,
    ) -> Self {
        let proxy_count = proxies.len();
        Self {
            name: name.into(),
            proxies,
            test_url: test_url.into(),
            test_interval,
            test_timeout: Duration::from_secs(5),
            available: RwLock::new(vec![true; proxy_count]), // Assume available initially
            last_check: RwLock::new(None),
        }
    }

    /// Set the test timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.test_timeout = timeout;
        self
    }

    /// Get the group name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get all proxy names
    pub fn proxy_names(&self) -> Vec<&str> {
        self.proxies.iter().map(|p| p.name()).collect()
    }

    /// Get the number of proxies
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Get the first available proxy
    pub fn first_available(&self) -> Option<&Arc<dyn Outbound>> {
        let available = self.available.read();
        self.proxies
            .iter()
            .enumerate()
            .find(|(idx, _)| available.get(*idx).copied().unwrap_or(false))
            .map(|(_, proxy)| proxy)
    }

    /// Get the name of the first available proxy
    pub fn first_available_name(&self) -> Option<&str> {
        self.first_available().map(|p| p.name())
    }

    /// Check if availability testing is needed
    pub fn needs_check(&self) -> bool {
        let last_check = self.last_check.read();
        match *last_check {
            None => true,
            Some(last) => last.elapsed() >= self.test_interval,
        }
    }

    /// Mark a proxy as unavailable by index
    pub fn mark_unavailable(&self, index: usize) {
        let mut available = self.available.write();
        if index < available.len() {
            available[index] = false;
            debug!(
                "Marked proxy '{}' as unavailable in group '{}'",
                self.proxies.get(index).map(|p| p.name()).unwrap_or("unknown"),
                self.name
            );
        }
    }

    /// Check all proxies and update availability
    pub async fn check_all(&self) {
        if self.proxies.is_empty() {
            return;
        }

        info!(
            "FallbackGroup '{}' checking {} proxies",
            self.name,
            self.proxies.len()
        );

        let mut results: Vec<bool> = vec![false; self.proxies.len()];

        // Check all proxies concurrently
        let handles: Vec<_> = self
            .proxies
            .iter()
            .enumerate()
            .map(|(idx, proxy)| {
                let proxy = proxy.clone();
                let url = self.test_url.clone();
                let timeout = self.test_timeout;
                tokio::spawn(async move {
                    let result = proxy.health_check(&url, timeout).await;
                    (idx, result.is_ok())
                })
            })
            .collect();

        for handle in handles {
            match handle.await {
                Ok((idx, available)) => {
                    debug!(
                        "Proxy '{}' available: {}",
                        self.proxies[idx].name(),
                        available
                    );
                    results[idx] = available;
                }
                Err(e) => {
                    warn!("Check task failed: {}", e);
                }
            }
        }

        // Update state
        {
            let mut available = self.available.write();
            *available = results;
        }
        {
            let mut last_check = self.last_check.write();
            *last_check = Some(Instant::now());
        }

        let first_avail = self.first_available_name();
        info!(
            "FallbackGroup '{}' first available: {:?}",
            self.name, first_avail
        );
    }

    /// Start a background task that periodically checks proxies
    pub fn start_background_check(self: Arc<Self>) {
        let group = self.clone();
        tokio::spawn(async move {
            loop {
                if group.needs_check() {
                    group.check_all().await;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
}

#[async_trait]
impl Outbound for FallbackGroup {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>> {
        // Check if needed (lazy checking)
        if self.needs_check() {
            self.check_all().await;
        }

        // Try to connect with the first available proxy
        let available = self.available.read().clone();
        drop(available); // Release lock before async operations

        for (idx, proxy) in self.proxies.iter().enumerate() {
            let is_available = {
                let available = self.available.read();
                available.get(idx).copied().unwrap_or(false)
            };

            if !is_available {
                continue;
            }

            debug!(
                "FallbackGroup '{}' trying proxy '{}'",
                self.name,
                proxy.name()
            );

            match proxy.connect(target).await {
                Ok(stream) => {
                    debug!(
                        "FallbackGroup '{}' connected via '{}'",
                        self.name,
                        proxy.name()
                    );
                    return Ok(stream);
                }
                Err(e) => {
                    warn!(
                        "FallbackGroup '{}' proxy '{}' failed: {}",
                        self.name,
                        proxy.name(),
                        e
                    );
                    self.mark_unavailable(idx);
                }
            }
        }

        Err(no_available_proxy_error(&self.name))
    }

    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration> {
        let proxy = self
            .first_available()
            .ok_or_else(|| no_available_proxy_error(&self.name))?;
        proxy.health_check(url, timeout).await
    }

    fn is_available(&self) -> bool {
        self.first_available().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectOutbound;

    fn create_test_group() -> FallbackGroup {
        let proxies: Vec<Arc<dyn Outbound>> = vec![Arc::new(DirectOutbound::new())];
        FallbackGroup::new(
            "test-fallback",
            proxies,
            "http://www.gstatic.com/generate_204",
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_fallback_group_new() {
        let group = create_test_group();
        assert_eq!(group.name(), "test-fallback");
        assert_eq!(group.len(), 1);
        assert!(!group.is_empty());
    }

    #[test]
    fn test_fallback_group_needs_check() {
        let group = create_test_group();
        assert!(group.needs_check()); // Should need check initially
    }

    #[test]
    fn test_fallback_group_first_available() {
        let group = create_test_group();
        assert!(group.first_available().is_some());
        assert_eq!(group.first_available_name(), Some("DIRECT"));
    }

    #[test]
    fn test_fallback_group_mark_unavailable() {
        let group = create_test_group();
        assert!(group.is_available());

        group.mark_unavailable(0);
        assert!(!group.is_available());
        assert!(group.first_available().is_none());
    }

    #[test]
    fn test_fallback_group_proxy_names() {
        let group = create_test_group();
        let names = group.proxy_names();
        assert_eq!(names, vec!["DIRECT"]);
    }

    #[test]
    fn test_fallback_group_with_timeout() {
        let proxies: Vec<Arc<dyn Outbound>> = vec![Arc::new(DirectOutbound::new())];
        let group = FallbackGroup::new("test", proxies, "http://test.com", Duration::from_secs(300))
            .with_timeout(Duration::from_secs(10));
        assert_eq!(group.test_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_empty_fallback_group() {
        let group = FallbackGroup::new(
            "empty",
            vec![],
            "http://test.com",
            Duration::from_secs(300),
        );
        assert!(group.is_empty());
        assert!(group.first_available().is_none());
        assert!(!group.is_available());
    }
}
