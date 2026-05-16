//! URL test proxy group
//!
//! Automatically selects the proxy with the lowest latency.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::io::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::no_available_proxy_error;
use crate::outbound::{Address, AsyncStream, Outbound};

/// URL test proxy group
///
/// Periodically tests all proxies and automatically selects the one
/// with the lowest latency.
pub struct UrlTestGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    test_url: String,
    test_interval: Duration,
    test_timeout: Duration,
    /// Index of the best (lowest latency) proxy
    best: AtomicUsize,
    /// Latency results for each proxy (None = not tested or failed)
    latencies: RwLock<Vec<Option<Duration>>>,
    /// Last test time
    last_test: RwLock<Option<Instant>>,
}

impl UrlTestGroup {
    /// Create a new URL test group
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
            best: AtomicUsize::new(0),
            latencies: RwLock::new(vec![None; proxy_count]),
            last_test: RwLock::new(None),
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

    /// Get the best proxy index
    pub fn best_index(&self) -> usize {
        self.best.load(Ordering::Relaxed)
    }

    /// Get the best proxy
    pub fn best_proxy(&self) -> Option<&Arc<dyn Outbound>> {
        let idx = self.best_index();
        self.proxies.get(idx)
    }

    /// Get the name of the best proxy
    pub fn best_name(&self) -> Option<&str> {
        self.best_proxy().map(|p| p.name())
    }

    /// Get the latency of a proxy by index
    pub fn get_latency(&self, index: usize) -> Option<Duration> {
        let latencies = self.latencies.read();
        latencies.get(index).and_then(|l| *l)
    }

    /// Check if testing is needed
    pub fn needs_test(&self) -> bool {
        let last_test = self.last_test.read();
        match *last_test {
            None => true,
            Some(last) => last.elapsed() >= self.test_interval,
        }
    }

    /// Test all proxies and update the best one
    pub async fn test_all(&self) {
        if self.proxies.is_empty() {
            return;
        }

        info!(
            "UrlTestGroup '{}' testing {} proxies",
            self.name,
            self.proxies.len()
        );

        let mut results: Vec<Option<Duration>> = vec![None; self.proxies.len()];
        let mut best_idx = 0;
        let mut best_latency = Duration::MAX;

        // Test all proxies concurrently
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
                    (idx, result)
                })
            })
            .collect();

        for handle in handles {
            match handle.await {
                Ok((idx, Ok(latency))) => {
                    debug!(
                        "Proxy '{}' latency: {:?}",
                        self.proxies[idx].name(),
                        latency
                    );
                    results[idx] = Some(latency);
                    if latency < best_latency {
                        best_latency = latency;
                        best_idx = idx;
                    }
                }
                Ok((idx, Err(e))) => {
                    warn!("Proxy '{}' test failed: {}", self.proxies[idx].name(), e);
                    results[idx] = None;
                }
                Err(e) => {
                    warn!("Test task failed: {}", e);
                }
            }
        }

        // Update state
        {
            let mut latencies = self.latencies.write();
            *latencies = results;
        }
        self.best.store(best_idx, Ordering::Relaxed);
        {
            let mut last_test = self.last_test.write();
            *last_test = Some(Instant::now());
        }

        info!(
            "UrlTestGroup '{}' best proxy: '{}' ({:?})",
            self.name,
            self.proxies.get(best_idx).map(|p| p.name()).unwrap_or("none"),
            if best_latency == Duration::MAX {
                None
            } else {
                Some(best_latency)
            }
        );
    }

    /// Start a background task that periodically tests proxies
    pub fn start_background_test(self: Arc<Self>) {
        let group = self.clone();
        tokio::spawn(async move {
            loop {
                if group.needs_test() {
                    group.test_all().await;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
}

#[async_trait]
impl Outbound for UrlTestGroup {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>> {
        // Test if needed (lazy testing)
        if self.needs_test() {
            self.test_all().await;
        }

        let proxy = self.best_proxy().ok_or_else(|| no_available_proxy_error(&self.name))?;
        debug!(
            "UrlTestGroup '{}' connecting via '{}'",
            self.name,
            proxy.name()
        );
        proxy.connect(target).await
    }

    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration> {
        let proxy = self.best_proxy().ok_or_else(|| no_available_proxy_error(&self.name))?;
        proxy.health_check(url, timeout).await
    }

    fn is_available(&self) -> bool {
        // Check if any proxy has a valid latency
        let latencies = self.latencies.read();
        latencies.iter().any(|l| l.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectOutbound;

    fn create_test_group() -> UrlTestGroup {
        let proxies: Vec<Arc<dyn Outbound>> = vec![Arc::new(DirectOutbound::new())];
        UrlTestGroup::new(
            "test-url-test",
            proxies,
            "http://www.gstatic.com/generate_204",
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_url_test_group_new() {
        let group = create_test_group();
        assert_eq!(group.name(), "test-url-test");
        assert_eq!(group.len(), 1);
        assert!(!group.is_empty());
    }

    #[test]
    fn test_url_test_group_needs_test() {
        let group = create_test_group();
        assert!(group.needs_test()); // Should need test initially
    }

    #[test]
    fn test_url_test_group_best() {
        let group = create_test_group();
        assert_eq!(group.best_index(), 0);
        assert!(group.best_proxy().is_some());
        assert_eq!(group.best_name(), Some("DIRECT"));
    }

    #[test]
    fn test_url_test_group_proxy_names() {
        let group = create_test_group();
        let names = group.proxy_names();
        assert_eq!(names, vec!["DIRECT"]);
    }

    #[test]
    fn test_url_test_group_with_timeout() {
        let proxies: Vec<Arc<dyn Outbound>> = vec![Arc::new(DirectOutbound::new())];
        let group = UrlTestGroup::new("test", proxies, "http://test.com", Duration::from_secs(300))
            .with_timeout(Duration::from_secs(10));
        assert_eq!(group.test_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_empty_url_test_group() {
        let group = UrlTestGroup::new(
            "empty",
            vec![],
            "http://test.com",
            Duration::from_secs(300),
        );
        assert!(group.is_empty());
        assert!(group.best_proxy().is_none());
    }
}
