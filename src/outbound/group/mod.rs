//! Proxy group implementations
//!
//! Provides different strategies for selecting proxies:
//! - Select: Manual selection
//! - UrlTest: Automatic selection based on latency
//! - Fallback: Use first available proxy

mod select;
mod url_test;
mod fallback;

pub use select::SelectGroup;
pub use url_test::UrlTestGroup;
pub use fallback::FallbackGroup;

use async_trait::async_trait;
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::time::Duration;

use super::{Address, AsyncStream, Outbound};

/// Proxy group that can contain multiple outbounds
#[derive(Clone)]
pub enum ProxyGroup {
    Select(Arc<SelectGroup>),
    UrlTest(Arc<UrlTestGroup>),
    Fallback(Arc<FallbackGroup>),
}

impl ProxyGroup {
    /// Get the group name
    pub fn name(&self) -> &str {
        match self {
            ProxyGroup::Select(g) => g.name(),
            ProxyGroup::UrlTest(g) => g.name(),
            ProxyGroup::Fallback(g) => g.name(),
        }
    }

    /// Get all proxy names in the group
    pub fn proxy_names(&self) -> Vec<&str> {
        match self {
            ProxyGroup::Select(g) => g.proxy_names(),
            ProxyGroup::UrlTest(g) => g.proxy_names(),
            ProxyGroup::Fallback(g) => g.proxy_names(),
        }
    }
}

#[async_trait]
impl Outbound for ProxyGroup {
    fn name(&self) -> &str {
        match self {
            ProxyGroup::Select(g) => g.name(),
            ProxyGroup::UrlTest(g) => g.name(),
            ProxyGroup::Fallback(g) => g.name(),
        }
    }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>> {
        match self {
            ProxyGroup::Select(g) => g.connect(target).await,
            ProxyGroup::UrlTest(g) => g.connect(target).await,
            ProxyGroup::Fallback(g) => g.connect(target).await,
        }
    }

    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration> {
        match self {
            ProxyGroup::Select(g) => g.health_check(url, timeout).await,
            ProxyGroup::UrlTest(g) => g.health_check(url, timeout).await,
            ProxyGroup::Fallback(g) => g.health_check(url, timeout).await,
        }
    }

    fn is_available(&self) -> bool {
        match self {
            ProxyGroup::Select(g) => g.is_available(),
            ProxyGroup::UrlTest(g) => g.is_available(),
            ProxyGroup::Fallback(g) => g.is_available(),
        }
    }
}

/// Get no available proxy error
pub(crate) fn no_available_proxy_error(group_name: &str) -> Error {
    Error::new(
        ErrorKind::NotConnected,
        format!("No available proxy in group '{}'", group_name),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_proxy_group_name() {
        // Basic test that group enum works
        // More detailed tests in individual group modules
    }
}
