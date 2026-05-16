//! Outbound proxy protocols
//!
//! This module provides implementations for various outbound proxy protocols:
//! - Direct connection
//! - Reject (block connection)
//! - Shadowsocks proxy
//! - Proxy groups (select, url-test, fallback)

pub mod group;
pub mod manager;
pub mod shadowsocks;

use async_trait::async_trait;
use std::io::Result;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

// Re-export main types
pub use group::{FallbackGroup, ProxyGroup, SelectGroup, UrlTestGroup};
pub use manager::OutboundManager;
pub use shadowsocks::{Address, ShadowsocksClient};

/// Trait for async streams that can be used for bidirectional I/O
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

// Implement AsyncStream for TcpStream
impl AsyncStream for TcpStream {}

/// Outbound connection handler trait
///
/// This trait defines the interface for all outbound connection types,
/// including direct connections, proxy connections, and reject handlers.
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Get the name of this outbound
    fn name(&self) -> &str;

    /// Connect to the target address
    ///
    /// Returns a stream that can be used for bidirectional communication.
    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>>;

    /// Perform a health check
    ///
    /// Returns the latency if the check succeeds.
    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration>;

    /// Check if this outbound is currently available
    fn is_available(&self) -> bool {
        true
    }
}

/// Direct outbound - connects directly to the target
pub struct DirectOutbound;

impl DirectOutbound {
    pub fn new() -> Self {
        DirectOutbound
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>> {
        let addr = target.to_socket_addr().await?;
        let stream = TcpStream::connect(addr).await?;
        Ok(Box::new(stream))
    }

    async fn health_check(&self, _url: &str, _timeout: Duration) -> Result<Duration> {
        // Direct connection is always considered healthy
        Ok(Duration::from_millis(0))
    }
}

/// Reject outbound - immediately rejects connections
pub struct RejectOutbound;

impl RejectOutbound {
    pub fn new() -> Self {
        RejectOutbound
    }
}

impl Default for RejectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outbound for RejectOutbound {
    fn name(&self) -> &str {
        "REJECT"
    }

    async fn connect(&self, _target: &Address) -> Result<Box<dyn AsyncStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection rejected by policy",
        ))
    }

    async fn health_check(&self, _url: &str, _timeout: Duration) -> Result<Duration> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Reject outbound has no health check",
        ))
    }

    fn is_available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_outbound_name() {
        let direct = DirectOutbound::new();
        assert_eq!(direct.name(), "DIRECT");
    }

    #[test]
    fn test_reject_outbound_name() {
        let reject = RejectOutbound::new();
        assert_eq!(reject.name(), "REJECT");
        assert!(!reject.is_available());
    }
}
