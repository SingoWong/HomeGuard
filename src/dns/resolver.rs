//! Upstream DNS resolver
//!
//! Forwards DNS queries to upstream servers with fallback support.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::{HomeGuardError, Result};

/// Maximum DNS packet size (UDP)
const MAX_DNS_PACKET_SIZE: usize = 512;

/// DNS resolver for upstream queries
pub struct DnsResolver {
    /// List of upstream DNS servers
    upstreams: Vec<SocketAddr>,
    /// Query timeout
    timeout: Duration,
}

impl DnsResolver {
    /// Create a new DNS resolver
    ///
    /// # Arguments
    /// * `upstreams` - List of upstream DNS servers (e.g., ["8.8.8.8:53", "1.1.1.1:53"])
    /// * `timeout` - Query timeout duration
    pub fn new(upstreams: Vec<String>, timeout_secs: u64) -> Result<Self> {
        if upstreams.is_empty() {
            return Err(HomeGuardError::InvalidConfig(
                "At least one upstream DNS server is required".to_string(),
            ));
        }

        let upstreams: Vec<SocketAddr> = upstreams
            .iter()
            .filter_map(|s| {
                s.parse().ok().or_else(|| {
                    // Try adding default port
                    format!("{}:53", s).parse().ok()
                })
            })
            .collect();

        if upstreams.is_empty() {
            return Err(HomeGuardError::InvalidConfig(
                "No valid upstream DNS server addresses".to_string(),
            ));
        }

        debug!("DNS resolver initialized with {} upstreams", upstreams.len());
        for upstream in &upstreams {
            debug!("  - {}", upstream);
        }

        Ok(Self {
            upstreams,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Create resolver with default settings
    pub fn with_defaults() -> Result<Self> {
        Self::new(
            vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            5,
        )
    }

    /// Resolve a DNS query using upstream servers
    ///
    /// Tries each upstream in order until one succeeds.
    /// Returns the raw DNS response packet.
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let mut last_error = None;

        for upstream in &self.upstreams {
            match self.query_upstream(query, *upstream).await {
                Ok(response) => {
                    debug!("DNS query resolved via {}", upstream);
                    return Ok(response);
                }
                Err(e) => {
                    warn!("DNS query to {} failed: {}", upstream, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            HomeGuardError::Dns("All upstream DNS servers failed".to_string())
        }))
    }

    /// Query a single upstream server
    async fn query_upstream(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        // Create a new UDP socket for this query
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            HomeGuardError::Dns(format!("Failed to bind UDP socket: {}", e))
        })?;

        // Send query
        socket.send_to(query, upstream).await.map_err(|e| {
            HomeGuardError::Dns(format!("Failed to send query to {}: {}", upstream, e))
        })?;

        // Receive response with timeout
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
        let recv_future = socket.recv_from(&mut buf);

        match timeout(self.timeout, recv_future).await {
            Ok(Ok((len, _))) => {
                buf.truncate(len);
                Ok(buf)
            }
            Ok(Err(e)) => Err(HomeGuardError::Dns(format!(
                "Failed to receive response from {}: {}",
                upstream, e
            ))),
            Err(_) => Err(HomeGuardError::Dns(format!(
                "Query to {} timed out",
                upstream
            ))),
        }
    }

    /// Get the list of upstream servers
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    /// Get the timeout duration
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_new() {
        let resolver = DnsResolver::new(
            vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            5,
        )
        .unwrap();

        assert_eq!(resolver.upstreams().len(), 2);
        assert_eq!(resolver.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_resolver_new_without_port() {
        let resolver = DnsResolver::new(vec!["8.8.8.8".to_string()], 5).unwrap();

        assert_eq!(resolver.upstreams().len(), 1);
        assert_eq!(
            resolver.upstreams()[0],
            "8.8.8.8:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_resolver_empty_upstreams() {
        let result = DnsResolver::new(vec![], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolver_invalid_upstreams() {
        let result = DnsResolver::new(vec!["not-a-valid-address".to_string()], 5);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_query() {
        // This test requires network access
        // Skip if we can't reach DNS servers
        let resolver = match DnsResolver::new(vec!["8.8.8.8:53".to_string()], 2) {
            Ok(r) => r,
            Err(_) => return,
        };

        // Build a simple DNS query for google.com A record
        // Header: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        // Question: QNAME + QTYPE(2) + QCLASS(2)
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // FLAGS: standard query, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // QNAME: google.com
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];

        match resolver.resolve(&query).await {
            Ok(response) => {
                // Basic validation: response should start with same ID
                assert!(response.len() >= 12);
                assert_eq!(response[0], query[0]);
                assert_eq!(response[1], query[1]);
            }
            Err(e) => {
                // Network might not be available in test environment
                eprintln!("DNS query test skipped: {}", e);
            }
        }
    }
}
