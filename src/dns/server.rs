//! UDP DNS server
//!
//! Listens for DNS queries on UDP port 53 and dispatches them to the handler.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use super::handler::DnsHandler;
use crate::error::{HomeGuardError, Result};

/// Maximum DNS packet size (UDP)
const MAX_DNS_PACKET_SIZE: usize = 512;

/// DNS server
pub struct DnsServer {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Query handler
    handler: Arc<DnsHandler>,
    /// Listen address (for logging)
    listen_addr: SocketAddr,
}

impl DnsServer {
    /// Create a new DNS server
    ///
    /// # Arguments
    /// * `listen_addr` - Address to listen on (e.g., "0.0.0.0:53")
    /// * `handler` - DNS query handler
    pub async fn new(listen_addr: &str, handler: Arc<DnsHandler>) -> Result<Self> {
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            HomeGuardError::InvalidConfig(format!("Invalid listen address '{}': {}", listen_addr, e))
        })?;

        let socket = UdpSocket::bind(addr).await.map_err(|e| {
            HomeGuardError::Dns(format!("Failed to bind DNS server to {}: {}", addr, e))
        })?;

        info!("DNS server bound to {}", addr);

        Ok(Self {
            socket: Arc::new(socket),
            handler,
            listen_addr: addr,
        })
    }

    /// Run the DNS server
    ///
    /// This method runs indefinitely, processing incoming DNS queries.
    pub async fn run(&self) -> Result<()> {
        info!("DNS server starting on {}", self.listen_addr);

        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let query = buf[..len].to_vec();
                    let handler = self.handler.clone();
                    let socket = self.socket.clone();

                    // Spawn a task to handle the query
                    tokio::spawn(async move {
                        Self::handle_query_task(handler, socket, query, src_addr).await;
                    });
                }
                Err(e) => {
                    error!("Error receiving DNS query: {}", e);
                    // Continue processing other queries
                }
            }
        }
    }

    /// Handle a single DNS query
    async fn handle_query_task(
        handler: Arc<DnsHandler>,
        socket: Arc<UdpSocket>,
        query: Vec<u8>,
        src_addr: SocketAddr,
    ) {
        debug!("DNS query from {}", src_addr);

        match handler.handle_query(&query, src_addr).await {
            Ok(response) => {
                if let Err(e) = socket.send_to(&response, src_addr).await {
                    warn!("Failed to send DNS response to {}: {}", src_addr, e);
                }
            }
            Err(e) => {
                warn!("Failed to handle DNS query from {}: {}", src_addr, e);
                // Try to send error response
                if let Ok(error_response) = build_servfail_response(&query) {
                    let _ = socket.send_to(&error_response, src_addr).await;
                }
            }
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get reference to the handler
    pub fn handler(&self) -> &Arc<DnsHandler> {
        &self.handler
    }
}

/// Build a SERVFAIL response
fn build_servfail_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(HomeGuardError::Dns("Query too short".to_string()));
    }

    let mut response = vec![0u8; 12];

    // Copy transaction ID
    response[0] = query[0];
    response[1] = query[1];

    // Flags: QR=1, RCODE=SERVFAIL (2)
    response[2] = 0x80;
    response[3] = 0x02;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_servfail_response() {
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // FLAGS
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let response = build_servfail_response(&query).unwrap();

        assert_eq!(response.len(), 12);
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_eq!(response[3] & 0x0F, 0x02); // RCODE=SERVFAIL
    }

    #[test]
    fn test_build_servfail_short_query() {
        let query = vec![0x12, 0x34]; // Too short
        let result = build_servfail_response(&query);
        assert!(result.is_err());
    }
}
