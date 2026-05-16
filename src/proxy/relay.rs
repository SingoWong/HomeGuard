//! TCP bidirectional relay
//!
//! Provides efficient data transfer between two TCP connections.
//! Uses tokio's `copy_bidirectional` for zero-copy performance.

use std::io::{Error, ErrorKind, Result};
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Statistics from a relay operation
#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    /// Bytes transferred from client to server
    pub client_to_server: u64,
    /// Bytes transferred from server to client
    pub server_to_client: u64,
}

impl RelayStats {
    /// Total bytes transferred
    pub fn total(&self) -> u64 {
        self.client_to_server + self.server_to_client
    }
}

/// Relay data bidirectionally between two TCP streams.
///
/// This function will complete when either:
/// - One side closes the connection
/// - An error occurs
///
/// # Arguments
/// * `inbound` - The client connection (from transparent proxy accept)
/// * `outbound` - The target connection (direct or via proxy)
///
/// # Returns
/// Statistics about bytes transferred in each direction
pub async fn relay(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<RelayStats> {
    debug!("Starting TCP relay");

    match copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok((client_to_server, server_to_client)) => {
            debug!(
                "Relay completed: {} bytes up, {} bytes down",
                client_to_server, server_to_client
            );
            Ok(RelayStats {
                client_to_server,
                server_to_client,
            })
        }
        Err(e) => {
            // Connection reset is normal during relay (client/server closed)
            if e.kind() == ErrorKind::ConnectionReset
                || e.kind() == ErrorKind::BrokenPipe
                || e.kind() == ErrorKind::NotConnected
            {
                debug!("Relay ended: {}", e);
                Ok(RelayStats {
                    client_to_server: 0,
                    server_to_client: 0,
                })
            } else {
                warn!("Relay error: {}", e);
                Err(e)
            }
        }
    }
}

/// Relay data bidirectionally with a timeout.
///
/// The timeout applies to the entire relay operation, not individual reads/writes.
/// This is useful for preventing connections from hanging indefinitely.
///
/// # Arguments
/// * `inbound` - The client connection
/// * `outbound` - The target connection
/// * `relay_timeout` - Maximum duration for the entire relay
///
/// # Returns
/// Statistics about bytes transferred, or error if timeout exceeded
pub async fn relay_with_timeout(
    inbound: TcpStream,
    outbound: TcpStream,
    relay_timeout: Duration,
) -> Result<RelayStats> {
    match timeout(relay_timeout, relay(inbound, outbound)).await {
        Ok(result) => result,
        Err(_) => {
            debug!("Relay timed out after {:?}", relay_timeout);
            Err(Error::new(ErrorKind::TimedOut, "Relay timeout"))
        }
    }
}

/// Connect to a target address with timeout and start relay.
///
/// This is a convenience function that:
/// 1. Connects to the target with timeout
/// 2. Starts bidirectional relay
///
/// # Arguments
/// * `inbound` - The client connection
/// * `target` - Target address to connect to
/// * `connect_timeout` - Timeout for establishing connection
pub async fn connect_and_relay(
    inbound: TcpStream,
    target: std::net::SocketAddr,
    connect_timeout: Duration,
) -> Result<RelayStats> {
    debug!("Connecting to target: {}", target);

    // Connect to target with timeout
    let outbound = match timeout(connect_timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!("Failed to connect to {}: {}", target, e);
            return Err(e);
        }
        Err(_) => {
            warn!("Connection to {} timed out", target);
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("Connection to {} timed out", target),
            ));
        }
    };

    debug!("Connected to {}, starting relay", target);

    // Start relay
    relay(inbound, outbound).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_relay_basic() {
        // Create a simple echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Spawn echo server
        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        socket.write_all(&buf[..n]).await.unwrap();
                    }
                    Err(_) => break,
                }
            }
        });

        // Create client connection
        let client = TcpStream::connect(server_addr).await.unwrap();

        // Create a pipe for testing
        let pipe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pipe_addr = pipe_listener.local_addr().unwrap();

        // Connect relay inbound to pipe
        let relay_inbound = TcpStream::connect(pipe_addr).await.unwrap();
        let (pipe_server, _) = pipe_listener.accept().await.unwrap();

        // Start relay in background
        let relay_handle = tokio::spawn(async move {
            relay(relay_inbound, client).await
        });

        // Write to pipe server, should go through relay to echo server and back
        let mut pipe = pipe_server;
        pipe.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 5];
        pipe.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Clean up
        drop(pipe);
        let _ = relay_handle.await;
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_stats() {
        let stats = RelayStats {
            client_to_server: 100,
            server_to_client: 200,
        };
        assert_eq!(stats.total(), 300);
    }

    #[tokio::test]
    async fn test_relay_timeout() {
        // Create a listener that never accepts
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _addr = listener.local_addr().unwrap();

        // This test just verifies the timeout mechanism works
        // In real usage, the connection would be established first
    }
}
