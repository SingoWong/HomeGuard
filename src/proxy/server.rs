//! Transparent proxy server
//!
//! Listens for TCP connections redirected by PF and dispatches them
//! to the connection handler.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use super::handler::ConnectionHandler;
use crate::control::ParentalController;
use crate::dns::FakeDns;
use crate::error::{HomeGuardError, Result};
use crate::outbound::OutboundManager;
use crate::rule::RuleEngine;

/// Transparent proxy server
pub struct TransparentProxy {
    /// TCP listener
    listener: TcpListener,

    /// Listen address (for logging)
    listen_addr: SocketAddr,

    /// Connection handler
    handler: Arc<ConnectionHandler>,
}

impl TransparentProxy {
    /// Create a new transparent proxy server
    ///
    /// # Arguments
    /// * `listen_addr` - Address to listen on (e.g., "127.0.0.1:7893")
    /// * `fake_dns` - Optional FakeDNS for domain lookup
    /// * `rule_engine` - Rule engine for policy matching
    /// * `outbound_manager` - Outbound manager for proxy connections
    pub async fn new(
        listen_addr: &str,
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            HomeGuardError::InvalidConfig(format!(
                "Invalid listen address '{}': {}",
                listen_addr, e
            ))
        })?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            HomeGuardError::Proxy(format!(
                "Failed to bind transparent proxy to {}: {}",
                addr, e
            ))
        })?;

        // Get the actual bound address (important when binding to port 0)
        let listen_addr = listener.local_addr().map_err(|e| {
            HomeGuardError::Proxy(format!("Failed to get local address: {}", e))
        })?;

        info!("Transparent proxy bound to {}", listen_addr);

        let handler = Arc::new(ConnectionHandler::new(fake_dns, rule_engine, outbound_manager));

        Ok(Self {
            listener,
            listen_addr,
            handler,
        })
    }

    /// Create a new transparent proxy server with parental control
    pub async fn with_parental_control(
        listen_addr: &str,
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        parental_controller: Arc<ParentalController>,
    ) -> Result<Self> {
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            HomeGuardError::InvalidConfig(format!(
                "Invalid listen address '{}': {}",
                listen_addr, e
            ))
        })?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            HomeGuardError::Proxy(format!(
                "Failed to bind transparent proxy to {}: {}",
                addr, e
            ))
        })?;

        let listen_addr = listener.local_addr().map_err(|e| {
            HomeGuardError::Proxy(format!("Failed to get local address: {}", e))
        })?;

        info!("Transparent proxy bound to {} (parental control enabled)", listen_addr);

        let handler = Arc::new(ConnectionHandler::with_parental_control(
            fake_dns,
            rule_engine,
            outbound_manager,
            parental_controller,
        ));

        Ok(Self {
            listener,
            listen_addr,
            handler,
        })
    }

    /// Run the transparent proxy server
    ///
    /// This method runs indefinitely, accepting and processing connections.
    pub async fn run(&self) -> Result<()> {
        info!("Transparent proxy starting on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((stream, src_addr)) => {
                    debug!("Accepted connection from {}", src_addr);

                    let handler = self.handler.clone();

                    // Spawn a task to handle the connection
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(stream, src_addr).await {
                            warn!("Connection handling error for {}: {}", src_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    // Continue accepting other connections
                }
            }
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get reference to the handler
    pub fn handler(&self) -> &Arc<ConnectionHandler> {
        &self.handler
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Rule, RuleType, Policy};

    #[tokio::test]
    async fn test_transparent_proxy_new() {
        // Create a simple rule engine
        let rules = vec![Rule::new(RuleType::Final, Policy::Direct)];
        let rule_engine = Arc::new(RuleEngine::new(rules, None).unwrap());
        let outbound_manager = Arc::new(OutboundManager::default());

        // Create transparent proxy on a random port
        let proxy = TransparentProxy::new("127.0.0.1:0", None, rule_engine, outbound_manager).await;

        assert!(proxy.is_ok());

        let proxy = proxy.unwrap();
        assert_ne!(proxy.listen_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_transparent_proxy_invalid_addr() {
        let rules = vec![Rule::new(RuleType::Final, Policy::Direct)];
        let rule_engine = Arc::new(RuleEngine::new(rules, None).unwrap());
        let outbound_manager = Arc::new(OutboundManager::default());

        let result = TransparentProxy::new("invalid:addr", None, rule_engine, outbound_manager).await;
        assert!(result.is_err());
    }
}
