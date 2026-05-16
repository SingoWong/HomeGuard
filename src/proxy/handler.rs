//! Connection handler for transparent proxy
//!
//! Handles individual connections:
//! 1. Gets original destination from PF NAT
//! 2. Looks up domain from FakeDNS if applicable
//! 3. Checks parental control (if enabled)
//! 4. Matches against rule engine
//! 5. Routes to appropriate outbound (DIRECT/REJECT/PROXY)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::nat::get_original_dst;
use super::relay::connect_and_relay;
use crate::control::ParentalController;
use crate::dns::FakeDns;
use crate::error::{HomeGuardError, Result};
use crate::outbound::{Address, AsyncStream, OutboundManager};
use crate::rule::{Policy, RuleEngine};

/// Default connection timeout
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection handler
pub struct ConnectionHandler {
    /// FakeDNS for IP -> Domain lookup
    fake_dns: Option<Arc<FakeDns>>,

    /// Rule engine for policy matching
    rule_engine: Arc<RuleEngine>,

    /// Outbound manager for proxy connections
    outbound_manager: Arc<OutboundManager>,

    /// Parental controller (optional)
    parental_controller: Option<Arc<ParentalController>>,

    /// Connection timeout
    connect_timeout: Duration,
}

impl ConnectionHandler {
    /// Create a new connection handler
    pub fn new(
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        Self {
            fake_dns,
            rule_engine,
            outbound_manager,
            parental_controller: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            fake_dns,
            rule_engine,
            outbound_manager,
            parental_controller: None,
            connect_timeout,
        }
    }

    /// Create with parental control
    pub fn with_parental_control(
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        parental_controller: Arc<ParentalController>,
    ) -> Self {
        Self {
            fake_dns,
            rule_engine,
            outbound_manager,
            parental_controller: Some(parental_controller),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Handle a single connection
    ///
    /// This is the main entry point for processing a redirected connection.
    pub async fn handle(&self, inbound: TcpStream, src_addr: SocketAddr) -> Result<()> {
        // Step 1: Get original destination address
        let original_dst = match get_original_dst(&inbound) {
            Ok(dst) => {
                debug!("Original destination: {} -> {}", src_addr, dst);
                dst
            }
            Err(e) => {
                warn!("Failed to get original destination for {}: {}", src_addr, e);
                return Err(HomeGuardError::Proxy(format!(
                    "Failed to get original destination: {}",
                    e
                )));
            }
        };

        // Step 2: Try to resolve domain from FakeDNS
        let domain = self.resolve_domain(original_dst.ip());

        // Step 3: Check parental control (if enabled)
        if let Some(ref controller) = self.parental_controller {
            if let Some(ref d) = domain {
                let decision = controller.check_access(src_addr.ip(), d);
                if decision.is_blocked() {
                    if let Some(reason) = decision.reason() {
                        info!(
                            "Parental control blocked: {} from {} ({})",
                            d,
                            src_addr.ip(),
                            reason
                        );
                    }
                    // Drop connection by returning Ok
                    return Ok(());
                }
            }
        }

        // Step 4: Match against rule engine
        let match_result = self.rule_engine.match_request(
            domain.as_deref(),
            Some(original_dst.ip()),
        );

        info!(
            "{} -> {} (domain: {:?}) => {} [{}]",
            src_addr,
            original_dst,
            domain,
            match_result.policy,
            match_result.matched_rule
        );

        // Step 5: Route based on policy
        match match_result.policy {
            Policy::Direct => self.handle_direct(inbound, original_dst).await,
            Policy::Reject => self.handle_reject(inbound, src_addr).await,
            Policy::Proxy(ref group) => {
                self.handle_proxy(inbound, original_dst, domain, group).await
            }
        }
    }

    /// Resolve domain from FakeDNS if the IP is a fake IP
    ///
    /// Only works for IPv4 addresses since FakeDNS uses IPv4 pool.
    fn resolve_domain(&self, ip: IpAddr) -> Option<String> {
        // FakeDNS only works with IPv4
        let ipv4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        };

        if let Some(ref fake_dns) = self.fake_dns {
            // Check if this is a fake IP
            if fake_dns.is_fake_ip(ipv4) {
                // Look up the domain
                if let Some(domain) = fake_dns.lookup(ipv4) {
                    return Some(domain);
                }
            }
        }
        None
    }

    /// Handle direct connection (connect to target directly)
    async fn handle_direct(&self, inbound: TcpStream, target: SocketAddr) -> Result<()> {
        debug!("DIRECT: connecting to {}", target);

        match connect_and_relay(inbound, target, self.connect_timeout).await {
            Ok(stats) => {
                debug!(
                    "DIRECT relay completed: {} bytes up, {} bytes down",
                    stats.client_to_server, stats.server_to_client
                );
                Ok(())
            }
            Err(e) => {
                warn!("DIRECT connection to {} failed: {}", target, e);
                Err(HomeGuardError::Proxy(format!(
                    "Direct connection failed: {}",
                    e
                )))
            }
        }
    }

    /// Handle rejected connection (close immediately)
    async fn handle_reject(&self, _inbound: TcpStream, src_addr: SocketAddr) -> Result<()> {
        debug!("REJECT: closing connection from {}", src_addr);
        // Just drop the connection - inbound will be dropped when this function returns
        Ok(())
    }

    /// Handle proxy connection (forward through proxy group)
    async fn handle_proxy(
        &self,
        mut inbound: TcpStream,
        target: SocketAddr,
        domain: Option<String>,
        group: &str,
    ) -> Result<()> {
        debug!("PROXY ({}): connecting to {} (domain: {:?})", group, target, domain);

        // Get the outbound from the manager
        let outbound = self
            .outbound_manager
            .get(&Policy::Proxy(group.to_string()))
            .ok_or_else(|| {
                HomeGuardError::Proxy(format!("Unknown proxy group: {}", group))
            })?;

        // Build target address (prefer domain if available for SNI)
        let addr = match domain {
            Some(d) => Address::from_domain(d, target.port()),
            None => Address::from_socket_addr(target),
        };

        // Connect through the proxy
        let outbound_stream = tokio::time::timeout(
            self.connect_timeout,
            outbound.connect(&addr),
        )
        .await
        .map_err(|_| HomeGuardError::Proxy("Proxy connection timed out".to_string()))?
        .map_err(|e| HomeGuardError::Proxy(format!("Proxy connection failed: {}", e)))?;

        // Relay data bidirectionally
        match relay_streams(&mut inbound, outbound_stream).await {
            Ok((up, down)) => {
                debug!(
                    "PROXY ({}) relay completed: {} bytes up, {} bytes down",
                    group, up, down
                );
                Ok(())
            }
            Err(e) => {
                warn!("PROXY ({}) relay error: {}", group, e);
                Err(HomeGuardError::Proxy(format!("Relay error: {}", e)))
            }
        }
    }

    /// Get handler statistics (placeholder for Phase 7)
    pub fn stats(&self) -> HandlerStats {
        HandlerStats::default()
    }

    /// Get a reference to the outbound manager
    pub fn outbound_manager(&self) -> &Arc<OutboundManager> {
        &self.outbound_manager
    }
}

/// Relay data bidirectionally between two async streams
async fn relay_streams<S>(
    inbound: &mut TcpStream,
    mut outbound: Box<S>,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncStream + ?Sized,
{
    tokio::io::copy_bidirectional(inbound, &mut *outbound).await
}

/// Handler statistics (placeholder for Phase 7 integration)
///
/// TODO: These stats are not currently collected. To implement:
/// 1. Add AtomicU64 counters to ConnectionHandler
/// 2. Update counters in handle_connection()
/// 3. Expose stats via a stats() method
/// 4. Integrate with storage/logging module
#[derive(Debug, Default, Clone)]
pub struct HandlerStats {
    /// Total connections handled
    pub total_connections: u64,
    /// Active connections
    pub active_connections: u64,
    /// Direct connections
    pub direct_connections: u64,
    /// Rejected connections
    pub rejected_connections: u64,
    /// Proxied connections
    pub proxied_connections: u64,
    /// Total bytes uploaded
    pub bytes_uploaded: u64,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Most handler tests require a running FakeDNS and RuleEngine
    // These are integration tests that would be in tests/ directory

    #[test]
    fn test_handler_stats_default() {
        let stats = HandlerStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
    }
}
