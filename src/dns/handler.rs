//! DNS query handler
//!
//! Coordinates DNS query processing:
//! 1. Parse query
//! 2. Check parental control (if enabled)
//! 3. Check filter (blocklist)
//! 4. Check cache
//! 5. FakeDNS allocation or upstream resolution
//! 6. Cache and return response

use simple_dns::{Packet, RCODE};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// DNS query type for A record
const QTYPE_A: u16 = 1;

use super::cache::DnsCache;
use super::fake_dns::FakeDns;
use super::filter::DnsFilterTrait;
use super::resolver::DnsResolver;
use crate::config::DnsConfig;
use crate::control::ParentalController;
use crate::error::{HomeGuardError, Result};

/// DNS query handler
pub struct DnsHandler {
    /// Domain filter (blocklist)
    filter: Arc<dyn DnsFilterTrait>,
    /// DNS response cache
    cache: Arc<DnsCache>,
    /// FakeDNS for transparent proxy (optional)
    fake_dns: Option<Arc<FakeDns>>,
    /// Upstream DNS resolver
    resolver: Arc<DnsResolver>,
    /// Parental controller (optional)
    parental_controller: Option<Arc<ParentalController>>,
    /// Configuration
    config: DnsConfig,
}

impl DnsHandler {
    /// Create a new DNS handler
    pub fn new(
        filter: Arc<dyn DnsFilterTrait>,
        cache: Arc<DnsCache>,
        fake_dns: Option<Arc<FakeDns>>,
        resolver: Arc<DnsResolver>,
        config: DnsConfig,
    ) -> Self {
        Self {
            filter,
            cache,
            fake_dns,
            resolver,
            parental_controller: None,
            config,
        }
    }

    /// Create a DNS handler with parental control
    pub fn with_parental_control(
        filter: Arc<dyn DnsFilterTrait>,
        cache: Arc<DnsCache>,
        fake_dns: Option<Arc<FakeDns>>,
        resolver: Arc<DnsResolver>,
        parental_controller: Arc<ParentalController>,
        config: DnsConfig,
    ) -> Self {
        Self {
            filter,
            cache,
            fake_dns,
            resolver,
            parental_controller: Some(parental_controller),
            config,
        }
    }

    /// Handle a DNS query
    ///
    /// Returns the raw DNS response packet.
    pub async fn handle_query(&self, query: &[u8], src_addr: SocketAddr) -> Result<Vec<u8>> {
        // Parse the query
        let packet = match Packet::parse(query) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse DNS query: {}", e);
                return self.build_error_response(query, RCODE::FormatError);
            }
        };

        // Get the first question (most DNS queries have exactly one)
        let question = match packet.questions.first() {
            Some(q) => q,
            None => {
                warn!("DNS query has no questions");
                return self.build_error_response(query, RCODE::FormatError);
            }
        };

        let domain = question.qname.to_string();
        let qtype = question.qtype;

        debug!("DNS query: {} {:?} from {}", domain, qtype, src_addr);

        // Step 1: Check parental control (device-specific blocking)
        if let Some(ref controller) = self.parental_controller {
            let decision = controller.check_access(src_addr.ip(), &domain);
            if decision.is_blocked() {
                if let Some(reason) = decision.reason() {
                    info!(
                        "Parental control blocked: {} from {} ({})",
                        domain,
                        src_addr.ip(),
                        reason
                    );
                }
                return self.build_nxdomain_response(query);
            }
        }

        // Step 2: Check filter (rule-based blocking)
        if self.filter.is_blocked(&domain) {
            debug!("Domain blocked by filter: {}", domain);
            return self.build_nxdomain_response(query);
        }

        // Step 3: Check cache
        if let Some(cached) = self.cache.get(&domain, qtype.into()) {
            debug!("Cache hit: {} {:?}", domain, qtype);
            // Update the transaction ID in cached response
            let mut response = cached;
            if response.len() >= 2 && query.len() >= 2 {
                response[0] = query[0];
                response[1] = query[1];
            }
            return Ok(response);
        }

        // Step 4: FakeDNS or upstream resolution
        if let Some(ref fake_dns) = self.fake_dns {
            // Only handle A queries with FakeDNS
            let qtype_value: u16 = qtype.into();
            if qtype_value == QTYPE_A {
                let fake_ip = fake_dns.allocate(&domain);
                debug!("FakeDNS: {} -> {}", domain, fake_ip);
                return self.build_a_response(query, &domain, fake_ip);
            }
            // For other types, fall through to upstream
        }

        // Step 5: Forward to upstream
        let response = self.resolver.resolve(query).await?;

        // Step 6: Cache the response
        if let Ok(resp_packet) = Packet::parse(&response) {
            // Extract TTL from first answer
            let ttl = resp_packet
                .answers
                .first()
                .map(|a| a.ttl)
                .unwrap_or(self.config.cache_ttl as u32);

            self.cache.insert(&domain, qtype.into(), response.clone(), ttl);
        }

        Ok(response)
    }

    /// Build an error response
    fn build_error_response(&self, query: &[u8], rcode: RCODE) -> Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(HomeGuardError::Dns("Query too short".to_string()));
        }

        let mut response = vec![0u8; 12];

        // Copy transaction ID
        response[0] = query[0];
        response[1] = query[1];

        // Flags: QR=1 (response), RCODE
        response[2] = 0x80; // QR=1
        response[3] = rcode as u8;

        // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = 0
        // Already zero from vec initialization

        Ok(response)
    }

    /// Build NXDOMAIN response
    fn build_nxdomain_response(&self, query: &[u8]) -> Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(HomeGuardError::Dns("Query too short".to_string()));
        }

        let mut response = query.to_vec();

        // Set QR=1 (response), RA=1 (recursion available), RCODE=NXDOMAIN
        response[2] = 0x81; // QR=1, RD=1 (preserve recursion desired)
        response[3] = (response[3] & 0xF0) | (RCODE::NameError as u8); // NXDOMAIN

        // Clear answer, authority, additional counts
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        // Truncate to header + question
        if let Ok(packet) = Packet::parse(query) {
            if let Some(q) = packet.questions.first() {
                let qname_len = q.qname.to_string().len() + 2; // +2 for length bytes and null
                let question_end = 12 + qname_len + 4; // +4 for QTYPE and QCLASS
                if response.len() > question_end {
                    response.truncate(question_end);
                }
            }
        }

        Ok(response)
    }

    /// Build A record response with fake IP
    fn build_a_response(&self, query: &[u8], _domain: &str, ip: Ipv4Addr) -> Result<Vec<u8>> {
        if query.len() < 12 {
            return Err(HomeGuardError::Dns("Query too short".to_string()));
        }

        let mut response = Vec::with_capacity(query.len() + 16);

        // Copy query header
        response.extend_from_slice(&query[..2]); // Transaction ID

        // Flags: QR=1, AA=0, TC=0, RD=1, RA=1, RCODE=0
        response.push(0x81); // QR=1, RD=1
        response.push(0x80); // RA=1

        // QDCOUNT: 1
        response.push(0);
        response.push(1);

        // ANCOUNT: 1
        response.push(0);
        response.push(1);

        // NSCOUNT: 0
        response.push(0);
        response.push(0);

        // ARCOUNT: 0
        response.push(0);
        response.push(0);

        // Copy question section from query
        if query.len() > 12 {
            // Find end of question section
            let mut offset = 12;
            while offset < query.len() {
                let len = query[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                offset += 1 + len;
            }
            offset += 4; // QTYPE + QCLASS

            if offset <= query.len() {
                response.extend_from_slice(&query[12..offset]);
            }
        }

        // Answer section
        // NAME: pointer to question (0xC00C points to offset 12)
        response.push(0xC0);
        response.push(0x0C);

        // TYPE: A (1)
        response.push(0);
        response.push(1);

        // CLASS: IN (1)
        response.push(0);
        response.push(1);

        // TTL: use configured TTL (default 300 seconds)
        let ttl = self.config.cache_ttl as u32;
        response.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH: 4 (IPv4 address)
        response.push(0);
        response.push(4);

        // RDATA: IP address
        response.extend_from_slice(&ip.octets());

        Ok(response)
    }

    /// Get reference to the cache
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Get reference to FakeDNS (if enabled)
    pub fn fake_dns(&self) -> Option<&Arc<FakeDns>> {
        self.fake_dns.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::super::filter::AllowAllFilter;
    use super::*;

    fn create_test_handler() -> DnsHandler {
        let filter = Arc::new(AllowAllFilter);
        let cache = Arc::new(DnsCache::with_defaults(100));
        let resolver = Arc::new(DnsResolver::with_defaults().unwrap());
        let config = DnsConfig::default();

        DnsHandler::new(filter, cache, None, resolver, config)
    }

    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // FLAGS
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Encode domain name
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Null terminator

        // QTYPE: A (1)
        query.push(0);
        query.push(1);

        // QCLASS: IN (1)
        query.push(0);
        query.push(1);

        query
    }

    #[test]
    fn test_build_nxdomain_response() {
        let handler = create_test_handler();
        let query = build_test_query("blocked.com");

        let response = handler.build_nxdomain_response(&query).unwrap();

        // Check response flags
        assert!(response.len() >= 12);
        assert_eq!(response[0], 0x12); // Transaction ID preserved
        assert_eq!(response[1], 0x34);
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_eq!(response[3] & 0x0F, RCODE::NameError as u8); // NXDOMAIN
    }

    #[test]
    fn test_build_a_response() {
        let handler = create_test_handler();
        let query = build_test_query("test.com");
        let ip = Ipv4Addr::new(198, 18, 0, 1);

        let response = handler.build_a_response(&query, "test.com", ip).unwrap();

        // Check response
        assert!(response.len() >= 12);
        assert_eq!(response[0], 0x12); // Transaction ID
        assert_eq!(response[1], 0x34);
        assert_eq!(response[2] & 0x80, 0x80); // QR=1

        // Should have 1 answer
        assert_eq!(response[6], 0);
        assert_eq!(response[7], 1);
    }

    #[tokio::test]
    async fn test_handler_with_cache() {
        let filter = Arc::new(AllowAllFilter);
        let cache = Arc::new(DnsCache::with_defaults(100));
        let fake_dns = Arc::new(FakeDns::with_defaults(1000).unwrap());
        let resolver = Arc::new(DnsResolver::with_defaults().unwrap());
        let config = DnsConfig::default();

        let handler = DnsHandler::new(
            filter,
            cache.clone(),
            Some(fake_dns.clone()),
            resolver,
            config,
        );

        let query = build_test_query("example.com");
        let src = "127.0.0.1:12345".parse().unwrap();

        // First query - should allocate fake IP
        let response1 = handler.handle_query(&query, src).await.unwrap();
        assert!(response1.len() > 12);

        // Second query - should use cache
        let response2 = handler.handle_query(&query, src).await.unwrap();
        assert!(response2.len() > 12);

        // Both should return the same IP (FakeDNS reuse)
        let ip1 = extract_answer_ip(&response1);
        let ip2 = extract_answer_ip(&response2);
        assert_eq!(ip1, ip2);
    }

    fn extract_answer_ip(response: &[u8]) -> Option<Ipv4Addr> {
        if response.len() < 16 {
            return None;
        }

        // Simple extraction - assumes single A record answer
        // Find the answer section (after question)
        let mut offset = 12;

        // Skip question
        while offset < response.len() {
            let len = response[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            offset += 1 + len;
        }
        offset += 4; // QTYPE + QCLASS

        // Now at answer section
        if offset + 12 > response.len() {
            return None;
        }

        // Skip NAME (pointer), TYPE, CLASS, TTL
        offset += 2 + 2 + 2 + 4;

        // RDLENGTH
        if offset + 2 > response.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;

        // RDATA (IP address)
        if rdlen == 4 && offset + 4 <= response.len() {
            Some(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ))
        } else {
            None
        }
    }
}
