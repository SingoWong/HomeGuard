//! FakeDNS implementation for transparent proxy
//!
//! FakeDNS allocates fake IP addresses from a reserved pool for domains.
//! This allows the transparent proxy to identify the original domain
//! when only the destination IP is available.
//!
//! Default pool: 198.18.0.0/15 (reserved for benchmarking, ~131K IPs)

use dashmap::DashMap;
use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::Mutex;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, warn};

use crate::error::Result;

/// FakeDNS - allocates fake IPs for domain identification
pub struct FakeDns {
    /// IP to domain mapping
    ip_to_domain: DashMap<Ipv4Addr, String>,
    /// Domain to IP mapping
    domain_to_ip: DashMap<String, Ipv4Addr>,
    /// LRU for tracking usage and eviction
    lru: Mutex<LruCache<Ipv4Addr, ()>>,
    /// IP pool start (as u32 for easy arithmetic)
    pool_start: u32,
    /// IP pool end (inclusive)
    pool_end: u32,
    /// Next IP to allocate (wraps around)
    next_ip: AtomicU32,
    /// Pool size
    pool_size: u32,
}

impl FakeDns {
    /// Create a new FakeDNS instance
    ///
    /// # Arguments
    /// * `cidr` - IP pool in CIDR notation (e.g., "198.18.0.0/15")
    /// * `capacity` - Maximum number of domain-IP mappings
    ///
    /// # Example
    /// ```
    /// use homeguard::dns::FakeDns;
    /// let fake_dns = FakeDns::new("198.18.0.0/15", 10000).unwrap();
    /// ```
    pub fn new(cidr: &str, capacity: usize) -> Result<Self> {
        let network: Ipv4Net = cidr
            .parse()
            .map_err(|e| crate::error::HomeGuardError::InvalidConfig(format!("Invalid CIDR: {}", e)))?;

        let hosts = network.hosts();
        let pool_start = u32::from(hosts.clone().next().unwrap_or(network.network()));
        let pool_end = u32::from(
            hosts
                .last()
                .unwrap_or(network.broadcast()),
        );

        // Exclude network and broadcast addresses
        let pool_start = pool_start.max(u32::from(network.network()) + 1);
        let pool_end = pool_end.min(u32::from(network.broadcast()) - 1);

        let pool_size = pool_end.saturating_sub(pool_start) + 1;

        // Capacity should not exceed pool size
        let capacity = capacity.min(pool_size as usize);
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());

        debug!(
            "FakeDNS initialized: pool {}-{} ({} IPs), capacity {}",
            Ipv4Addr::from(pool_start),
            Ipv4Addr::from(pool_end),
            pool_size,
            capacity
        );

        Ok(Self {
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
            lru: Mutex::new(LruCache::new(capacity)),
            pool_start,
            pool_end,
            next_ip: AtomicU32::new(pool_start),
            pool_size,
        })
    }

    /// Create FakeDNS with default pool (198.18.0.0/15)
    pub fn with_defaults(capacity: usize) -> Result<Self> {
        Self::new("198.18.0.0/15", capacity)
    }

    /// Allocate or retrieve existing FakeIP for a domain
    ///
    /// If the domain already has an allocated IP, returns it.
    /// Otherwise allocates a new IP from the pool.
    /// If the pool is full, evicts the least recently used entry.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_lowercase();
        let domain = domain.trim_end_matches('.').to_string();

        // Check if domain already has an IP
        if let Some(ip) = self.domain_to_ip.get(&domain) {
            let ip = *ip;
            // Update LRU
            self.lru.lock().get(&ip);
            debug!("FakeDNS: reusing {} for {}", ip, domain);
            return ip;
        }

        // Allocate new IP
        let ip = self.allocate_new_ip(&domain);
        debug!("FakeDNS: allocated {} for {}", ip, domain);
        ip
    }

    /// Allocate a new IP address for a domain
    fn allocate_new_ip(&self, domain: &str) -> Ipv4Addr {
        let mut lru = self.lru.lock();

        // Check if we need to evict
        if lru.len() >= lru.cap().get() {
            // Evict LRU entry
            if let Some((evicted_ip, _)) = lru.pop_lru() {
                if let Some((_, evicted_domain)) = self.ip_to_domain.remove(&evicted_ip) {
                    self.domain_to_ip.remove(&evicted_domain);
                    debug!("FakeDNS: evicted {} ({})", evicted_ip, evicted_domain);
                }
            }
        }

        // Get next IP (with wraparound)
        let ip_u32 = loop {
            let current = self.next_ip.load(Ordering::Relaxed);
            let next = if current >= self.pool_end {
                self.pool_start
            } else {
                current + 1
            };

            if self
                .next_ip
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break current;
            }
        };

        let ip = Ipv4Addr::from(ip_u32);

        // If this IP is still in use (shouldn't happen with proper LRU), skip it
        // This is a safety check
        if self.ip_to_domain.contains_key(&ip) {
            // Remove old mapping
            if let Some((_, old_domain)) = self.ip_to_domain.remove(&ip) {
                self.domain_to_ip.remove(&old_domain);
                lru.pop(&ip);
                warn!(
                    "FakeDNS: IP {} was still mapped to {}, overwriting",
                    ip, old_domain
                );
            }
        }

        // Insert new mapping
        self.ip_to_domain.insert(ip, domain.to_string());
        self.domain_to_ip.insert(domain.to_string(), ip);
        lru.put(ip, ());

        ip
    }

    /// Lookup domain by FakeIP
    ///
    /// Returns the domain associated with the given IP, if any.
    /// Also updates the LRU to mark this entry as recently used.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        if let Some(domain) = self.ip_to_domain.get(&ip) {
            // Update LRU
            self.lru.lock().get(&ip);
            Some(domain.clone())
        } else {
            None
        }
    }

    /// Check if an IP address is within the FakeDNS pool
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        ip_u32 >= self.pool_start && ip_u32 <= self.pool_end
    }

    /// Get the number of currently allocated IPs
    pub fn len(&self) -> usize {
        self.ip_to_domain.len()
    }

    /// Check if no IPs are allocated
    pub fn is_empty(&self) -> bool {
        self.ip_to_domain.is_empty()
    }

    /// Get pool size
    pub fn pool_size(&self) -> u32 {
        self.pool_size
    }

    /// Clear all mappings
    pub fn clear(&self) {
        self.ip_to_domain.clear();
        self.domain_to_ip.clear();
        self.lru.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_dns_new() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();
        assert!(fake_dns.pool_size() > 0);
        assert!(fake_dns.is_empty());
    }

    #[test]
    fn test_fake_dns_allocate() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        let ip1 = fake_dns.allocate("google.com");
        let ip2 = fake_dns.allocate("facebook.com");

        assert_ne!(ip1, ip2);
        assert!(fake_dns.is_fake_ip(ip1));
        assert!(fake_dns.is_fake_ip(ip2));
    }

    #[test]
    fn test_fake_dns_reuse() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        let ip1 = fake_dns.allocate("google.com");
        let ip2 = fake_dns.allocate("google.com");
        let ip3 = fake_dns.allocate("GOOGLE.COM"); // Case insensitive

        assert_eq!(ip1, ip2);
        assert_eq!(ip1, ip3);
    }

    #[test]
    fn test_fake_dns_trailing_dot() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        let ip1 = fake_dns.allocate("google.com");
        let ip2 = fake_dns.allocate("google.com.");

        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_fake_dns_lookup() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        let ip = fake_dns.allocate("google.com");
        let domain = fake_dns.lookup(ip);

        assert_eq!(domain, Some("google.com".to_string()));
    }

    #[test]
    fn test_fake_dns_lookup_not_found() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        let domain = fake_dns.lookup(Ipv4Addr::new(1, 2, 3, 4));
        assert!(domain.is_none());
    }

    #[test]
    fn test_fake_dns_is_fake_ip() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        assert!(fake_dns.is_fake_ip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(fake_dns.is_fake_ip(Ipv4Addr::new(198, 18, 0, 254)));
        assert!(!fake_dns.is_fake_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!fake_dns.is_fake_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_fake_dns_eviction() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 3).unwrap();

        let ip1 = fake_dns.allocate("a.com");
        let ip2 = fake_dns.allocate("b.com");
        let ip3 = fake_dns.allocate("c.com");

        assert_eq!(fake_dns.len(), 3);

        // Access a.com to make it recently used
        fake_dns.lookup(ip1);

        // Allocate d.com, should evict b.com (LRU)
        let _ip4 = fake_dns.allocate("d.com");

        assert_eq!(fake_dns.len(), 3);
        assert!(fake_dns.lookup(ip1).is_some()); // a.com still there
        assert!(fake_dns.lookup(ip2).is_none()); // b.com evicted
        assert!(fake_dns.lookup(ip3).is_some()); // c.com still there
    }

    #[test]
    fn test_fake_dns_large_pool() {
        let fake_dns = FakeDns::new("198.18.0.0/15", 10000).unwrap();

        // 198.18.0.0/15 should have ~131K usable IPs
        assert!(fake_dns.pool_size() > 100000);
    }

    #[test]
    fn test_fake_dns_clear() {
        let fake_dns = FakeDns::new("198.18.0.0/24", 100).unwrap();

        fake_dns.allocate("google.com");
        fake_dns.allocate("facebook.com");

        assert_eq!(fake_dns.len(), 2);

        fake_dns.clear();

        assert!(fake_dns.is_empty());
    }
}
