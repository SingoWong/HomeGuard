//! DNS response cache with LRU eviction
//!
//! Caches DNS responses with TTL management.
//! Respects original TTL but clamps to configured min/max range.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tracing::debug;

/// Cache key combining domain name and query type
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    domain: String,
    qtype: u16,
}

/// Cached DNS response entry
struct CacheEntry {
    /// Raw DNS response packet
    response: Vec<u8>,
    /// When this entry expires
    expires_at: Instant,
    /// Original TTL from response (for future statistics/debugging)
    #[allow(dead_code)]
    original_ttl: u32,
    /// When this entry was created (for future statistics/debugging)
    #[allow(dead_code)]
    created_at: Instant,
}

/// DNS response cache
pub struct DnsCache {
    cache: Mutex<LruCache<CacheKey, CacheEntry>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    /// Create a new DNS cache
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of entries
    /// * `min_ttl` - Minimum TTL in seconds (default: 60)
    /// * `max_ttl` - Maximum TTL in seconds (default: 3600)
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            min_ttl,
            max_ttl,
        }
    }

    /// Create cache with default settings
    pub fn with_defaults(capacity: usize) -> Self {
        Self::new(capacity, 60, 3600)
    }

    /// Get cached response for domain and query type
    ///
    /// Returns None if not found or expired.
    /// The returned response has TTL adjusted to remaining time.
    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = CacheKey {
            domain: domain.to_lowercase(),
            qtype,
        };

        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get(&key) {
            let now = Instant::now();

            // Check if expired
            if now >= entry.expires_at {
                debug!("Cache expired for {} (type {})", domain, qtype);
                cache.pop(&key);
                return None;
            }

            // Calculate remaining TTL
            let remaining = entry.expires_at.duration_since(now);
            let remaining_secs = remaining.as_secs() as u32;

            // Clone response and update TTL
            let mut response = entry.response.clone();
            update_response_ttl(&mut response, remaining_secs);

            debug!(
                "Cache hit for {} (type {}), remaining TTL: {}s",
                domain, qtype, remaining_secs
            );

            Some(response)
        } else {
            None
        }
    }

    /// Insert a DNS response into cache
    ///
    /// # Arguments
    /// * `domain` - Domain name
    /// * `qtype` - Query type (A=1, AAAA=28, etc.)
    /// * `response` - Raw DNS response packet
    /// * `ttl` - TTL from response (will be clamped to min/max)
    pub fn insert(&self, domain: &str, qtype: u16, response: Vec<u8>, ttl: u32) {
        let key = CacheKey {
            domain: domain.to_lowercase(),
            qtype,
        };

        // Clamp TTL to configured range
        let clamped_ttl = ttl.clamp(self.min_ttl, self.max_ttl);

        let now = Instant::now();
        let entry = CacheEntry {
            response,
            expires_at: now + Duration::from_secs(clamped_ttl as u64),
            original_ttl: ttl,
            created_at: now,
        };

        debug!(
            "Cache insert for {} (type {}), TTL: {} (clamped from {})",
            domain, qtype, clamped_ttl, ttl
        );

        self.cache.lock().put(key, entry);
    }

    /// Remove entry from cache
    pub fn remove(&self, domain: &str, qtype: u16) {
        let key = CacheKey {
            domain: domain.to_lowercase(),
            qtype,
        };
        self.cache.lock().pop(&key);
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    /// Get current cache size
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.lock().is_empty()
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut cache = self.cache.lock();
        let before = cache.len();

        // Collect keys to remove (can't modify while iterating)
        let expired_keys: Vec<_> = cache
            .iter()
            .filter(|(_, entry)| now >= entry.expires_at)
            .map(|(key, _)| key.clone())
            .collect();

        for key in &expired_keys {
            cache.pop(key);
        }

        let removed = before - cache.len();
        if removed > 0 {
            debug!("Cleaned up {} expired cache entries", removed);
        }
        removed
    }
}

/// Update TTL values in DNS response packet
///
/// DNS response format (simplified):
/// - Header: 12 bytes
/// - Questions: variable
/// - Answers: variable, each record has TTL at offset +4 from name end
fn update_response_ttl(response: &mut [u8], new_ttl: u32) {
    if response.len() < 12 {
        return;
    }

    // Parse header
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;
    let arcount = u16::from_be_bytes([response[10], response[11]]) as usize;

    let mut offset = 12;

    // Skip questions
    for _ in 0..qdcount {
        offset = skip_name(response, offset);
        if offset == 0 {
            return;
        }
        offset += 4; // QTYPE + QCLASS
    }

    // Update TTL in answer, authority, and additional sections
    let total_records = ancount + nscount + arcount;
    for _ in 0..total_records {
        offset = skip_name(response, offset);
        if offset == 0 || offset + 10 > response.len() {
            return;
        }

        // Skip TYPE (2) and CLASS (2), then update TTL (4)
        let ttl_offset = offset + 4;
        if ttl_offset + 4 <= response.len() {
            let ttl_bytes = new_ttl.to_be_bytes();
            response[ttl_offset..ttl_offset + 4].copy_from_slice(&ttl_bytes);
        }

        // Skip TYPE(2) + CLASS(2) + TTL(4) = 8, then read RDLENGTH
        if offset + 10 > response.len() {
            return;
        }
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;

        // Move to next record
        offset += 10 + rdlength;
    }
}

/// Skip DNS name in packet, handling compression
fn skip_name(data: &[u8], mut offset: usize) -> usize {
    if offset >= data.len() {
        return 0;
    }

    loop {
        if offset >= data.len() {
            return 0;
        }

        let len = data[offset] as usize;

        if len == 0 {
            // End of name
            return offset + 1;
        } else if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            return offset + 2;
        } else if len > 63 {
            // Invalid label length
            return 0;
        } else {
            // Regular label
            offset += 1 + len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_cache_insert_get() {
        let cache = DnsCache::with_defaults(100);

        let response = vec![0u8; 50];
        cache.insert("example.com", 1, response.clone(), 300);

        let cached = cache.get("example.com", 1);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 50);
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::with_defaults(100);

        let response = vec![0u8; 50];
        cache.insert("Example.COM", 1, response.clone(), 300);

        assert!(cache.get("example.com", 1).is_some());
        assert!(cache.get("EXAMPLE.COM", 1).is_some());
    }

    #[test]
    fn test_cache_different_qtypes() {
        let cache = DnsCache::with_defaults(100);

        cache.insert("example.com", 1, vec![1u8; 10], 300); // A record
        cache.insert("example.com", 28, vec![2u8; 20], 300); // AAAA record

        let a_record = cache.get("example.com", 1).unwrap();
        let aaaa_record = cache.get("example.com", 28).unwrap();

        assert_eq!(a_record.len(), 10);
        assert_eq!(aaaa_record.len(), 20);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = DnsCache::new(100, 1, 10); // min=1, max=10

        let response = vec![0u8; 50];
        cache.insert("example.com", 1, response, 1); // 1 second TTL

        assert!(cache.get("example.com", 1).is_some());

        // Wait for expiry
        sleep(Duration::from_millis(1100));

        assert!(cache.get("example.com", 1).is_none());
    }

    #[test]
    fn test_cache_ttl_clamping() {
        let cache = DnsCache::new(100, 60, 3600);

        // TTL too low should be clamped to min
        cache.insert("low.com", 1, vec![0u8; 10], 10);

        // TTL too high should be clamped to max
        cache.insert("high.com", 1, vec![0u8; 10], 86400);

        // Both should be cached
        assert!(cache.get("low.com", 1).is_some());
        assert!(cache.get("high.com", 1).is_some());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = DnsCache::with_defaults(3); // Only 3 entries

        cache.insert("a.com", 1, vec![1u8], 300);
        cache.insert("b.com", 1, vec![2u8], 300);
        cache.insert("c.com", 1, vec![3u8], 300);

        // Access a.com to make it recently used
        cache.get("a.com", 1);

        // Insert d.com, should evict b.com (least recently used)
        cache.insert("d.com", 1, vec![4u8], 300);

        assert!(cache.get("a.com", 1).is_some()); // Still there (recently used)
        assert!(cache.get("b.com", 1).is_none()); // Evicted
        assert!(cache.get("c.com", 1).is_some());
        assert!(cache.get("d.com", 1).is_some());
    }

    #[test]
    fn test_skip_name() {
        // Simple name: 3www6google3com0
        let data = [3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0];
        assert_eq!(skip_name(&data, 0), 16);

        // Compression pointer
        let data_with_ptr = [0xC0, 0x0C]; // Pointer to offset 12
        assert_eq!(skip_name(&data_with_ptr, 0), 2);
    }
}
