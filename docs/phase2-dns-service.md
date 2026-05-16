# Phase 2: DNS Service Design

## Overview

DNS service is the core component of HomeGuard, responsible for:
1. Receiving DNS queries from home devices
2. Filtering blocked domains (parental control)
3. Allocating FakeIP for transparent proxy
4. Caching DNS responses
5. Forwarding queries to upstream DNS servers

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           DNS Server (UDP:53)           │
                    │                server.rs                │
                    └─────────────────┬───────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │              DNS Handler                 │
                    │               handler.rs                 │
                    └─────────────────┬───────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
    │   DNS Filter    │    │    DNS Cache    │    │    FakeDNS      │
    │   filter.rs     │    │    cache.rs     │    │   fake_dns.rs   │
    └─────────────────┘    └─────────────────┘    └─────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │           Upstream Resolver             │
                    │             resolver.rs                 │
                    └─────────────────────────────────────────┘
```

## Module Design

### 1. DNS Server (`server.rs`)

UDP server listening on port 53.

```rust
pub struct DnsServer {
    socket: UdpSocket,
    handler: Arc<DnsHandler>,
}

impl DnsServer {
    pub fn new(config: &DnsConfig, handler: Arc<DnsHandler>) -> Result<Self>;
    pub async fn run(&self) -> Result<()>;
}
```

**Responsibilities:**
- Bind UDP socket
- Receive DNS packets
- Dispatch to handler
- Send responses

### 2. DNS Handler (`handler.rs`)

Core logic for processing DNS queries.

```rust
pub struct DnsHandler {
    filter: DnsFilter,
    cache: DnsCache,
    fake_dns: Option<FakeDns>,
    resolver: DnsResolver,
    config: DnsConfig,
}

impl DnsHandler {
    pub async fn handle_query(
        &self,
        query: &[u8],
        src_addr: SocketAddr
    ) -> Result<Vec<u8>>;
}
```

**Query Processing Flow:**
```
1. Parse DNS packet
2. Extract query name and type
3. Check filter (blocklist) → if blocked, return NXDOMAIN
4. Check cache → if hit, return cached response
5. If FakeDNS enabled:
   - Allocate FakeIP
   - Store domain → IP mapping
   - Return FakeIP response
6. Else:
   - Forward to upstream resolver
   - Cache response
   - Return response
```

### 3. DNS Filter (`filter.rs`)

Domain filtering for parental control.

```rust
pub struct DnsFilter {
    // Exact match: O(1) lookup
    exact_blocklist: HashSet<String>,

    // Suffix match: Trie tree, O(m) where m = domain length
    suffix_trie: DomainSuffixTrie,

    // Keyword match: Aho-Corasick, O(n) where n = domain length
    keyword_matcher: AhoCorasick,
}

impl DnsFilter {
    pub fn new() -> Self;
    pub fn load_blocklist(&mut self, path: &Path) -> Result<()>;
    pub fn is_blocked(&self, domain: &str) -> bool;
}
```

**Blocklist Format:**
```
# Comments start with #
# Exact domain
example.com

# Suffix match (matches *.porn.com and porn.com)
.porn.com

# Keyword match (matches any domain containing "gambling")
*gambling*
```

### 4. DNS Cache (`cache.rs`)

LRU cache for DNS responses.

```rust
pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    min_ttl: u32,
    max_ttl: u32,
}

pub struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
    original_ttl: u32,
}

impl DnsCache {
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32) -> Self;
    pub fn get(&self, domain: &str, qtype: u16) -> Option<Vec<u8>>;
    pub fn insert(&self, domain: &str, qtype: u16, response: Vec<u8>, ttl: u32);
}
```

**TTL Policy:**
- Respect original TTL from upstream
- Clamp to `[min_ttl, max_ttl]` range
- Default: `min_ttl=60`, `max_ttl=3600`

### 5. FakeDNS (`fake_dns.rs`)

Allocates fake IPs for transparent proxy domain identification.

```rust
pub struct FakeDns {
    // Bidirectional mapping
    ip_to_domain: DashMap<Ipv4Addr, String>,
    domain_to_ip: DashMap<String, Ipv4Addr>,

    // IP pool configuration
    pool_start: u32,  // 198.18.0.1 as u32
    pool_end: u32,    // 198.19.255.254 as u32
    pool_size: u32,

    // LRU for eviction
    lru: Mutex<LruCache<Ipv4Addr, ()>>,

    // Next IP to allocate
    next_ip: AtomicU32,
}

impl FakeDns {
    pub fn new(cidr: &str, capacity: usize) -> Result<Self>;

    /// Allocate or return existing FakeIP for domain
    pub fn allocate(&self, domain: &str) -> Ipv4Addr;

    /// Lookup domain by FakeIP (for transparent proxy)
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String>;

    /// Check if IP is in FakeDNS pool
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool;
}
```

**IP Pool:**
- Default: `198.18.0.0/15` (reserved for benchmarking)
- ~131,072 available IPs
- LRU eviction when pool is exhausted

### 6. Upstream Resolver (`resolver.rs`)

Forwards queries to upstream DNS servers.

```rust
pub struct DnsResolver {
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
}

impl DnsResolver {
    pub fn new(upstreams: Vec<String>, timeout: Duration) -> Result<Self>;

    /// Resolve using first successful upstream
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>>;
}
```

**Features:**
- Multiple upstreams with fallback
- Timeout handling
- Simple UDP forwarding

## File Structure

```
src/dns/
├── mod.rs           # Module exports
├── server.rs        # UDP DNS server
├── handler.rs       # Query processing logic
├── filter.rs        # Domain filtering
├── cache.rs         # LRU cache
├── fake_dns.rs      # FakeIP allocation
└── resolver.rs      # Upstream resolution
```

## Data Flow

### Normal Resolution (FakeDNS disabled)
```
Client                 HomeGuard                  Upstream
  │                        │                          │
  │── DNS Query ──────────▶│                          │
  │                        │── Check Filter ──┐       │
  │                        │◀─ Not Blocked ───┘       │
  │                        │── Check Cache ───┐       │
  │                        │◀─ Miss ──────────┘       │
  │                        │── Forward Query ────────▶│
  │                        │◀─ Response ──────────────│
  │                        │── Store Cache ───┐       │
  │                        │◀─────────────────┘       │
  │◀─ DNS Response ────────│                          │
```

### FakeDNS Resolution
```
Client                 HomeGuard
  │                        │
  │── DNS Query ──────────▶│
  │   (google.com)         │
  │                        │── Check Filter ──┐
  │                        │◀─ Not Blocked ───┘
  │                        │── Allocate FakeIP ─┐
  │                        │   198.18.0.1       │
  │                        │◀──────────────────┘
  │                        │── Store Mapping ───┐
  │                        │   198.18.0.1 ↔     │
  │                        │   google.com       │
  │                        │◀──────────────────┘
  │◀─ Response: 198.18.0.1─│
```

### Blocked Domain
```
Client                 HomeGuard
  │                        │
  │── DNS Query ──────────▶│
  │   (porn.com)           │
  │                        │── Check Filter ──┐
  │                        │◀─ BLOCKED ───────┘
  │◀─ NXDOMAIN ────────────│
```

## Configuration

```toml
[dns]
listen = "0.0.0.0:53"
upstream = ["8.8.8.8:53", "223.5.5.5:53"]
fake_dns = true
fake_dns_pool = "198.18.0.0/15"
cache_size = 10000
cache_ttl = 300        # Not used, we respect original TTL
min_ttl = 60           # Minimum cache TTL
max_ttl = 3600         # Maximum cache TTL
```

## Error Handling

| Error | Action |
|-------|--------|
| Parse error | Return FORMERR |
| Upstream timeout | Try next upstream |
| All upstreams fail | Return SERVFAIL |
| Filter blocked | Return NXDOMAIN |

## Testing Strategy

1. **Unit Tests:**
   - Filter: exact/suffix/keyword matching
   - Cache: insert/get/expiry/LRU eviction
   - FakeDNS: allocate/lookup/eviction

2. **Integration Tests:**
   - Full query flow
   - Blocking behavior
   - Cache hit/miss

## Dependencies

- `simple-dns` - DNS packet parsing
- `tokio` - Async UDP socket
- `lru` - LRU cache
- `dashmap` - Concurrent HashMap
- `aho-corasick` - Keyword matching
- `radix_trie` - Suffix matching
