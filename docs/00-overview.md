# HomeGuard Project Overview

## Project Goal

Build a Rust-based home network gateway deployed on Mac Mini, providing:
1. **Parental Control** - Block inappropriate websites, time-based access control
2. **Proxy Management** - Shadowsocks proxy with Surge-like routing rules

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           HomeGuard                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │
│  │ DNS Server  │    │  TProxy     │    │ Rule Engine │                  │
│  │  (Phase 2)  │    │  (Phase 4)  │    │  (Phase 3)  │                  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                  │
│         │                  │                  │                          │
│         ▼                  ▼                  ▼                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │
│  │  FakeDNS    │    │  Outbound   │    │  Parental   │                  │
│  │  (Phase 2)  │    │  (Phase 5)  │    │  (Phase 6)  │                  │
│  └─────────────┘    └─────────────┘    └─────────────┘                  │
│                                                                          │
│  ┌─────────────┐    ┌─────────────┐                                     │
│  │  Storage    │    │   Config    │                                     │
│  │  (Phase 7)  │    │  (Phase 1)  │                                     │
│  └─────────────┘    └─────────────┘                                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Phase Dependencies

```
Phase 1 (Config) ──────────────────────────────────────┐
     │                                                  │
     ▼                                                  │
Phase 2 (DNS) ──────────┐                              │
     │                   │                              │
     │                   ▼                              │
     │            Phase 3 (Rule Engine) ◀──────────────┤
     │                   │                              │
     ▼                   ▼                              │
Phase 4 (TProxy) ◀───────┘                             │
     │                                                  │
     ▼                                                  │
Phase 5 (Shadowsocks) ◀────────────────────────────────┤
                                                        │
Phase 6 (Parental Control) ◀───── Phase 3 ◀────────────┤
                                                        │
Phase 7 (Storage) ◀─────────────────────────────────────┘

Phase 8 (Deployment) ◀── All phases complete
```

## Phase Breakdown

### Phase 1: Project Framework ✅ COMPLETED
- [x] Cargo project setup with dependencies
- [x] Directory structure
- [x] Configuration module (TOML parsing)
- [x] Error types
- [x] Logging initialization
- [x] Main entry point

### Phase 2: DNS Service ✅ COMPLETED
**Scope:** Core DNS functionality only. No rule matching logic.

- [x] UDP DNS Server (`server.rs`)
  - Bind UDP socket on port 53
  - Receive/send DNS packets
  - Async query handling with tokio

- [x] DNS Cache (`cache.rs`)
  - LRU cache for responses
  - TTL management (respect original, clamp to min/max)
  - TTL update on cache hit

- [x] Upstream Resolver (`resolver.rs`)
  - Forward queries to upstream DNS
  - Multiple upstreams with fallback
  - Timeout handling

- [x] FakeDNS (`fake_dns.rs`)
  - IP pool allocation (198.18.0.0/15)
  - Domain ↔ IP bidirectional mapping
  - LRU eviction when pool exhausted

- [x] DNS Handler (`handler.rs`)
  - Coordinate components
  - **Filter interface only** (actual filtering in Phase 3/6)

- [x] DNS Filter (`filter.rs`)
  - Simple HashSet-based filter (temporary)
  - DnsFilterTrait interface for Phase 3

**NOT in Phase 2:**
- ❌ Domain matching algorithms (Trie, Aho-Corasick) → Phase 3
- ❌ Blocklist management → Phase 6
- ❌ Time-based control → Phase 6

### Phase 3: Rule Engine ✅ COMPLETED
**Scope:** Surge-like rule matching system.

- [x] Rule types: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6, GEOIP, FINAL
- [x] Domain Trie tree for suffix matching
- [x] Aho-Corasick for keyword matching
- [x] IP-CIDR matching (IPv4 and IPv6)
- [x] GeoIP matching (maxminddb)
- [x] Rule set parsing and loading
- [x] Policy: DIRECT, REJECT, Proxy(group_name)
- [x] Integration with DNS Handler (implements DnsFilterTrait)

### Phase 4: Transparent Proxy ✅ COMPLETED
**Scope:** TCP transparent proxy using PF redirection.

- [x] TCP listener for redirected traffic (`server.rs`)
- [x] Get original destination via macOS PF DIOCNATLOOK ioctl (`nat.rs`)
- [x] FakeDNS lookup to get domain name (`handler.rs`)
- [x] Rule matching to determine policy (DIRECT/REJECT/PROXY)
- [x] Connection relay - bidirectional TCP copy (`relay.rs`)
- [x] Integration with main.rs

### Phase 5: Shadowsocks Outbound ✅ COMPLETED
**Scope:** Shadowsocks proxy client implementation.

- [x] AEAD encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) (`cipher.rs`)
- [x] SS protocol: address encoding (`address.rs`), TCP relay (`mod.rs`)
- [x] Proxy groups: select, url-test, fallback (`group/`)
- [x] Health check with background testing
- [x] Outbound manager (`manager.rs`)
- [x] Integration with transparent proxy

### Phase 6: Parental Control ✅ COMPLETED
**Scope:** Device management and access control.

- [x] Device identification by IP (`device.rs`)
- [x] Blocklist management (global + category-based + suffix matching) (`blocklist.rs`)
- [x] Time schedule enforcement with cross-midnight support (`schedule.rs`)
- [x] ParentalController coordinating all components (`controller.rs`)
- [x] Integration with DNS Handler and Transparent Proxy
- [x] Configuration types (`ParentalConfig`)

### Phase 7: Data Storage ✅ COMPLETED
**Scope:** SQLite for configuration, file-based logging for access logs.

- [x] SQLite module with migrations (`sqlite.rs`)
- [x] ConfigStore for CRUD operations (`config_store.rs`)
  - Devices, schedules, blocklists
  - Proxy servers, proxy groups
  - Rules, global config (JSON key-value)
- [x] Data models (`models.rs`)
- [x] AccessLogger for file-based logging (`logger.rs`)
  - Configurable granularity (1=all, 2=blocked+proxy, 3=blocked only)
  - Daily rotation, configurable retention
  - NDJSON format

### Phase 8: Deployment ✅ COMPLETED
**Scope:** macOS deployment scripts.

- [x] PF firewall configuration script (`setup-pf.sh`)
  - Traffic redirection (DNS, HTTP, HTTPS)
  - Auto-detect network interface
  - Enable/disable commands
- [x] LaunchDaemon service configuration (`com.homeguard.plist`)
  - Auto-start on boot
  - Process supervision (restart on crash)
  - Resource limits
- [x] Installation script (`install.sh`)
  - Pre-flight checks
  - Binary/config installation
  - Service setup
- [x] Uninstallation script (`uninstall.sh`)
- [x] Production config template with storage/logging settings

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| DNS Protocol | UDP only | Covers 99% of cases, simple |
| FakeDNS Pool | 198.18.0.0/15 | Reserved address range, ~131K IPs |
| FakeDNS Eviction | LRU | Simple, effective for home use |
| Cache TTL | Respect original + clamp | min=60s, max=3600s |
| Config Format | TOML (static) | Human readable, good Rust support |
| Config Storage | SQLite | ACID transactions, easy querying |
| Access Logs | Files (NDJSON) | High throughput, simple rotation |
| Log Granularity | Configurable (1/2/3) | 1=all, 2=blocked+proxy, 3=blocked only |

## Files Modified Per Phase

### Phase 1 (Completed)
```
src/main.rs
src/lib.rs
src/error.rs
src/logging.rs
src/config/mod.rs
src/config/types.rs
src/config/parser.rs
config/homeguard.toml
Cargo.toml
```

### Phase 2 (Completed)
```
src/dns/mod.rs
src/dns/server.rs
src/dns/handler.rs
src/dns/cache.rs
src/dns/fake_dns.rs
src/dns/resolver.rs
src/main.rs (integration)
```

### Phase 3 (Completed)
```
src/rule/mod.rs
src/rule/engine.rs
src/rule/matcher/mod.rs
src/rule/matcher/domain.rs
src/rule/matcher/ip.rs
src/rule/matcher/geoip.rs
src/rule/parser.rs
docs/phase3-rule-engine.md
```

### Phase 4 (Completed)
```
src/proxy/mod.rs
src/proxy/server.rs      # TCP listener, accept loop
src/proxy/handler.rs     # Connection processing, FakeDNS lookup, rule matching
src/proxy/nat.rs         # macOS PF DIOCNATLOOK for original destination
src/proxy/relay.rs       # Bidirectional TCP relay
docs/phase4-transparent-proxy.md
```

### Phase 5 (Completed)
```
src/outbound/mod.rs           # Outbound trait, DirectOutbound, RejectOutbound
src/outbound/manager.rs       # OutboundManager - proxy creation and lookup
src/outbound/shadowsocks/
    mod.rs                    # ShadowsocksClient, ShadowsocksStream
    cipher.rs                 # AEAD encryption (AES-GCM, ChaCha20-Poly1305)
    address.rs                # Target address encoding/decoding
src/outbound/group/
    mod.rs                    # ProxyGroup enum
    select.rs                 # Manual selection group
    url_test.rs               # Auto-select by latency
    fallback.rs               # Fallback to first available
src/proxy/handler.rs          # Updated with OutboundManager integration
docs/phase5-shadowsocks.md
```

### Phase 6 (Completed)
```
src/control/mod.rs            # Module exports
src/control/blocklist.rs      # BlocklistManager - global/category blocklists
src/control/device.rs         # DeviceManager - IP-based device identification
src/control/schedule.rs       # ScheduleManager - time-based rules
src/control/controller.rs     # ParentalController - coordinator
src/config/types.rs           # Added ParentalConfig
src/dns/handler.rs            # Integration with parental control
src/proxy/handler.rs          # Integration with parental control
src/proxy/server.rs           # Added with_parental_control constructor
src/main.rs                   # ParentalController initialization
docs/phase6-parental-control.md
```

### Phase 7 (Completed)
```
src/storage/mod.rs            # Module exports
src/storage/sqlite.rs         # Database connection, migrations
src/storage/config_store.rs   # CRUD operations for all config tables
src/storage/models.rs         # Data models (Device, Schedule, Proxy, Rule, etc.)
src/storage/logger.rs         # AccessLogger - file-based logging
src/error.rs                  # Added From<rusqlite::Error>
docs/phase7-storage.md        # Design document with ER diagram
```

### Phase 8 (Completed)
```
scripts/install.sh                  # Main installation script
scripts/uninstall.sh                # Clean uninstallation
scripts/setup-pf.sh                 # PF firewall configuration
scripts/launchd/com.homeguard.plist # LaunchDaemon service config
config/homeguard.toml               # Updated with storage/logging settings
docs/phase8-deployment.md           # Design document
```
