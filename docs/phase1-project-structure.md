# Phase 1: Project Structure

## Overview

Phase 1 establishes the foundational project structure for HomeGuard, a home network gateway for parental control and proxy management.

## Completed Components

### 1. Cargo Project Setup

**File: `Cargo.toml`**

Key dependencies:
- `tokio` - Async runtime
- `simple-dns` - DNS protocol parsing
- `ring` - Cryptography (AEAD)
- `aho-corasick` - Multi-pattern string matching
- `radix_trie` - Domain suffix matching
- `maxminddb` - GeoIP database
- `rusqlite` - SQLite storage
- `tracing` - Structured logging

### 2. Directory Structure

```
homeguard/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── error.rs             # Error types
│   ├── logging.rs           # Logging initialization
│   ├── config/              # Configuration module
│   │   ├── mod.rs
│   │   ├── types.rs         # Config type definitions
│   │   └── parser.rs        # TOML parsing & validation
│   ├── dns/                 # DNS module (placeholder)
│   ├── proxy/               # Proxy module (placeholder)
│   ├── outbound/            # Outbound protocols (placeholder)
│   │   └── shadowsocks/
│   ├── rule/                # Rule engine (placeholder)
│   │   └── matcher/
│   ├── control/             # Parental control (placeholder)
│   └── storage/             # Data storage (placeholder)
├── config/
│   ├── homeguard.toml       # Main configuration
│   ├── rules/               # Rule sets
│   └── blocklists/          # Blocklist files
│       ├── opensource/
│       └── custom/
├── scripts/                 # Deployment scripts
│   └── launchd/
├── data/                    # Runtime data (GeoIP, etc.)
├── benches/                 # Benchmarks
└── docs/                    # Documentation
```

### 3. Configuration Module

**Files:**
- `src/config/types.rs` - Configuration type definitions
- `src/config/parser.rs` - TOML parsing and validation
- `src/config/mod.rs` - Module exports

**Key Types:**
```rust
Config
├── GeneralConfig      # log_level, data_dir
├── DnsConfig          # listen, upstream, fake_dns, cache
├── TransparentConfig  # listen, handle_udp
├── ProxyConfig        # shadowsocks[], group[]
├── RulesConfig        # rules_dir, geoip_db, rule_list
├── schedules          # HashMap<String, Schedule>
└── devices            # HashMap<String, DeviceConfig>
```

### 4. Error Handling

**File: `src/error.rs`**

```rust
pub enum HomeGuardError {
    Config(ConfigError),
    Dns(String),
    Proxy(String),
    Rule(String),
    Storage(String),
    Io(std::io::Error),
    Network(String),
    Crypto(String),
    Internal(String),
}
```

### 5. Logging

**File: `src/logging.rs`**

- Uses `tracing` + `tracing-subscriber`
- Configurable log level via config or env
- Structured logging with targets

### 6. Main Entry Point

**File: `src/main.rs`**

- Loads configuration from TOML file
- Initializes logging
- Prepares for service startup
- Handles graceful shutdown (Ctrl+C)

## Configuration Example

```toml
[general]
log_level = "info"
data_dir = "/var/lib/homeguard"

[dns]
listen = "0.0.0.0:53"
upstream = ["8.8.8.8:53", "223.5.5.5:53"]
fake_dns = true
fake_dns_pool = "198.18.0.0/15"

[transparent]
listen = "0.0.0.0:7893"

[rules]
rule_list = ["FINAL,DIRECT"]
```

## Tests

3 unit tests in `src/config/parser.rs`:
- `test_load_minimal_config` - Minimal valid config
- `test_load_full_config` - Full config with all options
- `test_invalid_ss_method` - Invalid Shadowsocks cipher

## Next Steps

Phase 2: DNS Service implementation
