# Phase 7: Data Storage Design

## Overview

Phase 7 implements two storage subsystems:
1. **SQLite** - Configuration storage (devices, schedules, blocklist metadata)
2. **File-based Logging** - Access logs with configurable retention

## Design Decisions

| Component | Storage | Reason |
|-----------|---------|--------|
| Configuration | SQLite | Structured data, ACID transactions, easy querying |
| Access Logs | Files | High throughput, simple rotation, external analysis |

## SQLite Configuration Storage

### ER Diagram

```
┌─────────────────────┐       ┌─────────────────────┐
│      devices        │       │     schedules       │
├─────────────────────┤       ├─────────────────────┤
│ id (PK)             │       │ id (PK)             │
│ name                │       │ name (UNIQUE)       │
│ ip                  │       │ days                │  (JSON array: ["Mon","Tue",...])
│ mac                 │       │ start_time          │  (TEXT: "08:00")
│ device_type         │       │ end_time            │  (TEXT: "16:00")
│ created_at          │       │ created_at          │
│ updated_at          │       │ updated_at          │
└─────────────────────┘       └─────────────────────┘
          │                             │
          │ N:M                         │ 1:N
          ▼                             ▼
┌─────────────────────┐       ┌─────────────────────┐
│  device_schedules   │       │  device_schedules   │
├─────────────────────┤       │    (same table)     │
│ device_id (FK)      │───────│                     │
│ schedule_id (FK)    │       └─────────────────────┘
│ PRIMARY KEY         │
└─────────────────────┘

┌─────────────────────┐       ┌─────────────────────┐
│    blocklists       │       │  device_blocklists  │
├─────────────────────┤       ├─────────────────────┤
│ id (PK)             │       │ device_id (FK)      │
│ category            │ 1:N   │ blocklist_id (FK)   │
│ source_type         │◀──────│ PRIMARY KEY         │
│ source_path         │       └─────────────────────┘
│ domain_count        │
│ last_updated        │
│ created_at          │
└─────────────────────┘

┌─────────────────────┐
│   proxy_servers     │
├─────────────────────┤
│ id (PK)             │
│ name (UNIQUE)       │
│ server              │
│ port                │
│ password            │  (encrypted)
│ method              │
│ enabled             │
│ created_at          │
│ updated_at          │
└─────────────────────┘

┌─────────────────────┐       ┌─────────────────────┐
│   proxy_groups      │       │ proxy_group_members │
├─────────────────────┤       ├─────────────────────┤
│ id (PK)             │       │ group_id (FK)       │
│ name (UNIQUE)       │ 1:N   │ proxy_id (FK)       │
│ strategy            │◀──────│ priority            │
│ interval            │       │ PRIMARY KEY         │
│ created_at          │       └─────────────────────┘
│ updated_at          │
└─────────────────────┘

┌─────────────────────┐
│       rules         │
├─────────────────────┤
│ id (PK)             │
│ priority            │  (order of evaluation)
│ rule_type           │  (DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP, FINAL)
│ pattern             │  (the match pattern)
│ policy              │  (DIRECT, REJECT, or proxy group name)
│ schedule_id (FK)    │  (optional, for time-based rules)
│ enabled             │
│ created_at          │
│ updated_at          │
└─────────────────────┘

┌─────────────────────┐
│   global_config     │
├─────────────────────┤
│ key (PK)            │
│ value               │  (JSON)
│ updated_at          │
└─────────────────────┘
```

### Tables Detail

#### devices
```sql
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    device_type TEXT NOT NULL DEFAULT 'child',  -- 'adult', 'child', 'guest'
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX idx_devices_ip ON devices(ip) WHERE ip IS NOT NULL;
CREATE UNIQUE INDEX idx_devices_mac ON devices(mac) WHERE mac IS NOT NULL;
```

#### schedules
```sql
CREATE TABLE schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    days TEXT NOT NULL,           -- JSON: ["Mon","Tue","Wed","Thu","Fri"]
    start_time TEXT NOT NULL,     -- "08:00"
    end_time TEXT NOT NULL,       -- "16:00"
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

#### device_schedules
```sql
CREATE TABLE device_schedules (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, schedule_id)
);
```

#### blocklists
```sql
CREATE TABLE blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL UNIQUE,    -- 'porn', 'gambling', 'games', 'global'
    source_type TEXT NOT NULL,        -- 'file', 'url', 'inline'
    source_path TEXT,                 -- file path or URL
    domain_count INTEGER DEFAULT 0,
    last_updated TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

#### device_blocklists
```sql
CREATE TABLE device_blocklists (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    blocklist_id INTEGER NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, blocklist_id)
);
```

#### proxy_servers
```sql
CREATE TABLE proxy_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    server TEXT NOT NULL,
    port INTEGER NOT NULL,
    password TEXT NOT NULL,           -- encrypted
    method TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

#### proxy_groups
```sql
CREATE TABLE proxy_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    strategy TEXT NOT NULL DEFAULT 'select',  -- 'select', 'url-test', 'fallback'
    test_url TEXT,
    test_interval INTEGER,            -- seconds
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

#### proxy_group_members
```sql
CREATE TABLE proxy_group_members (
    group_id INTEGER NOT NULL REFERENCES proxy_groups(id) ON DELETE CASCADE,
    proxy_id INTEGER NOT NULL REFERENCES proxy_servers(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, proxy_id)
);
```

#### rules
```sql
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    priority INTEGER NOT NULL,
    rule_type TEXT NOT NULL,          -- 'DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'GEOIP', 'FINAL'
    pattern TEXT,                     -- match pattern (NULL for FINAL)
    policy TEXT NOT NULL,             -- 'DIRECT', 'REJECT', or proxy group name
    schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_rules_priority ON rules(priority);
```

#### global_config
```sql
CREATE TABLE global_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,              -- JSON encoded value
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Global config keys:
- `dns.listen` - DNS server listen address
- `dns.upstream` - JSON array of upstream DNS servers
- `dns.fake_dns` - boolean
- `dns.fake_dns_pool` - CIDR string
- `dns.cache_size` - integer
- `transparent.listen` - Transparent proxy listen address
- `parental.enabled` - boolean
- `parental.default_policy` - string
- `logging.level` - log level
- `logging.granularity` - 1/2/3
- `logging.retention_days` - integer

## File-based Access Logging

### Log Granularity Levels

| Level | Description | Records |
|-------|-------------|---------|
| 1 | All | Every DNS query and TCP connection |
| 2 | Blocked + Proxy | Only blocked requests and proxy connections |
| 3 | Blocked Only | Only blocked/rejected requests |

### Log Format

Using structured JSON logging (one JSON object per line - NDJSON):

```json
{"ts":"2024-01-15T10:30:45.123Z","type":"dns","src":"192.168.0.100","domain":"example.com","result":"allow","latency_ms":12}
{"ts":"2024-01-15T10:30:45.456Z","type":"tcp","src":"192.168.0.100","dst":"93.184.216.34:443","domain":"example.com","policy":"DIRECT","bytes_up":1234,"bytes_down":5678}
{"ts":"2024-01-15T10:30:46.789Z","type":"dns","src":"192.168.0.100","domain":"blocked.com","result":"blocked","reason":"Global blocklist"}
```

### Log File Structure

```
/var/lib/homeguard/logs/
├── access-2024-01-15.log
├── access-2024-01-14.log
├── access-2024-01-13.log
└── ...
```

### Log Rotation

- Daily rotation (midnight)
- Automatic deletion after `retention_days`
- File naming: `access-YYYY-MM-DD.log`

### Implementation

```rust
pub struct AccessLogger {
    /// Log file directory
    log_dir: PathBuf,
    /// Current log file handle
    current_file: Option<BufWriter<File>>,
    /// Current date for rotation
    current_date: NaiveDate,
    /// Granularity level (1, 2, 3)
    granularity: u8,
    /// Retention days
    retention_days: u32,
}

impl AccessLogger {
    pub fn log_dns_query(&mut self, entry: &DnsLogEntry);
    pub fn log_tcp_connection(&mut self, entry: &TcpLogEntry);
    fn rotate_if_needed(&mut self);
    fn cleanup_old_logs(&self);
}

pub struct DnsLogEntry {
    pub src: IpAddr,
    pub domain: String,
    pub result: QueryResult,  // Allow, Blocked(reason)
    pub latency_ms: u64,
}

pub struct TcpLogEntry {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub domain: Option<String>,
    pub policy: Policy,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
}
```

## Module Structure

```
src/storage/
├── mod.rs
├── sqlite.rs          # SQLite connection and migrations
├── config_store.rs    # ConfigStore for CRUD operations
├── logger.rs          # AccessLogger for file logging
└── models.rs          # Data models for storage
```

## Migration Strategy

SQLite schema versioning:
```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Migrations are embedded in binary and applied on startup.

## Configuration

```toml
[storage]
# SQLite database path
database = "/var/lib/homeguard/config.db"

[logging]
# Log directory
log_dir = "/var/lib/homeguard/logs"
# Granularity: 1=all, 2=blocked+proxy, 3=blocked only
granularity = 2
# Days to keep logs
retention_days = 30
```

## API (Future - Phase 8+)

Not implemented in this phase. A separate management system will:
1. Connect to SQLite for configuration CRUD
2. Read log files for analysis and reporting
