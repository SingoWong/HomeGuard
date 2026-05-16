# Phase 6: Parental Control (儿童管控)

## Overview

Phase 6 implements device-aware access control with time-based restrictions. This enables:
- Device identification (by IP address)
- Per-device blocklist application
- Time schedule enforcement (e.g., no gaming during school hours)

## Prerequisites

**Important: Static IP or DHCP Reservation Required**

This implementation identifies devices by IP address. To ensure reliable device identification:

1. **Configure DHCP Reservation** on your router for all managed devices
   - Most routers support binding MAC address to IP address
   - This ensures devices always receive the same IP

2. **Alternatively, use Static IP** on the device itself

Without static IP binding, device identification will be unreliable as DHCP may assign different IPs.

**Future Enhancement:** MAC address identification (requires ARP table access) may be added in future versions.

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │           ParentalController             │
                         ├─────────────────────────────────────────┤
                         │                                         │
    ┌──────────────┐     │  ┌─────────────┐   ┌─────────────────┐  │
    │  DNS Handler │────▶│  │DeviceManager│   │ScheduleManager  │  │
    │    or        │     │  └──────┬──────┘   └────────┬────────┘  │
    │  TProxy      │     │         │                   │           │
    └──────────────┘     │         ▼                   ▼           │
                         │  ┌─────────────────────────────────────┐│
  Source IP ─────────────│  │         BlocklistManager             ││
                         │  │  ┌──────────┐  ┌──────────────────┐ ││
                         │  │  │OpenSource│  │Device-specific   │ ││
                         │  │  │Blocklists│  │Blocklists        │ ││
                         │  │  └──────────┘  └──────────────────┘ ││
                         │  └──────────────────────┬──────────────┘│
                         │                         │               │
                         │                         ▼               │
                         │               ┌─────────────────┐       │
                         │               │  Access Decision │       │
                         │               │  ALLOW / BLOCK   │       │
                         │               └─────────────────┘       │
                         └─────────────────────────────────────────┘
```

## Components

### 1. DeviceManager

Manages device identification and lookup by IP address.

```rust
pub struct DeviceManager {
    /// Device configs keyed by device ID
    devices: HashMap<String, DeviceConfig>,

    /// IP -> Device ID mapping for quick lookup
    ip_to_device: HashMap<IpAddr, String>,
}

impl DeviceManager {
    /// Create from config
    pub fn from_config(devices: &HashMap<String, DeviceConfig>) -> Self;

    /// Get device by source IP
    pub fn get_device_by_ip(&self, ip: IpAddr) -> Option<&DeviceConfig>;

    /// Get device type by IP
    pub fn get_device_type(&self, ip: IpAddr) -> DeviceType;

    /// Check if device is a child device
    pub fn is_child_device(&self, ip: IpAddr) -> bool;
}
```

### 2. ScheduleManager

Handles time-based schedule evaluation.

```rust
pub struct ScheduleManager {
    /// Schedule definitions keyed by name
    schedules: HashMap<String, Schedule>,
}

impl ScheduleManager {
    /// Create from config
    pub fn from_config(schedules: &HashMap<String, Schedule>) -> Self;

    /// Check if a schedule is currently active
    pub fn is_active(&self, schedule_name: &str) -> bool;

    /// Check if ANY of the given schedules is active
    pub fn any_active(&self, schedule_names: &[String]) -> bool;

    /// Get time until next schedule change (for caching)
    pub fn time_until_change(&self, schedule_name: &str) -> Option<Duration>;
}
```

### 3. BlocklistManager

Manages blocklists from multiple sources.

```rust
pub struct BlocklistManager {
    /// Global blocklists (apply to all devices)
    global_domains: HashSet<String>,

    /// Category-based blocklists
    categories: HashMap<String, HashSet<String>>,

    /// Domain suffix trie for efficient matching
    suffix_matcher: DomainMatcher,
}

impl BlocklistManager {
    /// Create empty manager
    pub fn new() -> Self;

    /// Load blocklist from file (domains, one per line)
    pub fn load_file(&mut self, path: &Path, category: Option<&str>) -> Result<usize>;

    /// Load all blocklists from directory
    pub fn load_directory(&mut self, dir: &Path) -> Result<()>;

    /// Check if domain is in global blocklist
    pub fn is_blocked_globally(&self, domain: &str) -> bool;

    /// Check if domain is in specific category
    pub fn is_in_category(&self, domain: &str, category: &str) -> bool;

    /// Check if domain is in ANY of the given categories
    pub fn is_in_any_category(&self, domain: &str, categories: &[String]) -> bool;
}
```

### 4. ParentalController

Main controller that coordinates all components.

```rust
pub struct ParentalController {
    /// Device manager
    device_manager: DeviceManager,

    /// Schedule manager
    schedule_manager: ScheduleManager,

    /// Blocklist manager
    blocklist_manager: BlocklistManager,

    /// Default policy for unknown devices
    default_policy: ParentalPolicy,
}

pub enum ParentalPolicy {
    /// Allow all traffic
    Allow,
    /// Block if in blocklist
    BlockIfListed,
    /// Block all (total internet cutoff)
    BlockAll,
}

pub enum ParentalDecision {
    /// Allow the request
    Allow,
    /// Block the request
    Block { reason: String },
}

impl ParentalController {
    /// Create from full config
    pub fn from_config(config: &Config, blocklist_dir: &Path) -> Result<Self>;

    /// Check if a domain access should be allowed for a device
    pub fn check_access(
        &self,
        source_ip: IpAddr,
        domain: &str,
    ) -> ParentalDecision;

    /// Get device info for logging
    pub fn get_device_info(&self, ip: IpAddr) -> Option<DeviceInfo>;
}
```

## Integration Points

### 1. DNS Handler Integration

The DNS handler will call ParentalController before resolving:

```rust
// In dns/handler.rs

impl DnsHandler {
    async fn handle_query(&self, query: &Message, src: SocketAddr) -> Result<Message> {
        let domain = extract_domain(query);

        // Check parental control first
        if let Some(ref controller) = self.parental_controller {
            match controller.check_access(src.ip(), &domain) {
                ParentalDecision::Block { reason } => {
                    info!("Blocked {} for {}: {}", domain, src.ip(), reason);
                    return Ok(create_nxdomain_response(query));
                }
                ParentalDecision::Allow => {}
            }
        }

        // Continue with normal resolution...
    }
}
```

### 2. Transparent Proxy Integration

The connection handler will also check parental control:

```rust
// In proxy/handler.rs

impl ConnectionHandler {
    async fn handle(&self, inbound: TcpStream, src_addr: SocketAddr) -> Result<()> {
        // ... get original_dst and domain ...

        // Check parental control
        if let Some(ref controller) = self.parental_controller {
            if let Some(domain) = &domain {
                match controller.check_access(src_addr.ip(), domain) {
                    ParentalDecision::Block { reason } => {
                        info!("Blocked {} for {}: {}", domain, src_addr.ip(), reason);
                        return Ok(()); // Drop connection
                    }
                    ParentalDecision::Allow => {}
                }
            }
        }

        // Continue with normal routing...
    }
}
```

## Blocklist File Format

Blocklists are simple text files with one domain per line:

```
# Comment lines start with #
# Blank lines are ignored

example.com
bad-site.org
# Wildcards are supported via domain suffix matching
*.adult-content.com
```

### Directory Structure

```
config/blocklists/
├── global/               # Apply to all devices
│   └── ads.txt          # Ad domains
├── categories/           # Category-based lists
│   ├── porn.txt
│   ├── gambling.txt
│   ├── games.txt
│   └── social.txt
└── opensource/           # Downloaded from public sources
    ├── steven-black-hosts.txt
    └── anti-ad.txt
```

## Configuration

### Schedule Configuration

```toml
[schedules.school_hours]
days = ["Mon", "Tue", "Wed", "Thu", "Fri"]
start = "08:00"
end = "16:00"

[schedules.bedtime]
days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
start = "21:00"
end = "07:00"  # Next day (crosses midnight)

[schedules.weekend_morning]
days = ["Sat", "Sun"]
start = "06:00"
end = "10:00"
```

### Device Configuration

```toml
[devices.child_ipad]
name = "Child's iPad"
ip = "192.168.0.100"
device_type = "child"
schedules = ["school_hours", "bedtime"]  # Apply schedules
extra_blocklists = ["games", "social"]   # Extra categories to block

[devices.child_laptop]
name = "Child's Laptop"
ip = "192.168.0.101"
device_type = "child"
schedules = ["school_hours"]
extra_blocklists = ["games"]

[devices.parents_phone]
name = "Parent's Phone"
ip = "192.168.0.50"
device_type = "adult"
# No schedules or extra blocklists - full access
```

### Parental Control Settings

```toml
[parental]
enabled = true
blocklist_dir = "./config/blocklists"
global_categories = ["porn", "gambling"]  # Block for ALL devices
default_policy = "allow"  # For unknown devices: "allow" | "block_if_listed" | "block_all"
log_blocked = true
```

## Decision Flow

```
check_access(source_ip, domain)
    │
    ▼
┌─────────────────────┐
│ Get device by IP    │
└──────────┬──────────┘
           │
     ┌─────┴─────┐
     │           │
  Found       Not Found
     │           │
     ▼           ▼
┌─────────┐  ┌─────────────┐
│ Device  │  │Apply default│
│ Config  │  │   policy    │
└────┬────┘  └──────┬──────┘
     │              │
     ▼              │
┌─────────────────┐ │
│Check if schedule│ │
│  is active      │ │
└────────┬────────┘ │
         │          │
    ┌────┴────┐     │
    │         │     │
  Active   Inactive │
    │         │     │
    ▼         │     │
┌───────────┐ │     │
│Check extra│ │     │
│blocklists │ │     │
└─────┬─────┘ │     │
      │       │     │
      ▼       ▼     ▼
┌─────────────────────┐
│ Check global        │
│ blocklists          │
└──────────┬──────────┘
           │
     ┌─────┴─────┐
     │           │
  Blocked     Not Blocked
     │           │
     ▼           ▼
   BLOCK       ALLOW
```

## File Structure

```
src/control/
├── mod.rs              # Module exports
├── device.rs           # DeviceManager
├── schedule.rs         # ScheduleManager
├── blocklist.rs        # BlocklistManager
└── controller.rs       # ParentalController
```

## Implementation Plan

### Step 1: ScheduleManager
- Parse schedule config
- Implement `is_active()` with timezone support
- Handle cross-midnight schedules

### Step 2: DeviceManager
- Parse device config
- Implement IP lookup
- Device type helpers

### Step 3: BlocklistManager
- Load blocklist files
- Efficient domain matching
- Category management

### Step 4: ParentalController
- Coordinate all managers
- Implement access decision logic
- Logging

### Step 5: Integration
- Add to DnsHandler
- Add to ConnectionHandler
- Add to main.rs initialization

## Testing Strategy

### Unit Tests
- ScheduleManager: time parsing, active/inactive checks, midnight crossing
- DeviceManager: IP lookup, device type
- BlocklistManager: domain matching, category checks
- ParentalController: decision logic

### Integration Tests
- Full flow: device + schedule + blocklist
- Config loading
- Real blocklist file parsing

### Manual Testing
- Set up test schedules
- Configure test device
- Verify blocking behavior

## Performance Considerations

1. **Blocklist Loading**: Load at startup, keep in memory
2. **Domain Matching**: Reuse DomainMatcher from rule engine for efficient suffix matching
3. **Schedule Checks**: Cache schedule state with TTL (1 minute)
4. **Device Lookup**: HashMap O(1) lookup by IP

## Error Handling

- Missing blocklist files: Log warning, continue without
- Invalid schedule times: Error at config parse time
- Unknown device: Apply default policy (configurable)
- Schedule parse errors: Fail fast at startup

## Future Enhancements (Not in Phase 6)

- MAC address identification (requires ARP table access)
- Web UI for management
- Real-time blocklist updates
- Per-device statistics
- Bypass codes for temporary access
