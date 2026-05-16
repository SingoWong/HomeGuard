# HomeGuard

A Rust-based home network gateway for parental control and proxy management, designed for macOS.

## Features

- **Parental Control** - Block inappropriate websites with category-based blocklists, device-specific rules, and time-based schedules
- **Transparent Proxy** - Intercept and route network traffic using macOS PF firewall
- **Shadowsocks Proxy** - Built-in Shadowsocks client with multiple encryption methods
- **Surge-like Rules** - Flexible routing rules (DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP)
- **FakeDNS** - Domain preservation for transparent proxy routing
- **Access Logging** - Configurable logging with daily rotation and retention

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HomeGuard                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   DNS Server ──▶ FakeDNS ──▶ Rule Engine ──▶ Upstream/Block     │
│   (port 5353)                                                    │
│                                                                  │
│   TProxy ──▶ FakeDNS Lookup ──▶ Rule Match ──▶ Outbound         │
│   (port 7893)                     │                              │
│                              ┌────┴────┐                         │
│                              ▼         ▼                         │
│                           DIRECT    PROXY (Shadowsocks)          │
│                                                                  │
│   Parental Control ──▶ Device ID ──▶ Schedule ──▶ Blocklist     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

- macOS 10.15 (Catalina) or later
- Rust 1.75+
- Root privileges (for DNS binding and PF configuration)

## Quick Start

### Build

```bash
# Clone repository
git clone https://github.com/your-username/homeguard.git
cd homeguard

# Build release
cargo build --release
```

### Install

```bash
# Run installation script
sudo ./scripts/install.sh
```

This will:
1. Install binary to `/usr/local/bin/homeguard`
2. Install config to `/usr/local/etc/homeguard/`
3. Configure PF firewall rules
4. Install and start LaunchDaemon service

### Configuration

Edit `/usr/local/etc/homeguard/homeguard.toml`:

```toml
[dns]
listen = "127.0.0.1:5353"
upstream = ["8.8.8.8:53", "1.1.1.1:53"]
fake_dns = true

[transparent]
listen = "127.0.0.1:7893"

[parental]
enabled = true
blocklist_dir = "blocklists"

[rules]
rule_list = [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "GEOIP,CN,DIRECT",
    "FINAL,DIRECT",
]
```

### Service Management

```bash
# Stop service
sudo launchctl stop com.homeguard

# Start service
sudo launchctl start com.homeguard

# View logs
tail -f /var/log/homeguard/homeguard.log

# Uninstall
sudo ./scripts/uninstall.sh
```

## Project Structure

```
homeguard/
├── src/
│   ├── main.rs              # Entry point
│   ├── config/              # Configuration parsing
│   ├── dns/                 # DNS server, cache, FakeDNS
│   ├── proxy/               # Transparent proxy
│   ├── outbound/            # Outbound handlers (Direct, Shadowsocks)
│   ├── rule/                # Rule engine
│   ├── control/             # Parental control
│   └── storage/             # SQLite config, file logging
├── config/
│   └── homeguard.toml       # Configuration template
├── scripts/
│   ├── install.sh           # Installation script
│   ├── uninstall.sh         # Uninstallation script
│   ├── setup-pf.sh          # PF firewall setup
│   └── launchd/             # LaunchDaemon plist
└── docs/                    # Design documents
```

## Documentation

| Document | Description |
|----------|-------------|
| [00-overview.md](docs/00-overview.md) | Project overview and phase breakdown |
| [phase3-rule-engine.md](docs/phase3-rule-engine.md) | Rule engine design |
| [phase4-transparent-proxy.md](docs/phase4-transparent-proxy.md) | Transparent proxy design |
| [phase5-shadowsocks.md](docs/phase5-shadowsocks.md) | Shadowsocks implementation |
| [phase6-parental-control.md](docs/phase6-parental-control.md) | Parental control design |
| [phase7-storage.md](docs/phase7-storage.md) | Storage design (SQLite + file logging) |
| [phase8-deployment.md](docs/phase8-deployment.md) | Deployment scripts design |

## Configuration Reference

### DNS Settings

| Option | Default | Description |
|--------|---------|-------------|
| `listen` | `127.0.0.1:5353` | DNS server listen address |
| `upstream` | `["8.8.8.8:53"]` | Upstream DNS servers |
| `fake_dns` | `true` | Enable FakeDNS for proxy |
| `fake_dns_pool` | `198.18.0.0/15` | FakeDNS IP pool |
| `cache_size` | `10000` | DNS cache entries |
| `cache_ttl` | `300` | Default TTL in seconds |

### Rule Types

| Type | Example | Description |
|------|---------|-------------|
| `DOMAIN` | `DOMAIN,example.com,DIRECT` | Exact domain match |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,google.com,Proxy` | Domain suffix match |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,youtube,Proxy` | Domain keyword match |
| `IP-CIDR` | `IP-CIDR,192.168.0.0/16,DIRECT` | IP range match |
| `GEOIP` | `GEOIP,CN,DIRECT` | GeoIP country match |
| `FINAL` | `FINAL,DIRECT` | Default policy |

### Parental Control

```toml
[parental]
enabled = true
blocklist_dir = "blocklists"
global_categories = ["malware"]
default_policy = "allow"

[devices.child_ipad]
ip = "192.168.0.100"
name = "Child iPad"
device_type = "child"
schedules = ["school_hours"]
extra_blocklists = ["games", "social"]

[schedules.school_hours]
days = ["Mon", "Tue", "Wed", "Thu", "Fri"]
start = "08:00"
end = "16:00"
```

### Shadowsocks Proxy

```toml
[[proxy.shadowsocks]]
name = "hk-server"
server = "hk.example.com"
port = 8388
password = "your-password"
method = "chacha20-ietf-poly1305"

[[proxy.group]]
name = "Proxy"
type = "url-test"
proxies = ["hk-server"]
url = "http://www.gstatic.com/generate_204"
interval = 300
```

Supported encryption methods:
- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`

## Network Setup

HomeGuard requires router/DHCP configuration to work:

1. **DHCP Reservation** - Assign static IPs to devices for parental control
2. **Gateway Setting** - Set Mac Mini (HomeGuard) as the default gateway
3. **DNS Setting** - Point DNS to Mac Mini

Example network topology:
```
Internet ──▶ Router ──▶ Mac Mini (HomeGuard) ──▶ Home Devices
                        192.168.0.5
```

## Development

### Running Tests

```bash
cargo test
```

### Running Locally (Development)

```bash
# Run with custom config
cargo run -- ./config/homeguard.toml
```

### Debug Logging

```bash
RUST_LOG=debug cargo run -- ./config/homeguard.toml
```

## Troubleshooting

### DNS Not Working

```bash
# Check PF status
sudo pfctl -s info

# Check NAT rules
sudo pfctl -s nat

# Test DNS directly
dig @127.0.0.1 -p 5353 example.com
```

### Service Not Starting

```bash
# Check service status
sudo launchctl list | grep homeguard

# View error logs
tail -f /var/log/homeguard/homeguard.err
```

### Reset PF Rules

```bash
sudo ./scripts/setup-pf.sh --disable
sudo ./scripts/setup-pf.sh
```

## License

MIT License

## Acknowledgments

- [tokio](https://tokio.rs/) - Async runtime
- [simple-dns](https://github.com/balliegojr/simple-dns) - DNS parsing
- [ring](https://github.com/briansmith/ring) - Cryptography
- [maxminddb](https://github.com/oschwald/maxminddb-rust) - GeoIP database
