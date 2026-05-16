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
git clone https://github.com/singowong/homeguard.git
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
# Rules live in their own plain-text file; this TOML only points at it.
rule_file = "./rules.list"
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
│   ├── homeguard.toml       # Infrastructure configuration (stable)
│   ├── rules.list           # Routing rules (changes often, edited solo)
│   ├── rules/               # Optional RULE-SET files referenced from rules.list
│   └── blocklists/          # Category blocklists for parental control
├── scripts/
│   ├── install.sh           # Installation script
│   ├── uninstall.sh         # Uninstallation script
│   ├── setup-pf.sh          # PF firewall setup
│   └── launchd/             # LaunchDaemon plist
└── docs/                    # Design documents
```

## Documentation

| Document                                                        | Description                               |
| --------------------------------------------------------------- | ----------------------------------------- |
| [00-overview.md](docs/00-overview.md)                           | Project overview and phase breakdown      |
| [network.md](docs/network.md)                                   | End-to-end packet flow & PF redirect 原理 |
| [phase1-project-structure.md](docs/phase1-project-structure.md) | Project framework and configuration       |
| [phase2-dns-service.md](docs/phase2-dns-service.md)             | DNS server, cache, FakeDNS                |
| [phase3-rule-engine.md](docs/phase3-rule-engine.md)             | Rule engine design                        |
| [phase4-transparent-proxy.md](docs/phase4-transparent-proxy.md) | Transparent proxy design                  |
| [phase5-shadowsocks.md](docs/phase5-shadowsocks.md)             | Shadowsocks implementation                |
| [phase6-parental-control.md](docs/phase6-parental-control.md)   | Parental control design                   |
| [phase7-storage.md](docs/phase7-storage.md)                     | Storage design (SQLite + file logging)    |
| [phase8-deployment.md](docs/phase8-deployment.md)               | Deployment scripts design                 |

## Configuration Reference

### DNS Settings

| Option          | Default          | Description               |
| --------------- | ---------------- | ------------------------- |
| `listen`        | `127.0.0.1:5353` | DNS server listen address |
| `upstream`      | `["8.8.8.8:53"]` | Upstream DNS servers      |
| `fake_dns`      | `true`           | Enable FakeDNS for proxy  |
| `fake_dns_pool` | `198.18.0.0/15`  | FakeDNS IP pool           |
| `cache_size`    | `10000`          | DNS cache entries         |
| `cache_ttl`     | `300`            | Default TTL in seconds    |

### Rule Types

Rules live in [config/rules.list](config/rules.list), **one rule per line**, with `#` or `//` for comments. This file is intentionally kept out of `homeguard.toml` because rules change much more frequently than infrastructure settings — editing/diffing/version-controlling a flat list is far easier than maintaining a TOML array.

```text
# Order matters: the first match wins.
DOMAIN-SUFFIX,google.com,SS-HK
DOMAIN-KEYWORD,youtube,SS-HK
GEOIP,CN,DIRECT
RULE-SET,blocklist/games.list,REJECT,schedule=school_hours
FINAL,DIRECT
```

| Type             | Example                                | Description                                                   |
| ---------------- | -------------------------------------- | ------------------------------------------------------------- |
| `DOMAIN`         | `DOMAIN,example.com,DIRECT`            | Exact domain match                                            |
| `DOMAIN-SUFFIX`  | `DOMAIN-SUFFIX,google.com,SS-HK`       | Domain suffix match                                           |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,youtube,SS-HK`         | Domain keyword match                                          |
| `IP-CIDR`        | `IP-CIDR,192.168.0.0/16,DIRECT`        | IP range match                                                |
| `GEOIP`          | `GEOIP,CN,DIRECT`                      | GeoIP country match (requires `[rules].geoip_db`)             |
| `RULE-SET`       | `RULE-SET,blocklist/games.list,REJECT` | Include another file; path is relative to `[rules].rules_dir` |
| `FINAL`          | `FINAL,DIRECT`                         | Catch-all; required, exactly one, last line                   |

Optional trailing options after the policy, comma-separated:

- `no-resolve` — for `IP-CIDR`/`GEOIP`: only match when the IP is already known, skip the DNS lookup
- `schedule=<name>` — only apply during the named schedule (see Parental Control)

**Layout of `config/`:**

```
config/
├── homeguard.toml          # Infrastructure (changes rarely)
├── rules.list              # Main rule entry — top-level routing strategy
├── rules/                  # Sub-files referenced by `RULE-SET` in rules.list
│   └── README.md           #   ↑ format and conventions for this directory
└── blocklists/             # Parental-control category lists (separate code path)
    ├── custom/
    └── opensource/
```

The `rules/` directory is the root for **all** `RULE-SET` references —
`RULE-SET,proxy-ai.list,SS-US` looks up `config/rules/proxy-ai.list`. Sub-paths
like `RULE-SET,blocklist/games.list,REJECT` are fine too. See
[config/rules/README.md](config/rules/README.md) for the sub-file format
(no policy column per line; policy is supplied once at the `RULE-SET` call site).

After editing `rules.list` or any sub-file, restart the service (`sudo launchctl kickstart -k system/com.homeguard`); hot-reload is not implemented yet.

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

Building and starting the binary on the Mac Mini / dedicated server is only half the job. HomeGuard intercepts traffic by acting as the LAN's **DNS server and default gateway**, so the host needs a fixed address and the router has to push that address to every client. For parental control, the child devices in turn need stable IPs of their own. The three steps below must all be done before the gateway will actually filter anything.

Throughout the examples we assume:

| Role                | IP             | Notes                                |
| ------------------- | -------------- | ------------------------------------ |
| Router (LAN side)   | `192.168.0.1`  | Existing home router                 |
| HomeGuard host      | `192.168.0.5`  | Mac Mini / dedicated server (static) |
| DHCP pool           | `.100`–`.200`  | For normal devices                   |
| Child device (iPad) | `192.168.0.50` | DHCP-reserved by MAC                 |

Adjust to your own subnet.

### 1. Give the HomeGuard Host a Static IP

The Mac Mini's address is referenced by every client's gateway/DNS setting and by `[devices.*]` rules, so it must never change.

**macOS GUI:** System Settings → Network → select the active interface (wired Ethernet is strongly recommended over Wi-Fi) → Details → TCP/IP, then set:

- **Configure IPv4:** Manually
- **IP Address:** `192.168.0.5` (outside the router's DHCP pool)
- **Subnet Mask:** `255.255.255.0`
- **Router:** `192.168.0.1`
- **DNS Server (TCP/IP → DNS tab):** `127.0.0.1` first, then a fallback like `223.5.5.5` so the host can still resolve names if `homeguard` itself is stopped

**macOS command line equivalent** (replace `Ethernet` with the service name from `networksetup -listallnetworkservices`):

```bash
sudo networksetup -setmanual        Ethernet 192.168.0.5 255.255.255.0 192.168.0.1
sudo networksetup -setdnsservers    Ethernet 127.0.0.1 223.5.5.5
sudo networksetup -setsearchdomains Ethernet "Empty"
```

Verify:

```bash
ifconfig en0 | grep 'inet '
scutil --dns | grep nameserver
```

> Linux / other server: configure a static IP through the distro's tooling (`netplan`, `nmcli`, `/etc/network/interfaces`, etc.). The principle is identical — the host gets `192.168.0.5/24`, default route `192.168.0.1`, and its own DNS resolver pointed at `127.0.0.1`.

### 2. Configure the Router's DHCP

Two things need to change on the router. The wording differs per vendor (look under **LAN / DHCP Server / Local Network**), but the concepts are universal.

**(a) Shrink the DHCP pool so it does not overlap the static IP**

| Before              | After                           |
| ------------------- | ------------------------------- |
| `192.168.0.2 – 254` | `192.168.0.100 – 192.168.0.200` |

This leaves `.2 – .99` available for hand-assigned static IPs (HomeGuard host, NAS, printers, child devices, …) and prevents DHCP from ever handing out `.5` to someone else.

**(b) Push HomeGuard as the Gateway _and_ DNS to every DHCP client**

In the router's DHCP settings, override the two values it advertises:

- **Default Gateway (Option 3):** `192.168.0.5`
- **DNS Server (Option 6):** `192.168.0.5`

Without (b), clients will keep using the router directly and HomeGuard will see no traffic, regardless of how the binary is configured.

> ⚠️ Some ISP-supplied routers do not allow changing the pushed gateway/DNS. If yours doesn't, either switch the device into bridge mode and put your own router behind it, or set the gateway/DNS manually on every client.

After saving, force a DHCP renew on each client (Wi-Fi off → on, or `sudo ipconfig set en0 DHCP` on macOS).

### 3. Reserve Fixed IPs for Child Devices

Parental control identifies who is making a request by **source IP**. If a child's iPad gets a different IP each time it reconnects, the schedule and blocklists silently stop applying to it.

**Recommended: DHCP reservation on the router** (a.k.a. _Static DHCP_, _Address Reservation_, _MAC Binding_):

1. Find the child device's Wi-Fi MAC address:
   - iOS: Settings → General → About → Wi-Fi Address
   - Android: Settings → About phone → Status → Wi-Fi MAC address
   - macOS: System Settings → Network → details → Hardware → MAC Address
2. In the router's DHCP reservation page, bind that MAC to a specific IP outside the DHCP pool, e.g. `AA:BB:CC:DD:EE:FF → 192.168.0.50`.
3. Make the device reconnect to Wi-Fi; confirm it received the reserved IP (`ifconfig` / device network info).
4. Reference the same IP in `homeguard.toml`:

   ```toml
   [devices.child_ipad]
   ip          = "192.168.0.50"
   mac         = "AA:BB:CC:DD:EE:FF"   # currently informational; runtime matching is by ip
   name        = "Child iPad"
   device_type = "child"
   schedules   = ["school_hours", "sleep_time"]
   extra_blocklists = ["games", "social"]
   ```

> Tip: keep one block of IPs (e.g. `.50 – .99`) reserved exclusively for child / restricted devices. It makes the rule list readable, and lets you write coarse `IP-CIDR,192.168.0.48/28,REJECT` style rules later if you ever need them.

**Why not just set a manual IP on the iPad itself?** You can, but a kid can change it back in 30 seconds. Reservation on the router can't be bypassed from the device — bind the MAC and the IP follows.

> ⚠️ MAC randomization: iOS and modern Android default to using a _private_ MAC per SSID. Disable "Private Wi-Fi Address" (iOS: Settings → Wi-Fi → ⓘ next to the SSID) for the home network on every device you want to reserve, otherwise the MAC the router sees will change.

### 4. Verify the Whole Path

From a client on the LAN (after DHCP renew):

```bash
# Gateway and DNS should both be 192.168.0.5
netstat -nr | grep default        # macOS / BSD
ip route                          # Linux
scutil --dns | grep nameserver    # macOS

# Names should resolve through HomeGuard
dig example.com                   # answer should come back fine
dig blocked-domain.test           # should be REJECTed if it matches a blocklist
```

From the HomeGuard host:

```bash
sudo tail -f /var/log/homeguard/homeguard.log
# you should see DNS queries arriving from your client's IP
```

If you don't see any queries from the client, step 2(b) is almost always the culprit — the router is still answering DNS itself.

### Example Topology

```
                       Internet
                          │
                          ▼
                ┌──────────────────────┐
                │  Router  192.168.0.1 │
                │  DHCP pool .100–.200 │
                │  Pushes:             │
                │    Gateway = .5      │
                │    DNS     = .5      │
                │  Reservations:       │
                │    iPad MAC → .50    │
                └──────────┬───────────┘
                           │ LAN
        ┌──────────────────┼────────────────────┐
        ▼                  ▼                    ▼
┌────────────────┐  ┌──────────────┐   ┌────────────────┐
│ Mac Mini       │  │ Child iPad   │   │ Other devices  │
│ HomeGuard      │  │ DHCP-reserved│   │ DHCP .100–.200 │
│ 192.168.0.5    │  │ 192.168.0.50 │   │                │
│ (static IP)    │  │ (MAC bound)  │   │                │
└────────────────┘  └──────────────┘   └────────────────┘
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
