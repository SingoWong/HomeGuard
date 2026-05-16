# Phase 8: Deployment Design

## Overview

Phase 8 provides macOS deployment scripts for HomeGuard:
1. **PF Firewall Configuration** - Traffic redirection to HomeGuard
2. **LaunchDaemon Service** - Auto-start on boot, process supervision
3. **Installation Script** - Automated setup

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         macOS System                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Client Devices ──▶ PF Firewall (NAT Redirect)                         │
│         │                    │                                           │
│         │          ┌─────────┴─────────┐                                │
│         │          ▼                   ▼                                │
│         │    DNS (port 53)      TCP (port 80/443)                       │
│         │          │                   │                                │
│         │          ▼                   ▼                                │
│         │    HomeGuard DNS      HomeGuard TProxy                        │
│         │    (127.0.0.1:5353)   (127.0.0.1:7893)                       │
│         │                                                               │
│   LaunchDaemon ──▶ /usr/local/bin/homeguard                            │
│         │                                                               │
│   Config ──▶ /usr/local/etc/homeguard/                                 │
│   Data   ──▶ /var/lib/homeguard/                                       │
│   Logs   ──▶ /var/log/homeguard/                                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
/usr/local/
├── bin/
│   └── homeguard                    # Binary executable
├── etc/
│   └── homeguard/
│       ├── homeguard.toml           # Main configuration
│       ├── rules/                   # Rule files
│       │   └── *.txt
│       └── blocklists/              # Blocklist files
│           ├── global.txt
│           └── categories/
│               ├── porn.txt
│               ├── gambling.txt
│               └── games.txt
/var/
├── lib/
│   └── homeguard/
│       ├── config.db                # SQLite database
│       └── logs/
│           └── access-YYYY-MM-DD.log
├── log/
│   └── homeguard/
│       ├── homeguard.log            # Application log
│       └── homeguard.err            # Error log
/Library/
└── LaunchDaemons/
    └── com.homeguard.plist          # LaunchDaemon config
/etc/
└── pf.anchors/
    └── com.homeguard                # PF anchor rules
```

## PF Firewall Configuration

### Traffic Flow

```
1. DNS Queries (UDP 53)
   Client ──▶ Gateway:53 ──▶ rdr-anchor ──▶ 127.0.0.1:5353 (HomeGuard DNS)

2. HTTP/HTTPS Traffic (TCP 80, 443)
   Client ──▶ Gateway:80/443 ──▶ rdr-anchor ──▶ 127.0.0.1:7893 (HomeGuard TProxy)
```

### PF Anchor File (`/etc/pf.anchors/com.homeguard`)

```pf
# HomeGuard PF Anchor Rules
# Redirect DNS and HTTP/HTTPS traffic to HomeGuard

# Define the interface (en0 for Ethernet, en1 for WiFi)
# This will be set by the setup script

# Skip localhost traffic
set skip on lo0

# NAT Redirect Rules
# Redirect DNS (UDP 53) to HomeGuard DNS server
rdr pass on $homeguard_if inet proto udp from any to any port 53 -> 127.0.0.1 port 5353

# Redirect HTTP (TCP 80) to HomeGuard transparent proxy
rdr pass on $homeguard_if inet proto tcp from any to any port 80 -> 127.0.0.1 port 7893

# Redirect HTTPS (TCP 443) to HomeGuard transparent proxy
rdr pass on $homeguard_if inet proto tcp from any to any port 443 -> 127.0.0.1 port 7893

# Pass all other traffic
pass all
```

### Main PF Config Addition (`/etc/pf.conf`)

Add to `/etc/pf.conf`:
```pf
# HomeGuard anchor
rdr-anchor "com.homeguard"
load anchor "com.homeguard" from "/etc/pf.anchors/com.homeguard"
```

## LaunchDaemon Configuration

### Plist File (`/Library/LaunchDaemons/com.homeguard.plist`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.homeguard</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/homeguard</string>
        <string>/usr/local/etc/homeguard/homeguard.toml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>WorkingDirectory</key>
    <string>/usr/local/etc/homeguard</string>

    <key>StandardOutPath</key>
    <string>/var/log/homeguard/homeguard.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/homeguard/homeguard.err</string>

    <key>UserName</key>
    <string>root</string>

    <key>GroupName</key>
    <string>wheel</string>

    <!-- Environment variables -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>

    <!-- Resource limits -->
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
```

### Service Management Commands

```bash
# Load service
sudo launchctl load /Library/LaunchDaemons/com.homeguard.plist

# Unload service
sudo launchctl unload /Library/LaunchDaemons/com.homeguard.plist

# Start service
sudo launchctl start com.homeguard

# Stop service
sudo launchctl stop com.homeguard

# Check status
sudo launchctl list | grep homeguard
```

## Installation Script

### Features

1. **Pre-flight checks**
   - Root privileges
   - macOS version compatibility
   - Required dependencies

2. **Installation steps**
   - Create directories
   - Copy binary and config files
   - Set permissions
   - Configure PF firewall
   - Install LaunchDaemon

3. **Configuration**
   - Auto-detect network interface
   - Generate default config if not exists
   - Validate configuration

4. **Service management**
   - Enable PF
   - Load LaunchDaemon
   - Verify service running

### Script Flow

```
┌─────────────────┐
│  Pre-flight     │
│  Checks         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Create         │
│  Directories    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Install        │
│  Binary/Config  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Setup PF       │
│  Firewall       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Install        │
│  LaunchDaemon   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Start          │
│  Service        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Verify         │
│  Running        │
└─────────────────┘
```

## Scripts Structure

```
scripts/
├── install.sh              # Main installation script
├── uninstall.sh            # Uninstallation script
├── setup-pf.sh             # PF firewall setup
└── launchd/
    └── com.homeguard.plist # LaunchDaemon template
```

## Configuration Templates

### Default Config (`config/homeguard.toml`)

Update listen addresses for production:
```toml
[dns]
listen = "127.0.0.1:5353"      # Internal DNS (PF redirects to here)
upstream = ["8.8.8.8:53", "1.1.1.1:53"]
fake_dns = true
fake_dns_pool = "198.18.0.0/15"
cache_size = 10000
cache_ttl = 300

[transparent]
listen = "127.0.0.1:7893"      # Internal proxy (PF redirects to here)

[parental]
enabled = true
blocklist_dir = "blocklists"
global_categories = []
default_policy = "allow"
log_blocked = true

[storage]
database = "/var/lib/homeguard/config.db"

[logging]
log_dir = "/var/lib/homeguard/logs"
granularity = 2
retention_days = 30
```

## Security Considerations

1. **Permissions**
   - Binary: `root:wheel 755`
   - Config: `root:wheel 644`
   - Data directory: `root:wheel 700`
   - Log directory: `root:wheel 755`

2. **Network Isolation**
   - HomeGuard binds to `127.0.0.1` only
   - PF redirects external traffic to localhost
   - No direct external access to HomeGuard ports

3. **PF Bypass Prevention**
   - Block direct access to upstream DNS
   - Ensure all LAN traffic goes through PF

## Uninstallation

1. Stop and unload service
2. Remove PF anchor
3. Restore original PF config
4. Remove files and directories

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| DNS not working | PF not enabled | `sudo pfctl -e` |
| Service not starting | Permission denied | Check binary permissions |
| Clients can't connect | Wrong interface | Update `$homeguard_if` in PF |
| High CPU usage | Too many connections | Increase file limits |

### Debug Commands

```bash
# Check PF status
sudo pfctl -s info

# View PF rules
sudo pfctl -s rules

# View NAT rules
sudo pfctl -s nat

# Check service logs
tail -f /var/log/homeguard/homeguard.log

# Test DNS redirect
dig @127.0.0.1 -p 5353 example.com
```

## Implementation Checklist

- [ ] `scripts/install.sh` - Main installation
- [ ] `scripts/uninstall.sh` - Clean uninstallation
- [ ] `scripts/setup-pf.sh` - PF configuration
- [ ] `scripts/launchd/com.homeguard.plist` - LaunchDaemon
- [ ] Update `config/homeguard.toml` with production defaults
- [ ] Add systemctl-style commands (start/stop/status)
