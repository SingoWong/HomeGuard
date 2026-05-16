# Phase 4: Transparent Proxy Design

## Overview

透明代理是 HomeGuard 的核心组件，拦截家庭网络中所有 TCP 流量，根据规则决定：
- **DIRECT**: 直接连接目标
- **REJECT**: 拒绝连接
- **Proxy**: 通过 Shadowsocks 代理 (Phase 5)

## 流量劫持原理

### macOS PF (Packet Filter) 配置

```
┌─────────────────────────────────────────────────────────────────┐
│                     家庭设备                                      │
│  (192.168.0.100)                                                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Mac Mini (192.168.0.5) - 网关                       │
│                                                                  │
│  ┌─────────────────┐                                            │
│  │   PF Firewall   │                                            │
│  │                 │                                            │
│  │  rdr on en0     │──────┐                                     │
│  │  port 80,443    │      │                                     │
│  │  -> 127.0.0.1   │      │                                     │
│  │     :7893       │      │                                     │
│  └─────────────────┘      │                                     │
│                           ▼                                      │
│  ┌─────────────────────────────────────────┐                    │
│  │        HomeGuard Transparent Proxy       │                    │
│  │             (127.0.0.1:7893)             │                    │
│  │                                          │                    │
│  │  1. Accept connection                    │                    │
│  │  2. Get original dst (getsockopt)        │                    │
│  │  3. FakeDNS lookup → domain              │                    │
│  │  4. Rule match → policy                  │                    │
│  │  5. Connect to target/proxy              │                    │
│  │  6. Relay data bidirectionally           │                    │
│  └─────────────────────────────────────────┘                    │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                           │
                           ▼
                      互联网 / 代理服务器
```

### PF 规则示例

```bash
# /etc/pf.anchors/homeguard

# 重定向非本机的 HTTP/HTTPS 流量到透明代理
rdr pass on en0 proto tcp from any to any port {80, 443} -> 127.0.0.1 port 7893

# 可选：重定向所有 TCP 流量
# rdr pass on en0 proto tcp from any to any -> 127.0.0.1 port 7893
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transparent Proxy Module                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │  TcpListener    │    │   Connection    │                     │
│  │   (server.rs)   │───▶│    Handler      │                     │
│  │                 │    │  (handler.rs)   │                     │
│  └─────────────────┘    └────────┬────────┘                     │
│                                  │                               │
│                    ┌─────────────┼─────────────┐                │
│                    ▼             ▼             ▼                │
│           ┌──────────────┐ ┌──────────┐ ┌──────────────┐       │
│           │ get_original │ │ FakeDNS  │ │ Rule Engine  │       │
│           │    _dst()    │ │  lookup  │ │    match     │       │
│           └──────────────┘ └──────────┘ └──────────────┘       │
│                                  │                               │
│                    ┌─────────────┼─────────────┐                │
│                    ▼             ▼             ▼                │
│           ┌──────────────┐ ┌──────────┐ ┌──────────────┐       │
│           │    DIRECT    │ │  REJECT  │ │    PROXY     │       │
│           │   Outbound   │ │          │ │   Outbound   │       │
│           │   (relay.rs) │ │  (drop)  │ │  (Phase 5)   │       │
│           └──────────────┘ └──────────┘ └──────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Module Design

### 1. 获取原始目标地址 (`nat.rs`)

macOS 上使用 `getsockopt` 配合 PF 的 `DIOCNATLOOK` 来获取原始目标地址。

```rust
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;

/// 获取被 PF NAT 重定向前的原始目标地址
///
/// macOS 使用 PF (Packet Filter)，需要通过 /dev/pf 设备查询
pub fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    // macOS PF 方案：通过 ioctl DIOCNATLOOK 查询
    get_original_dst_pf(stream)
}

#[cfg(target_os = "macos")]
fn get_original_dst_pf(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::fs::File;
    use std::os::unix::io::FromRawFd;

    // 打开 /dev/pf 设备
    let pf_fd = unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const i8, libc::O_RDONLY) };
    if pf_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 构造 pfioc_natlook 结构体查询原始地址
    // ... (详见实现)
}
```

**注意**: macOS 上获取原始目标地址比 Linux 复杂：
- Linux: 使用 `SO_ORIGINAL_DST` socket option
- macOS: 需要通过 `/dev/pf` 设备和 `DIOCNATLOOK` ioctl

### 2. 透明代理服务器 (`server.rs`)

```rust
pub struct TransparentProxy {
    /// 监听地址
    listen_addr: SocketAddr,

    /// FakeDNS 引用（用于 IP -> Domain 查询）
    fake_dns: Option<Arc<FakeDns>>,

    /// 规则引擎（用于策略匹配）
    rule_engine: Arc<RuleEngine>,

    /// 代理出站管理器 (Phase 5)
    // outbound_manager: Arc<OutboundManager>,
}

impl TransparentProxy {
    pub async fn new(
        listen_addr: &str,
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
    ) -> Result<Self>;

    /// 运行透明代理服务器
    pub async fn run(&self) -> Result<()>;
}
```

### 3. 连接处理器 (`handler.rs`)

```rust
pub struct ConnectionHandler {
    fake_dns: Option<Arc<FakeDns>>,
    rule_engine: Arc<RuleEngine>,
}

impl ConnectionHandler {
    /// 处理单个连接
    pub async fn handle(&self, inbound: TcpStream, src_addr: SocketAddr) -> Result<()> {
        // 1. 获取原始目标地址
        let original_dst = get_original_dst(&inbound)?;

        // 2. FakeDNS 查询域名（如果是 FakeIP）
        let domain = self.resolve_domain(&original_dst);

        // 3. 规则匹配
        let match_result = self.rule_engine.match_request(
            domain.as_deref(),
            Some(original_dst.ip()),
        );

        // 4. 根据策略处理
        match match_result.policy {
            Policy::Direct => self.handle_direct(inbound, original_dst).await,
            Policy::Reject => self.handle_reject(inbound).await,
            Policy::Proxy(group) => self.handle_proxy(inbound, original_dst, &group).await,
        }
    }

    /// 直连处理
    async fn handle_direct(&self, inbound: TcpStream, dst: SocketAddr) -> Result<()>;

    /// 拒绝处理
    async fn handle_reject(&self, inbound: TcpStream) -> Result<()>;

    /// 代理处理 (Phase 5)
    async fn handle_proxy(&self, inbound: TcpStream, dst: SocketAddr, group: &str) -> Result<()>;
}
```

### 4. TCP 中继 (`relay.rs`)

双向数据转发，高效的 zero-copy 实现：

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;

/// 双向中继两个 TCP 连接
pub async fn relay(mut inbound: TcpStream, mut outbound: TcpStream) -> Result<(u64, u64)> {
    // tokio 提供的高效双向复制
    let (client_to_server, server_to_client) = copy_bidirectional(&mut inbound, &mut outbound).await?;

    Ok((client_to_server, server_to_client))
}

/// 带超时的中继
pub async fn relay_with_timeout(
    inbound: TcpStream,
    outbound: TcpStream,
    timeout: Duration,
) -> Result<(u64, u64)>;
```

## File Structure

```
src/proxy/
├── mod.rs              # Module exports
├── server.rs           # Transparent proxy server
├── handler.rs          # Connection handler
├── nat.rs              # Get original destination (macOS PF)
└── relay.rs            # TCP bidirectional relay
```

## Connection Flow

```
Client (192.168.0.100:54321)
    │
    │  TCP SYN to google.com:443 (FakeIP: 198.18.0.42:443)
    ▼
┌─────────────────────────────────────────────────────────────┐
│  PF Firewall                                                 │
│  rdr: 198.18.0.42:443 -> 127.0.0.1:7893                     │
└─────────────────────────────────────────────────────────────┘
    │
    │  TCP connection to 127.0.0.1:7893
    │  (original dst saved by PF)
    ▼
┌─────────────────────────────────────────────────────────────┐
│  TransparentProxy.accept()                                   │
│                                                              │
│  1. get_original_dst() -> 198.18.0.42:443                   │
│  2. fake_dns.lookup(198.18.0.42) -> "google.com"            │
│  3. rule_engine.match_domain("google.com") -> Proxy         │
│  4. outbound.connect("google.com:443") via Shadowsocks      │
│  5. relay(client <-> proxy)                                  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
Shadowsocks Server -> google.com:443
```

## macOS 特殊处理

### 1. `/dev/pf` 权限

需要 root 权限或特殊 entitlements 才能访问 `/dev/pf`：

```bash
# 运行时需要 sudo
sudo ./homeguard
```

### 2. PF NAT Lookup 结构体

```rust
#[repr(C)]
struct pfioc_natlook {
    saddr: pf_addr,      // 源地址
    daddr: pf_addr,      // 目标地址（原始）
    rsaddr: pf_addr,     // 重定向后源地址
    rdaddr: pf_addr,     // 重定向后目标地址
    sport: u16,          // 源端口
    dport: u16,          // 目标端口（原始）
    rsport: u16,
    rdport: u16,
    af: u8,              // 地址族 (AF_INET/AF_INET6)
    proto: u8,           // 协议 (IPPROTO_TCP)
    direction: u8,       // PF_IN/PF_OUT
}
```

### 3. DIOCNATLOOK ioctl

```rust
const DIOCNATLOOK: libc::c_ulong = 0xC0544417; // macOS specific

fn pf_natlook(pf_fd: i32, nl: &mut pfioc_natlook) -> std::io::Result<()> {
    let ret = unsafe { libc::ioctl(pf_fd, DIOCNATLOOK, nl as *mut _) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
```

## Error Handling

| 错误场景 | 处理方式 |
|---------|---------|
| 无法获取原始目标 | 关闭连接，记录警告 |
| FakeDNS 查询失败 | 使用 IP 直接匹配规则 |
| 规则匹配返回 REJECT | 立即关闭连接 |
| 目标连接失败 | 关闭客户端连接，记录错误 |
| 中继过程中断开 | 正常关闭两端连接 |

## Performance Considerations

1. **Zero-copy relay**: 使用 `tokio::io::copy_bidirectional`
2. **Connection pooling**: 对于代理连接可复用 (Phase 5)
3. **Buffer size**: 默认 8KB，可配置
4. **Timeout**:
   - 连接超时: 10s
   - 空闲超时: 300s

## Testing Strategy

1. **Unit Tests**:
   - NAT lookup 结构体序列化
   - 地址解析逻辑

2. **Integration Tests**:
   - 本地回环测试（不需要 PF）
   - Mock FakeDNS 和 RuleEngine

3. **Manual Tests**:
   - 配置 PF 规则
   - 实际流量测试

## Dependencies

```toml
# 已有依赖
tokio = { version = "1.35", features = ["full"] }
socket2 = { version = "0.5", features = ["all"] }

# 可能需要
libc = "0.2"  # 用于 ioctl 调用
nix = "0.28"  # Unix 系统调用封装（可选）
```

## NOT in Phase 4

- ❌ UDP 透明代理（需要 TPROXY，macOS 支持有限）
- ❌ Shadowsocks 出站 → Phase 5
- ❌ 代理组选择 → Phase 5
- ❌ 连接统计 → Phase 7

## Integration with Main

```rust
// main.rs
use homeguard::proxy::TransparentProxy;

// After DNS server initialization
let transparent_proxy = TransparentProxy::new(
    &config.transparent.listen.to_string(),
    fake_dns.clone(),
    filter.clone(), // RuleEngine
).await?;

let proxy_handle = tokio::spawn(async move {
    if let Err(e) = transparent_proxy.run().await {
        error!("Transparent proxy error: {}", e);
    }
});
```
