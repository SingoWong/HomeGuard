# Network Design: 数据如何在 HomeGuard 中流转

> 本文档专门解释「一个 LAN 客户端发出的请求，从离开网卡到被 HomeGuard 处理、再到拿到响应」这条端到端链路上的每一跳，以及背后的设计权衡。
>
> 关于**如何配置**静态 IP、路由器 DHCP、儿童设备保留地址，见 [README.md 的 Network Setup 段](../README.md#network-setup)。本文只回答**为什么这样配能 work**。

---

## 1. 问题陈述

HomeGuard 默认配置长这样（[config/homeguard.toml](../config/homeguard.toml)）：

```toml
[dns]
listen = "127.0.0.1:5353"        # 监听本地回环 + 非标端口

[transparent]
listen = "127.0.0.1:7893"        # 同上
```

但路由器通过 DHCP 推送给客户端的，只有**两个 IP 字段**：

- Gateway（DHCP Option 3）
- DNS Server（DHCP Option 6）

**DHCP 协议本身就没有「DNS 端口」这个字段**——客户端永远只会去查 `<DNS>:53`，永远只会把 TCP SYN 发到 `<Gateway>` 然后路由出去。

那为什么客户端发往 `192.168.0.5:53` 的 UDP 包，能被监听在 `127.0.0.1:5353` 的进程收到？为什么发往 `198.18.0.42:443` 的 TCP 连接，能被监听在 `127.0.0.1:7893` 的进程接管？

答案是：**PF 防火墙在内核层做了目的地址改写（NAT redirect），用户态进程根本不知道改写发生过。**

---

## 2. 全局拓扑

```
                       Internet
                          │
                          ▼
                ┌──────────────────────────────┐
                │           Router             │
                │         192.168.0.1          │
                │  DHCP 推送：                  │
                │    Gateway = 192.168.0.5     │
                │    DNS     = 192.168.0.5     │
                └─────────────┬────────────────┘
                              │ LAN
        ┌─────────────────────┼──────────────────────┐
        ▼                                            ▼
┌─────────────────────────────────┐         ┌────────────────┐
│  Mac Mini   192.168.0.5         │         │ LAN Client     │
│ ┌─────────────────────────────┐ │         │ 192.168.0.50   │
│ │  Kernel (PF)                │ │ ◀────── │ (e.g. iPad)    │
│ │  ┌───────────────────────┐  │ │         └────────────────┘
│ │  │ rdr 规则（NAT 表）    │  │ │
│ │  │  udp :53  → :5353     │  │ │
│ │  │  tcp :80  → :7893     │  │ │
│ │  │  tcp :443 → :7893     │  │ │
│ │  └───────────────────────┘  │ │
│ └────────────┬────────────────┘ │
│              │ (改写后的目的)   │
│              ▼                  │
│ ┌─────────────────────────────┐ │
│ │  Userland (HomeGuard)       │ │
│ │  ├─ DnsServer  127.0.0.1:5353│ │
│ │  └─ TProxy     127.0.0.1:7893│ │
│ └─────────────────────────────┘ │
└─────────────────────────────────┘
```

三类参与者各司其职：

| 角色 | 职责 | 配置在哪 |
| --- | --- | --- |
| **路由器** | 推送 Gateway/DNS = HomeGuard 主机 IP | 路由器管理界面 |
| **PF（内核）** | 改写 `dst port` 把流量塞进用户态服务的非标端口 | [scripts/setup-pf.sh](../scripts/setup-pf.sh) |
| **HomeGuard（用户态）** | DNS / 规则 / 家长控制 / 出站策略 | [config/homeguard.toml](../config/homeguard.toml) |

任何一环缺失，链路都断。

---

## 3. DNS 请求的完整链路

以一台客户端（`192.168.0.50`）查询 `youtube.com` 为例：

```
Client (192.168.0.50)
   │  ① 发起 DNS 查询
   │     UDP src=192.168.0.50:54321  dst=192.168.0.5:53
   │     payload = "QUERY youtube.com A"
   ▼
Mac Mini en0 网卡
   │
   ▼
┌──────────────── 内核 PF ────────────────┐
│ ② 命中规则:                              │
│   rdr pass on en0 inet proto udp        │
│       from any to any port 53           │
│       -> 127.0.0.1 port 5353            │
│                                          │
│ ③ 改写包头:                              │
│   dst 192.168.0.5:53  →  127.0.0.1:5353 │
│   （src 不动，仍是 .50:54321）          │
│                                          │
│ ④ NAT 状态表记录一条映射，用于响应回流  │
└────────────┬─────────────────────────────┘
             │ (包此时看起来像本地 loopback 来的)
             ▼
┌──────────── HomeGuard (用户态) ─────────────┐
│ DnsServer.recv_from() 收到包               │
│   ├─ peer = 192.168.0.50:54321  ← 客户端真实 IP，没丢
│   └─ local = 127.0.0.1:5353                │
│                                             │
│ DnsHandler 处理:                            │
│   1) 缓存命中？ → 直接回                    │
│   2) FakeDNS 启用 + 域名命中规则需要代理？  │
│      → 在 198.18.0.0/15 池里分配一个 IP，  │
│        写入双向映射（域名 ⇄ 虚拟 IP），   │
│        响应客户端"youtube.com A 198.18.0.42"│
│   3) 否则转发上游（8.8.8.8 / 223.5.5.5）   │
│      拿到响应后回写                         │
└────────────┬────────────────────────────────┘
             │ ⑤ 用户态 sendto:
             │   src=127.0.0.1:5353  dst=192.168.0.50:54321
             ▼
┌──────────────── 内核 PF ─────────────────┐
│ ⑥ 反查 NAT 状态表，找到出向映射，         │
│   反向改写 src:                          │
│   src 127.0.0.1:5353  →  192.168.0.5:53  │
└────────────┬─────────────────────────────┘
             ▼
   返回给客户端的包看起来是从 192.168.0.5:53 来的
   ── 与客户端的查询目标对得上，客户端无感知

Client 收到响应，缓存 "youtube.com → 198.18.0.42"
```

**关键点**：

1. 用户态进程 `recvfrom` 拿到的 `peer addr` 是**客户端的真实 IP**（`192.168.0.50:54321`），PF 改的是 `dst`，没动 `src`。这就是为什么 HomeGuard 能按"哪个客户端发起的查询"做家长控制（[src/control/device.rs](../src/control/device.rs)）。
2. NAT 状态表是**有连接性**的：响应包会自动找到正确的反向改写规则，不需要用户态做任何事。
3. 客户端看到的回包源地址是 `192.168.0.5:53`——和它发出去的目的完全对称，所以 DNS 解析正常完成。

---

## 4. TCP（HTTP/HTTPS）请求的完整链路

DNS 解析完成后，客户端拿到 `youtube.com → 198.18.0.42`。注意这是一个**FakeDNS 虚拟 IP**，互联网上根本不存在。下一步它会发起 TCP 连接：

```
Client (192.168.0.50)
   │  ① 发起 TCP 连接
   │     SYN src=192.168.0.50:51000  dst=198.18.0.42:443
   │
   │  ② 按路由表，dst 不在 LAN 网段内 → 走默认网关
   │     默认网关 = 192.168.0.5（DHCP 推的）
   ▼
Mac Mini en0 网卡
   │
   ▼
┌──────────────── 内核 PF ────────────────┐
│ ③ 命中规则:                              │
│   rdr pass on en0 inet proto tcp        │
│       from any to any port 443          │
│       -> 127.0.0.1 port 7893            │
│                                          │
│ ④ 改写:                                  │
│   dst 198.18.0.42:443  →  127.0.0.1:7893│
│   ❗ 但 PF 在 NAT 表里保留了原始 dst:    │
│      "198.18.0.42:443"                  │
│   这是后面 DIOCNATLOOK 反查的关键        │
└────────────┬─────────────────────────────┘
             ▼
┌──────────── HomeGuard TransparentProxy ─────────────┐
│ accept() 收到新连接:                                │
│   peer  = 192.168.0.50:51000   ← 客户端            │
│   local = 127.0.0.1:7893       ← 被改写后的 dst    │
│                                                     │
│ ⑤ 调 nat::lookup_original_dst()                    │
│   open("/dev/pf", RW)                              │
│   ioctl(fd, DIOCNATLOOK, &pfioc_natlook { ... })   │
│   → 返回 198.18.0.42:443                            │
│   （见 src/proxy/nat.rs）                          │
│                                                     │
│ ⑥ FakeDNS 反查 198.18.0.42 → "youtube.com"         │
│   （没有反查到则按 IP 走 IP-CIDR/GEOIP 规则）      │
│                                                     │
│ ⑦ Parental Control 按 src=192.168.0.50 判定:       │
│   是儿童设备？当前在 school_hours？                │
│   命中 extra_blocklists.games？→ REJECT            │
│                                                     │
│ ⑧ 规则引擎匹配 youtube.com:                        │
│   DOMAIN-SUFFIX,youtube.com,Proxy  → 命中           │
│   policy = ProxyGroup("Proxy")                     │
│                                                     │
│ ⑨ OutboundManager 拿到 Outbound:                   │
│   - DIRECT → 直连原始目标（但是 .42 不是真实 IP，  │
│              所以只在 FakeDNS 反查成功时才有意义）  │
│   - REJECT → 立刻断开                              │
│   - Shadowsocks → AEAD 加密后送往代理服务器        │
│                                                     │
│ ⑩ 拨号成功 → 双向 relay（TcpStream ⇆ TcpStream）  │
└─────────────────────────────────────────────────────┘
```

**TCP 链路里的两个"魔法"**：

- **FakeDNS 是连接 DNS 和 TCP 的桥**。透明代理 accept 的瞬间，TLS 还没开始握手，SNI 还看不到，**唯一能拿到"客户端想去哪个域名"的途径就是用刚才在 DNS 阶段建立的 IP↔域名映射**。这就是为什么 FakeDNS 是开启透明代理必须搭配的组件（[src/dns/fake_dns.rs](../src/dns/fake_dns.rs)）。
- **`DIOCNATLOOK` 是 macOS 透明代理的固有约束**。`accept()` 在 socket 层只能看到改写后的 `local addr`（永远是 `127.0.0.1:7893`），原始目的必须通过 `ioctl` 反查 PF NAT 表才能拿到。Linux 上对应的是 `SO_ORIGINAL_DST`（iptables REDIRECT）或 `IP_TRANSPARENT`（TPROXY），机制不同但解决的是同一个问题。

---

## 5. 端到端例子：iPad 访问 `youtube.com`

把上面两段拼起来，看一次完整的访问发生了什么。假设这台 iPad 是 `[devices.child_ipad]`，当前命中 `school_hours`，规则集里有 `DOMAIN-SUFFIX,youtube.com,REJECT,schedule=school_hours`。

```
T+0    iPad 用户点了 youtube.com
       浏览器: 查 youtube.com 的 A 记录

T+1    iPad → 路由器 → Mac Mini (.5:53)
T+2    PF rdr: .5:53 → 127.0.0.1:5353
T+3    HomeGuard DNS:
        - FakeDNS 给 youtube.com 分一个 IP: 198.18.0.42
        - 返回 A 记录: youtube.com → 198.18.0.42
T+4    iPad 缓存解析结果

T+5    iPad TCP SYN → 198.18.0.42:443（按路由走默认网关 .5）
T+6    PF rdr: 198.18.0.42:443 → 127.0.0.1:7893
       （PF NAT 表记录原始 dst = 198.18.0.42:443）
T+7    HomeGuard TProxy accept:
        - DIOCNATLOOK → 原始 dst = 198.18.0.42:443
        - FakeDNS 反查 → youtube.com
        - ParentalControl: src=.50 = child_ipad，在 school_hours ✓
        - 规则: DOMAIN-SUFFIX,youtube.com,REJECT,schedule=school_hours ✓
        - Policy = REJECT
T+8    HomeGuard 直接 close 连接
T+9    iPad 收到 RST，Safari 显示"无法连接"

T+10   AccessLogger（Phase 7，启用时）写入一行 NDJSON:
       {"ts":"...","type":"tcp","src":"192.168.0.50",
        "dst":"198.18.0.42:443","domain":"youtube.com",
        "policy":"REJECT","reason":"parental:school_hours"}
```

整个过程客户端无任何感知（除了被拒），全部由 PF 改写 + FakeDNS 桥接 + 规则引擎判定串起来。

---

## 6. 为什么 DNS 默认监听 `127.0.0.1` 而不是 `0.0.0.0`

[config/homeguard.toml](../config/homeguard.toml) 里其实留了第二种部署模式：

```toml
# Use 127.0.0.1:5353 for production (PF redirects to this port)
# Use 0.0.0.0:53 for direct DNS server mode
listen = "127.0.0.1:5353"
```

两种模式的对比：

| 维度 | `127.0.0.1:5353` + PF rdr（默认） | `0.0.0.0:53` 直监 |
| --- | --- | --- |
| 客户端配置 | DHCP 推 `.5` 作 DNS | 同左 |
| 路径 | 网卡 → PF 改写 → 用户态 | 网卡 → 用户态 |
| 需要 root | 是（PF 操作） | 是（绑特权端口） |
| 端口占用 | 不会和系统 mDNSResponder/named 抢 | 必须先停掉系统占用 |
| 调试 | 多一层 NAT，看 `pfctl -s nat` | 直观，`lsof -iUDP:53` |
| 一致性 | 和 TCP 透明代理对称（两者都靠 PF） | DNS 走快路径，TCP 仍需 PF |
| 安全 | DNS 端口不暴露到 LAN（仅内核可达） | 53 端口对 LAN 直接开放 |

**默认选 PF 模式的核心理由**：TCP 透明代理那一侧**无论如何都得用 PF**——因为要拿原始目的 IP，必须通过 `DIOCNATLOOK` 反查 PF NAT 表，没有其他途径。DNS 顺势也走 PF，整套架构保持一致，调试和心智负担更低。

直监模式只在「PF 出问题需要快速验证 DNS 处理逻辑本身是否正确」时切一下，平常不推荐。

---

## 7. 为什么 FakeDNS 是透明代理的前提

很多人第一次看 HomeGuard 的设计会问："直接拿真实 DNS 解析结果不行吗？为什么要造一个虚拟 IP？"

考虑下面的场景：客户端访问 `youtube.com`，真实 DNS 解析到 `142.250.66.78`。

- 客户端 SYN → `142.250.66.78:443`
- PF rdr → `127.0.0.1:7893`
- HomeGuard accept → DIOCNATLOOK → `142.250.66.78:443`

**问题：HomeGuard 拿到 `142.250.66.78:443`，怎么知道这是 youtube.com？**

- 反查 DNS？同一个 IP 可能服务很多域名（CDN），反向 PTR 几乎没用。
- 等 TLS ClientHello 看 SNI？要做 TLS 解析，且 ECH（Encrypted ClientHello）越来越普及之后 SNI 也会加密。
- 直接按 IP 匹配规则？只能写 `IP-CIDR` 规则，写不了 `DOMAIN-SUFFIX,youtube.com,Proxy`，整套 Surge 风格规则全废。

FakeDNS 把这个难题在 DNS 阶段就解掉：

1. DNS 阶段，对每个 A 查询分配一个 `198.18.0.0/15` 池里的虚拟 IP，**同时记录"虚拟 IP → 域名"映射**。
2. 客户端用虚拟 IP 发起 TCP。
3. 透明代理 accept 时，用虚拟 IP 直接反查域名——**这个映射是 HomeGuard 自己造的，绝对准确**。

代价是池子大小有限（`/15` ≈ 131K 个 IP），到上限后按 LRU 回收最久没用的映射。家庭网络一天的活跃域名远低于这个量级，实践中不会成为瓶颈。

---

## 8. 故障排查清单

按"链路从外到内"的顺序排查：

### 客户端拿到的 Gateway/DNS 不对
- `netstat -nr | grep default`（macOS）或 `ip route`（Linux）应显示 `192.168.0.5`
- `scutil --dns | grep nameserver` 应显示 `192.168.0.5`
- 不对 → 路由器 DHCP 没改 Option 3/6，或客户端没 DHCP 续约（关 Wi-Fi 再开）
- 路由器不支持改 DHCP 推送 → 把光猫改成桥接 / 端侧手动改 / 换路由器

### 客户端 ping 得通 .5，但 DNS 不通
- 在 Mac Mini 上：`sudo pfctl -s info` 看 PF 是否 `Enabled`
- `sudo pfctl -a com.homeguard -s nat` 看 rdr 规则是否加载
- 都正常 → 在另一台机器上 `dig @192.168.0.5 example.com` 测一下；同时在 Mac Mini 看 `tail -f /var/log/homeguard/homeguard.log`，应该有查询到达
- 日志没动静 → PF 规则没生效，跑 `sudo ./scripts/setup-pf.sh --disable && sudo ./scripts/setup-pf.sh` 重载
- macOS 系统 mDNSResponder 占了 53？检查 `sudo lsof -iUDP:53`；HomeGuard 默认监听 5353 应该不会冲突，但如果你切到了直监模式就要注意

### DNS 通了，TCP 不通（网页打不开）
- FakeDNS 是否启用？`fake_dns = true`
- 透明代理日志有没有 accept？`grep TProxy /var/log/homeguard/homeguard.log`
- 有 accept 但 `DIOCNATLOOK` 失败 → `/dev/pf` 权限或者 PF 没启用（同上）
- `DIOCNATLOOK` 成功但拿不到域名 → FakeDNS 反查失败，可能客户端没走 HomeGuard 解析（自带了 DoH/DoT 绕过，见下条）

### 部分应用绕过 HomeGuard（iOS App、Chrome、Firefox 等）
- 这些客户端可能用了 **DoH（DNS over HTTPS）**或 **DoT（DNS over TLS）**，DNS 查询走 TCP/443，**不经过 .5:53**，HomeGuard 看不到，也就分不到 FakeDNS IP
- 现象：客户端能联网，但完全没经过家长控制
- 解决：
  - 路由器层屏蔽常见 DoH 端点（`dns.google` `cloudflare-dns.com` `mozilla.cloudflare-dns.com` 等）
  - 设备层关闭"加密 DNS"（iOS: 设置 → Wi-Fi → ⓘ → 配置 DNS → 手动；Chrome/Firefox: 设置里搜 "secure DNS"）
  - 写一条 `DOMAIN-SUFFIX,dns.google,REJECT` 之类的兜底规则

### FakeDNS 池"用完"
- 不会真用完——LRU 会淘汰最久未使用的，新查询永远拿得到 IP
- 但如果一个老映射被淘汰后客户端还在用旧的虚拟 IP 发 TCP（缓存了 DNS 响应），就会反查失败
- 解决：调小客户端的 DNS TTL（HomeGuard 默认 `cache_ttl = 300`），或者调大 `fake_dns_pool`

---

## 9. 参考阅读

| 文档 | 关联章节 |
| --- | --- |
| [phase2-dns-service.md](phase2-dns-service.md) | DNS 服务内部结构、缓存、上游解析 |
| [phase4-transparent-proxy.md](phase4-transparent-proxy.md) | TransparentProxy 实现细节、`DIOCNATLOOK` 调用 |
| [phase5-shadowsocks.md](phase5-shadowsocks.md) | Outbound 出站、Shadowsocks AEAD 加密 |
| [phase6-parental-control.md](phase6-parental-control.md) | 设备识别、Schedule 判定、Blocklist 匹配 |
| [phase8-deployment.md](phase8-deployment.md) | 部署脚本、PF anchor 文件、LaunchDaemon |
| [README.md#network-setup](../README.md#network-setup) | 路由器/DHCP/儿童设备 IP 的**操作步骤** |
| [scripts/setup-pf.sh](../scripts/setup-pf.sh) | 实际生成的 PF 规则 |
