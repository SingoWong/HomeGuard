# Phase 5: Shadowsocks Outbound

## Overview

实现 Shadowsocks 出站协议，支持 AEAD 加密方式，并提供代理组功能（手动选择、自动测速、故障转移）。

## Shadowsocks 协议简介

Shadowsocks 是一种安全的 SOCKS5 代理协议，使用 AEAD 加密保护流量。

### AEAD 加密流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEAD Encryption                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Password ──▶ Key Derivation (HKDF) ──▶ Master Key              │
│                                                                  │
│  Master Key + Salt ──▶ Subkey                                   │
│                                                                  │
│  Subkey + Nonce + Plaintext ──▶ Ciphertext + Tag               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### TCP 数据包格式

```
Initial Request (Client → Server):
┌──────────┬──────────────────────────────────────────────────────┐
│  Salt    │  Encrypted Payload                                   │
│ (varies) │  [Length][Tag][Data][Tag]...                         │
└──────────┴──────────────────────────────────────────────────────┘

Encrypted Payload:
┌─────────────────┬───────────┬─────────────────┬───────────┐
│ Length (2 bytes)│ Tag (16B) │ Data (variable) │ Tag (16B) │
├─────────────────┴───────────┼─────────────────┴───────────┤
│    Encrypted Length Chunk   │    Encrypted Data Chunk     │
└─────────────────────────────┴─────────────────────────────┘

Target Address (First Payload):
┌────────┬───────────────────────────────────────┬──────────┐
│  Type  │              Address                  │   Port   │
│ (1B)   │              (variable)               │  (2B)    │
└────────┴───────────────────────────────────────┴──────────┘

Type:
  0x01 = IPv4 (4 bytes)
  0x03 = Domain (1 byte length + domain)
  0x04 = IPv6 (16 bytes)
```

## 支持的加密方法

| Method | Key Size | Salt Size | Nonce Size | Tag Size |
|--------|----------|-----------|------------|----------|
| aes-128-gcm | 16 | 16 | 12 | 16 |
| aes-256-gcm | 32 | 32 | 12 | 16 |
| chacha20-ietf-poly1305 | 32 | 32 | 12 | 16 |

## 模块设计

### 目录结构

```
src/outbound/
├── mod.rs              # Outbound trait, DirectOutbound, RejectOutbound
├── manager.rs          # OutboundManager - 出站管理器
├── shadowsocks/
│   ├── mod.rs          # ShadowsocksClient, ShadowsocksStream
│   ├── cipher.rs       # AEAD 加密/解密
│   └── address.rs      # 目标地址编解码
└── group/
    ├── mod.rs          # ProxyGroup 枚举
    ├── select.rs       # 手动选择组
    ├── url_test.rs     # URL 测试组 (自动选择延迟最低)
    └── fallback.rs     # 故障转移组
```

### 核心 Trait

```rust
/// 出站连接 trait
#[async_trait]
pub trait Outbound: Send + Sync {
    /// 出站名称
    fn name(&self) -> &str;

    /// 建立到目标的连接
    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>>;

    /// 健康检查
    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration>;
}

/// 异步读写流
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

/// 目标地址
pub enum Address {
    SocketAddr(SocketAddr),
    Domain(String, u16),
}
```

## 模块详细设计

### 1. cipher.rs - AEAD 加密

```rust
/// 加密方法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl CipherMethod {
    pub fn key_size(&self) -> usize;
    pub fn salt_size(&self) -> usize;
    pub fn tag_size(&self) -> usize;  // Always 16 for AEAD
    pub fn nonce_size(&self) -> usize; // Always 12
}

/// AEAD 加密器
pub struct AeadCipher {
    method: CipherMethod,
    key: Vec<u8>,
}

impl AeadCipher {
    /// 从密码创建加密器
    pub fn new(method: CipherMethod, password: &str) -> Self;

    /// 派生主密钥 (EVP_BytesToKey compatible)
    fn derive_key(password: &str, key_size: usize) -> Vec<u8>;

    /// 创建加密会话 (with salt)
    pub fn encryptor(&self, salt: &[u8]) -> AeadEncryptor;

    /// 创建解密会话 (with salt)
    pub fn decryptor(&self, salt: &[u8]) -> AeadDecryptor;
}

/// 加密会话 (包含递增的 nonce)
pub struct AeadEncryptor {
    cipher: ring::aead::SealingKey,
    nonce: [u8; 12],
}

impl AeadEncryptor {
    /// 加密数据块
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8>;

    /// 加密 length + payload 格式
    pub fn encrypt_payload(&mut self, payload: &[u8]) -> Vec<u8>;
}

/// 解密会话
pub struct AeadDecryptor {
    cipher: ring::aead::OpeningKey,
    nonce: [u8; 12],
}

impl AeadDecryptor {
    /// 解密数据块
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// 解密 length + payload 格式
    pub fn decrypt_payload(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}
```

**密钥派生流程：**

```
1. Master Key = EVP_BytesToKey(password)
   - MD5 based key derivation (for compatibility)

2. Subkey = HKDF-SHA1(
     salt = random(salt_size),
     ikm = master_key,
     info = "ss-subkey"
   )

3. Nonce = 0, increments after each encrypt/decrypt
```

### 2. address.rs - 目标地址

```rust
/// Shadowsocks 目标地址
#[derive(Debug, Clone)]
pub enum Address {
    /// IPv4 地址
    SocketAddrV4(SocketAddrV4),
    /// IPv6 地址
    SocketAddrV6(SocketAddrV6),
    /// 域名地址
    Domain(String, u16),
}

impl Address {
    /// 从 socket 地址创建
    pub fn from_socket_addr(addr: SocketAddr) -> Self;

    /// 从域名创建
    pub fn from_domain(domain: String, port: u16) -> Self;

    /// 编码为字节
    pub fn encode(&self) -> Vec<u8>;

    /// 从字节解码
    pub fn decode(data: &[u8]) -> Result<(Self, usize)>;

    /// 获取端口
    pub fn port(&self) -> u16;

    /// 转换为 socket 地址（域名需要解析）
    pub async fn to_socket_addr(&self) -> Result<SocketAddr>;
}

// 地址类型常量
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
```

### 3. tcp.rs - TCP 中继

```rust
/// Shadowsocks TCP 流
pub struct ShadowsocksStream {
    inner: TcpStream,
    encryptor: AeadEncryptor,
    decryptor: Option<AeadDecryptor>,
    cipher: AeadCipher,
    read_buf: BytesMut,
    write_buf: BytesMut,
    first_packet_sent: bool,
}

impl ShadowsocksStream {
    /// 连接到 SS 服务器并发送目标地址
    pub async fn connect(
        server_addr: SocketAddr,
        target: &Address,
        cipher: AeadCipher,
    ) -> Result<Self>;

    /// 发送握手（salt + encrypted target address）
    async fn send_handshake(&mut self, target: &Address) -> Result<()>;

    /// 接收服务器响应的 salt
    async fn recv_server_salt(&mut self) -> Result<()>;
}

impl AsyncRead for ShadowsocksStream {
    /// 从加密流读取并解密
}

impl AsyncWrite for ShadowsocksStream {
    /// 加密并写入流
}
```

**TCP 连接流程：**

```
Client                              SS Server
   │                                    │
   │──── TCP Connect ──────────────────▶│
   │                                    │
   │──── Salt + Encrypted(Target) ─────▶│
   │                                    │
   │◀─── Salt (Response) ───────────────│
   │                                    │
   │◀───── Encrypted Data ─────────────▶│
   │        (bidirectional)             │
```

### 4. client.rs - SS 客户端

```rust
/// Shadowsocks 客户端
pub struct ShadowsocksClient {
    name: String,
    server_addr: SocketAddr,
    cipher: AeadCipher,
}

impl ShadowsocksClient {
    /// 从配置创建
    pub fn from_config(config: &ShadowsocksConfig) -> Result<Self>;

    /// 连接到目标
    pub async fn connect(&self, target: &Address) -> Result<ShadowsocksStream>;
}

#[async_trait]
impl Outbound for ShadowsocksClient {
    fn name(&self) -> &str { &self.name }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>>;

    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration>;
}
```

### 5. group.rs - 代理组

```rust
/// 代理组类型
pub enum ProxyGroup {
    /// 手动选择
    Select(SelectGroup),
    /// URL 测试（选择延迟最低）
    UrlTest(UrlTestGroup),
    /// 故障转移
    Fallback(FallbackGroup),
}

/// 手动选择组
pub struct SelectGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    selected: AtomicUsize,
}

impl SelectGroup {
    /// 切换选择的代理
    pub fn select(&self, index: usize) -> Result<()>;

    /// 获取当前选择的代理
    pub fn current(&self) -> &Arc<dyn Outbound>;
}

/// URL 测试组
pub struct UrlTestGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    test_url: String,
    test_interval: Duration,
    best: AtomicUsize,
    latencies: RwLock<Vec<Option<Duration>>>,
}

impl UrlTestGroup {
    /// 执行延迟测试
    pub async fn test_all(&self) -> Result<()>;

    /// 获取延迟最低的代理
    pub fn best(&self) -> &Arc<dyn Outbound>;

    /// 启动后台测试任务
    pub fn start_background_test(self: Arc<Self>);
}

/// 故障转移组
pub struct FallbackGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    test_url: String,
    test_interval: Duration,
    available: RwLock<Vec<bool>>,
}

impl FallbackGroup {
    /// 获取第一个可用的代理
    pub fn first_available(&self) -> Option<&Arc<dyn Outbound>>;

    /// 检查所有代理的可用性
    pub async fn check_all(&self) -> Result<()>;
}

#[async_trait]
impl Outbound for ProxyGroup {
    // 代理组也实现 Outbound trait
}
```

### 6. manager.rs - 出站管理器

```rust
/// 出站管理器
pub struct OutboundManager {
    /// 直连出站
    direct: Arc<DirectOutbound>,
    /// 拒绝出站
    reject: Arc<RejectOutbound>,
    /// SS 代理
    shadowsocks: HashMap<String, Arc<ShadowsocksClient>>,
    /// 代理组
    groups: HashMap<String, Arc<ProxyGroup>>,
}

impl OutboundManager {
    /// 从配置创建
    pub fn from_config(config: &ProxyConfig) -> Result<Self>;

    /// 根据策略获取出站
    pub fn get(&self, policy: &Policy) -> Option<Arc<dyn Outbound>>;

    /// 获取代理组（用于切换选择）
    pub fn get_group(&self, name: &str) -> Option<&Arc<ProxyGroup>>;
}
```

## 与 Phase 4 集成

修改 `src/proxy/handler.rs`：

```rust
impl ConnectionHandler {
    pub fn new(
        fake_dns: Option<Arc<FakeDns>>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,  // 新增
    ) -> Self;

    async fn handle_proxy(
        &self,
        inbound: TcpStream,
        original_dst: SocketAddr,
        domain: Option<String>,
        group_name: &str,
    ) -> Result<()> {
        // 1. 获取出站
        let outbound = self.outbound_manager
            .get(&Policy::Proxy(group_name.to_string()))
            .ok_or_else(|| HomeGuardError::Proxy("Unknown proxy group".into()))?;

        // 2. 构造目标地址
        let target = match domain {
            Some(d) => Address::Domain(d, original_dst.port()),
            None => Address::from_socket_addr(original_dst),
        };

        // 3. 通过代理连接
        let outbound_stream = outbound.connect(&target).await?;

        // 4. 中继数据
        relay_streams(inbound, outbound_stream).await
    }
}
```

## AEAD 实现细节

### 使用 ring crate

```rust
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, SealingKey, OpeningKey};
use ring::hkdf;

/// 递增 Nonce 序列
struct CounterNonceSequence {
    counter: u64,
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let nonce = {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
            Nonce::assume_unique_for_key(nonce_bytes)
        };
        self.counter += 1;
        Ok(nonce)
    }
}
```

### EVP_BytesToKey 兼容实现

```rust
/// OpenSSL EVP_BytesToKey 兼容的密钥派生
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    use ring::digest::{Context, MD5};

    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();

    while key.len() < key_len {
        let mut ctx = Context::new(&MD5);
        if !prev.is_empty() {
            ctx.update(&prev);
        }
        ctx.update(password);
        prev = ctx.finish().as_ref().to_vec();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_len);
    key
}
```

## 健康检查

```rust
impl ShadowsocksClient {
    /// HTTP GET 健康检查，返回延迟
    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();

        // 解析 URL
        let (host, port, path) = parse_url(url)?;

        // 通过代理连接
        let target = Address::Domain(host.clone(), port);
        let mut stream = tokio::time::timeout(timeout, self.connect(&target)).await??;

        // 发送 HTTP HEAD 请求
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        stream.write_all(request.as_bytes()).await?;

        // 读取响应 (只需确认有响应)
        let mut buf = [0u8; 128];
        stream.read(&mut buf).await?;

        Ok(start.elapsed())
    }
}
```

## 配置示例

```toml
[[proxy.shadowsocks]]
name = "ss-hk"
server = "hk.example.com"
port = 8388
password = "password123"
method = "chacha20-ietf-poly1305"

[[proxy.shadowsocks]]
name = "ss-jp"
server = "jp.example.com"
port = 8388
password = "password456"
method = "aes-256-gcm"

[[proxy.group]]
name = "Proxy"
type = "url-test"
proxies = ["ss-hk", "ss-jp"]
url = "http://www.gstatic.com/generate_204"
interval = 300

[[proxy.group]]
name = "Manual"
type = "select"
proxies = ["DIRECT", "ss-hk", "ss-jp", "Proxy"]
```

## 测试计划

### 单元测试

1. **cipher.rs**
   - 密钥派生正确性
   - AEAD 加密/解密往返
   - Nonce 递增
   - 各加密方法测试

2. **address.rs**
   - IPv4/IPv6/Domain 编解码
   - 边界情况（最长域名等）

3. **tcp.rs**
   - 连接建立
   - 数据中继

### 集成测试

1. 连接到真实/模拟 SS 服务器
2. 代理组切换
3. 健康检查

## 实现顺序

1. `cipher.rs` - AEAD 加密核心
2. `address.rs` - 地址编解码
3. `tcp.rs` - TCP 中继
4. `client.rs` - SS 客户端封装
5. `direct.rs` + `reject.rs` - 直连/拒绝出站
6. `group.rs` - 代理组
7. `manager.rs` - 出站管理器
8. 集成到 `handler.rs`

## 依赖

```toml
# 已有
ring = "0.17"        # AEAD, HKDF, MD5
bytes = "1.5"        # BytesMut for buffer
tokio = { ... }      # 异步运行时

# 可能需要
async-trait = "0.1"  # async trait
```
