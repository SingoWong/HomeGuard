# Phase 3: Rule Engine Design

## Overview

规则引擎是 HomeGuard 的核心组件，实现 Surge 风格的规则匹配系统，用于：
1. DNS 过滤（拦截/放行域名）
2. 透明代理路由决策（DIRECT/REJECT/Proxy）

## Surge 规则格式

参考 Surge 配置，支持以下规则类型：

```
DOMAIN,example.com,DIRECT              # 精确域名匹配
DOMAIN-SUFFIX,google.com,Proxy         # 域名后缀匹配 (*.google.com)
DOMAIN-KEYWORD,facebook,Proxy          # 域名关键词匹配
IP-CIDR,192.168.0.0/16,DIRECT          # IPv4 CIDR 匹配
IP-CIDR6,2001:db8::/32,Proxy           # IPv6 CIDR 匹配
GEOIP,CN,DIRECT                        # GeoIP 国家匹配
FINAL,DIRECT                           # 默认规则
```

### 规则选项

- `no-resolve`: 不解析域名到 IP（用于 IP 规则跳过 DNS 解析）

### 策略类型

| Policy | 说明 |
|--------|------|
| DIRECT | 直连 |
| REJECT | 拒绝（返回 NXDOMAIN 或断开连接）|
| Proxy | 通过指定代理组 |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Rule Engine                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Domain Matcher │  │   IP Matcher    │  │  GeoIP Matcher  │ │
│  │                 │  │                 │  │                 │ │
│  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │ │
│  │  │   Trie    │  │  │  │  IP-CIDR  │  │  │  │ MaxMindDB │  │ │
│  │  │  (Suffix) │  │  │  │   Tree    │  │  │  │           │  │ │
│  │  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │ │
│  │  ┌───────────┐  │  │  ┌───────────┐  │  │                 │ │
│  │  │    AC     │  │  │  │ IP-CIDR6  │  │  │                 │ │
│  │  │ (Keyword) │  │  │  │   Tree    │  │  │                 │ │
│  │  └───────────┘  │  │  └───────────┘  │  │                 │ │
│  │  ┌───────────┐  │  │                 │  │                 │ │
│  │  │  HashSet  │  │  │                 │  │                 │ │
│  │  │  (Exact)  │  │  │                 │  │                 │ │
│  │  └───────────┘  │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Rule List (Ordered)                     ││
│  │  [Rule1] -> [Rule2] -> [Rule3] -> ... -> [FINAL]            ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Module Design

### 1. Rule Types (`types.rs`)

```rust
/// 规则类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    /// 精确域名匹配
    Domain(String),
    /// 域名后缀匹配 (e.g., google.com matches *.google.com)
    DomainSuffix(String),
    /// 域名关键词匹配
    DomainKeyword(String),
    /// IPv4 CIDR
    IpCidr(Ipv4Net),
    /// IPv6 CIDR
    IpCidr6(Ipv6Net),
    /// GeoIP 国家代码
    GeoIp(String),
    /// 默认规则
    Final,
}

/// 策略类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// 直连
    Direct,
    /// 拒绝
    Reject,
    /// 通过代理组
    Proxy(String),
}

/// 规则选项
#[derive(Debug, Clone, Default)]
pub struct RuleOptions {
    /// 不解析域名到 IP
    pub no_resolve: bool,
}

/// 完整规则
#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_type: RuleType,
    pub policy: Policy,
    pub options: RuleOptions,
}

/// 匹配结果
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub policy: Policy,
    pub rule_index: usize,
    pub matched_rule: String,
}
```

### 2. Domain Matcher (`matcher/domain.rs`)

域名匹配使用三种数据结构：

```rust
pub struct DomainMatcher {
    /// 精确匹配: O(1)
    exact: HashMap<String, usize>,

    /// 后缀匹配: Reverse Trie, O(m) where m = domain length
    suffix_trie: ReverseDomainTrie,

    /// 关键词匹配: Aho-Corasick, O(n) where n = domain length
    keyword_ac: AhoCorasick,
    keyword_indices: Vec<usize>,
}
```

**后缀 Trie 设计:**

域名后缀匹配使用反转 Trie 树。例如 `google.com` 存储为 `com.google`:

```
Root
 └── com
      ├── google -> [rule_index]
      ├── facebook -> [rule_index]
      └── apple
           └── icloud -> [rule_index]
```

查找 `www.google.com`:
1. 反转为 `com.google.www`
2. 沿 Trie 匹配 `com` -> `google`
3. 找到匹配，返回 rule_index

**关键词匹配:**

使用 Aho-Corasick 算法同时匹配多个关键词，时间复杂度 O(n + m)：
- n = 域名长度
- m = 匹配数

### 3. IP Matcher (`matcher/ip.rs`)

```rust
pub struct IpMatcher {
    /// IPv4 CIDR 列表
    ipv4_cidrs: Vec<(Ipv4Net, usize)>,

    /// IPv6 CIDR 列表
    ipv6_cidrs: Vec<(Ipv6Net, usize)>,
}

impl IpMatcher {
    /// 匹配 IPv4 地址
    pub fn match_ipv4(&self, ip: Ipv4Addr) -> Option<usize>;

    /// 匹配 IPv6 地址
    pub fn match_ipv6(&self, ip: Ipv6Addr) -> Option<usize>;
}
```

**优化考虑:**
- 对于大量 CIDR 规则，可使用 Patricia Trie
- 目前使用简单线性扫描，对于家庭使用场景足够

### 4. GeoIP Matcher (`matcher/geoip.rs`)

```rust
pub struct GeoIpMatcher {
    /// MaxMind DB reader
    reader: Option<maxminddb::Reader<Vec<u8>>>,

    /// 国家代码到规则索引映射
    country_rules: HashMap<String, usize>,
}

impl GeoIpMatcher {
    /// 从 .mmdb 文件加载
    pub fn load(path: &Path) -> Result<Self>;

    /// 匹配 IP 地址的国家
    pub fn match_ip(&self, ip: IpAddr) -> Option<usize>;
}
```

### 5. Rule Engine (`engine.rs`)

```rust
pub struct RuleEngine {
    /// 所有规则（保持顺序）
    rules: Vec<Rule>,

    /// 域名匹配器
    domain_matcher: DomainMatcher,

    /// IP 匹配器
    ip_matcher: IpMatcher,

    /// GeoIP 匹配器
    geoip_matcher: GeoIpMatcher,

    /// FINAL 规则的 policy
    final_policy: Policy,
}

impl RuleEngine {
    /// 创建规则引擎
    pub fn new(rules: Vec<Rule>, geoip_db: Option<&Path>) -> Result<Self>;

    /// 匹配域名
    pub fn match_domain(&self, domain: &str) -> MatchResult;

    /// 匹配 IP 地址
    pub fn match_ip(&self, ip: IpAddr) -> MatchResult;

    /// 完整匹配（先域名后 IP）
    pub fn match_request(&self, domain: Option<&str>, ip: Option<IpAddr>) -> MatchResult;
}
```

**匹配流程:**

```
match_request(domain, ip):
    1. 如果有 domain:
       a. 检查 DOMAIN 精确匹配
       b. 检查 DOMAIN-SUFFIX 后缀匹配
       c. 检查 DOMAIN-KEYWORD 关键词匹配

    2. 如果有 ip (且规则没有 no-resolve):
       a. 检查 IP-CIDR / IP-CIDR6 匹配
       b. 检查 GEOIP 匹配

    3. 按规则顺序，返回第一个匹配的结果

    4. 如果没有匹配，返回 FINAL 策略
```

### 6. Rule Parser (`parser.rs`)

```rust
pub struct RuleParser;

impl RuleParser {
    /// 解析单条规则
    pub fn parse_rule(line: &str) -> Result<Rule>;

    /// 从文件加载规则集
    pub fn load_ruleset(path: &Path) -> Result<Vec<Rule>>;

    /// 从配置加载所有规则
    pub fn load_rules(config: &RulesConfig) -> Result<Vec<Rule>>;
}
```

**规则格式:**

```
# 注释
RULE-TYPE,PATTERN,POLICY[,options]

# 示例
DOMAIN,example.com,DIRECT
DOMAIN-SUFFIX,google.com,Proxy
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,DIRECT
```

## File Structure

```
src/rule/
├── mod.rs           # Module exports
├── types.rs         # Type definitions
├── engine.rs        # Rule engine
├── parser.rs        # Rule parsing
└── matcher/
    ├── mod.rs       # Matcher exports
    ├── domain.rs    # Domain matching (Trie + AC)
    ├── ip.rs        # IP-CIDR matching
    └── geoip.rs     # GeoIP matching
```

## Integration with DNS Handler

Phase 3 完成后，替换 DNS Handler 中的 `DnsFilterTrait`:

```rust
// Before (Phase 2)
let filter = Arc::new(AllowAllFilter);

// After (Phase 3)
let rule_engine = Arc::new(RuleEngine::new(rules, geoip_db)?);

// In DnsHandler
impl DnsFilterTrait for RuleEngine {
    fn is_blocked(&self, domain: &str) -> bool {
        let result = self.match_domain(domain);
        result.policy == Policy::Reject
    }
}
```

## Dependencies

```toml
# 已有依赖
aho-corasick = "1.1"    # 关键词匹配
radix_trie = "0.2"      # Trie 树
ipnet = "2.7"           # IP 网段
maxminddb = "0.24"      # GeoIP
```

## Testing Strategy

1. **Unit Tests:**
   - Domain matching: exact/suffix/keyword
   - IP-CIDR matching: IPv4/IPv6
   - GeoIP matching (需要测试 DB)
   - Rule parsing

2. **Integration Tests:**
   - 完整规则匹配流程
   - 大量规则性能测试

## Performance Considerations

| Operation | Time Complexity | Space |
|-----------|----------------|-------|
| Domain Exact | O(1) | O(n) |
| Domain Suffix | O(m) | O(n*m) |
| Domain Keyword | O(len + matches) | O(n) |
| IP-CIDR | O(n) | O(n) |
| GeoIP | O(log n) | O(DB size) |

其中:
- n = 规则数量
- m = 域名长度
- len = 被匹配字符串长度

## NOT in Phase 3

- ❌ PROCESS-NAME 规则（不需要，透明代理无法获取进程）
- ❌ USER-AGENT 规则（不需要，需要 HTTP 解析）
- ❌ URL-REGEX 规则（不需要，需要 HTTP 解析）
- ❌ RULE-SET 远程加载（Phase 6 blocklist 管理）
- ❌ 时间段控制 schedule（Phase 6 parental control）
