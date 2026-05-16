//! Configuration type definitions for HomeGuard

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub transparent: TransparentConfig,
    pub proxy: ProxyConfig,
    pub rules: RulesConfig,
    #[serde(default)]
    pub parental: ParentalConfig,
    #[serde(default)]
    pub schedules: HashMap<String, Schedule>,
    #[serde(default)]
    pub devices: HashMap<String, DeviceConfig>,
}

/// General configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/homeguard")
}

/// DNS server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_listen")]
    pub listen: SocketAddr,
    pub upstream: Vec<String>,
    #[serde(default)]
    pub fake_dns: bool,
    #[serde(default = "default_fake_dns_pool")]
    pub fake_dns_pool: String,
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
}

fn default_dns_listen() -> SocketAddr {
    "0.0.0.0:53".parse().unwrap()
}

fn default_fake_dns_pool() -> String {
    "198.18.0.0/15".to_string()
}

fn default_cache_size() -> usize {
    10000
}

fn default_cache_ttl() -> u64 {
    300
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            listen: default_dns_listen(),
            upstream: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            fake_dns: true,
            fake_dns_pool: default_fake_dns_pool(),
            cache_size: default_cache_size(),
            cache_ttl: default_cache_ttl(),
        }
    }
}

/// Transparent proxy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransparentConfig {
    #[serde(default = "default_transparent_listen")]
    pub listen: SocketAddr,
}

fn default_transparent_listen() -> SocketAddr {
    "0.0.0.0:7893".parse().unwrap()
}

/// Proxy configuration (outbound)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub shadowsocks: Vec<ShadowsocksConfig>,
    #[serde(default)]
    pub group: Vec<ProxyGroupConfig>,
}

/// Shadowsocks proxy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowsocksConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default = "default_ss_method")]
    pub method: String,
}

fn default_ss_method() -> String {
    "chacha20-ietf-poly1305".to_string()
}

/// Proxy group configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyGroupConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: ProxyGroupType,
    pub proxies: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGroupType {
    Select,
    UrlTest,
    Fallback,
}

/// Rules configuration
///
/// `rule_file` points at a plain-text rule list (one rule per line, `#` / `//`
/// comments allowed). Kept separate from the main TOML because rules churn far
/// more often than infrastructure settings, and a flat file is easier to edit
/// and diff than a TOML array.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesConfig {
    #[serde(default = "default_rules_dir")]
    pub rules_dir: PathBuf,
    pub geoip_db: Option<PathBuf>,
    #[serde(default = "default_rule_file")]
    pub rule_file: PathBuf,
}

fn default_rules_dir() -> PathBuf {
    PathBuf::from("./rules")
}

fn default_rule_file() -> PathBuf {
    PathBuf::from("./rules.list")
}

/// Time schedule definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Schedule {
    pub days: Vec<Weekday>,
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    pub fn from_chrono(weekday: chrono::Weekday) -> Self {
        match weekday {
            chrono::Weekday::Mon => Weekday::Mon,
            chrono::Weekday::Tue => Weekday::Tue,
            chrono::Weekday::Wed => Weekday::Wed,
            chrono::Weekday::Thu => Weekday::Thu,
            chrono::Weekday::Fri => Weekday::Fri,
            chrono::Weekday::Sat => Weekday::Sat,
            chrono::Weekday::Sun => Weekday::Sun,
        }
    }
}

/// Device configuration for parental control
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub name: String,
    #[serde(default)]
    pub device_type: DeviceType,
    #[serde(default)]
    pub schedules: Vec<String>,
    #[serde(default)]
    pub extra_blocklists: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Child,
    Adult,
    IoT,
    #[default]
    Unknown,
}

/// Parental control configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ParentalConfig {
    /// Enable parental control
    #[serde(default)]
    pub enabled: bool,

    /// Directory containing blocklist files
    #[serde(default = "default_blocklist_dir")]
    pub blocklist_dir: PathBuf,

    /// Categories blocked for ALL devices (including adults)
    #[serde(default)]
    pub global_categories: Vec<String>,

    /// Default policy for unknown devices: "allow", "block_if_listed", "block_all"
    #[serde(default = "default_unknown_policy")]
    pub default_policy: String,

    /// Log blocked requests
    #[serde(default = "default_log_blocked")]
    pub log_blocked: bool,
}

fn default_blocklist_dir() -> PathBuf {
    PathBuf::from("./config/blocklists")
}

fn default_unknown_policy() -> String {
    "allow".to_string()
}

fn default_log_blocked() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            general: GeneralConfig {
                log_level: default_log_level(),
                data_dir: default_data_dir(),
            },
            dns: DnsConfig {
                listen: default_dns_listen(),
                upstream: vec!["8.8.8.8:53".to_string()],
                fake_dns: true,
                fake_dns_pool: default_fake_dns_pool(),
                cache_size: default_cache_size(),
                cache_ttl: default_cache_ttl(),
            },
            transparent: TransparentConfig {
                listen: default_transparent_listen(),
            },
            proxy: ProxyConfig {
                shadowsocks: vec![],
                group: vec![],
            },
            rules: RulesConfig {
                rules_dir: default_rules_dir(),
                geoip_db: None,
                rule_file: default_rule_file(),
            },
            parental: ParentalConfig::default(),
            schedules: HashMap::new(),
            devices: HashMap::new(),
        }
    }
}
