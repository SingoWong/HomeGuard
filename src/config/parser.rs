//! Configuration file parser

use crate::config::types::Config;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

/// Load configuration from a TOML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    validate_config(&config)?;
    Ok(config)
}

/// Load configuration from a string
pub fn load_config_from_str(content: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(content)?;
    validate_config(&config)?;
    Ok(config)
}

/// Validate configuration
fn validate_config(config: &Config) -> Result<(), ConfigError> {
    // Validate DNS upstream
    if config.dns.upstream.is_empty() {
        return Err(ConfigError::ValidationError(
            "At least one DNS upstream server is required".to_string(),
        ));
    }

    // Validate FakeDNS pool
    if config.dns.fake_dns {
        if config.dns.fake_dns_pool.is_empty() {
            return Err(ConfigError::ValidationError(
                "FakeDNS pool is required when fake_dns is enabled".to_string(),
            ));
        }
        // Parse CIDR to validate format
        config
            .dns
            .fake_dns_pool
            .parse::<ipnet::IpNet>()
            .map_err(|e| {
                ConfigError::ValidationError(format!("Invalid FakeDNS pool CIDR: {}", e))
            })?;
    }

    // Validate Shadowsocks configs
    for ss in &config.proxy.shadowsocks {
        if ss.name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Shadowsocks proxy name is required".to_string(),
            ));
        }
        if ss.server.is_empty() {
            return Err(ConfigError::ValidationError(format!(
                "Shadowsocks proxy '{}' server address is required",
                ss.name
            )));
        }
        // Validate cipher method
        validate_ss_method(&ss.method).map_err(|e| {
            ConfigError::ValidationError(format!(
                "Shadowsocks proxy '{}' has invalid method: {}",
                ss.name, e
            ))
        })?;
    }

    // Validate proxy groups reference existing proxies
    let proxy_names: std::collections::HashSet<_> = config
        .proxy
        .shadowsocks
        .iter()
        .map(|s| s.name.as_str())
        .chain(["DIRECT", "REJECT"].iter().copied())
        .collect();

    for group in &config.proxy.group {
        for proxy_name in &group.proxies {
            if !proxy_names.contains(proxy_name.as_str()) {
                return Err(ConfigError::ValidationError(format!(
                    "Proxy group '{}' references unknown proxy '{}'",
                    group.name, proxy_name
                )));
            }
        }
    }

    // Validate schedules
    for (name, schedule) in &config.schedules {
        if schedule.days.is_empty() {
            return Err(ConfigError::ValidationError(format!(
                "Schedule '{}' has no days specified",
                name
            )));
        }
        // Validate time format
        parse_time(&schedule.start).map_err(|e| {
            ConfigError::ValidationError(format!(
                "Schedule '{}' has invalid start time: {}",
                name, e
            ))
        })?;
        parse_time(&schedule.end).map_err(|e| {
            ConfigError::ValidationError(format!(
                "Schedule '{}' has invalid end time: {}",
                name, e
            ))
        })?;
    }

    // Validate device schedules reference existing schedules
    for (device_name, device) in &config.devices {
        for schedule_name in &device.schedules {
            if !config.schedules.contains_key(schedule_name) {
                return Err(ConfigError::ValidationError(format!(
                    "Device '{}' references unknown schedule '{}'",
                    device_name, schedule_name
                )));
            }
        }
    }

    Ok(())
}

/// Validate Shadowsocks cipher method
fn validate_ss_method(method: &str) -> Result<(), String> {
    const VALID_METHODS: &[&str] = &[
        "chacha20-ietf-poly1305",
        "aes-256-gcm",
        "aes-128-gcm",
        "aes-256-cfb",
        "aes-128-cfb",
    ];

    if VALID_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(format!(
            "Unknown cipher method. Valid methods: {}",
            VALID_METHODS.join(", ")
        ))
    }
}

/// Parse time string (HH:MM format)
fn parse_time(time_str: &str) -> Result<chrono::NaiveTime, String> {
    chrono::NaiveTime::parse_from_str(time_str, "%H:%M")
        .map_err(|e| format!("Invalid time format (expected HH:MM): {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_minimal_config() {
        let config_str = r#"
[general]
log_level = "info"

[dns]
upstream = ["8.8.8.8:53"]

[transparent]

[proxy]

[rules]
rule_list = ["FINAL,DIRECT"]
"#;
        let config = load_config_from_str(config_str).unwrap();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.dns.upstream.len(), 1);
    }

    #[test]
    fn test_load_full_config() {
        let config_str = r#"
[general]
log_level = "debug"
data_dir = "/tmp/homeguard"

[dns]
listen = "0.0.0.0:5353"
upstream = ["8.8.8.8:53", "1.1.1.1:53"]
fake_dns = true
fake_dns_pool = "198.18.0.0/15"
cache_size = 5000

[transparent]
listen = "0.0.0.0:7893"
handle_udp = true

[[proxy.shadowsocks]]
name = "ss-hk"
server = "hk.example.com"
port = 8388
password = "secret"
method = "chacha20-ietf-poly1305"

[[proxy.group]]
name = "Proxy"
type = "select"
proxies = ["ss-hk", "DIRECT"]

[rules]
rules_dir = "./rules"
geoip_db = "./data/GeoLite2-Country.mmdb"
rule_list = [
    "DOMAIN-SUFFIX,google.com,Proxy",
    "FINAL,DIRECT",
]

[schedules.school_hours]
days = ["Mon", "Tue", "Wed", "Thu", "Fri"]
start = "08:00"
end = "16:00"

[devices.child_ipad]
ip = "192.168.0.100"
name = "Child iPad"
device_type = "child"
schedules = ["school_hours"]
extra_blocklists = ["games"]
"#;
        let config = load_config_from_str(config_str).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.proxy.shadowsocks.len(), 1);
        assert_eq!(config.proxy.shadowsocks[0].name, "ss-hk");
        assert!(config.schedules.contains_key("school_hours"));
        assert!(config.devices.contains_key("child_ipad"));
    }

    #[test]
    fn test_invalid_ss_method() {
        let config_str = r#"
[general]
[dns]
upstream = ["8.8.8.8:53"]
[transparent]
[[proxy.shadowsocks]]
name = "bad"
server = "example.com"
port = 8388
password = "secret"
method = "invalid-method"
[rules]
"#;
        let result = load_config_from_str(config_str);
        assert!(result.is_err());
    }
}
