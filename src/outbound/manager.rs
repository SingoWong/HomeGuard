//! Outbound connection manager
//!
//! Manages all outbound connections and proxy groups.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use super::group::{FallbackGroup, ProxyGroup, SelectGroup, UrlTestGroup};
use super::shadowsocks::ShadowsocksClient;
use super::{DirectOutbound, Outbound, RejectOutbound};
use crate::config::{ProxyConfig, ProxyGroupConfig, ProxyGroupType};
use crate::rule::Policy;

/// Default URL for health checks
const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

/// Default test interval (5 minutes)
const DEFAULT_TEST_INTERVAL: Duration = Duration::from_secs(300);

/// Outbound connection manager
///
/// Manages all outbound connections including:
/// - Built-in outbounds (DIRECT, REJECT)
/// - Shadowsocks proxies
/// - Proxy groups
pub struct OutboundManager {
    /// Direct outbound (always available)
    direct: Arc<DirectOutbound>,
    /// Reject outbound (always available)
    reject: Arc<RejectOutbound>,
    /// Shadowsocks proxies by name
    shadowsocks: HashMap<String, Arc<ShadowsocksClient>>,
    /// Proxy groups by name
    groups: HashMap<String, Arc<ProxyGroup>>,
    /// All outbounds (for lookup)
    all_outbounds: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    /// Create a new outbound manager from configuration
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let direct = Arc::new(DirectOutbound::new());
        let reject = Arc::new(RejectOutbound::new());

        // Create Shadowsocks clients
        let mut shadowsocks: HashMap<String, Arc<ShadowsocksClient>> = HashMap::new();
        for ss_config in &config.shadowsocks {
            match ShadowsocksClient::from_config(ss_config) {
                Ok(client) => {
                    info!("Created Shadowsocks proxy: {}", ss_config.name);
                    shadowsocks.insert(ss_config.name.clone(), Arc::new(client));
                }
                Err(e) => {
                    warn!(
                        "Failed to create Shadowsocks proxy '{}': {}",
                        ss_config.name, e
                    );
                }
            }
        }

        // Build all outbounds map (for group creation)
        let mut all_outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        all_outbounds.insert("DIRECT".to_string(), direct.clone() as Arc<dyn Outbound>);
        all_outbounds.insert("REJECT".to_string(), reject.clone() as Arc<dyn Outbound>);
        for (name, client) in &shadowsocks {
            all_outbounds.insert(name.clone(), client.clone() as Arc<dyn Outbound>);
        }

        // Create proxy groups
        let mut groups: HashMap<String, Arc<ProxyGroup>> = HashMap::new();
        for group_config in &config.group {
            match Self::create_group(group_config, &all_outbounds) {
                Ok(group) => {
                    info!(
                        "Created proxy group: {} ({:?})",
                        group_config.name, group_config.group_type
                    );
                    let group = Arc::new(group);
                    groups.insert(group_config.name.clone(), group.clone());
                    // Also add group to all_outbounds for nested groups
                    all_outbounds
                        .insert(group_config.name.clone(), group as Arc<dyn Outbound>);
                }
                Err(e) => {
                    warn!(
                        "Failed to create proxy group '{}': {}",
                        group_config.name, e
                    );
                }
            }
        }

        Ok(Self {
            direct,
            reject,
            shadowsocks,
            groups,
            all_outbounds,
        })
    }

    /// Create a proxy group from configuration
    fn create_group(
        config: &ProxyGroupConfig,
        outbounds: &HashMap<String, Arc<dyn Outbound>>,
    ) -> Result<ProxyGroup> {
        // Collect proxies
        let mut proxies: Vec<Arc<dyn Outbound>> = Vec::new();
        for proxy_name in &config.proxies {
            if let Some(outbound) = outbounds.get(proxy_name) {
                proxies.push(outbound.clone());
            } else {
                warn!(
                    "Proxy '{}' not found for group '{}'",
                    proxy_name, config.name
                );
            }
        }

        if proxies.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Group '{}' has no valid proxies", config.name),
            ));
        }

        let test_url = config
            .url
            .clone()
            .unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
        let test_interval = config
            .interval
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TEST_INTERVAL);

        match config.group_type {
            ProxyGroupType::Select => Ok(ProxyGroup::Select(Arc::new(SelectGroup::new(
                &config.name,
                proxies,
            )))),
            ProxyGroupType::UrlTest => Ok(ProxyGroup::UrlTest(Arc::new(UrlTestGroup::new(
                &config.name,
                proxies,
                test_url,
                test_interval,
            )))),
            ProxyGroupType::Fallback => Ok(ProxyGroup::Fallback(Arc::new(FallbackGroup::new(
                &config.name,
                proxies,
                test_url,
                test_interval,
            )))),
        }
    }

    /// Get an outbound by policy
    pub fn get(&self, policy: &Policy) -> Option<Arc<dyn Outbound>> {
        match policy {
            Policy::Direct => Some(self.direct.clone() as Arc<dyn Outbound>),
            Policy::Reject => Some(self.reject.clone() as Arc<dyn Outbound>),
            Policy::Proxy(name) => self.get_by_name(name),
        }
    }

    /// Get an outbound by name
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.all_outbounds.get(name).cloned()
    }

    /// Get the direct outbound
    pub fn direct(&self) -> &Arc<DirectOutbound> {
        &self.direct
    }

    /// Get the reject outbound
    pub fn reject(&self) -> &Arc<RejectOutbound> {
        &self.reject
    }

    /// Get a Shadowsocks client by name
    pub fn get_shadowsocks(&self, name: &str) -> Option<&Arc<ShadowsocksClient>> {
        self.shadowsocks.get(name)
    }

    /// Get a proxy group by name
    pub fn get_group(&self, name: &str) -> Option<&Arc<ProxyGroup>> {
        self.groups.get(name)
    }

    /// Get all outbound names
    pub fn outbound_names(&self) -> Vec<&str> {
        self.all_outbounds.keys().map(|s| s.as_str()).collect()
    }

    /// Get all group names
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(|s| s.as_str()).collect()
    }

    /// Select a proxy in a select group
    pub fn select_proxy(&self, group_name: &str, proxy_name: &str) -> Result<()> {
        let group = self.groups.get(group_name).ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("Group '{}' not found", group_name),
            )
        })?;

        match group.as_ref() {
            ProxyGroup::Select(g) => g.select_by_name(proxy_name),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Group '{}' is not a select group", group_name),
            )),
        }
    }

    /// Start background health checks for url-test and fallback groups
    pub fn start_health_checks(&self) {
        for (name, group) in &self.groups {
            match group.as_ref() {
                ProxyGroup::UrlTest(g) => {
                    debug!("Starting background test for url-test group '{}'", name);
                    g.clone().start_background_test();
                }
                ProxyGroup::Fallback(g) => {
                    debug!("Starting background check for fallback group '{}'", name);
                    g.clone().start_background_check();
                }
                _ => {}
            }
        }
    }
}

impl Default for OutboundManager {
    fn default() -> Self {
        Self::from_config(&ProxyConfig::default()).expect("Default config should be valid")
    }
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
            .field("shadowsocks_count", &self.shadowsocks.len())
            .field("group_count", &self.groups.len())
            .field("total_outbounds", &self.all_outbounds.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, ShadowsocksConfig};

    #[test]
    fn test_outbound_manager_default() {
        let manager = OutboundManager::default();
        assert!(manager.get(&Policy::Direct).is_some());
        assert!(manager.get(&Policy::Reject).is_some());
    }

    #[test]
    fn test_outbound_manager_direct_reject() {
        let config = ProxyConfig {
            shadowsocks: vec![],
            group: vec![],
        };
        let manager = OutboundManager::from_config(&config).unwrap();

        // Direct should always be available
        let direct = manager.get(&Policy::Direct).unwrap();
        assert_eq!(direct.name(), "DIRECT");

        // Reject should always be available
        let reject = manager.get(&Policy::Reject).unwrap();
        assert_eq!(reject.name(), "REJECT");
    }

    #[test]
    fn test_outbound_manager_with_shadowsocks() {
        let config = ProxyConfig {
            shadowsocks: vec![ShadowsocksConfig {
                name: "test-ss".to_string(),
                server: "127.0.0.1".to_string(),
                port: 8388,
                password: "password".to_string(),
                method: "chacha20-ietf-poly1305".to_string(),
            }],
            group: vec![],
        };
        let manager = OutboundManager::from_config(&config).unwrap();

        assert!(manager.get_shadowsocks("test-ss").is_some());
        assert!(manager.get_by_name("test-ss").is_some());
    }

    #[test]
    fn test_outbound_manager_with_groups() {
        let config = ProxyConfig {
            shadowsocks: vec![ShadowsocksConfig {
                name: "ss1".to_string(),
                server: "127.0.0.1".to_string(),
                port: 8388,
                password: "pass1".to_string(),
                method: "aes-256-gcm".to_string(),
            }],
            group: vec![ProxyGroupConfig {
                name: "Proxy".to_string(),
                group_type: ProxyGroupType::Select,
                proxies: vec!["DIRECT".to_string(), "ss1".to_string()],
                url: None,
                interval: None,
            }],
        };
        let manager = OutboundManager::from_config(&config).unwrap();

        assert!(manager.get_group("Proxy").is_some());
        assert!(manager.get_by_name("Proxy").is_some());

        // Test select
        assert!(manager.select_proxy("Proxy", "ss1").is_ok());
        assert!(manager.select_proxy("Proxy", "unknown").is_err());
        assert!(manager.select_proxy("unknown-group", "ss1").is_err());
    }

    #[test]
    fn test_outbound_manager_outbound_names() {
        let manager = OutboundManager::default();
        let names = manager.outbound_names();
        assert!(names.contains(&"DIRECT"));
        assert!(names.contains(&"REJECT"));
    }

    #[test]
    fn test_outbound_manager_debug() {
        let manager = OutboundManager::default();
        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("OutboundManager"));
    }
}
