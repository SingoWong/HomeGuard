//! Device Manager
//!
//! Handles device identification and lookup by IP address.

use std::collections::HashMap;
use std::net::IpAddr;

use tracing::{debug, warn};

use crate::config::{DeviceConfig, DeviceType};

/// Device information for logging and display
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Device ID (config key)
    pub id: String,
    /// Device name
    pub name: String,
    /// Device type
    pub device_type: DeviceType,
    /// IP address (if configured)
    pub ip: Option<IpAddr>,
}

/// Manages device identification and lookup
pub struct DeviceManager {
    /// Device configs keyed by device ID
    devices: HashMap<String, DeviceConfig>,

    /// IP -> Device ID mapping for quick lookup
    ip_to_device: HashMap<IpAddr, String>,
}

impl DeviceManager {
    /// Create from config
    pub fn from_config(devices: &HashMap<String, DeviceConfig>) -> Self {
        let mut ip_to_device = HashMap::new();

        for (id, config) in devices {
            if let Some(ref ip_str) = config.ip {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip) => {
                        debug!("Registered device '{}' ({}) at IP {}", config.name, id, ip);
                        ip_to_device.insert(ip, id.clone());
                    }
                    Err(e) => {
                        warn!(
                            "Invalid IP address '{}' for device '{}': {}",
                            ip_str, id, e
                        );
                    }
                }
            }
        }

        debug!(
            "DeviceManager initialized with {} devices ({} with IP)",
            devices.len(),
            ip_to_device.len()
        );

        Self {
            devices: devices.clone(),
            ip_to_device,
        }
    }

    /// Get device config by source IP
    pub fn get_device_by_ip(&self, ip: IpAddr) -> Option<&DeviceConfig> {
        self.ip_to_device
            .get(&ip)
            .and_then(|id| self.devices.get(id))
    }

    /// Get device ID by source IP
    pub fn get_device_id_by_ip(&self, ip: IpAddr) -> Option<&str> {
        self.ip_to_device.get(&ip).map(|s| s.as_str())
    }

    /// Get device config by ID
    pub fn get_device(&self, id: &str) -> Option<&DeviceConfig> {
        self.devices.get(id)
    }

    /// Get device type by IP
    pub fn get_device_type(&self, ip: IpAddr) -> DeviceType {
        self.get_device_by_ip(ip)
            .map(|d| d.device_type.clone())
            .unwrap_or_default()
    }

    /// Check if device is a child device
    pub fn is_child_device(&self, ip: IpAddr) -> bool {
        self.get_device_type(ip) == DeviceType::Child
    }

    /// Check if device is an adult device
    pub fn is_adult_device(&self, ip: IpAddr) -> bool {
        self.get_device_type(ip) == DeviceType::Adult
    }

    /// Get device info for logging
    pub fn get_device_info(&self, ip: IpAddr) -> Option<DeviceInfo> {
        let id = self.ip_to_device.get(&ip)?;
        let config = self.devices.get(id)?;

        Some(DeviceInfo {
            id: id.clone(),
            name: config.name.clone(),
            device_type: config.device_type.clone(),
            ip: Some(ip),
        })
    }

    /// Get all device IDs
    pub fn device_ids(&self) -> Vec<&str> {
        self.devices.keys().map(|s| s.as_str()).collect()
    }

    /// Get hard-block categories for a device by IP. These are always blocked
    /// and can never be unlocked by a grant.
    pub fn get_device_hard_blocklists(&self, ip: IpAddr) -> Vec<String> {
        self.get_device_by_ip(ip)
            .map(|d| d.hard_blocklists.clone())
            .unwrap_or_default()
    }

    /// Get grantable-block categories for a device by IP. These are blocked by
    /// default but can be temporarily unlocked by an active grant.
    pub fn get_device_grantable_blocklists(&self, ip: IpAddr) -> Vec<String> {
        self.get_device_by_ip(ip)
            .map(|d| d.grantable_blocklists.clone())
            .unwrap_or_default()
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self {
            devices: HashMap::new(),
            ip_to_device: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_devices() -> HashMap<String, DeviceConfig> {
        let mut devices = HashMap::new();

        devices.insert(
            "child_ipad".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.100".to_string()),
                mac: None,
                name: "Child's iPad".to_string(),
                device_type: DeviceType::Child,
                hard_blocklists: vec!["porn".to_string()],
                grantable_blocklists: vec!["games".to_string(), "social".to_string()],
                extra_blocklists: vec![],
            },
        );

        devices.insert(
            "parent_phone".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.50".to_string()),
                mac: None,
                name: "Parent's Phone".to_string(),
                device_type: DeviceType::Adult,
                hard_blocklists: vec![],
                grantable_blocklists: vec![],
                extra_blocklists: vec![],
            },
        );

        devices.insert(
            "smart_tv".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.200".to_string()),
                mac: None,
                name: "Living Room TV".to_string(),
                device_type: DeviceType::IoT,
                hard_blocklists: vec![],
                grantable_blocklists: vec![],
                extra_blocklists: vec![],
            },
        );

        devices
    }

    #[test]
    fn test_device_manager_from_config() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        assert_eq!(manager.device_ids().len(), 3);
    }

    #[test]
    fn test_get_device_by_ip() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let device = manager.get_device_by_ip(child_ip);

        assert!(device.is_some());
        assert_eq!(device.unwrap().name, "Child's iPad");
    }

    #[test]
    fn test_get_device_by_ip_not_found() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();
        assert!(manager.get_device_by_ip(unknown_ip).is_none());
    }

    #[test]
    fn test_device_type() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let parent_ip: IpAddr = "192.168.0.50".parse().unwrap();
        let tv_ip: IpAddr = "192.168.0.200".parse().unwrap();
        let unknown_ip: IpAddr = "192.168.0.1".parse().unwrap();

        assert_eq!(manager.get_device_type(child_ip), DeviceType::Child);
        assert_eq!(manager.get_device_type(parent_ip), DeviceType::Adult);
        assert_eq!(manager.get_device_type(tv_ip), DeviceType::IoT);
        assert_eq!(manager.get_device_type(unknown_ip), DeviceType::Unknown);
    }

    #[test]
    fn test_is_child_device() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let parent_ip: IpAddr = "192.168.0.50".parse().unwrap();

        assert!(manager.is_child_device(child_ip));
        assert!(!manager.is_child_device(parent_ip));
    }

    #[test]
    fn test_get_device_hard_blocklists() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        assert_eq!(
            manager.get_device_hard_blocklists(child_ip),
            vec!["porn".to_string()]
        );
    }

    #[test]
    fn test_get_device_grantable_blocklists() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        assert_eq!(
            manager.get_device_grantable_blocklists(child_ip),
            vec!["games".to_string(), "social".to_string()]
        );
    }

    #[test]
    fn test_get_device_info() {
        let devices = create_test_devices();
        let manager = DeviceManager::from_config(&devices);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let info = manager.get_device_info(child_ip);

        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.id, "child_ipad");
        assert_eq!(info.name, "Child's iPad");
        assert_eq!(info.device_type, DeviceType::Child);
    }

    #[test]
    fn test_invalid_ip_in_config() {
        let mut devices = HashMap::new();
        devices.insert(
            "bad_device".to_string(),
            DeviceConfig {
                ip: Some("not-an-ip".to_string()),
                mac: None,
                name: "Bad Device".to_string(),
                device_type: DeviceType::Unknown,
                hard_blocklists: vec![],
                grantable_blocklists: vec![],
                extra_blocklists: vec![],
            },
        );

        let manager = DeviceManager::from_config(&devices);

        // Device exists but can't be looked up by IP
        assert!(manager.get_device("bad_device").is_some());
        assert!(manager.ip_to_device.is_empty());
    }
}
