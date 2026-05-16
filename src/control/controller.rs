//! Parental Controller
//!
//! Main controller that coordinates device management, schedule evaluation,
//! and blocklist checking for parental control.

use std::net::IpAddr;
use std::path::Path;

use tracing::{debug, info};

use super::blocklist::BlocklistManager;
use super::device::{DeviceInfo, DeviceManager};
use super::schedule::ScheduleManager;
use crate::config::{Config, DeviceType};
use crate::error::Result;

/// Default policy for unknown devices
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ParentalPolicy {
    /// Allow all traffic (no parental control)
    #[default]
    Allow,
    /// Block only if domain is in global blocklist
    BlockIfListed,
    /// Block all traffic (total internet cutoff)
    BlockAll,
}

/// Access decision result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentalDecision {
    /// Allow the request to proceed
    Allow,
    /// Block the request
    Block {
        /// Reason for blocking
        reason: String,
    },
}

impl ParentalDecision {
    /// Create an allow decision
    pub fn allow() -> Self {
        ParentalDecision::Allow
    }

    /// Create a block decision
    pub fn block(reason: impl Into<String>) -> Self {
        ParentalDecision::Block {
            reason: reason.into(),
        }
    }

    /// Check if this is an allow decision
    pub fn is_allowed(&self) -> bool {
        matches!(self, ParentalDecision::Allow)
    }

    /// Check if this is a block decision
    pub fn is_blocked(&self) -> bool {
        matches!(self, ParentalDecision::Block { .. })
    }

    /// Get the block reason, if blocked
    pub fn reason(&self) -> Option<&str> {
        match self {
            ParentalDecision::Block { reason } => Some(reason),
            ParentalDecision::Allow => None,
        }
    }
}

/// Main parental control controller
pub struct ParentalController {
    /// Device manager
    device_manager: DeviceManager,

    /// Schedule manager
    schedule_manager: ScheduleManager,

    /// Blocklist manager
    blocklist_manager: BlocklistManager,

    /// Global categories to block for ALL devices (including adults)
    global_categories: Vec<String>,

    /// Default policy for unknown devices
    default_policy: ParentalPolicy,

    /// Whether to log blocked requests
    #[allow(dead_code)]
    log_blocked: bool,
}

impl ParentalController {
    /// Create from configuration
    pub fn from_config(config: &Config, blocklist_dir: Option<&Path>) -> Result<Self> {
        // Initialize managers
        let device_manager = DeviceManager::from_config(&config.devices);
        let schedule_manager = ScheduleManager::from_config(&config.schedules);

        // Load blocklists
        let mut blocklist_manager = BlocklistManager::new();
        if let Some(dir) = blocklist_dir {
            blocklist_manager.load_directory(dir)?;
        }

        info!(
            "ParentalController initialized: {} devices, {} schedules, {} global domains",
            config.devices.len(),
            config.schedules.len(),
            blocklist_manager.global_count()
        );

        Ok(Self {
            device_manager,
            schedule_manager,
            blocklist_manager,
            global_categories: vec![], // Will be configurable in future
            default_policy: ParentalPolicy::Allow,
            log_blocked: true,
        })
    }

    /// Create with custom settings
    pub fn new(
        device_manager: DeviceManager,
        schedule_manager: ScheduleManager,
        blocklist_manager: BlocklistManager,
        global_categories: Vec<String>,
        default_policy: ParentalPolicy,
    ) -> Self {
        Self {
            device_manager,
            schedule_manager,
            blocklist_manager,
            global_categories,
            default_policy,
            log_blocked: true,
        }
    }

    /// Set global categories (blocked for ALL devices)
    pub fn set_global_categories(&mut self, categories: Vec<String>) {
        self.global_categories = categories;
    }

    /// Set default policy for unknown devices
    pub fn set_default_policy(&mut self, policy: ParentalPolicy) {
        self.default_policy = policy;
    }

    /// Check if a domain access should be allowed for a device
    pub fn check_access(&self, source_ip: IpAddr, domain: &str) -> ParentalDecision {
        let domain = domain.trim_end_matches('.').to_lowercase();

        // Step 1: Check global blocklist (applies to ALL traffic)
        if self.blocklist_manager.is_blocked_globally(&domain) {
            return ParentalDecision::block("Global blocklist");
        }

        // Step 2: Check global categories (applies to ALL devices including adults)
        if !self.global_categories.is_empty()
            && self
                .blocklist_manager
                .is_in_any_category(&domain, &self.global_categories)
        {
            return ParentalDecision::block(format!(
                "Global category: {}",
                self.global_categories.join(", ")
            ));
        }

        // Step 3: Get device info
        let device = match self.device_manager.get_device_by_ip(source_ip) {
            Some(d) => d,
            None => {
                // Unknown device - apply default policy
                return self.apply_default_policy(&domain);
            }
        };

        // Step 4: Adults bypass device-specific controls
        if device.device_type == DeviceType::Adult {
            debug!("Adult device {} - allowing {}", source_ip, domain);
            return ParentalDecision::allow();
        }

        // Step 5: Check if any schedule is active for this device
        let schedules_active = if device.schedules.is_empty() {
            // No schedules configured - device-specific rules always apply
            true
        } else {
            // Check if ANY configured schedule is active
            self.schedule_manager.any_active(&device.schedules)
        };

        if schedules_active {
            // Step 6: Check device-specific blocklists
            if !device.extra_blocklists.is_empty()
                && self
                    .blocklist_manager
                    .is_in_any_category(&domain, &device.extra_blocklists)
            {
                let active_schedules: Vec<&str> = device
                    .schedules
                    .iter()
                    .filter(|s| self.schedule_manager.is_active(s))
                    .map(|s| s.as_str())
                    .collect();

                let reason = if active_schedules.is_empty() {
                    format!("Device blocklist: {}", device.extra_blocklists.join(", "))
                } else {
                    format!(
                        "Device blocklist during {}: {}",
                        active_schedules.join(", "),
                        device.extra_blocklists.join(", ")
                    )
                };

                return ParentalDecision::block(reason);
            }
        }

        // Allow by default
        ParentalDecision::allow()
    }

    /// Apply default policy for unknown devices
    fn apply_default_policy(&self, _domain: &str) -> ParentalDecision {
        match self.default_policy {
            ParentalPolicy::Allow => ParentalDecision::allow(),
            ParentalPolicy::BlockIfListed => {
                // Already checked global blocklist above, so allow
                ParentalDecision::allow()
            }
            ParentalPolicy::BlockAll => {
                ParentalDecision::block("Unknown device - blocked by default policy")
            }
        }
    }

    /// Get device info for logging
    pub fn get_device_info(&self, ip: IpAddr) -> Option<DeviceInfo> {
        self.device_manager.get_device_info(ip)
    }

    /// Get reference to device manager
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Get reference to schedule manager
    pub fn schedule_manager(&self) -> &ScheduleManager {
        &self.schedule_manager
    }

    /// Get reference to blocklist manager
    pub fn blocklist_manager(&self) -> &BlocklistManager {
        &self.blocklist_manager
    }

    /// Get mutable reference to blocklist manager
    pub fn blocklist_manager_mut(&mut self) -> &mut BlocklistManager {
        &mut self.blocklist_manager
    }
}

impl Default for ParentalController {
    fn default() -> Self {
        Self {
            device_manager: DeviceManager::default(),
            schedule_manager: ScheduleManager::from_config(&std::collections::HashMap::new()),
            blocklist_manager: BlocklistManager::new(),
            global_categories: vec![],
            default_policy: ParentalPolicy::Allow,
            log_blocked: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, Schedule, Weekday};
    use std::collections::HashMap;

    fn create_test_device_manager() -> DeviceManager {
        let mut devices = HashMap::new();

        devices.insert(
            "child_device".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.100".to_string()),
                mac: None,
                name: "Child's Device".to_string(),
                device_type: DeviceType::Child,
                schedules: vec!["always".to_string()],
                extra_blocklists: vec!["games".to_string()],
            },
        );

        devices.insert(
            "adult_device".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.50".to_string()),
                mac: None,
                name: "Adult's Device".to_string(),
                device_type: DeviceType::Adult,
                schedules: vec![],
                extra_blocklists: vec![],
            },
        );

        DeviceManager::from_config(&devices)
    }

    fn create_test_schedule_manager() -> ScheduleManager {
        let mut schedules = HashMap::new();

        // Schedule that's always active
        schedules.insert(
            "always".to_string(),
            Schedule {
                days: vec![
                    Weekday::Mon,
                    Weekday::Tue,
                    Weekday::Wed,
                    Weekday::Thu,
                    Weekday::Fri,
                    Weekday::Sat,
                    Weekday::Sun,
                ],
                start: "00:00".to_string(),
                end: "23:59".to_string(),
            },
        );

        ScheduleManager::from_config(&schedules)
    }

    fn create_test_blocklist_manager() -> BlocklistManager {
        let mut manager = BlocklistManager::new();

        // Global blocklist
        manager.add_global("malware.com");
        manager.add_global("phishing.org");

        // Category blocklists
        manager.add_to_category("game1.com", "games");
        manager.add_to_category("game2.org", "games");
        manager.add_to_category("social1.com", "social");

        manager
    }

    #[test]
    fn test_parental_decision() {
        let allow = ParentalDecision::allow();
        assert!(allow.is_allowed());
        assert!(!allow.is_blocked());
        assert!(allow.reason().is_none());

        let block = ParentalDecision::block("Test reason");
        assert!(!block.is_allowed());
        assert!(block.is_blocked());
        assert_eq!(block.reason(), Some("Test reason"));
    }

    #[test]
    fn test_global_blocklist() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();
        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();

        // Global blocklist should block for ALL devices
        assert!(controller.check_access(child_ip, "malware.com").is_blocked());
        assert!(controller.check_access(adult_ip, "malware.com").is_blocked());
        assert!(controller
            .check_access(unknown_ip, "malware.com")
            .is_blocked());
    }

    #[test]
    fn test_device_specific_blocklist() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();

        // Child device should have games blocked
        assert!(controller.check_access(child_ip, "game1.com").is_blocked());
        assert!(controller.check_access(child_ip, "game2.org").is_blocked());

        // Adult device should NOT have games blocked
        assert!(controller.check_access(adult_ip, "game1.com").is_allowed());
        assert!(controller.check_access(adult_ip, "game2.org").is_allowed());

        // Child should have access to unblocked sites
        assert!(controller.check_access(child_ip, "allowed.com").is_allowed());
    }

    #[test]
    fn test_unknown_device_default_allow() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();

        // Unknown device with Allow policy - should allow non-global-blocked sites
        assert!(controller.check_access(unknown_ip, "game1.com").is_allowed());
        assert!(controller.check_access(unknown_ip, "anything.com").is_allowed());

        // But global blocklist still applies
        assert!(controller
            .check_access(unknown_ip, "malware.com")
            .is_blocked());
    }

    #[test]
    fn test_unknown_device_default_block_all() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::BlockAll,
        );

        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();

        // Unknown device with BlockAll policy - should block everything
        assert!(controller.check_access(unknown_ip, "game1.com").is_blocked());
        assert!(controller
            .check_access(unknown_ip, "anything.com")
            .is_blocked());
    }

    #[test]
    fn test_global_categories() {
        let mut controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        // Set social as global category (blocked for everyone)
        controller.set_global_categories(vec!["social".to_string()]);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();

        // Social should be blocked for both child and adult
        assert!(controller
            .check_access(child_ip, "social1.com")
            .is_blocked());
        assert!(controller
            .check_access(adult_ip, "social1.com")
            .is_blocked());
    }

    #[test]
    fn test_case_insensitivity() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();

        // Domain matching should be case-insensitive
        assert!(controller.check_access(child_ip, "GAME1.COM").is_blocked());
        assert!(controller.check_access(child_ip, "Game1.Com").is_blocked());
        assert!(controller.check_access(child_ip, "MALWARE.COM").is_blocked());
    }

    #[test]
    fn test_trailing_dot_removal() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();

        // Trailing dot (FQDN) should be handled
        assert!(controller.check_access(child_ip, "game1.com.").is_blocked());
        assert!(controller
            .check_access(child_ip, "malware.com.")
            .is_blocked());
    }

    #[test]
    fn test_device_info() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_schedule_manager(),
            create_test_blocklist_manager(),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let info = controller.get_device_info(child_ip);

        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.id, "child_device");
        assert_eq!(info.name, "Child's Device");
        assert_eq!(info.device_type, DeviceType::Child);
    }
}
