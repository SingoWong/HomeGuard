//! Parental Controller
//!
//! Coordinates device identification, hard/grantable blocklist evaluation,
//! and grant lookups to answer one question: *should this domain request
//! from this source IP be blocked right now?*
//!
//! As of v2 this controller is **grant-based**, not schedule-based: each
//! child device declares two category lists — `hard_blocklists` (always
//! blocked) and `grantable_blocklists` (blocked by default, openable via an
//! active row in the SQLite `grants` table).

use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, info};

use super::blocklist::BlocklistManager;
use super::device::{DeviceInfo, DeviceManager};
use super::grant::GrantStore;
use crate::config::DeviceType;

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
    /// Device manager (IP → device record)
    device_manager: DeviceManager,

    /// Blocklist manager (file-backed; category → domain sets)
    blocklist_manager: BlocklistManager,

    /// Active grants store (SQLite-backed; (device, category) → expiry).
    /// Optional so tests and pre-v2 callers can construct a controller without
    /// a real DB; in production it's always Some after main.rs wires it up.
    grant_store: Option<Arc<GrantStore>>,

    /// Global categories blocked for ALL devices (including adults)
    global_categories: Vec<String>,

    /// Default policy for unknown devices
    default_policy: ParentalPolicy,

    /// Whether to log blocked requests
    #[allow(dead_code)]
    log_blocked: bool,
}

impl ParentalController {
    /// Construct with explicit dependencies. main.rs uses this after loading
    /// devices from SQLite and opening the GrantStore.
    pub fn new(
        device_manager: DeviceManager,
        blocklist_manager: BlocklistManager,
        grant_store: Option<Arc<GrantStore>>,
        global_categories: Vec<String>,
        default_policy: ParentalPolicy,
    ) -> Self {
        info!(
            "ParentalController initialized: {} devices, {} global domains, grants={}",
            device_manager.device_ids().len(),
            blocklist_manager.global_count(),
            if grant_store.is_some() { "enabled" } else { "disabled" }
        );
        Self {
            device_manager,
            blocklist_manager,
            grant_store,
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

    /// Check if a domain access should be allowed for a device.
    ///
    /// Order of evaluation (first match wins):
    /// 1. Global blocklist (always-block list applied to everyone)
    /// 2. Global categories (named blocklists applied to everyone)
    /// 3. Unknown device → default policy
    /// 4. Adult device → always allow
    /// 5. Any hard_blocklists category matches → block (no grant can override)
    /// 6. Any grantable_blocklists category matches:
    ///    - active grant for (device, category) → allow
    ///    - no grant → block
    /// 7. Otherwise → allow
    pub fn check_access(&self, source_ip: IpAddr, domain: &str) -> ParentalDecision {
        let domain = domain.trim_end_matches('.').to_lowercase();

        // 1. Global blocklist
        if self.blocklist_manager.is_blocked_globally(&domain) {
            return ParentalDecision::block("Global blocklist");
        }

        // 2. Global categories
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

        // 3. Identify device
        let device = match self.device_manager.get_device_by_ip(source_ip) {
            Some(d) => d,
            None => return self.apply_default_policy(&domain),
        };
        let device_id = self
            .device_manager
            .get_device_id_by_ip(source_ip)
            .unwrap_or("");

        // 4. Adults bypass device-specific controls
        if device.device_type == DeviceType::Adult {
            debug!("Adult device {} - allowing {}", source_ip, domain);
            return ParentalDecision::allow();
        }

        // 5. Hard blocklists — find the category that hit (if any) and block
        for category in &device.hard_blocklists {
            if self.blocklist_manager.is_in_category(&domain, category) {
                return ParentalDecision::block(format!("hard:{}", category));
            }
        }

        // 6. Grantable blocklists — block by default; active grant unblocks
        for category in &device.grantable_blocklists {
            if self.blocklist_manager.is_in_category(&domain, category) {
                let granted = self
                    .grant_store
                    .as_ref()
                    .map(|gs| gs.has_active(device_id, category))
                    .unwrap_or(false);
                if granted {
                    debug!(
                        "Active grant unblocks {} for device {} (category {})",
                        domain, device_id, category
                    );
                    return ParentalDecision::allow();
                }
                return ParentalDecision::block(format!("grantable:{}", category));
            }
        }

        // 7. Default allow
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
            blocklist_manager: BlocklistManager::new(),
            grant_store: None,
            global_categories: vec![],
            default_policy: ParentalPolicy::Allow,
            log_blocked: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeviceConfig;
    use crate::storage::{ConfigStore, Database, NewDevice, NewGrant};
    use parking_lot::Mutex;
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
                hard_blocklists: vec!["porn".to_string()],
                grantable_blocklists: vec!["games".to_string()],
                extra_blocklists: vec![],
            },
        );

        devices.insert(
            "adult_device".to_string(),
            DeviceConfig {
                ip: Some("192.168.0.50".to_string()),
                mac: None,
                name: "Adult's Device".to_string(),
                device_type: DeviceType::Adult,
                hard_blocklists: vec![],
                grantable_blocklists: vec![],
                extra_blocklists: vec![],
            },
        );

        DeviceManager::from_config(&devices)
    }

    fn create_test_blocklist_manager() -> BlocklistManager {
        let mut manager = BlocklistManager::new();
        manager.add_global("malware.com");
        manager.add_global("phishing.org");
        manager.add_to_category("porn1.com", "porn");
        manager.add_to_category("game1.com", "games");
        manager.add_to_category("game2.org", "games");
        manager.add_to_category("social1.com", "social");
        manager
    }

    fn make_grant_store_with_device(device_id: &str) -> (Arc<GrantStore>, Arc<Mutex<ConfigStore>>) {
        let db = Database::open_in_memory().unwrap();
        let store = ConfigStore::new(db);
        // Seed the device so FK on grants resolves
        store.insert_device(&NewDevice {
            id: device_id.to_string(),
            name: device_id.to_string(),
            ip: Some("192.168.0.100".to_string()),
            mac: None,
            device_type: "child".to_string(),
        }).unwrap();
        let store = Arc::new(Mutex::new(store));
        let gs = GrantStore::open(store.clone()).unwrap();
        (gs, store)
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
    fn test_global_blocklist_blocks_everyone() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();
        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();

        assert!(controller.check_access(child_ip, "malware.com").is_blocked());
        assert!(controller.check_access(adult_ip, "malware.com").is_blocked());
        assert!(controller.check_access(unknown_ip, "malware.com").is_blocked());
    }

    #[test]
    fn test_hard_blocklist_always_blocks_child_even_with_grant() {
        let (gs, store) = make_grant_store_with_device("child_device");

        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            Some(gs.clone()),
            vec![],
            ParentalPolicy::Allow,
        );

        // Issue an active grant on `porn` (hard category) — should be ignored.
        store.lock().insert_grant(&NewGrant {
            device_id: "child_device".to_string(),
            category: "porn".to_string(),
            granted_at: None,
            expires_at: "9999-12-31 23:59:59".to_string(),
            note: None,
        }).unwrap();
        gs.refresh().unwrap();

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        assert!(controller.check_access(child_ip, "porn1.com").is_blocked());
        assert_eq!(
            controller.check_access(child_ip, "porn1.com").reason(),
            Some("hard:porn")
        );
    }

    #[test]
    fn test_grantable_blocked_by_default_allowed_with_active_grant() {
        let (gs, store) = make_grant_store_with_device("child_device");

        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            Some(gs.clone()),
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();

        // Default state: games is grantable -> blocked
        assert!(controller.check_access(child_ip, "game1.com").is_blocked());
        assert_eq!(
            controller.check_access(child_ip, "game1.com").reason(),
            Some("grantable:games")
        );

        // Issue grant on games, refresh
        let id = store.lock().insert_grant(&NewGrant {
            device_id: "child_device".to_string(),
            category: "games".to_string(),
            granted_at: None,
            expires_at: "9999-12-31 23:59:59".to_string(),
            note: None,
        }).unwrap();
        gs.refresh().unwrap();

        // Now allowed
        assert!(controller.check_access(child_ip, "game1.com").is_allowed());
        assert!(controller.check_access(child_ip, "game2.org").is_allowed());

        // Other grantable categories not in this grant remain blocked
        // (social isn't even in child_device's grantable_blocklists, but
        // social1.com isn't in games either; either way blocked or allowed
        // by absence — controller falls through to allow since social isn't
        // in child's grantable list at all)
        assert!(controller.check_access(child_ip, "social1.com").is_allowed());

        // Revoke
        store.lock().revoke_grant(id).unwrap();
        gs.refresh().unwrap();
        assert!(controller.check_access(child_ip, "game1.com").is_blocked());
    }

    #[test]
    fn test_adult_device_bypasses_all_device_rules() {
        let (gs, _store) = make_grant_store_with_device("child_device");

        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            Some(gs),
            vec![],
            ParentalPolicy::Allow,
        );

        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();
        // Adult sees no hard/grantable enforcement
        assert!(controller.check_access(adult_ip, "porn1.com").is_allowed());
        assert!(controller.check_access(adult_ip, "game1.com").is_allowed());
    }

    #[test]
    fn test_unknown_device_default_allow() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::Allow,
        );

        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();
        assert!(controller.check_access(unknown_ip, "game1.com").is_allowed());
        assert!(controller.check_access(unknown_ip, "anything.com").is_allowed());
        // But global blocklist still applies
        assert!(controller.check_access(unknown_ip, "malware.com").is_blocked());
    }

    #[test]
    fn test_unknown_device_default_block_all() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::BlockAll,
        );

        let unknown_ip: IpAddr = "192.168.0.99".parse().unwrap();
        assert!(controller.check_access(unknown_ip, "game1.com").is_blocked());
        assert!(controller.check_access(unknown_ip, "anything.com").is_blocked());
    }

    #[test]
    fn test_global_categories_block_everyone() {
        let mut controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::Allow,
        );
        controller.set_global_categories(vec!["social".to_string()]);

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let adult_ip: IpAddr = "192.168.0.50".parse().unwrap();
        assert!(controller.check_access(child_ip, "social1.com").is_blocked());
        assert!(controller.check_access(adult_ip, "social1.com").is_blocked());
    }

    #[test]
    fn test_case_and_trailing_dot_normalization() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        assert!(controller.check_access(child_ip, "GAME1.COM").is_blocked());
        assert!(controller.check_access(child_ip, "Game1.Com.").is_blocked());
        assert!(controller.check_access(child_ip, "MALWARE.COM.").is_blocked());
    }

    #[test]
    fn test_device_info() {
        let controller = ParentalController::new(
            create_test_device_manager(),
            create_test_blocklist_manager(),
            None,
            vec![],
            ParentalPolicy::Allow,
        );

        let child_ip: IpAddr = "192.168.0.100".parse().unwrap();
        let info = controller.get_device_info(child_ip).unwrap();
        assert_eq!(info.id, "child_device");
        assert_eq!(info.name, "Child's Device");
        assert_eq!(info.device_type, DeviceType::Child);
    }
}
