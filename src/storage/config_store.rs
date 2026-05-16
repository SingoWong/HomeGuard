//! Configuration store
//!
//! CRUD operations for configuration data stored in SQLite.

use rusqlite::params;
use serde_json;
use tracing::debug;

use super::models::*;
use super::sqlite::Database;
use crate::error::{HomeGuardError, Result};

/// Configuration store for SQLite operations
pub struct ConfigStore {
    db: Database,
}

impl ConfigStore {
    /// Create a new config store with database
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get database reference
    pub fn db(&self) -> &Database {
        &self.db
    }

    // ==================== Device Operations ====================

    /// Insert a new device
    pub fn insert_device(&self, device: &NewDevice) -> Result<()> {
        self.db.conn().execute(
            "INSERT INTO devices (id, name, ip, mac, device_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device.id,
                device.name,
                device.ip,
                device.mac,
                device.device_type
            ],
        )?;
        debug!("Inserted device: {}", device.id);
        Ok(())
    }

    /// Get device by ID
    pub fn get_device(&self, id: &str) -> Result<Option<DeviceRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, ip, mac, device_type, created_at, updated_at FROM devices WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| {
            Ok(DeviceRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                ip: row.get(2)?,
                mac: row.get(3)?,
                device_type: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(device) => Ok(Some(device)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// Get device by IP
    pub fn get_device_by_ip(&self, ip: &str) -> Result<Option<DeviceRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, ip, mac, device_type, created_at, updated_at FROM devices WHERE ip = ?1",
        )?;

        let result = stmt.query_row(params![ip], |row| {
            Ok(DeviceRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                ip: row.get(2)?,
                mac: row.get(3)?,
                device_type: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(device) => Ok(Some(device)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// List all devices
    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, ip, mac, device_type, created_at, updated_at FROM devices ORDER BY name",
        )?;

        let devices = stmt
            .query_map([], |row| {
                Ok(DeviceRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    ip: row.get(2)?,
                    mac: row.get(3)?,
                    device_type: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(devices)
    }

    /// Update device
    pub fn update_device(&self, id: &str, name: &str, ip: Option<&str>, mac: Option<&str>, device_type: &str) -> Result<bool> {
        let rows = self.db.conn().execute(
            "UPDATE devices SET name = ?2, ip = ?3, mac = ?4, device_type = ?5, updated_at = datetime('now') WHERE id = ?1",
            params![id, name, ip, mac, device_type],
        )?;
        Ok(rows > 0)
    }

    /// Delete device
    pub fn delete_device(&self, id: &str) -> Result<bool> {
        let rows = self.db.conn().execute("DELETE FROM devices WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    // ==================== Schedule Operations ====================

    /// Insert a new schedule
    pub fn insert_schedule(&self, schedule: &NewSchedule) -> Result<i64> {
        let days_json = serde_json::to_string(&schedule.days)
            .map_err(|e| HomeGuardError::Storage(e.to_string()))?;

        self.db.conn().execute(
            "INSERT INTO schedules (name, days, start_time, end_time) VALUES (?1, ?2, ?3, ?4)",
            params![schedule.name, days_json, schedule.start_time, schedule.end_time],
        )?;

        let id = self.db.conn().last_insert_rowid();
        debug!("Inserted schedule: {} (id={})", schedule.name, id);
        Ok(id)
    }

    /// Get schedule by ID
    pub fn get_schedule(&self, id: i64) -> Result<Option<ScheduleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, days, start_time, end_time, created_at, updated_at FROM schedules WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| {
            Ok(ScheduleRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                days: row.get(2)?,
                start_time: row.get(3)?,
                end_time: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(schedule) => Ok(Some(schedule)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// Get schedule by name
    pub fn get_schedule_by_name(&self, name: &str) -> Result<Option<ScheduleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, days, start_time, end_time, created_at, updated_at FROM schedules WHERE name = ?1",
        )?;

        let result = stmt.query_row(params![name], |row| {
            Ok(ScheduleRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                days: row.get(2)?,
                start_time: row.get(3)?,
                end_time: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(schedule) => Ok(Some(schedule)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// List all schedules
    pub fn list_schedules(&self) -> Result<Vec<ScheduleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, days, start_time, end_time, created_at, updated_at FROM schedules ORDER BY name",
        )?;

        let schedules = stmt
            .query_map([], |row| {
                Ok(ScheduleRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    days: row.get(2)?,
                    start_time: row.get(3)?,
                    end_time: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(schedules)
    }

    /// Delete schedule
    pub fn delete_schedule(&self, id: i64) -> Result<bool> {
        let rows = self.db.conn().execute("DELETE FROM schedules WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    // ==================== Device-Schedule Association ====================

    /// Add schedule to device
    pub fn add_device_schedule(&self, device_id: &str, schedule_id: i64) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR IGNORE INTO device_schedules (device_id, schedule_id) VALUES (?1, ?2)",
            params![device_id, schedule_id],
        )?;
        Ok(())
    }

    /// Remove schedule from device
    pub fn remove_device_schedule(&self, device_id: &str, schedule_id: i64) -> Result<bool> {
        let rows = self.db.conn().execute(
            "DELETE FROM device_schedules WHERE device_id = ?1 AND schedule_id = ?2",
            params![device_id, schedule_id],
        )?;
        Ok(rows > 0)
    }

    /// Get schedules for device
    pub fn get_device_schedules(&self, device_id: &str) -> Result<Vec<ScheduleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT s.id, s.name, s.days, s.start_time, s.end_time, s.created_at, s.updated_at
             FROM schedules s
             JOIN device_schedules ds ON s.id = ds.schedule_id
             WHERE ds.device_id = ?1
             ORDER BY s.name",
        )?;

        let schedules = stmt
            .query_map(params![device_id], |row| {
                Ok(ScheduleRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    days: row.get(2)?,
                    start_time: row.get(3)?,
                    end_time: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(schedules)
    }

    // ==================== Proxy Server Operations ====================

    /// Insert a new proxy server
    pub fn insert_proxy_server(&self, proxy: &NewProxyServer) -> Result<i64> {
        self.db.conn().execute(
            "INSERT INTO proxy_servers (name, server, port, password, method) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![proxy.name, proxy.server, proxy.port, proxy.password, proxy.method],
        )?;

        let id = self.db.conn().last_insert_rowid();
        debug!("Inserted proxy server: {} (id={})", proxy.name, id);
        Ok(id)
    }

    /// Get proxy server by ID
    pub fn get_proxy_server(&self, id: i64) -> Result<Option<ProxyServerRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, server, port, password, method, enabled, created_at, updated_at FROM proxy_servers WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| {
            Ok(ProxyServerRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                server: row.get(2)?,
                port: row.get(3)?,
                password: row.get(4)?,
                method: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        });

        match result {
            Ok(proxy) => Ok(Some(proxy)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// List all proxy servers
    pub fn list_proxy_servers(&self) -> Result<Vec<ProxyServerRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, server, port, password, method, enabled, created_at, updated_at FROM proxy_servers ORDER BY name",
        )?;

        let proxies = stmt
            .query_map([], |row| {
                Ok(ProxyServerRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    server: row.get(2)?,
                    port: row.get(3)?,
                    password: row.get(4)?,
                    method: row.get(5)?,
                    enabled: row.get::<_, i64>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(proxies)
    }

    /// Delete proxy server
    pub fn delete_proxy_server(&self, id: i64) -> Result<bool> {
        let rows = self.db.conn().execute("DELETE FROM proxy_servers WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    // ==================== Proxy Group Operations ====================

    /// Insert a new proxy group
    pub fn insert_proxy_group(&self, group: &NewProxyGroup) -> Result<i64> {
        self.db.conn().execute(
            "INSERT INTO proxy_groups (name, strategy, test_url, test_interval) VALUES (?1, ?2, ?3, ?4)",
            params![group.name, group.strategy, group.test_url, group.test_interval],
        )?;

        let id = self.db.conn().last_insert_rowid();
        debug!("Inserted proxy group: {} (id={})", group.name, id);
        Ok(id)
    }

    /// Get proxy group by ID
    pub fn get_proxy_group(&self, id: i64) -> Result<Option<ProxyGroupRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, strategy, test_url, test_interval, created_at, updated_at FROM proxy_groups WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| {
            Ok(ProxyGroupRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                strategy: row.get(2)?,
                test_url: row.get(3)?,
                test_interval: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(group) => Ok(Some(group)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// List all proxy groups
    pub fn list_proxy_groups(&self) -> Result<Vec<ProxyGroupRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, strategy, test_url, test_interval, created_at, updated_at FROM proxy_groups ORDER BY name",
        )?;

        let groups = stmt
            .query_map([], |row| {
                Ok(ProxyGroupRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    strategy: row.get(2)?,
                    test_url: row.get(3)?,
                    test_interval: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(groups)
    }

    /// Add proxy server to group
    pub fn add_group_member(&self, group_id: i64, proxy_id: i64, priority: i32) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR REPLACE INTO proxy_group_members (group_id, proxy_id, priority) VALUES (?1, ?2, ?3)",
            params![group_id, proxy_id, priority],
        )?;
        Ok(())
    }

    /// Remove proxy server from group
    pub fn remove_group_member(&self, group_id: i64, proxy_id: i64) -> Result<bool> {
        let rows = self.db.conn().execute(
            "DELETE FROM proxy_group_members WHERE group_id = ?1 AND proxy_id = ?2",
            params![group_id, proxy_id],
        )?;
        Ok(rows > 0)
    }

    /// Get proxy servers in group
    pub fn get_group_members(&self, group_id: i64) -> Result<Vec<ProxyServerRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT p.id, p.name, p.server, p.port, p.password, p.method, p.enabled, p.created_at, p.updated_at
             FROM proxy_servers p
             JOIN proxy_group_members pgm ON p.id = pgm.proxy_id
             WHERE pgm.group_id = ?1
             ORDER BY pgm.priority",
        )?;

        let proxies = stmt
            .query_map(params![group_id], |row| {
                Ok(ProxyServerRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    server: row.get(2)?,
                    port: row.get(3)?,
                    password: row.get(4)?,
                    method: row.get(5)?,
                    enabled: row.get::<_, i64>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(proxies)
    }

    // ==================== Rule Operations ====================

    /// Insert a new rule
    pub fn insert_rule(&self, rule: &NewRule) -> Result<i64> {
        self.db.conn().execute(
            "INSERT INTO rules (priority, rule_type, pattern, policy, schedule_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![rule.priority, rule.rule_type, rule.pattern, rule.policy, rule.schedule_id],
        )?;

        let id = self.db.conn().last_insert_rowid();
        debug!("Inserted rule: {} {:?} -> {} (id={})", rule.rule_type, rule.pattern, rule.policy, id);
        Ok(id)
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: i64) -> Result<Option<RuleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, priority, rule_type, pattern, policy, schedule_id, enabled, created_at, updated_at FROM rules WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| {
            Ok(RuleRecord {
                id: row.get(0)?,
                priority: row.get(1)?,
                rule_type: row.get(2)?,
                pattern: row.get(3)?,
                policy: row.get(4)?,
                schedule_id: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        });

        match result {
            Ok(rule) => Ok(Some(rule)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// List all rules (ordered by priority)
    pub fn list_rules(&self) -> Result<Vec<RuleRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, priority, rule_type, pattern, policy, schedule_id, enabled, created_at, updated_at FROM rules ORDER BY priority",
        )?;

        let rules = stmt
            .query_map([], |row| {
                Ok(RuleRecord {
                    id: row.get(0)?,
                    priority: row.get(1)?,
                    rule_type: row.get(2)?,
                    pattern: row.get(3)?,
                    policy: row.get(4)?,
                    schedule_id: row.get(5)?,
                    enabled: row.get::<_, i64>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rules)
    }

    /// Delete rule
    pub fn delete_rule(&self, id: i64) -> Result<bool> {
        let rows = self.db.conn().execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    // ==================== Global Config Operations ====================

    /// Set global config value
    pub fn set_config<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let json = serde_json::to_string(value)
            .map_err(|e| HomeGuardError::Storage(e.to_string()))?;

        self.db.conn().execute(
            "INSERT OR REPLACE INTO global_config (key, value, updated_at) VALUES (?1, ?2, datetime('now'))",
            params![key, json],
        )?;

        debug!("Set config: {} = {}", key, json);
        Ok(())
    }

    /// Get global config value
    pub fn get_config<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT value FROM global_config WHERE key = ?1",
        )?;

        let result: std::result::Result<String, _> = stmt.query_row(params![key], |row| row.get(0));

        match result {
            Ok(json) => {
                let value = serde_json::from_str(&json)
                    .map_err(|e| HomeGuardError::Storage(e.to_string()))?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HomeGuardError::Storage(e.to_string())),
        }
    }

    /// Delete global config value
    pub fn delete_config(&self, key: &str) -> Result<bool> {
        let rows = self.db.conn().execute("DELETE FROM global_config WHERE key = ?1", params![key])?;
        Ok(rows > 0)
    }

    /// List all global config entries
    pub fn list_config(&self) -> Result<Vec<GlobalConfigEntry>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT key, value, updated_at FROM global_config ORDER BY key",
        )?;

        let entries = stmt
            .query_map([], |row| {
                Ok(GlobalConfigEntry {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    updated_at: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> ConfigStore {
        let db = Database::open_in_memory().expect("Failed to open database");
        ConfigStore::new(db)
    }

    #[test]
    fn test_device_crud() {
        let store = create_test_store();

        // Create
        let device = NewDevice {
            id: "test_device".to_string(),
            name: "Test Device".to_string(),
            ip: Some("192.168.0.100".to_string()),
            mac: None,
            device_type: "child".to_string(),
        };
        store.insert_device(&device).expect("Failed to insert device");

        // Read
        let retrieved = store.get_device("test_device").expect("Failed to get device");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name, "Test Device");
        assert_eq!(retrieved.ip, Some("192.168.0.100".to_string()));

        // Read by IP
        let by_ip = store.get_device_by_ip("192.168.0.100").expect("Failed to get by IP");
        assert!(by_ip.is_some());
        assert_eq!(by_ip.unwrap().id, "test_device");

        // Update
        store.update_device("test_device", "Updated Device", Some("192.168.0.101"), None, "adult")
            .expect("Failed to update");
        let updated = store.get_device("test_device").expect("Failed to get").unwrap();
        assert_eq!(updated.name, "Updated Device");
        assert_eq!(updated.ip, Some("192.168.0.101".to_string()));
        assert_eq!(updated.device_type, "adult");

        // List
        let devices = store.list_devices().expect("Failed to list");
        assert_eq!(devices.len(), 1);

        // Delete
        assert!(store.delete_device("test_device").expect("Failed to delete"));
        assert!(store.get_device("test_device").expect("Failed to get").is_none());
    }

    #[test]
    fn test_schedule_crud() {
        let store = create_test_store();

        // Create
        let schedule = NewSchedule {
            name: "school_hours".to_string(),
            days: vec!["Mon".to_string(), "Tue".to_string(), "Wed".to_string()],
            start_time: "08:00".to_string(),
            end_time: "16:00".to_string(),
        };
        let id = store.insert_schedule(&schedule).expect("Failed to insert");
        assert!(id > 0);

        // Read by name
        let retrieved = store.get_schedule_by_name("school_hours").expect("Failed to get");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.start_time, "08:00");
        assert_eq!(retrieved.end_time, "16:00");

        // List
        let schedules = store.list_schedules().expect("Failed to list");
        assert_eq!(schedules.len(), 1);

        // Delete
        assert!(store.delete_schedule(id).expect("Failed to delete"));
    }

    #[test]
    fn test_device_schedule_association() {
        let store = create_test_store();

        // Create device
        let device = NewDevice {
            id: "child1".to_string(),
            name: "Child Device".to_string(),
            ip: Some("192.168.0.100".to_string()),
            mac: None,
            device_type: "child".to_string(),
        };
        store.insert_device(&device).expect("Failed to insert device");

        // Create schedules
        let schedule1 = NewSchedule {
            name: "morning".to_string(),
            days: vec!["Mon".to_string()],
            start_time: "08:00".to_string(),
            end_time: "12:00".to_string(),
        };
        let schedule2 = NewSchedule {
            name: "afternoon".to_string(),
            days: vec!["Mon".to_string()],
            start_time: "13:00".to_string(),
            end_time: "17:00".to_string(),
        };
        let sid1 = store.insert_schedule(&schedule1).expect("Failed to insert");
        let sid2 = store.insert_schedule(&schedule2).expect("Failed to insert");

        // Associate
        store.add_device_schedule("child1", sid1).expect("Failed to add");
        store.add_device_schedule("child1", sid2).expect("Failed to add");

        // Get device schedules
        let schedules = store.get_device_schedules("child1").expect("Failed to get");
        assert_eq!(schedules.len(), 2);

        // Remove association
        store.remove_device_schedule("child1", sid1).expect("Failed to remove");
        let schedules = store.get_device_schedules("child1").expect("Failed to get");
        assert_eq!(schedules.len(), 1);
    }

    #[test]
    fn test_proxy_server_crud() {
        let store = create_test_store();

        let proxy = NewProxyServer {
            name: "hk-server".to_string(),
            server: "hk.example.com".to_string(),
            port: 8388,
            password: "secret".to_string(),
            method: "chacha20-ietf-poly1305".to_string(),
        };
        let id = store.insert_proxy_server(&proxy).expect("Failed to insert");

        let retrieved = store.get_proxy_server(id).expect("Failed to get").unwrap();
        assert_eq!(retrieved.name, "hk-server");
        assert_eq!(retrieved.server, "hk.example.com");
        assert!(retrieved.enabled);

        let proxies = store.list_proxy_servers().expect("Failed to list");
        assert_eq!(proxies.len(), 1);
    }

    #[test]
    fn test_proxy_group_with_members() {
        let store = create_test_store();

        // Create proxies
        let proxy1 = NewProxyServer {
            name: "proxy1".to_string(),
            server: "s1.example.com".to_string(),
            port: 8388,
            password: "pass1".to_string(),
            method: "aes-256-gcm".to_string(),
        };
        let proxy2 = NewProxyServer {
            name: "proxy2".to_string(),
            server: "s2.example.com".to_string(),
            port: 8388,
            password: "pass2".to_string(),
            method: "aes-256-gcm".to_string(),
        };
        let pid1 = store.insert_proxy_server(&proxy1).expect("Failed to insert");
        let pid2 = store.insert_proxy_server(&proxy2).expect("Failed to insert");

        // Create group
        let group = NewProxyGroup {
            name: "auto".to_string(),
            strategy: "url-test".to_string(),
            test_url: Some("http://www.gstatic.com/generate_204".to_string()),
            test_interval: Some(300),
        };
        let gid = store.insert_proxy_group(&group).expect("Failed to insert");

        // Add members
        store.add_group_member(gid, pid1, 0).expect("Failed to add");
        store.add_group_member(gid, pid2, 1).expect("Failed to add");

        // Get members
        let members = store.get_group_members(gid).expect("Failed to get");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "proxy1"); // priority 0
        assert_eq!(members[1].name, "proxy2"); // priority 1
    }

    #[test]
    fn test_rule_crud() {
        let store = create_test_store();

        let rule = NewRule {
            priority: 100,
            rule_type: "DOMAIN-SUFFIX".to_string(),
            pattern: Some("google.com".to_string()),
            policy: "Proxy".to_string(),
            schedule_id: None,
        };
        let id = store.insert_rule(&rule).expect("Failed to insert");

        let retrieved = store.get_rule(id).expect("Failed to get").unwrap();
        assert_eq!(retrieved.rule_type, "DOMAIN-SUFFIX");
        assert_eq!(retrieved.pattern, Some("google.com".to_string()));
        assert_eq!(retrieved.policy, "Proxy");
        assert!(retrieved.enabled);

        let rules = store.list_rules().expect("Failed to list");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_global_config() {
        let store = create_test_store();

        // Set various types
        store.set_config("dns.listen", &"0.0.0.0:53").expect("Failed to set");
        store.set_config("dns.cache_size", &1000i32).expect("Failed to set");
        store.set_config("dns.fake_dns", &true).expect("Failed to set");
        store.set_config("dns.upstream", &vec!["8.8.8.8", "1.1.1.1"]).expect("Failed to set");

        // Get
        let listen: String = store.get_config("dns.listen").expect("Failed to get").unwrap();
        assert_eq!(listen, "0.0.0.0:53");

        let cache_size: i32 = store.get_config("dns.cache_size").expect("Failed to get").unwrap();
        assert_eq!(cache_size, 1000);

        let fake_dns: bool = store.get_config("dns.fake_dns").expect("Failed to get").unwrap();
        assert!(fake_dns);

        let upstream: Vec<String> = store.get_config("dns.upstream").expect("Failed to get").unwrap();
        assert_eq!(upstream.len(), 2);

        // Non-existent key
        let missing: Option<String> = store.get_config("nonexistent").expect("Failed to get");
        assert!(missing.is_none());

        // List
        let entries = store.list_config().expect("Failed to list");
        assert_eq!(entries.len(), 4);
    }
}
