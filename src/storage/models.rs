//! Storage data models
//!
//! Data structures for SQLite configuration storage.

use serde::{Deserialize, Serialize};

/// Device record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub device_type: String,
    pub created_at: String,
    pub updated_at: String,
}

/// New device for insertion
#[derive(Debug, Clone)]
pub struct NewDevice {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub device_type: String,
}

/// Schedule record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRecord {
    pub id: i64,
    pub name: String,
    pub days: String, // JSON array
    pub start_time: String,
    pub end_time: String,
    pub created_at: String,
    pub updated_at: String,
}

/// New schedule for insertion
#[derive(Debug, Clone)]
pub struct NewSchedule {
    pub name: String,
    pub days: Vec<String>,
    pub start_time: String,
    pub end_time: String,
}

/// Blocklist record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistRecord {
    pub id: i64,
    pub category: String,
    pub source_type: String,
    pub source_path: Option<String>,
    pub domain_count: i64,
    pub last_updated: Option<String>,
    pub created_at: String,
}

/// New blocklist for insertion
#[derive(Debug, Clone)]
pub struct NewBlocklist {
    pub category: String,
    pub source_type: String,
    pub source_path: Option<String>,
}

/// Proxy server record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyServerRecord {
    pub id: i64,
    pub name: String,
    pub server: String,
    pub port: i64,
    pub password: String, // encrypted
    pub method: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// New proxy server for insertion
#[derive(Debug, Clone)]
pub struct NewProxyServer {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub method: String,
}

/// Proxy group record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGroupRecord {
    pub id: i64,
    pub name: String,
    pub strategy: String,
    pub test_url: Option<String>,
    pub test_interval: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

/// New proxy group for insertion
#[derive(Debug, Clone)]
pub struct NewProxyGroup {
    pub name: String,
    pub strategy: String,
    pub test_url: Option<String>,
    pub test_interval: Option<u32>,
}

/// Rule record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRecord {
    pub id: i64,
    pub priority: i64,
    pub rule_type: String,
    pub pattern: Option<String>,
    pub policy: String,
    pub schedule_id: Option<i64>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// New rule for insertion
#[derive(Debug, Clone)]
pub struct NewRule {
    pub priority: i64,
    pub rule_type: String,
    pub pattern: Option<String>,
    pub policy: String,
    pub schedule_id: Option<i64>,
}

/// Global config entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfigEntry {
    pub key: String,
    pub value: String, // JSON encoded
    pub updated_at: String,
}
