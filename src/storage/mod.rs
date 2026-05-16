//! Storage module
//!
//! Provides two storage subsystems:
//! - SQLite for configuration storage
//! - File-based logging for access logs

pub mod config_store;
pub mod logger;
pub mod models;
pub mod sqlite;

pub use config_store::ConfigStore;
pub use logger::{AccessLogger, DnsLogEntry, LogGranularity, TcpLogEntry};
pub use models::*;
pub use sqlite::Database;
