//! Access Logger
//!
//! File-based logging for DNS queries and TCP connections.
//! Supports configurable granularity and automatic log rotation.

use chrono::{Local, NaiveDate};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

use crate::error::Result;
use crate::rule::Policy;

/// Log granularity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogGranularity {
    /// Log all requests (DNS queries, all TCP connections)
    All = 1,
    /// Log blocked requests and proxy connections only
    #[default]
    BlockedAndProxy = 2,
    /// Log blocked requests only
    BlockedOnly = 3,
}

impl LogGranularity {
    /// Create from integer value
    pub fn from_value(value: u8) -> Self {
        match value {
            1 => LogGranularity::All,
            2 => LogGranularity::BlockedAndProxy,
            3 => LogGranularity::BlockedOnly,
            _ => LogGranularity::BlockedAndProxy,
        }
    }

    /// Check if DNS query should be logged
    pub fn should_log_dns(&self, is_blocked: bool) -> bool {
        match self {
            LogGranularity::All => true,
            LogGranularity::BlockedAndProxy => is_blocked,
            LogGranularity::BlockedOnly => is_blocked,
        }
    }

    /// Check if TCP connection should be logged
    pub fn should_log_tcp(&self, policy: &Policy) -> bool {
        match self {
            LogGranularity::All => true,
            LogGranularity::BlockedAndProxy => {
                matches!(policy, Policy::Reject | Policy::Proxy(_))
            }
            LogGranularity::BlockedOnly => matches!(policy, Policy::Reject),
        }
    }
}

/// DNS query log entry
#[derive(Debug, Serialize)]
pub struct DnsLogEntry {
    /// Timestamp in ISO 8601 format
    pub ts: String,
    /// Entry type
    #[serde(rename = "type")]
    pub entry_type: &'static str,
    /// Source IP address
    pub src: IpAddr,
    /// Queried domain
    pub domain: String,
    /// Query result
    pub result: String,
    /// Block reason (if blocked)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Query latency in milliseconds
    pub latency_ms: u64,
}

impl DnsLogEntry {
    /// Create an allowed DNS entry
    pub fn allowed(src: IpAddr, domain: String, latency_ms: u64) -> Self {
        Self {
            ts: Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            entry_type: "dns",
            src,
            domain,
            result: "allow".to_string(),
            reason: None,
            latency_ms,
        }
    }

    /// Create a blocked DNS entry
    pub fn blocked(src: IpAddr, domain: String, reason: String, latency_ms: u64) -> Self {
        Self {
            ts: Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            entry_type: "dns",
            src,
            domain,
            result: "blocked".to_string(),
            reason: Some(reason),
            latency_ms,
        }
    }
}

/// TCP connection log entry
#[derive(Debug, Serialize)]
pub struct TcpLogEntry {
    /// Timestamp in ISO 8601 format
    pub ts: String,
    /// Entry type
    #[serde(rename = "type")]
    pub entry_type: &'static str,
    /// Source address
    pub src: SocketAddr,
    /// Destination address
    pub dst: SocketAddr,
    /// Domain name (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Routing policy applied
    pub policy: String,
    /// Bytes uploaded
    pub bytes_up: u64,
    /// Bytes downloaded
    pub bytes_down: u64,
    /// Connection duration in milliseconds
    pub duration_ms: u64,
}

impl TcpLogEntry {
    /// Create a new TCP log entry
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        domain: Option<String>,
        policy: &Policy,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
    ) -> Self {
        Self {
            ts: Local::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            entry_type: "tcp",
            src,
            dst,
            domain,
            policy: format!("{}", policy),
            bytes_up,
            bytes_down,
            duration_ms,
        }
    }
}

/// Access logger with daily rotation
pub struct AccessLogger {
    /// Log file directory
    log_dir: PathBuf,
    /// Current log file writer
    writer: Option<BufWriter<File>>,
    /// Current date for rotation
    current_date: NaiveDate,
    /// Granularity level
    granularity: LogGranularity,
    /// Retention days (0 = no cleanup)
    retention_days: u32,
    /// Whether logger is enabled
    enabled: bool,
}

impl AccessLogger {
    /// Create a new access logger
    pub fn new(log_dir: PathBuf, granularity: LogGranularity, retention_days: u32) -> Self {
        Self {
            log_dir,
            writer: None,
            current_date: Local::now().date_naive(),
            granularity,
            retention_days,
            enabled: true,
        }
    }

    /// Create a disabled logger (no-op)
    pub fn disabled() -> Self {
        Self {
            log_dir: PathBuf::new(),
            writer: None,
            current_date: Local::now().date_naive(),
            granularity: LogGranularity::BlockedAndProxy,
            retention_days: 0,
            enabled: false,
        }
    }

    /// Initialize the logger (create directory, open file)
    pub fn init(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Create log directory if not exists
        fs::create_dir_all(&self.log_dir)?;

        // Open current day's log file
        self.open_log_file()?;

        // Clean up old logs
        self.cleanup_old_logs();

        info!(
            "Access logger initialized: dir={}, granularity={:?}, retention={}d",
            self.log_dir.display(),
            self.granularity,
            self.retention_days
        );

        Ok(())
    }

    /// Log a DNS query
    pub fn log_dns(&mut self, entry: &DnsLogEntry) {
        if !self.enabled {
            return;
        }

        let is_blocked = entry.result == "blocked";
        if !self.granularity.should_log_dns(is_blocked) {
            return;
        }

        self.write_entry(entry);
    }

    /// Log a TCP connection
    pub fn log_tcp(&mut self, entry: &TcpLogEntry, policy: &Policy) {
        if !self.enabled {
            return;
        }

        if !self.granularity.should_log_tcp(policy) {
            return;
        }

        self.write_entry(entry);
    }

    /// Set granularity level
    pub fn set_granularity(&mut self, granularity: LogGranularity) {
        self.granularity = granularity;
    }

    /// Write an entry to the log file
    fn write_entry<T: Serialize>(&mut self, entry: &T) {
        // Check for rotation
        self.rotate_if_needed();

        // Ensure we have a writer
        if self.writer.is_none() {
            if let Err(e) = self.open_log_file() {
                error!("Failed to open log file: {}", e);
                return;
            }
        }

        // Serialize and write
        if let Some(ref mut writer) = self.writer {
            match serde_json::to_string(entry) {
                Ok(json) => {
                    if let Err(e) = writeln!(writer, "{}", json) {
                        error!("Failed to write log entry: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to serialize log entry: {}", e);
                }
            }
        }
    }

    /// Flush the log buffer
    pub fn flush(&mut self) {
        if let Some(ref mut writer) = self.writer {
            let _ = writer.flush();
        }
    }

    /// Open log file for current date
    fn open_log_file(&mut self) -> Result<()> {
        let filename = format!("access-{}.log", self.current_date.format("%Y-%m-%d"));
        let path = self.log_dir.join(filename);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        self.writer = Some(BufWriter::new(file));
        debug!("Opened log file: {}", path.display());

        Ok(())
    }

    /// Rotate log file if date changed
    fn rotate_if_needed(&mut self) {
        let today = Local::now().date_naive();
        if today != self.current_date {
            info!("Rotating log file for new day: {}", today);

            // Flush and close current file
            if let Some(ref mut writer) = self.writer {
                let _ = writer.flush();
            }
            self.writer = None;

            // Update date
            self.current_date = today;

            // Open new file
            if let Err(e) = self.open_log_file() {
                error!("Failed to open new log file: {}", e);
            }

            // Cleanup old logs
            self.cleanup_old_logs();
        }
    }

    /// Clean up old log files
    fn cleanup_old_logs(&self) {
        if self.retention_days == 0 {
            return;
        }

        let cutoff = Local::now().date_naive() - chrono::Duration::days(self.retention_days as i64);

        let entries = match fs::read_dir(&self.log_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read log directory: {}", e);
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                // Parse date from filename: access-YYYY-MM-DD.log
                if filename.starts_with("access-") && filename.ends_with(".log") {
                    let date_str = &filename[7..17]; // Extract YYYY-MM-DD
                    if let Ok(file_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                        if file_date < cutoff {
                            info!("Deleting old log file: {}", filename);
                            if let Err(e) = fs::remove_file(&path) {
                                warn!("Failed to delete old log file: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for AccessLogger {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_log_granularity_from_value() {
        assert_eq!(LogGranularity::from_value(1), LogGranularity::All);
        assert_eq!(LogGranularity::from_value(2), LogGranularity::BlockedAndProxy);
        assert_eq!(LogGranularity::from_value(3), LogGranularity::BlockedOnly);
        assert_eq!(LogGranularity::from_value(99), LogGranularity::BlockedAndProxy);
    }

    #[test]
    fn test_should_log_dns() {
        // All
        assert!(LogGranularity::All.should_log_dns(true));
        assert!(LogGranularity::All.should_log_dns(false));

        // BlockedAndProxy
        assert!(LogGranularity::BlockedAndProxy.should_log_dns(true));
        assert!(!LogGranularity::BlockedAndProxy.should_log_dns(false));

        // BlockedOnly
        assert!(LogGranularity::BlockedOnly.should_log_dns(true));
        assert!(!LogGranularity::BlockedOnly.should_log_dns(false));
    }

    #[test]
    fn test_should_log_tcp() {
        // All
        assert!(LogGranularity::All.should_log_tcp(&Policy::Direct));
        assert!(LogGranularity::All.should_log_tcp(&Policy::Reject));
        assert!(LogGranularity::All.should_log_tcp(&Policy::Proxy("test".to_string())));

        // BlockedAndProxy
        assert!(!LogGranularity::BlockedAndProxy.should_log_tcp(&Policy::Direct));
        assert!(LogGranularity::BlockedAndProxy.should_log_tcp(&Policy::Reject));
        assert!(LogGranularity::BlockedAndProxy.should_log_tcp(&Policy::Proxy("test".to_string())));

        // BlockedOnly
        assert!(!LogGranularity::BlockedOnly.should_log_tcp(&Policy::Direct));
        assert!(LogGranularity::BlockedOnly.should_log_tcp(&Policy::Reject));
        assert!(!LogGranularity::BlockedOnly.should_log_tcp(&Policy::Proxy("test".to_string())));
    }

    #[test]
    fn test_dns_log_entry_serialization() {
        let entry = DnsLogEntry::allowed(
            "192.168.0.100".parse().unwrap(),
            "example.com".to_string(),
            15,
        );

        let json = serde_json::to_string(&entry).expect("Failed to serialize");
        assert!(json.contains("\"type\":\"dns\""));
        assert!(json.contains("\"result\":\"allow\""));
        assert!(json.contains("\"domain\":\"example.com\""));
        assert!(!json.contains("reason")); // Should be skipped when None
    }

    #[test]
    fn test_dns_log_entry_blocked() {
        let entry = DnsLogEntry::blocked(
            "192.168.0.100".parse().unwrap(),
            "blocked.com".to_string(),
            "Global blocklist".to_string(),
            5,
        );

        let json = serde_json::to_string(&entry).expect("Failed to serialize");
        assert!(json.contains("\"result\":\"blocked\""));
        assert!(json.contains("\"reason\":\"Global blocklist\""));
    }

    #[test]
    fn test_tcp_log_entry_serialization() {
        let entry = TcpLogEntry::new(
            "192.168.0.100:12345".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            Some("example.com".to_string()),
            &Policy::Direct,
            1024,
            2048,
            150,
        );

        let json = serde_json::to_string(&entry).expect("Failed to serialize");
        assert!(json.contains("\"type\":\"tcp\""));
        assert!(json.contains("\"policy\":\"DIRECT\""));
        assert!(json.contains("\"bytes_up\":1024"));
    }

    #[test]
    fn test_logger_init() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let log_dir = temp_dir.path().join("logs");

        let mut logger = AccessLogger::new(log_dir.clone(), LogGranularity::All, 7);
        logger.init().expect("Failed to init logger");

        assert!(log_dir.exists());

        // Check log file exists
        let today = Local::now().date_naive();
        let log_file = log_dir.join(format!("access-{}.log", today.format("%Y-%m-%d")));
        assert!(log_file.exists());
    }

    #[test]
    fn test_logger_write() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let log_dir = temp_dir.path().join("logs");

        let mut logger = AccessLogger::new(log_dir.clone(), LogGranularity::All, 7);
        logger.init().expect("Failed to init logger");

        // Log DNS entry
        let dns_entry = DnsLogEntry::allowed(
            "192.168.0.100".parse().unwrap(),
            "example.com".to_string(),
            10,
        );
        logger.log_dns(&dns_entry);

        // Log TCP entry
        let tcp_entry = TcpLogEntry::new(
            "192.168.0.100:12345".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
            &Policy::Direct,
            100,
            200,
            50,
        );
        logger.log_tcp(&tcp_entry, &Policy::Direct);

        // Flush
        logger.flush();

        // Read log file
        let today = Local::now().date_naive();
        let log_file = log_dir.join(format!("access-{}.log", today.format("%Y-%m-%d")));
        let content = fs::read_to_string(&log_file).expect("Failed to read log");

        assert!(content.contains("example.com"));
        assert!(content.contains("\"type\":\"dns\""));
        assert!(content.contains("\"type\":\"tcp\""));
    }

    #[test]
    fn test_logger_granularity_filter() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let log_dir = temp_dir.path().join("logs");

        // Use BlockedOnly granularity
        let mut logger = AccessLogger::new(log_dir.clone(), LogGranularity::BlockedOnly, 7);
        logger.init().expect("Failed to init logger");

        // This should NOT be logged (allowed DNS)
        let allowed_dns = DnsLogEntry::allowed(
            "192.168.0.100".parse().unwrap(),
            "allowed.com".to_string(),
            10,
        );
        logger.log_dns(&allowed_dns);

        // This SHOULD be logged (blocked DNS)
        let blocked_dns = DnsLogEntry::blocked(
            "192.168.0.100".parse().unwrap(),
            "blocked.com".to_string(),
            "Test reason".to_string(),
            5,
        );
        logger.log_dns(&blocked_dns);

        // This should NOT be logged (DIRECT TCP)
        let direct_tcp = TcpLogEntry::new(
            "192.168.0.100:12345".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
            &Policy::Direct,
            100,
            200,
            50,
        );
        logger.log_tcp(&direct_tcp, &Policy::Direct);

        // This SHOULD be logged (REJECT TCP)
        let reject_tcp = TcpLogEntry::new(
            "192.168.0.100:12346".parse().unwrap(),
            "1.2.3.4:80".parse().unwrap(),
            None,
            &Policy::Reject,
            0,
            0,
            1,
        );
        logger.log_tcp(&reject_tcp, &Policy::Reject);

        logger.flush();

        // Read and verify
        let today = Local::now().date_naive();
        let log_file = log_dir.join(format!("access-{}.log", today.format("%Y-%m-%d")));
        let content = fs::read_to_string(&log_file).expect("Failed to read log");

        assert!(!content.contains("allowed.com"));
        assert!(content.contains("blocked.com"));
        assert!(!content.contains("\"policy\":\"DIRECT\""));
        assert!(content.contains("\"policy\":\"REJECT\""));
    }

    #[test]
    fn test_disabled_logger() {
        let mut logger = AccessLogger::disabled();
        logger.init().expect("Should succeed for disabled logger");

        // These should be no-ops
        let entry = DnsLogEntry::allowed(
            "192.168.0.100".parse().unwrap(),
            "test.com".to_string(),
            10,
        );
        logger.log_dns(&entry);
        logger.flush();
    }
}
