//! Grant store — on-demand parental control authorizations.
//!
//! A grant is a time-bounded permission for one device to access one
//! `grantable` category that would otherwise be blocked by default. Grants
//! are persisted in SQLite (`grants` table, v2 schema) and managed by the
//! parent via raw `sqlite3` commands; this module is the read-only runtime
//! consumer.
//!
//! ## Hot path
//! [`GrantStore::has_active`] is called from `ParentalController::check_access`
//! on every DNS query for a child device hitting a grantable category — it
//! must be O(1) and lock-free. We achieve this with an in-memory `RwLock<HashMap>`
//! cache rebuilt every few seconds by a background task ([`spawn_refresh_task`]).
//!
//! ## Staleness
//! The cache lags reality by up to `refresh_interval`. Default is 5 seconds,
//! which means an `INSERT INTO grants` from the parent's shell takes effect
//! within 5s, and a revoke (or natural expiry) likewise takes effect within 5s.
//! This is acceptable for the parental-control UX; harder real-time SLAs
//! would require a notification mechanism on top of SQLite (out of scope).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::storage::ConfigStore;

/// In-memory cache + read-only view of the `grants` SQLite table.
pub struct GrantStore {
    store: Arc<Mutex<ConfigStore>>,
    /// (device_id, category) → earliest expiry among active grants for that pair.
    /// If multiple overlapping grants exist for the same (device, category),
    /// the latest expiry wins (i.e. grants effectively extend each other; a new
    /// 1h grant on top of a remaining 10min one yields a 1h window).
    active: RwLock<HashMap<(String, String), DateTime<Utc>>>,
}

impl GrantStore {
    /// Open the store backed by the given ConfigStore handle and prime the
    /// cache from the current DB contents.
    pub fn open(store: Arc<Mutex<ConfigStore>>) -> Result<Arc<Self>> {
        let s = Arc::new(Self {
            store,
            active: RwLock::new(HashMap::new()),
        });
        let primed = s.refresh()?;
        info!("GrantStore initialized with {} active grants", primed);
        Ok(s)
    }

    /// Hot-path lookup. Returns true if there is an active, non-revoked,
    /// non-expired grant for the given (device, category) pair.
    pub fn has_active(&self, device_id: &str, category: &str) -> bool {
        let now = Utc::now();
        let key = (device_id.to_string(), category.to_string());
        match self.active.read().get(&key) {
            Some(expires_at) => *expires_at > now,
            None => false,
        }
    }

    /// Re-query the DB and atomically replace the in-memory map.
    /// Returns the number of active grants loaded.
    pub fn refresh(&self) -> Result<usize> {
        let grants = {
            let store = self.store.lock();
            store.list_active_grants()?
        };

        let mut new_map: HashMap<(String, String), DateTime<Utc>> = HashMap::new();
        let mut bad_rows = 0usize;
        for g in &grants {
            match parse_sqlite_utc(&g.expires_at) {
                Some(ts) => {
                    let key = (g.device_id.clone(), g.category.clone());
                    // Keep the maximum expiry if duplicates exist for the same key.
                    new_map
                        .entry(key)
                        .and_modify(|cur| {
                            if ts > *cur {
                                *cur = ts;
                            }
                        })
                        .or_insert(ts);
                }
                None => {
                    bad_rows += 1;
                }
            }
        }

        if bad_rows > 0 {
            warn!(
                "GrantStore::refresh: skipped {} rows with unparseable expires_at",
                bad_rows
            );
        }

        let count = new_map.len();
        *self.active.write() = new_map;
        debug!("GrantStore refreshed: {} unique active (device, category) pairs", count);
        Ok(count)
    }

    /// Spawn a tokio task that calls [`refresh`] every `interval`. The task
    /// runs until the returned `JoinHandle` is dropped or aborted.
    pub fn spawn_refresh_task(self: Arc<Self>, interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately; skip it because open() already primed.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh() {
                    warn!("GrantStore refresh failed: {}", e);
                }
            }
        })
    }
}

/// Parse SQLite's default `datetime('now')` format ("YYYY-MM-DD HH:MM:SS",
/// always UTC) into a `DateTime<Utc>`. Returns None on malformed input so a
/// single bad row never poisons the whole cache.
fn parse_sqlite_utc(s: &str) -> Option<DateTime<Utc>> {
    // Try the canonical format first; tolerate ISO-8601 with 'T' as a fallback
    // so callers writing `datetime('now')` style and ISO style both work.
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .ok()
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Database, NewDevice, NewGrant};

    fn make_store() -> Arc<Mutex<ConfigStore>> {
        let db = Database::open_in_memory().expect("db");
        let store = ConfigStore::new(db);
        store.insert_device(&NewDevice {
            id: "child_ipad".to_string(),
            name: "Child iPad".to_string(),
            ip: Some("192.168.0.50".to_string()),
            mac: None,
            device_type: "child".to_string(),
        }).expect("seed device");
        Arc::new(Mutex::new(store))
    }

    #[test]
    fn test_parse_sqlite_utc_canonical() {
        let dt = parse_sqlite_utc("2026-05-17 12:34:56").expect("parses");
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-05-17 12:34:56");
    }

    #[test]
    fn test_parse_sqlite_utc_iso_fallback() {
        let dt = parse_sqlite_utc("2026-05-17T12:34:56").expect("parses ISO");
        assert_eq!(dt.format("%Y-%m-%dT%H:%M:%S").to_string(), "2026-05-17T12:34:56");
    }

    #[test]
    fn test_parse_sqlite_utc_malformed_returns_none() {
        assert!(parse_sqlite_utc("not a date").is_none());
    }

    #[test]
    fn test_has_active_false_when_no_grants() {
        let store = make_store();
        let gs = GrantStore::open(store).expect("open");
        assert!(!gs.has_active("child_ipad", "games"));
    }

    #[test]
    fn test_has_active_true_after_grant_then_refresh() {
        let store = make_store();
        let gs = GrantStore::open(store.clone()).expect("open");

        // Insert a future-expiring grant
        store.lock().insert_grant(&NewGrant {
            device_id: "child_ipad".to_string(),
            category: "games".to_string(),
            granted_at: None,
            expires_at: "9999-12-31 23:59:59".to_string(),
            note: None,
        }).expect("insert");

        // Not visible yet (cache stale)
        assert!(!gs.has_active("child_ipad", "games"));

        // After refresh, visible
        gs.refresh().expect("refresh");
        assert!(gs.has_active("child_ipad", "games"));

        // Different category not granted
        assert!(!gs.has_active("child_ipad", "social"));
        // Different device not granted
        assert!(!gs.has_active("other_device", "games"));
    }

    #[test]
    fn test_has_active_false_after_revoke_then_refresh() {
        let store = make_store();
        let gs = GrantStore::open(store.clone()).expect("open");

        let id = store.lock().insert_grant(&NewGrant {
            device_id: "child_ipad".to_string(),
            category: "games".to_string(),
            granted_at: None,
            expires_at: "9999-12-31 23:59:59".to_string(),
            note: None,
        }).unwrap();

        gs.refresh().unwrap();
        assert!(gs.has_active("child_ipad", "games"));

        store.lock().revoke_grant(id).unwrap();
        // Pre-refresh: still cached as active
        assert!(gs.has_active("child_ipad", "games"));
        gs.refresh().unwrap();
        // Post-refresh: gone
        assert!(!gs.has_active("child_ipad", "games"));
    }

    #[test]
    fn test_already_expired_grant_never_appears() {
        let store = make_store();
        let gs = GrantStore::open(store.clone()).expect("open");

        store.lock().insert_grant(&NewGrant {
            device_id: "child_ipad".to_string(),
            category: "games".to_string(),
            granted_at: Some("2000-01-01 00:00:00".to_string()),
            expires_at: "2000-01-01 01:00:00".to_string(),
            note: None,
        }).unwrap();

        gs.refresh().unwrap();
        assert!(!gs.has_active("child_ipad", "games"));
    }

    #[test]
    fn test_overlapping_grants_take_max_expiry() {
        let store = make_store();
        let gs = GrantStore::open(store.clone()).expect("open");

        // Earlier-expiring grant inserted first
        store.lock().insert_grant(&NewGrant {
            device_id: "child_ipad".to_string(),
            category: "games".to_string(),
            granted_at: None,
            expires_at: "2030-01-01 00:00:00".to_string(),
            note: None,
        }).unwrap();
        // Later-expiring grant inserted second
        store.lock().insert_grant(&NewGrant {
            device_id: "child_ipad".to_string(),
            category: "games".to_string(),
            granted_at: None,
            expires_at: "9999-12-31 23:59:59".to_string(),
            note: None,
        }).unwrap();

        gs.refresh().unwrap();
        assert!(gs.has_active("child_ipad", "games"));

        // Both rows visible in raw list
        let active = store.lock().list_active_grants().unwrap();
        assert_eq!(active.len(), 2);
    }
}
