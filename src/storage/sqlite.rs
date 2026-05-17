//! SQLite database management
//!
//! Handles database connection, migrations, and schema versioning.

use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;
use tracing::{debug, info};

/// Current schema version
const SCHEMA_VERSION: i32 = 2;

/// Database wrapper
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open database at path, creating if not exists
    pub fn open(path: &Path) -> SqliteResult<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(path)?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let mut db = Self { conn };
        db.run_migrations()?;

        Ok(db)
    }

    /// Open in-memory database (for testing)
    pub fn open_in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let mut db = Self { conn };
        db.run_migrations()?;

        Ok(db)
    }

    /// Get connection reference
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get mutable connection reference
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Run database migrations
    fn run_migrations(&mut self) -> SqliteResult<()> {
        // Create schema_version table if not exists
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        )?;

        // Get current version
        let current_version: i32 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        debug!("Current schema version: {}", current_version);

        // Apply migrations
        if current_version < 1 {
            self.migrate_v1()?;
        }
        if current_version < 2 {
            self.migrate_v2()?;
        }

        info!("Database schema is up to date (version {})", SCHEMA_VERSION);
        Ok(())
    }

    /// Migration to version 1 - initial schema
    fn migrate_v1(&mut self) -> SqliteResult<()> {
        info!("Applying migration v1: initial schema");

        let tx = self.conn.transaction()?;

        // devices table
        tx.execute_batch(
            "CREATE TABLE devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                device_type TEXT NOT NULL DEFAULT 'child',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE UNIQUE INDEX idx_devices_ip ON devices(ip) WHERE ip IS NOT NULL;
            CREATE UNIQUE INDEX idx_devices_mac ON devices(mac) WHERE mac IS NOT NULL;",
        )?;

        // schedules table
        tx.execute_batch(
            "CREATE TABLE schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                days TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        // device_schedules table
        tx.execute_batch(
            "CREATE TABLE device_schedules (
                device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
                PRIMARY KEY (device_id, schedule_id)
            );",
        )?;

        // blocklists table
        tx.execute_batch(
            "CREATE TABLE blocklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL,
                source_path TEXT,
                domain_count INTEGER DEFAULT 0,
                last_updated TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        // device_blocklists table
        tx.execute_batch(
            "CREATE TABLE device_blocklists (
                device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                blocklist_id INTEGER NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
                PRIMARY KEY (device_id, blocklist_id)
            );",
        )?;

        // proxy_servers table
        tx.execute_batch(
            "CREATE TABLE proxy_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                password TEXT NOT NULL,
                method TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        // proxy_groups table
        tx.execute_batch(
            "CREATE TABLE proxy_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                strategy TEXT NOT NULL DEFAULT 'select',
                test_url TEXT,
                test_interval INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        // proxy_group_members table
        tx.execute_batch(
            "CREATE TABLE proxy_group_members (
                group_id INTEGER NOT NULL REFERENCES proxy_groups(id) ON DELETE CASCADE,
                proxy_id INTEGER NOT NULL REFERENCES proxy_servers(id) ON DELETE CASCADE,
                priority INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, proxy_id)
            );",
        )?;

        // rules table
        tx.execute_batch(
            "CREATE TABLE rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL,
                rule_type TEXT NOT NULL,
                pattern TEXT,
                policy TEXT NOT NULL,
                schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX idx_rules_priority ON rules(priority);",
        )?;

        // global_config table
        tx.execute_batch(
            "CREATE TABLE global_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        // Record migration
        tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])?;

        tx.commit()?;

        info!("Migration v1 applied successfully");
        Ok(())
    }

    /// Migration to version 2 — grant-based parental control.
    ///
    /// Adds:
    /// * `grants` — time-bounded permissions issued by the parent that
    ///   temporarily unblock a `grantable` category for a device.
    /// * Rebuilds `device_blocklists` to key off category **name** (not
    ///   `blocklists(id)`) and to carry a `mode` discriminator (`hard` /
    ///   `grantable`). The v1 shape FK'd into a `blocklists` table that was
    ///   never populated in practice (Phase 7 was code-only), so dropping and
    ///   recreating is safe and produces a cleaner schema than ALTER + dead FK.
    ///
    /// `schedules` / `device_schedules` are left in place as no-op tables.
    /// They remain only as a migration anchor and may be dropped in v3.
    fn migrate_v2(&mut self) -> SqliteResult<()> {
        info!("Applying migration v2: grant-based parental control");

        let tx = self.conn.transaction()?;

        // grants table
        tx.execute_batch(
            "CREATE TABLE grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                category   TEXT NOT NULL,
                granted_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                note       TEXT
            );
            CREATE INDEX idx_grants_active
                ON grants(device_id, category, expires_at)
                WHERE revoked_at IS NULL;",
        )?;

        // Rebuild device_blocklists: drop old (empty in any real deployment) and
        // recreate with `category` text column + `mode` discriminator. No data
        // migration is needed because Phase 7 was never wired into main.rs.
        tx.execute_batch(
            "DROP TABLE device_blocklists;
             CREATE TABLE device_blocklists (
                device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                category  TEXT NOT NULL,
                mode      TEXT NOT NULL CHECK (mode IN ('hard', 'grantable')),
                PRIMARY KEY (device_id, category)
             );",
        )?;

        // Record migration
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;

        tx.commit()?;

        info!("Migration v2 applied successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let db = Database::open_in_memory().expect("Failed to open in-memory database");

        // Verify tables exist
        let tables: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"devices".to_string()));
        assert!(tables.contains(&"schedules".to_string()));
        assert!(tables.contains(&"blocklists".to_string()));
        assert!(tables.contains(&"proxy_servers".to_string()));
        assert!(tables.contains(&"proxy_groups".to_string()));
        assert!(tables.contains(&"rules".to_string()));
        assert!(tables.contains(&"global_config".to_string()));
        // v2 additions
        assert!(tables.contains(&"grants".to_string()));
    }

    #[test]
    fn test_v2_device_blocklists_shape() {
        let db = Database::open_in_memory().expect("Failed to open database");

        // pragma table_info returns (cid, name, type, notnull, dflt_value, pk)
        let cols: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM pragma_table_info('device_blocklists')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        for expected in &["device_id", "category", "mode"] {
            assert!(cols.contains(&expected.to_string()), "device_blocklists missing column {}; got {:?}", expected, cols);
        }
        assert!(!cols.contains(&"blocklist_id".to_string()), "device_blocklists still has old blocklist_id column");
    }

    #[test]
    fn test_v2_grants_table_shape() {
        let db = Database::open_in_memory().expect("Failed to open database");

        let cols: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM pragma_table_info('grants') ORDER BY cid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        for expected in &["id", "device_id", "category", "granted_at", "expires_at", "revoked_at", "note"] {
            assert!(cols.contains(&expected.to_string()), "grants missing column {}", expected);
        }
    }

    #[test]
    fn test_schema_version() {
        let db = Database::open_in_memory().expect("Failed to open database");

        let version: i32 = db
            .conn()
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_foreign_keys_enabled() {
        let db = Database::open_in_memory().expect("Failed to open database");

        let fk_enabled: i32 = db
            .conn()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();

        assert_eq!(fk_enabled, 1);
    }
}
