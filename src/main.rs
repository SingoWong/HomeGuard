//! HomeGuard - Home Network Gateway
//!
//! Main entry point for the HomeGuard application.

use homeguard::config::{DeviceConfig, DeviceType};
use homeguard::control::{
    BlocklistManager, DeviceManager, GrantStore, ParentalController, ParentalPolicy,
};
use homeguard::dns::{DnsCache, DnsHandler, DnsResolver, DnsServer, FakeDns};
use homeguard::outbound::OutboundManager;
use homeguard::proxy::TransparentProxy;
use homeguard::rule::{RuleEngine, RuleParser};
use homeguard::storage::{BlocklistMode, ConfigStore, Database, NewDevice};
use homeguard::{config, logging, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn};

/// How often the GrantStore refreshes its in-memory cache from SQLite.
/// `INSERT INTO grants ...` from the parent's shell takes effect within this
/// interval. See docs/parental-control.md for the staleness rationale.
const GRANT_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Default config file path
const DEFAULT_CONFIG_PATH: &str = "./config/homeguard.toml";

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    // Initialize logging with default level first
    logging::init_default_logging();

    info!("HomeGuard starting...");
    info!("Loading configuration from: {}", config_path.display());

    // Load configuration
    let config = match config::load_config(&config_path) {
        Ok(cfg) => {
            info!("Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(e.into());
        }
    };

    // Wrap config in Arc for sharing across tasks
    let config = Arc::new(config);

    info!("HomeGuard initialized");
    info!("DNS server will listen on: {}", config.dns.listen);
    info!("Transparent proxy will listen on: {}", config.transparent.listen);

    if config.dns.fake_dns {
        info!("FakeDNS enabled with pool: {}", config.dns.fake_dns_pool);
    }

    info!(
        "Loaded {} Shadowsocks proxies",
        config.proxy.shadowsocks.len()
    );
    info!("Loaded {} proxy groups", config.proxy.group.len());
    info!("Loaded {} device configs (TOML seeds)", config.devices.len());

    // Phase 2: Initialize DNS components
    info!("Initializing DNS service...");

    // Phase 3: Initialize Rule Engine
    // Rules live in a separate plain-text file (config.rules.rule_file) because
    // they change much more often than the rest of the configuration.
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let rule_file_path = if config.rules.rule_file.is_absolute() {
        config.rules.rule_file.clone()
    } else {
        config_dir.join(&config.rules.rule_file)
    };

    let rule_strings = match config::load_rule_file(&rule_file_path) {
        Ok(lines) => {
            info!(
                "Loaded {} rule entries from {}",
                lines.len(),
                rule_file_path.display()
            );
            lines
        }
        Err(e) => {
            error!(
                "Failed to read rule file {}: {}",
                rule_file_path.display(),
                e
            );
            return Err(e.into());
        }
    };

    // RULE-SET references resolve relative to `rules.rules_dir` (a dedicated
    // sub-directory for grouped rule sets, kept separate from the main entry
    // file so users can split rules.list into themed pieces like proxy-ai.list,
    // direct-cn.list, etc.). If the configured path is relative, it is resolved
    // against the config file's directory.
    let rule_base = if config.rules.rules_dir.is_absolute() {
        config.rules.rules_dir.clone()
    } else {
        config_dir.join(&config.rules.rules_dir)
    };

    let rules = match RuleParser::load_rules(&rule_strings, Some(&rule_base)) {
        Ok(r) => {
            info!("Parsed {} rules (including RULE-SET expansions)", r.len());
            r
        }
        Err(e) => {
            error!("Failed to parse rules: {}", e);
            return Err(e);
        }
    };

    // Create rule engine (GeoIP DB path from config if available)
    let geoip_db = config.rules.geoip_db.as_ref().map(|p| p.as_path());
    let filter: Arc<RuleEngine> = match RuleEngine::new(rules, geoip_db) {
        Ok(engine) => {
            info!("Rule engine initialized with {} rules", engine.rule_count());
            Arc::new(engine)
        }
        Err(e) => {
            error!("Failed to initialize rule engine: {}", e);
            return Err(e);
        }
    };

    // DNS Cache
    let cache = Arc::new(DnsCache::with_defaults(config.dns.cache_size));

    // FakeDNS (optional, based on config)
    let fake_dns = if config.dns.fake_dns {
        match FakeDns::new(&config.dns.fake_dns_pool, config.dns.cache_size) {
            Ok(fd) => {
                info!("FakeDNS initialized with pool: {}", config.dns.fake_dns_pool);
                Some(Arc::new(fd))
            }
            Err(e) => {
                error!("Failed to initialize FakeDNS: {}", e);
                return Err(e);
            }
        }
    } else {
        None
    };

    // Upstream Resolver
    let resolver = match DnsResolver::new(config.dns.upstream.clone(), 5) {
        Ok(r) => {
            info!("DNS resolver initialized with {} upstreams", config.dns.upstream.len());
            Arc::new(r)
        }
        Err(e) => {
            error!("Failed to initialize DNS resolver: {}", e);
            return Err(e);
        }
    };

    // Phase 7: Open SQLite storage (always, regardless of parental.enabled,
    // since grants live here and may be added later).
    let db_path = if config.general.data_dir.is_absolute() {
        config.general.data_dir.join("config.db")
    } else {
        config_dir.join(&config.general.data_dir).join("config.db")
    };
    let store = match Database::open(&db_path) {
        Ok(db) => Arc::new(Mutex::new(ConfigStore::new(db))),
        Err(e) => {
            error!("Failed to open SQLite DB at {}: {}", db_path.display(), e);
            return Err(homeguard::error::HomeGuardError::Storage(e.to_string()));
        }
    };
    info!("Storage opened: {}", db_path.display());

    // First-boot seed: if DB has zero devices and TOML has [devices.*],
    // import them so the runtime has something to identify. After this seed
    // runs, the TOML section is informational only.
    if let Err(e) = maybe_seed_devices_from_toml(&store, &config.devices) {
        error!("Device seeding failed: {}", e);
        return Err(e);
    }

    // Phase 6: Initialize Parental Control (optional)
    let parental_controller = if config.parental.enabled {
        info!("Initializing parental control...");

        // Determine blocklist directory
        let blocklist_dir = if config.parental.blocklist_dir.is_absolute() {
            config.parental.blocklist_dir.clone()
        } else {
            config_dir.join(&config.parental.blocklist_dir)
        };

        // Build device map from SQLite (authoritative source).
        let device_records = store.lock().list_devices()
            .map_err(|e| { error!("list_devices failed: {}", e); e })?;
        let blocklist_groups = store.lock().list_device_blocklists_grouped()
            .map_err(|e| { error!("list_device_blocklists_grouped failed: {}", e); e })?;

        let device_configs: HashMap<String, DeviceConfig> = device_records
            .into_iter()
            .map(|rec| {
                let (hard, grantable) = blocklist_groups
                    .get(&rec.id)
                    .cloned()
                    .unwrap_or_default();
                let device_type = match rec.device_type.as_str() {
                    "child" => DeviceType::Child,
                    "adult" => DeviceType::Adult,
                    "iot" => DeviceType::IoT,
                    _ => DeviceType::Unknown,
                };
                let cfg = DeviceConfig {
                    ip: rec.ip,
                    mac: rec.mac,
                    name: rec.name,
                    device_type,
                    hard_blocklists: hard,
                    grantable_blocklists: grantable,
                    extra_blocklists: vec![],
                };
                (rec.id, cfg)
            })
            .collect();

        let device_manager = DeviceManager::from_config(&device_configs);

        let mut blocklist_manager = BlocklistManager::new();
        if let Err(e) = blocklist_manager.load_directory(&blocklist_dir) {
            error!("Failed to load blocklists from {}: {}", blocklist_dir.display(), e);
            return Err(e);
        }

        // GrantStore — refreshes from SQLite every GRANT_REFRESH_INTERVAL.
        let grant_store = match GrantStore::open(store.clone()) {
            Ok(gs) => gs,
            Err(e) => {
                error!("Failed to open GrantStore: {}", e);
                return Err(e);
            }
        };
        // Background task: keep cache fresh. Handle is kept implicitly alive
        // by the tokio runtime until main returns.
        let _grant_refresh = grant_store.clone().spawn_refresh_task(GRANT_REFRESH_INTERVAL);

        let default_policy = match config.parental.default_policy.as_str() {
            "block_all" => ParentalPolicy::BlockAll,
            "block_if_listed" => ParentalPolicy::BlockIfListed,
            _ => ParentalPolicy::Allow,
        };

        let mut controller = ParentalController::new(
            device_manager,
            blocklist_manager,
            Some(grant_store),
            config.parental.global_categories.clone(),
            default_policy,
        );
        controller.set_global_categories(config.parental.global_categories.clone());

        info!(
            "Parental control enabled: {} devices loaded from DB, grant refresh every {:?}",
            device_configs.len(),
            GRANT_REFRESH_INTERVAL
        );
        Some(Arc::new(controller))
    } else {
        info!("Parental control disabled");
        None
    };

    // DNS Handler (share filter, fake_dns, and parental_controller with transparent proxy)
    let handler = if let Some(ref pc) = parental_controller {
        Arc::new(DnsHandler::with_parental_control(
            filter.clone(),
            cache,
            fake_dns.clone(),
            resolver,
            pc.clone(),
            config.dns.clone(),
        ))
    } else {
        Arc::new(DnsHandler::new(
            filter.clone(),
            cache,
            fake_dns.clone(),
            resolver,
            config.dns.clone(),
        ))
    };

    // DNS Server
    let dns_server = match DnsServer::new(&config.dns.listen.to_string(), handler).await {
        Ok(s) => {
            info!("DNS server initialized");
            s
        }
        Err(e) => {
            error!("Failed to initialize DNS server: {}", e);
            return Err(e);
        }
    };

    // Start DNS server in background
    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            error!("DNS server error: {}", e);
        }
    });

    // Phase 5: Initialize Outbound Manager
    info!("Initializing outbound manager...");

    let outbound_manager = match OutboundManager::from_config(&config.proxy) {
        Ok(m) => {
            info!(
                "Outbound manager initialized ({} proxies, {} groups)",
                config.proxy.shadowsocks.len(),
                config.proxy.group.len()
            );
            Arc::new(m)
        }
        Err(e) => {
            error!("Failed to initialize outbound manager: {}", e);
            return Err(e.into());
        }
    };

    // Start background health checks for proxy groups
    outbound_manager.start_health_checks();

    // Phase 4: Initialize Transparent Proxy
    info!("Initializing transparent proxy...");

    let transparent_proxy = if let Some(ref pc) = parental_controller {
        match TransparentProxy::with_parental_control(
            &config.transparent.listen.to_string(),
            fake_dns,
            filter,
            outbound_manager,
            pc.clone(),
        ).await {
            Ok(p) => {
                info!("Transparent proxy initialized on {} (parental control enabled)", p.listen_addr());
                p
            }
            Err(e) => {
                error!("Failed to initialize transparent proxy: {}", e);
                return Err(e);
            }
        }
    } else {
        match TransparentProxy::new(
            &config.transparent.listen.to_string(),
            fake_dns,
            filter,
            outbound_manager,
        ).await {
            Ok(p) => {
                info!("Transparent proxy initialized on {}", p.listen_addr());
                p
            }
            Err(e) => {
                error!("Failed to initialize transparent proxy: {}", e);
                return Err(e);
            }
        }
    };

    // Start transparent proxy in background
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = transparent_proxy.run().await {
            error!("Transparent proxy error: {}", e);
        }
    });

    info!("HomeGuard is running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    info!("HomeGuard shutting down...");

    // Abort servers
    dns_handle.abort();
    proxy_handle.abort();

    Ok(())
}

/// If the SQLite `devices` table is empty and the TOML config has a
/// `[devices.*]` section, import each one as a seed. After this runs, the
/// runtime treats the SQLite table as authoritative — further edits to
/// `[devices.*]` have no effect (we log a warning telling the user this).
///
/// Also handles the deprecated `extra_blocklists` field: its contents are
/// merged into `grantable_blocklists` with a warning.
fn maybe_seed_devices_from_toml(
    store: &Arc<Mutex<ConfigStore>>,
    toml_devices: &HashMap<String, DeviceConfig>,
) -> Result<()> {
    if toml_devices.is_empty() {
        return Ok(());
    }
    let existing = store.lock().list_devices()?;
    if !existing.is_empty() {
        // DB already populated; warn if TOML still has device blocks so user
        // doesn't expect TOML edits to take effect.
        warn!(
            "[devices.*] in homeguard.toml is ignored: SQLite already has {} device(s). \
             Edit devices via SQL instead.",
            existing.len()
        );
        return Ok(());
    }

    info!("Seeding {} device(s) from homeguard.toml into SQLite", toml_devices.len());
    for (id, cfg) in toml_devices {
        let device_type = match cfg.device_type {
            DeviceType::Child => "child",
            DeviceType::Adult => "adult",
            DeviceType::IoT => "iot",
            DeviceType::Unknown => "unknown",
        };
        store.lock().insert_device(&NewDevice {
            id: id.clone(),
            name: cfg.name.clone(),
            ip: cfg.ip.clone(),
            mac: cfg.mac.clone(),
            device_type: device_type.to_string(),
        })?;

        for category in &cfg.hard_blocklists {
            store.lock().add_device_blocklist(id, category, BlocklistMode::Hard)?;
        }
        for category in &cfg.grantable_blocklists {
            store.lock().add_device_blocklist(id, category, BlocklistMode::Grantable)?;
        }
        // Backward-compat: extra_blocklists collapses into grantable
        if !cfg.extra_blocklists.is_empty() {
            warn!(
                "Device '{}': `extra_blocklists` is deprecated; treating as `grantable_blocklists`",
                id
            );
            for category in &cfg.extra_blocklists {
                store.lock().add_device_blocklist(id, category, BlocklistMode::Grantable)?;
            }
        }
    }
    warn!(
        "Seeded {} device(s) from TOML. The [devices.*] section is now persisted in SQLite; \
         further device changes should be made via SQL (see docs/parental-control.md).",
        toml_devices.len()
    );
    Ok(())
}
