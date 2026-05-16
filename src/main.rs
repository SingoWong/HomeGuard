//! HomeGuard - Home Network Gateway
//!
//! Main entry point for the HomeGuard application.

use homeguard::control::ParentalController;
use homeguard::dns::{DnsCache, DnsHandler, DnsResolver, DnsServer, FakeDns};
use homeguard::outbound::OutboundManager;
use homeguard::proxy::TransparentProxy;
use homeguard::rule::{RuleEngine, RuleParser};
use homeguard::{config, logging, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

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
    info!("Loaded {} schedules", config.schedules.len());
    info!("Loaded {} device configs", config.devices.len());

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

    // Phase 6: Initialize Parental Control (optional)
    let parental_controller = if config.parental.enabled {
        info!("Initializing parental control...");

        // Determine blocklist directory
        let blocklist_dir = if config.parental.blocklist_dir.is_absolute() {
            config.parental.blocklist_dir.clone()
        } else {
            config_path
                .parent()
                .unwrap_or(&PathBuf::from("."))
                .join(&config.parental.blocklist_dir)
        };

        match ParentalController::from_config(&config, Some(&blocklist_dir)) {
            Ok(mut controller) => {
                // Set global categories
                if !config.parental.global_categories.is_empty() {
                    controller.set_global_categories(config.parental.global_categories.clone());
                }

                info!(
                    "Parental control enabled: {} devices, {} schedules",
                    config.devices.len(),
                    config.schedules.len()
                );
                Some(Arc::new(controller))
            }
            Err(e) => {
                error!("Failed to initialize parental control: {}", e);
                return Err(e);
            }
        }
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

    // TODO: Phase 7 - Initialize SQLite storage

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
