//! Logging initialization for HomeGuard

use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Initialize the logging system
///
/// # Arguments
/// * `log_level` - Log level string (e.g., "info", "debug", "warn", "error")
pub fn init_logging(log_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("homeguard={}", log_level)));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

/// Initialize logging with default settings (info level)
pub fn init_default_logging() {
    init_logging("info");
}
