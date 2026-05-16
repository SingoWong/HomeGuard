//! Error types for HomeGuard

use thiserror::Error;

/// Main error type for HomeGuard
#[derive(Debug, Error)]
pub enum HomeGuardError {
    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Rule error: {0}")]
    Rule(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<rusqlite::Error> for HomeGuardError {
    fn from(err: rusqlite::Error) -> Self {
        HomeGuardError::Storage(err.to_string())
    }
}

/// Result type alias for HomeGuard operations
pub type Result<T> = std::result::Result<T, HomeGuardError>;
