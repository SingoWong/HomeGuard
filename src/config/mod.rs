//! Configuration module for HomeGuard
//!
//! This module handles loading and validating configuration from TOML files.

mod parser;
mod types;

pub use parser::{load_config, load_config_from_str, ConfigError};
pub use types::*;
