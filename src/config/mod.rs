//! Configuration module for HomeGuard
//!
//! This module handles loading and validating configuration from TOML files.

mod parser;
mod types;

pub use parser::{load_config, load_config_from_str, load_rule_file, ConfigError};
pub use types::*;
