//! HomeGuard - Home Network Gateway
//!
//! A Rust-based home network gateway for parental control and proxy management.
//!
//! # Features
//!
//! - **Parental Control**: Block inappropriate websites and enforce time-based access controls
//! - **Transparent Proxy**: Intercept and route network traffic
//! - **Shadowsocks Proxy**: Support for Shadowsocks proxy protocol
//! - **Surge-like Rules**: Domain/IP-CIDR/GeoIP based routing rules

pub mod config;
pub mod dns;
pub mod error;
pub mod logging;

pub mod proxy;

pub mod outbound;

pub mod rule;

pub mod control;

pub mod storage;

pub use config::Config;
pub use error::{HomeGuardError, Result};
