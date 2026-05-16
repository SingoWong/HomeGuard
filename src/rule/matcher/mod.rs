//! Matchers for different rule types
//!
//! - DomainMatcher: Exact, suffix, and keyword domain matching
//! - IpMatcher: IPv4/IPv6 CIDR matching
//! - GeoIpMatcher: Country code matching using MaxMind DB

mod domain;
mod geoip;
mod ip;

pub use domain::DomainMatcher;
pub use geoip::GeoIpMatcher;
pub use ip::IpMatcher;
