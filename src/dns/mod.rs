//! DNS service module
//!
//! This module provides the core DNS functionality for HomeGuard:
//! - DNS server (UDP)
//! - DNS caching with TTL management
//! - FakeDNS for transparent proxy domain identification
//! - Upstream DNS resolution
//! - DNS filtering interface (actual rules in Phase 3)

mod cache;
mod filter;
mod fake_dns;
mod resolver;
mod handler;
mod server;

pub use cache::DnsCache;
pub use filter::{AllowAllFilter, DnsFilterTrait, SimpleDnsFilter};
pub use fake_dns::FakeDns;
pub use resolver::DnsResolver;
pub use handler::DnsHandler;
pub use server::DnsServer;
