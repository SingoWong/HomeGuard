//! Transparent Proxy Module
//!
//! Intercepts TCP traffic redirected by macOS PF (Packet Filter) and routes
//! according to rule engine decisions.
//!
//! # Flow
//! 1. Accept connection from PF-redirected traffic
//! 2. Get original destination using DIOCNATLOOK
//! 3. Lookup domain from FakeDNS (if FakeIP)
//! 4. Match against rule engine
//! 5. Route to DIRECT/REJECT/PROXY

mod handler;
mod nat;
mod relay;
mod server;

pub use handler::ConnectionHandler;
pub use nat::get_original_dst;
pub use relay::{relay, relay_with_timeout};
pub use server::TransparentProxy;
