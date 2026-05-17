//! Parental Control Module
//!
//! Provides device-aware access control with grant-based authorizations.
//!
//! Components:
//! - DeviceManager: Identifies devices by IP
//! - BlocklistManager: Manages domain blocklists (loaded from files)
//! - GrantStore: Tracks active time-bounded permissions (SQLite-backed)
//! - ParentalController: Coordinates all components

pub mod blocklist;
pub mod controller;
pub mod device;
pub mod grant;

// Re-export main types
pub use blocklist::BlocklistManager;
pub use controller::{ParentalController, ParentalDecision, ParentalPolicy};
pub use device::DeviceManager;
pub use grant::GrantStore;
