//! Parental Control Module
//!
//! Provides device-aware access control with time-based restrictions.
//!
//! Components:
//! - DeviceManager: Identifies devices by IP
//! - ScheduleManager: Evaluates time-based schedules
//! - BlocklistManager: Manages domain blocklists
//! - ParentalController: Coordinates all components

pub mod blocklist;
pub mod controller;
pub mod device;
pub mod schedule;

// Re-export main types
pub use blocklist::BlocklistManager;
pub use controller::{ParentalController, ParentalDecision, ParentalPolicy};
pub use device::DeviceManager;
pub use schedule::ScheduleManager;
