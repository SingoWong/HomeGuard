//! Rule Engine Module
//!
//! Implements Surge-style rule matching for:
//! - DNS filtering (block/allow domains)
//! - Transparent proxy routing (DIRECT/REJECT/Proxy)

mod engine;
pub mod matcher;
mod parser;
mod types;

pub use engine::RuleEngine;
pub use parser::RuleParser;
pub use types::{MatchResult, Policy, Rule, RuleOptions, RuleType};
