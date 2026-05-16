//! Manual proxy selection group
//!
//! Allows users to manually select which proxy to use from a list.

use async_trait::async_trait;
use std::io::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use super::no_available_proxy_error;
use crate::outbound::{Address, AsyncStream, Outbound};

/// Manual selection proxy group
///
/// Users can select which proxy to use from the list.
pub struct SelectGroup {
    name: String,
    proxies: Vec<Arc<dyn Outbound>>,
    selected: AtomicUsize,
}

impl SelectGroup {
    /// Create a new select group
    pub fn new(name: impl Into<String>, proxies: Vec<Arc<dyn Outbound>>) -> Self {
        Self {
            name: name.into(),
            proxies,
            selected: AtomicUsize::new(0),
        }
    }

    /// Get the group name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get all proxy names
    pub fn proxy_names(&self) -> Vec<&str> {
        self.proxies.iter().map(|p| p.name()).collect()
    }

    /// Get the number of proxies in the group
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if the group is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Get the currently selected proxy index
    pub fn selected_index(&self) -> usize {
        self.selected.load(Ordering::Relaxed)
    }

    /// Get the currently selected proxy
    pub fn current(&self) -> Option<&Arc<dyn Outbound>> {
        let idx = self.selected_index();
        self.proxies.get(idx)
    }

    /// Get the name of the currently selected proxy
    pub fn current_name(&self) -> Option<&str> {
        self.current().map(|p| p.name())
    }

    /// Select a proxy by index
    ///
    /// Returns an error if the index is out of bounds.
    pub fn select(&self, index: usize) -> Result<()> {
        if index >= self.proxies.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Index {} out of bounds (group has {} proxies)",
                    index,
                    self.proxies.len()
                ),
            ));
        }
        self.selected.store(index, Ordering::Relaxed);
        debug!(
            "Selected proxy '{}' in group '{}'",
            self.proxies[index].name(),
            self.name
        );
        Ok(())
    }

    /// Select a proxy by name
    ///
    /// Returns an error if no proxy with the given name exists.
    pub fn select_by_name(&self, name: &str) -> Result<()> {
        let idx = self
            .proxies
            .iter()
            .position(|p| p.name() == name)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Proxy '{}' not found in group '{}'", name, self.name),
                )
            })?;
        self.select(idx)
    }
}

#[async_trait]
impl Outbound for SelectGroup {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect(&self, target: &Address) -> Result<Box<dyn AsyncStream>> {
        let proxy = self.current().ok_or_else(|| no_available_proxy_error(&self.name))?;
        debug!(
            "SelectGroup '{}' connecting via '{}'",
            self.name,
            proxy.name()
        );
        proxy.connect(target).await
    }

    async fn health_check(&self, url: &str, timeout: Duration) -> Result<Duration> {
        let proxy = self.current().ok_or_else(|| no_available_proxy_error(&self.name))?;
        proxy.health_check(url, timeout).await
    }

    fn is_available(&self) -> bool {
        self.current().is_some_and(|p| p.is_available())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectOutbound;

    fn create_test_group() -> SelectGroup {
        let proxies: Vec<Arc<dyn Outbound>> = vec![
            Arc::new(DirectOutbound::new()),
        ];
        SelectGroup::new("test-select", proxies)
    }

    #[test]
    fn test_select_group_new() {
        let group = create_test_group();
        assert_eq!(group.name(), "test-select");
        assert_eq!(group.len(), 1);
        assert!(!group.is_empty());
    }

    #[test]
    fn test_select_group_select() {
        let proxies: Vec<Arc<dyn Outbound>> = vec![
            Arc::new(DirectOutbound::new()),
            Arc::new(DirectOutbound::new()),
        ];
        let group = SelectGroup::new("test", proxies);

        assert_eq!(group.selected_index(), 0);

        group.select(1).unwrap();
        assert_eq!(group.selected_index(), 1);

        // Out of bounds should fail
        assert!(group.select(10).is_err());
    }

    #[test]
    fn test_select_group_select_by_name() {
        let group = create_test_group();

        // DIRECT should exist
        assert!(group.select_by_name("DIRECT").is_ok());

        // Unknown name should fail
        assert!(group.select_by_name("UNKNOWN").is_err());
    }

    #[test]
    fn test_select_group_current() {
        let group = create_test_group();
        assert!(group.current().is_some());
        assert_eq!(group.current_name(), Some("DIRECT"));
    }

    #[test]
    fn test_select_group_proxy_names() {
        let group = create_test_group();
        let names = group.proxy_names();
        assert_eq!(names, vec!["DIRECT"]);
    }

    #[test]
    fn test_select_group_is_available() {
        let group = create_test_group();
        assert!(group.is_available());
    }

    #[test]
    fn test_empty_select_group() {
        let group = SelectGroup::new("empty", vec![]);
        assert!(group.is_empty());
        assert!(!group.is_available());
        assert!(group.current().is_none());
    }
}
