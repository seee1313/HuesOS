//! Small fixed-size service registry owned by DriverManager.

use crate::manifest::{DriverHostManifest, DRIVER_HOSTS};

const MAX_SERVICES: usize = 8;

/// Runtime service state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is known from manifest but not online yet.
    Offline,
    /// Service provider reported ready.
    Online,
    /// Service provider reported failure.
    Failed,
}

/// One registered service entry.
#[derive(Clone, Copy)]
pub struct ServiceEntry {
    /// Service name.
    pub name: &'static str,
    /// Owning DriverHost name.
    pub host: &'static str,
    /// Runtime state.
    pub state: ServiceState,
}

/// Fixed service registry.
pub struct ServiceRegistry {
    services: [Option<ServiceEntry>; MAX_SERVICES],
}

impl ServiceRegistry {
    /// Build registry from static manifests.
    pub const fn new() -> Self {
        Self {
            services: [None; MAX_SERVICES],
        }
    }

    /// Populate from `DRIVER_HOSTS` manifest table.
    pub fn populate_from_manifests(&mut self) {
        let mut host_idx = 0;
        while host_idx < DRIVER_HOSTS.len() {
            self.add_host(DRIVER_HOSTS[host_idx]);
            host_idx += 1;
        }
    }

    /// Return the manifest owner for a registered service.
    pub fn owner(&self, name: &str) -> Option<&'static str> {
        self.services
            .iter()
            .flatten()
            .find(|service| service.name == name)
            .map(|service| service.host)
    }

    /// Mark a service online.
    pub fn mark_online(&mut self, name: &str) {
        self.set_state(name, ServiceState::Online);
    }

    /// Mark a service failed.
    pub fn mark_failed(&mut self, name: &str) {
        self.set_state(name, ServiceState::Failed);
    }

    /// Return service state by name.
    pub fn state(&self, name: &str) -> Option<ServiceState> {
        let mut idx = 0;
        while idx < self.services.len() {
            if let Some(service) = self.services[idx] {
                if service.name.as_bytes() == name.as_bytes() {
                    return Some(service.state);
                }
            }
            idx += 1;
        }
        None
    }

    fn add_host(&mut self, host: DriverHostManifest) {
        let mut service_idx = 0;
        while service_idx < host.services.len() {
            let service = host.services[service_idx];
            self.insert(ServiceEntry {
                name: service.name,
                host: host.name,
                state: ServiceState::Offline,
            });
            service_idx += 1;
        }
    }

    fn insert(&mut self, entry: ServiceEntry) {
        let mut idx = 0;
        while idx < self.services.len() {
            if self.services[idx].is_none() {
                self.services[idx] = Some(entry);
                return;
            }
            idx += 1;
        }
    }

    fn set_state(&mut self, name: &str, state: ServiceState) {
        let mut idx = 0;
        while idx < self.services.len() {
            if let Some(mut service) = self.services[idx] {
                if service.name.as_bytes() == name.as_bytes() {
                    service.state = state;
                    self.services[idx] = Some(service);
                    return;
                }
            }
            idx += 1;
        }
    }
}
