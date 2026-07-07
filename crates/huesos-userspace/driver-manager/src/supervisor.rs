//! DriverHost launch/supervision loop.

use crate::manifest::INPUT_HOST;
use crate::protocol;
use crate::registry::{ServiceRegistry, ServiceState};
use libcanvas::{println, Channel, ErrorCode, Process};

/// Input DriverHost ELF bytes embedded into DriverManager by build.rs.
pub static INPUT_DRIVER_HOST_ELF: &[u8] = include_bytes!(env!("HUESOS_INPUT_DRIVER_HOST_PATH"));

/// DriverManager runtime.
pub struct DriverManager {
    registry: ServiceRegistry,
    input_host: Option<ManagedHost>,
    heartbeat_count: u64,
}

struct ManagedHost {
    process: Process,
    bootstrap: Channel,
}

impl DriverManager {
    /// Create DriverManager state from static manifests.
    pub fn new() -> Self {
        let mut registry = ServiceRegistry::new();
        registry.populate_from_manifests();
        Self {
            registry,
            input_host: None,
            heartbeat_count: 0,
        }
    }

    /// Launch all MVP DriverHosts and wait until mandatory services are ready.
    pub fn start_driver_hosts(&mut self) {
        self.describe_manifest();
        match libcanvas::process::spawn_elf(INPUT_HOST.name, INPUT_DRIVER_HOST_ELF) {
            Ok((process, bootstrap)) => {
                println!("[driver-manager] launched DriverHost {}", INPUT_HOST.name);
                self.input_host = Some(ManagedHost { process, bootstrap });
                self.wait_for_input_host_ready();
            }
            Err(e) => {
                println!(
                    "[driver-manager] failed to launch DriverHost {}: {}",
                    INPUT_HOST.name,
                    e.as_str()
                );
                self.registry.mark_failed("keyboard");
            }
        }
    }

    /// Main supervision loop.
    pub fn run(&mut self) -> ! {
        loop {
            self.poll_input_host();
            libcanvas::process::yield_now();
        }
    }

    /// Return whether the keyboard service is online.
    pub fn keyboard_ready(&self) -> bool {
        self.registry.state("keyboard") == Some(ServiceState::Online)
    }

    fn describe_manifest(&self) {
        println!(
            "[driver-manager] manifest: host={} services={} irqs={} io_ports={}",
            INPUT_HOST.name,
            INPUT_HOST.services.len(),
            INPUT_HOST.irqs.len(),
            INPUT_HOST.io_ports.len()
        );
    }

    fn wait_for_input_host_ready(&mut self) {
        for _ in 0..4096 {
            self.poll_input_host();
            if self.keyboard_ready() {
                return;
            }
            libcanvas::process::yield_now();
        }
        println!("[driver-manager] input DriverHost did not become ready in time");
    }

    fn poll_input_host(&mut self) {
        let mut buf = [0u8; 64];
        loop {
            let Some(host) = self.input_host.as_ref() else {
                return;
            };
            let _keep_process_alive = &host.process;
            match host.bootstrap.read_into(&mut buf) {
                Ok(n) => self.handle_input_host_message(&buf[..n]),
                Err(ErrorCode::ShouldWait) => return,
                Err(e) => {
                    println!("[driver-manager] input host channel read failed: {}", e.as_str());
                    return;
                }
            }
        }
    }

    fn handle_input_host_message(&mut self, msg: &[u8]) {
        if msg == protocol::INPUT_HOST_STARTING.as_bytes() {
            println!("[driver-manager] input DriverHost starting");
        } else if msg == protocol::KEYBOARD_SERVICE_READY.as_bytes() {
            println!("[driver-manager] registered service keyboard from input-host");
            self.registry.mark_online("keyboard");
        } else if msg == protocol::INPUT_HOST_READY.as_bytes() {
            println!("[driver-manager] input DriverHost ready");
        } else if msg == protocol::KEYBOARD_SERVICE_FAILED.as_bytes() {
            println!("[driver-manager] keyboard service failed");
            self.registry.mark_failed("keyboard");
        } else if msg == protocol::INPUT_HOST_ERROR.as_bytes() {
            println!("[driver-manager] input DriverHost reported error");
        } else if msg == protocol::INPUT_HEARTBEAT.as_bytes() {
            self.heartbeat_count += 1;
            if self.heartbeat_count <= 3 || self.heartbeat_count % 64 == 0 {
                println!("[driver-manager] input heartbeat #{}", self.heartbeat_count);
            }
        } else {
            println!("[driver-manager] unknown input-host message");
        }
    }
}
