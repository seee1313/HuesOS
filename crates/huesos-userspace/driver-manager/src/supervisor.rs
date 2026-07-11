//! DriverHost launch/supervision loop.

use crate::fs_service::FileSystemService;
use crate::manifest::INPUT_HOST;
use crate::protocol;
use crate::registry::{ServiceRegistry, ServiceState};
use libcanvas::{println, Channel, ErrorCode, Process, Vmo};

/// Fallback embedded DriverHost image (same binary packaged into BOOTFS).
/// Prefer this over spawn_elf_from_vmo until VMO-backed launch is fully solid.
static INPUT_HOST_ELF: &[u8] = include_bytes!(env!("HUESOS_INPUT_DRIVER_HOST_PATH"));

/// DriverManager runtime.
pub struct DriverManager {
    registry: ServiceRegistry,
    input_host: Option<ManagedHost>,
    registry_channel: Option<Channel>,
    fs: FileSystemService,
    heartbeat_count: u64,
    bootfs_loaded: bool,
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
            registry_channel: None,
            fs: FileSystemService::new(),
            heartbeat_count: 0,
            bootfs_loaded: false,
        }
    }

    /// Launch all MVP DriverHosts and wait until mandatory services are ready.
    pub fn start_driver_hosts(&mut self) {
        self.describe_manifest();
        let bootfs = match self.fs.bootfs() {
            Some(b) => b,
            None => {
                println!("[driver-manager] cannot start drivers: BOOTFS not loaded");
                return;
            }
        };

        let vmo = match self.fs.vmo() {
            Some(v) => v,
            None => return,
        };

        // 1. Read the manifest for input-host.
        let mut manifest_buf = [0u8; 1024];
        let manifest_path = "/manifests/input-host.hdriver";
        let n = match bootfs.read_file(manifest_path, &mut manifest_buf) {
            Ok(n) => n,
            Err(e) => {
                println!(
                    "[driver-manager] failed to read manifest {}: {}",
                    manifest_path,
                    e.as_str()
                );
                return;
            }
        };

        let manifest = match crate::manifest::parse_hdriver(&manifest_buf[..n]) {
            Some(m) => m,
            None => {
                println!(
                    "[driver-manager] failed to parse manifest {}",
                    manifest_path
                );
                return;
            }
        };

        println!(
            "[driver-manager] manifest loaded: host={} elf={}",
            manifest.name_as_str(),
            manifest.elf_path_as_str()
        );

        // 2. Find the ELF in BOOTFS.
        let elf_path = manifest.elf_path_as_str();
        let entry = match bootfs.get_entry(elf_path) {
            Ok(Some(e)) => e,
            _ => {
                println!("[driver-manager] ELF not found in BOOTFS: {}", elf_path);
                return;
            }
        };

        // 3. Launch DriverHost.
        // Prefer the build-time embedded ELF (reliable). Fall back to BOOTFS VMO
        // launch if embedding is unavailable for some reason.
        let launched = libcanvas::process::spawn_elf(manifest.name_as_str(), INPUT_HOST_ELF)
            .or_else(|e| {
                println!(
                    "[driver-manager] embedded launch failed ({}), trying BOOTFS VMO",
                    e.as_str()
                );
                let _ = entry; // used only for VMO path
                let _ = vmo;
                libcanvas::process::spawn_elf_from_vmo(
                    manifest.name_as_str(),
                    vmo,
                    entry.offset,
                    entry.len,
                )
            });
        match launched {
            Ok((process, bootstrap)) => {
                println!(
                    "[driver-manager] launched DriverHost {}",
                    manifest.name_as_str()
                );
                self.input_host = Some(ManagedHost { process, bootstrap });
                self.wait_for_input_host_ready();
            }
            Err(e) => {
                println!(
                    "[driver-manager] failed to launch DriverHost {}: {}",
                    manifest.name_as_str(),
                    e.as_str()
                );
                self.registry.mark_failed("keyboard");
            }
        }
    }

    /// Main supervision loop.
    pub fn run(&mut self, init_bootstrap: Channel) -> ! {
        loop {
            self.poll_init_bootstrap(&init_bootstrap);
            self.poll_registry_requests();
            self.fs.poll();
            self.poll_input_host();
            // Multi-channel poll: cannot block on one fd without starving others.
            // Yield cooperatively; hot IRQ path is already blocking in the host.
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
        for service in INPUT_HOST.services {
            println!(
                "[driver-manager] capability: service={} required={}",
                service.name, service.required as u8
            );
        }
        for irq in INPUT_HOST.irqs {
            println!("[driver-manager] capability: irq={}", irq);
        }
        for range in INPUT_HOST.io_ports {
            println!(
                "[driver-manager] capability: io={:#x}+{}",
                range.base, range.len
            );
        }
    }

    fn wait_for_input_host_ready(&mut self) {
        // Cooperative poll only — do not timed-park (can eat ready messages
        // or hang if park/wake races). Host sends ready then stays alive.
        for _ in 0..20_000 {
            self.poll_input_host();
            if self.keyboard_ready() {
                return;
            }
            libcanvas::process::yield_now();
        }
        println!("[driver-manager] input DriverHost did not become ready in time");
    }

    fn poll_init_bootstrap(&mut self, init_bootstrap: &Channel) {
        let mut buf = [0u8; 64];
        loop {
            match init_bootstrap.read_handle(&mut buf) {
                Ok((n, handle)) if &buf[..n] == protocol::REGISTRY_CHANNEL.as_bytes() => {
                    println!("[driver-manager] received service registry channel from init");
                    self.registry_channel = Some(Channel::from_handle(handle));
                }
                Ok((n, handle)) if &buf[..n] == protocol::BOOTFS_VMO.as_bytes() => {
                    println!("[driver-manager] received BOOTFS VMO from init");
                    self.fs.install_bootfs(Vmo::from_handle(handle));
                    self.bootfs_loaded = true;
                    self.start_driver_hosts();
                }
                Ok((_n, _handle)) => println!("[driver-manager] unknown bootstrap handle message"),
                Err(ErrorCode::ShouldWait) => return,
                Err(e) => {
                    // Plain heartbeat/control messages may arrive without handles later.
                    if e != ErrorCode::InvalidArgs {
                        println!("[driver-manager] bootstrap read failed: {}", e.as_str());
                    }
                    return;
                }
            }
        }
    }

    fn poll_registry_requests(&mut self) {
        let mut buf = [0u8; 64];
        loop {
            let Some(registry) = self.registry_channel.as_ref() else {
                return;
            };
            match registry.read_into(&mut buf) {
                Ok(n) if &buf[..n] == protocol::OPEN_KEYBOARD.as_bytes() => {
                    self.open_keyboard_service()
                }
                Ok(n) if &buf[..n] == protocol::OPEN_FILESYSTEM.as_bytes() => {
                    self.open_filesystem_service()
                }
                Ok(_) => println!("[driver-manager] unknown registry request"),
                Err(ErrorCode::ShouldWait) => return,
                Err(e) => {
                    println!("[driver-manager] registry read failed: {}", e.as_str());
                    return;
                }
            }
        }
    }

    fn open_filesystem_service(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        self.fs.open_for_registry(registry);
    }

    fn open_keyboard_service(&mut self) {
        if !self.keyboard_ready() {
            println!("[driver-manager] keyboard service requested before ready");
            return;
        }
        let Some(input_host) = self.input_host.as_ref() else {
            return;
        };
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        match Channel::pair() {
            Ok((client_end, driver_end)) => {
                if let Err(e) = input_host.bootstrap.write_handle(
                    protocol::ATTACH_KEYBOARD_CLIENT.as_bytes(),
                    driver_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to attach keyboard client: {}",
                        e.as_str()
                    );
                    return;
                }
                if let Err(e) = registry.write_handle(
                    protocol::KEYBOARD_CHANNEL.as_bytes(),
                    client_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return keyboard channel: {}",
                        e.as_str()
                    );
                    return;
                }
                println!("[driver-manager] opened keyboard service channel for client");
            }
            Err(e) => println!(
                "[driver-manager] failed to create keyboard service channel: {}",
                e.as_str()
            ),
        }
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
                    println!(
                        "[driver-manager] input host channel read failed: {}",
                        e.as_str()
                    );
                    return;
                }
            }
        }
    }

    fn handle_input_host_message(&mut self, msg: &[u8]) {
        if msg == protocol::INPUT_HOST_STARTING.as_bytes() {
            println!("[driver-manager] input DriverHost starting");
        } else if msg == protocol::KEYBOARD_SERVICE_READY.as_bytes() {
            let owner = self.registry.owner("keyboard").unwrap_or("unknown-host");
            println!(
                "[driver-manager] registered service keyboard from {}",
                owner
            );
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
            if self.heartbeat_count <= 3 || self.heartbeat_count.is_multiple_of(64) {
                println!("[driver-manager] input heartbeat #{}", self.heartbeat_count);
            }
        } else {
            println!("[driver-manager] unknown input-host message");
        }
    }
}
