//! DriverHost launch/supervision loop.

use crate::fs_service::FileSystemService;
use crate::manifest::INPUT_HOST;
use crate::protocol;
use crate::protocol::MANIFEST_GRANTS_COMPLETE_PREFIX;
use crate::registry::{ServiceRegistry, ServiceState};
use libcanvas::{println, Channel, ErrorCode, Handle, Process, Vmo};

/// Fallback embedded DriverHost image (same binary packaged into BOOTFS).
/// Prefer this over spawn_elf_from_vmo until VMO-backed launch is fully solid.
static INPUT_HOST_ELF: &[u8] = include_bytes!(env!("HUESOS_INPUT_DRIVER_HOST_PATH"));

/// Wire label prefix init prepends when transferring a
/// manifest-driven resource handle for `<driver_name>`. See
/// `docs/ARCHITECTURE_ROADMAP.md` §4.
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const CRITICAL_INTENT_LABEL_PREFIX: &[u8] = b"resource:mark-critical:";

/// Maximum resource handles a single DriverHost manifest may request.
/// Mirrors the manifest parser's `MAX_RESOURCE_GRANTS` bound; kept as
/// a private constant so the accumulator array size is a compile-time
/// literal.
const MAX_PENDING_RESOURCES_PER_DRIVER: usize = 8;

/// Buffered resource handles + labels for one driver, waiting to be
/// forwarded to that driver's bootstrap channel once its host process
/// spawns. This is the DriverManager forward layer that closes the
/// PR-C limitation: init mints handles here, DriverManager holds them,
/// forwards them at spawn time so the driver actually receives them.
struct PendingResources {
    /// Driver name the handles are destined for
    /// (e.g. `"input-host"`), extracted from each label.
    driver: [u8; 32],
    driver_len: usize,
    /// The transferred handles + their original wire labels. Labels
    /// carry `<kind>:<base>:<len>:<mode>` so the driver knows what it
    /// is receiving.
    entries: [PendingResource; MAX_PENDING_RESOURCES_PER_DRIVER],
    count: usize,
    /// Whether init has signalled that this driver's process should
    /// be marked critical after spawn.
    critical_requested: bool,
}

struct PendingResource {
    handle: Option<Handle>,
    label: [u8; 96],
    label_len: usize,
}

impl PendingResources {
    const fn empty() -> Self {
        Self {
            driver: [0; 32],
            driver_len: 0,
            entries: [
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
                PendingResource {
                    handle: None,
                    label: [0; 96],
                    label_len: 0,
                },
            ],
            count: 0,
            critical_requested: false,
        }
    }

    fn driver_name(&self) -> &str {
        core::str::from_utf8(&self.driver[..self.driver_len]).unwrap_or("")
    }
}

/// DriverManager runtime.
pub struct DriverManager {
    registry: ServiceRegistry,
    input_host: Option<ManagedHost>,
    acpi_manager: Option<ManagedHost>,
    acpi_tables: Option<Vmo>,
    acpi_broker: Option<Handle>,
    registry_channel: Option<Channel>,
    fs: FileSystemService,
    heartbeat_count: u64,
    acpi_heartbeat_count: u64,
    bootfs_loaded: bool,
    /// Resource handles received from init but not yet forwarded to
    /// their target drivers. Indexed implicitly by driver name via a
    /// linear scan; the number of drivers is small in the MVP so no
    /// hash-map is warranted.
    pending_resources: [PendingResources; 4],
    pending_resource_count: usize,
    /// Driver names for which init has signalled that every
    /// declared resource grant has been transferred. Populated by
    /// `manifest:grants-complete:<driver>` control messages from
    /// init; consulted by [`try_start_pending_hosts`] before it
    /// spawns any host. A driver never spawns until its name
    /// appears here (or the driver declares zero grants in its
    /// manifest, in which case init still sends the signal so the
    /// two paths converge).
    grants_ready: [[u8; 32]; MAX_TRACKED_HOSTS],
    grants_ready_len: [usize; MAX_TRACKED_HOSTS],
    grants_ready_count: usize,
}

const MAX_TRACKED_HOSTS: usize = 4;

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
            acpi_manager: None,
            acpi_tables: None,
            acpi_broker: None,
            registry_channel: None,
            fs: FileSystemService::new(),
            heartbeat_count: 0,
            acpi_heartbeat_count: 0,
            bootfs_loaded: false,
            pending_resources: [
                PendingResources::empty(),
                PendingResources::empty(),
                PendingResources::empty(),
                PendingResources::empty(),
            ],
            pending_resource_count: 0,
            grants_ready: [[0; 32]; MAX_TRACKED_HOSTS],
            grants_ready_len: [0; MAX_TRACKED_HOSTS],
            grants_ready_count: 0,
        }
    }

    fn mark_driver_grants_ready(&mut self, driver: &[u8]) {
        if self.grants_ready_count >= self.grants_ready.len() {
            println!("[driver-manager] grants-ready table full, ignoring");
            return;
        }
        // De-dup: init may retransmit if a message races. Silently
        // ignore duplicates rather than blowing the small table.
        for i in 0..self.grants_ready_count {
            if &self.grants_ready[i][..self.grants_ready_len[i]] == driver {
                return;
            }
        }
        let idx = self.grants_ready_count;
        let take = driver.len().min(self.grants_ready[idx].len());
        self.grants_ready[idx][..take].copy_from_slice(&driver[..take]);
        self.grants_ready_len[idx] = take;
        self.grants_ready_count += 1;
        println!(
            "[driver-manager] grants-complete for {}",
            core::str::from_utf8(driver).unwrap_or("?")
        );
    }

    fn driver_grants_ready(&self, driver: &[u8]) -> bool {
        for i in 0..self.grants_ready_count {
            if &self.grants_ready[i][..self.grants_ready_len[i]] == driver {
                return true;
            }
        }
        false
    }

    /// Called every time either the BOOTFS VMO or a
    /// `manifest:grants-complete` message lands. Attempts to spawn
    /// each declared host whose prerequisites have all arrived;
    /// hosts whose grants are still in flight are silently skipped
    /// and will be picked up on the next tick.
    fn try_start_pending_hosts(&mut self) {
        if !self.bootfs_loaded || self.input_host.is_some() {
            return;
        }
        if !self.driver_grants_ready(b"input-host") {
            return;
        }
        self.start_driver_hosts();
    }

    fn record_resource_handle(&mut self, label: &[u8], handle: Handle) {
        // Label format is `resource:<driver>:<kind>:<base>:<len>:<mode>`.
        let tail = &label[RESOURCE_LABEL_PREFIX.len()..];
        let Some(colon) = tail.iter().position(|&b| b == b':') else {
            println!("[driver-manager] malformed resource label, dropping handle");
            drop(handle);
            return;
        };
        let driver = &tail[..colon];
        let bucket = self.find_or_create_bucket(driver);
        let Some(bucket) = bucket else {
            println!(
                "[driver-manager] no bucket for driver {:?}; dropping handle",
                core::str::from_utf8(driver).unwrap_or("?")
            );
            drop(handle);
            return;
        };
        if bucket.count >= MAX_PENDING_RESOURCES_PER_DRIVER {
            println!(
                "[driver-manager] resource bucket full for {}; dropping handle",
                bucket.driver_name()
            );
            drop(handle);
            return;
        }
        let slot = &mut bucket.entries[bucket.count];
        let take = label.len().min(slot.label.len());
        slot.label[..take].copy_from_slice(&label[..take]);
        slot.label_len = take;
        slot.handle = Some(handle);
        bucket.count += 1;
    }

    fn record_critical_intent(&mut self, driver_name: &[u8]) {
        let bucket = self.find_or_create_bucket(driver_name);
        let Some(bucket) = bucket else {
            println!(
                "[driver-manager] no bucket for critical intent {:?}",
                core::str::from_utf8(driver_name).unwrap_or("?")
            );
            return;
        };
        bucket.critical_requested = true;
    }

    fn find_or_create_bucket(&mut self, driver: &[u8]) -> Option<&mut PendingResources> {
        // Linear search first (tiny N; simpler than a map and avoids
        // an alloc).
        for i in 0..self.pending_resource_count {
            if &self.pending_resources[i].driver[..self.pending_resources[i].driver_len] == driver {
                return Some(&mut self.pending_resources[i]);
            }
        }
        if self.pending_resource_count >= self.pending_resources.len() {
            return None;
        }
        let idx = self.pending_resource_count;
        let bucket = &mut self.pending_resources[idx];
        let take = driver.len().min(bucket.driver.len());
        bucket.driver[..take].copy_from_slice(&driver[..take]);
        bucket.driver_len = take;
        self.pending_resource_count += 1;
        Some(&mut self.pending_resources[idx])
    }

    /// Take (removing) the pending resource bucket for `driver`, if any.
    fn take_pending_bucket(&mut self, driver: &[u8]) -> Option<PendingResources> {
        for i in 0..self.pending_resource_count {
            if &self.pending_resources[i].driver[..self.pending_resources[i].driver_len] == driver {
                // Swap the last-used slot into place to keep the
                // occupied range compact without an alloc.
                self.pending_resource_count -= 1;
                let last = self.pending_resource_count;
                let taken =
                    core::mem::replace(&mut self.pending_resources[i], PendingResources::empty());
                if i != last {
                    let moved = core::mem::replace(
                        &mut self.pending_resources[last],
                        PendingResources::empty(),
                    );
                    self.pending_resources[i] = moved;
                }
                return Some(taken);
            }
        }
        None
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
                // Forward every manifest-driven Resource handle init
                // buffered for this driver. This closes the PR-C
                // limitation (handles were minted but never delivered
                // to the driver process) end-to-end.
                self.forward_pending_resources(manifest.name_as_str(), &bootstrap, &process);
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
            self.poll_acpi_manager();
            // Multi-channel poll: cannot block on one fd without starving others.
            // Yield cooperatively; hot IRQ path is already blocking in the host.
            libcanvas::process::yield_now();
        }
    }

    /// Return whether the keyboard service is online.
    pub fn keyboard_ready(&self) -> bool {
        self.registry.state("keyboard") == Some(ServiceState::Online)
    }

    fn try_start_acpi_manager(&mut self) {
        if self.acpi_manager.is_some()
            || !self.bootfs_loaded
            || self.acpi_tables.is_none()
            || self.acpi_broker.is_none()
        {
            return;
        }
        let Some(bootfs) = self.fs.bootfs() else {
            return;
        };
        let Ok(Some(entry)) = bootfs.get_entry("/services/acpi-manager.elf") else {
            println!("[driver-manager] ACPI manager ELF missing from BOOTFS");
            return;
        };
        let Some(bootfs_vmo) = self.fs.vmo() else {
            return;
        };
        let launched = libcanvas::process::spawn_elf_from_vmo(
            "acpi-manager",
            bootfs_vmo,
            entry.offset,
            entry.len,
        );
        let Ok((process, bootstrap)) = launched else {
            println!("[driver-manager] failed to launch isolated ACPI manager");
            return;
        };
        let Some(archive) = self.acpi_tables.take() else {
            return;
        };
        if bootstrap
            .write_handle(
                protocol::ACPI_MANAGER_TABLES.as_bytes(),
                archive.into_handle(),
            )
            .is_err()
        {
            println!("[driver-manager] failed to transfer ACPI table archive");
            return;
        }
        let Some(broker) = self.acpi_broker.take() else {
            return;
        };
        if bootstrap
            .write_handle(protocol::ACPI_MANAGER_BROKER.as_bytes(), broker)
            .is_err()
        {
            println!("[driver-manager] failed to transfer ACPI broker capability");
            return;
        }
        println!("[driver-manager] launched isolated Ring-3 ACPI manager");
        self.acpi_manager = Some(ManagedHost { process, bootstrap });
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

    /// Forward every manifest-driven Resource handle init has buffered
    /// for `driver` to that driver's bootstrap channel, using the
    /// original wire label. If init also requested criticality, invoke
    /// `mark_process_critical` on the freshly-spawned process. This
    /// closes the PR-C limitation where handles were minted but never
    /// consumed. See `docs/ARCHITECTURE_ROADMAP.md` §4.
    fn forward_pending_resources(
        &mut self,
        driver: &str,
        child_bootstrap: &Channel,
        child_process: &Process,
    ) {
        let Some(mut bucket) = self.take_pending_bucket(driver.as_bytes()) else {
            println!(
                "[driver-manager] no pending resources for {} (manifest declared none, or already forwarded)",
                driver
            );
            return;
        };
        let total = bucket.count;
        let mut sent = 0usize;
        for entry_idx in 0..total {
            // `handle.take()` on the &mut we already own moves the
            // Handle out without triggering its Drop; write_handle
            // then becomes the sole owner. This is the safe form of
            // the more general "move-out-of-array" pattern.
            let Some(handle) = bucket.entries[entry_idx].handle.take() else {
                continue;
            };
            let entry = &bucket.entries[entry_idx];
            let label = &entry.label[..entry.label_len];
            match child_bootstrap.write_handle(label, handle) {
                Ok(()) => sent += 1,
                Err(e) => println!(
                    "[driver-manager] forward to {} failed for {}: {}",
                    driver,
                    core::str::from_utf8(label).unwrap_or("?"),
                    e.as_str()
                ),
            }
        }
        println!(
            "[driver-manager] forwarded {}/{} resource handle(s) to {}",
            sent, total, driver
        );
        if bucket.critical_requested {
            match libcanvas::resource::mark_process_critical(child_process.handle().raw()) {
                Ok(()) => println!("[driver-manager] marked {} critical", driver),
                Err(e) => println!(
                    "[driver-manager] mark_critical({}) failed: {}",
                    driver,
                    e.as_str()
                ),
            }
        }
    }

    fn poll_init_bootstrap(&mut self, init_bootstrap: &Channel) {
        let mut buf = [0u8; 96];
        loop {
            // Use `read_optional_handle` so we consume every message
            // exactly once regardless of whether it carries a
            // transferred handle. The old `read_handle` path would
            // silently drop plain (no-handle) control messages —
            // `read_optional_handle` returns `Ok(bytes, None)` for
            // them so we can dispatch on the payload string. This is
            // what the `manifest:grants-complete:<driver>` barrier
            // depends on: it flows through init's bootstrap channel
            // interleaved with handle transfers and must not be lost
            // just because it happens to have no handle attached.
            match init_bootstrap.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == protocol::REGISTRY_CHANNEL.as_bytes() => {
                    println!("[driver-manager] received service registry channel from init");
                    self.registry_channel = Some(Channel::from_handle(handle));
                }
                Ok((n, Some(handle))) if &buf[..n] == protocol::BOOTFS_VMO.as_bytes() => {
                    println!("[driver-manager] received BOOTFS VMO from init");
                    self.fs.install_bootfs(Vmo::from_handle(handle));
                    self.bootfs_loaded = true;
                    // NOTE: spawn is deferred to the explicit
                    // `manifest:grants-complete:<driver>` control
                    // message so init has time to mint and
                    // transfer the Resource handles this driver
                    // needs before we hand it off. See
                    // `docs/ARCHITECTURE_ROADMAP.md` §4.
                    self.try_start_pending_hosts();
                    self.try_start_acpi_manager();
                }
                Ok((n, Some(handle))) if &buf[..n] == protocol::ACPI_TABLES_VMO.as_bytes() => {
                    println!("[driver-manager] received immutable ACPI table archive");
                    self.acpi_tables = Some(Vmo::from_handle(handle));
                    self.try_start_acpi_manager();
                }
                Ok((n, Some(handle))) if &buf[..n] == protocol::ACPI_BROKER.as_bytes() => {
                    println!("[driver-manager] received unique ACPI broker capability");
                    self.acpi_broker = Some(handle);
                    self.try_start_acpi_manager();
                }
                Ok((n, Some(handle))) if buf[..n].starts_with(RESOURCE_LABEL_PREFIX) => {
                    // Manifest-driven resource grant from init
                    // (PR-C/PR-D). Buffer here; forward at spawn.
                    self.record_resource_handle(&buf[..n], handle);
                }
                Ok((_n, Some(_handle))) => {
                    println!("[driver-manager] unknown bootstrap handle message")
                }
                Ok((n, None)) if buf[..n].starts_with(CRITICAL_INTENT_LABEL_PREFIX) => {
                    let driver = &buf[CRITICAL_INTENT_LABEL_PREFIX.len()..n];
                    self.record_critical_intent(driver);
                }
                Ok((n, None))
                    if buf[..n].starts_with(MANIFEST_GRANTS_COMPLETE_PREFIX.as_bytes()) =>
                {
                    let driver = &buf[MANIFEST_GRANTS_COMPLETE_PREFIX.len()..n];
                    self.mark_driver_grants_ready(driver);
                    self.try_start_pending_hosts();
                }
                Ok((n, None)) => println!(
                    "[driver-manager] unrecognised init control message ({} B)",
                    n
                ),
                Err(ErrorCode::ShouldWait) => return,
                Err(e) => {
                    println!("[driver-manager] bootstrap read failed: {}", e.as_str());
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

    fn poll_acpi_manager(&mut self) {
        let mut buffer = [0u8; 64];
        loop {
            let Some(host) = self.acpi_manager.as_ref() else {
                return;
            };
            let _keep_process_alive = &host.process;
            match host.bootstrap.read_into(&mut buffer) {
                Ok(length) if &buffer[..length] == protocol::ACPI_MANAGER_READY.as_bytes() => {
                    println!("[driver-manager] ACPI manager archive validation ready");
                }
                Ok(length) if &buffer[..length] == protocol::ACPI_HEARTBEAT.as_bytes() => {
                    self.acpi_heartbeat_count = self.acpi_heartbeat_count.wrapping_add(1);
                }
                Ok(_) => {}
                Err(ErrorCode::ShouldWait) => return,
                Err(error) => {
                    println!(
                        "[driver-manager] ACPI manager channel failed: {}",
                        error.as_str()
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
