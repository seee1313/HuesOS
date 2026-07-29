//! DriverHost launch/supervision loop.

use crate::blobfs_service::BlobFsService;
use crate::devfs_service::DevFsService;
use crate::fs_service::FileSystemService;
use crate::manifest::INPUT_HOST;
use crate::protocol;
use crate::protocol::MANIFEST_GRANTS_COMPLETE_PREFIX;
use crate::registry::{ServiceRegistry, ServiceState};
use crate::volume_service::VolumeManagerService;
use libcanvas::{hbi_boot, println, storage_boot, Channel, ErrorCode, Handle, Process, Vmo};

/// Fallback embedded DriverHost image (same binary packaged into BOOTFS).
/// Prefer this over spawn_elf_from_vmo until VMO-backed launch is fully solid.
static INPUT_HOST_ELF: &[u8] = include_bytes!(env!("HUESOS_INPUT_DRIVER_HOST_PATH"));

/// Wire label prefix init prepends when transferring a
/// manifest-driven resource handle for `<driver_name>`. See
/// `docs/ARCHITECTURE_ROADMAP.md` §4.
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const CRITICAL_INTENT_LABEL_PREFIX: &[u8] = b"resource:mark-critical:";
const NVME_DRIVER_NAME: &[u8] = b"driver-host-nvme";

#[derive(Clone, Copy)]
struct BootDriverSpec {
    elf_path: [u8; hbi_boot::PATH_BYTES],
    elf_path_len: usize,
    manifest_path: [u8; hbi_boot::PATH_BYTES],
    manifest_path_len: usize,
}

impl BootDriverSpec {
    const fn empty() -> Self {
        Self {
            elf_path: [0; hbi_boot::PATH_BYTES],
            elf_path_len: 0,
            manifest_path: [0; hbi_boot::PATH_BYTES],
            manifest_path_len: 0,
        }
    }

    fn elf_path(&self) -> &str {
        core::str::from_utf8(&self.elf_path[..self.elf_path_len]).unwrap_or("")
    }

    fn manifest_path(&self) -> &str {
        core::str::from_utf8(&self.manifest_path[..self.manifest_path_len]).unwrap_or("")
    }
}

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
    nvme_host: Option<ManagedHost>,
    hxfs_service: Option<ManagedHost>,
    hxfs_failed: bool,
    hxfs_ready: bool,
    acpi_manager: Option<ManagedHost>,
    acpi_tables: Option<Vmo>,
    acpi_broker: Option<Handle>,
    registry_channel: Option<Channel>,
    fs: FileSystemService,
    volume: VolumeManagerService,
    devfs: DevFsService,
    blobfs: BlobFsService,
    heartbeat_count: u64,
    acpi_heartbeat_count: u64,
    nvme_heartbeat_count: u64,
    bootfs_loaded: bool,
    storage_boot: Option<storage_boot::StorageBootInfo>,
    nvme_boot_driver: Option<BootDriverSpec>,
    /// Resource handles received from init but not yet forwarded to
    /// their target drivers. Indexed implicitly by driver name via a
    /// linear scan; the number of drivers is small in the MVP so no
    /// hash-map is warranted.
    pending_resources: [PendingResources; 8],
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

const MAX_TRACKED_HOSTS: usize = 8;

struct ManagedHost {
    process: Process,
    bootstrap: Channel,
}

fn parse_nvme_boot_driver_spec(bytes: &[u8]) -> Option<BootDriverSpec> {
    let header_len = 8usize;
    let entry_len = hbi_boot::PATH_BYTES * 2 + 4;
    if bytes.len() < header_len {
        return None;
    }
    let header = hbi_boot::BootDriverManifestHeader {
        magic: read_u32(bytes, 0)?,
        version: read_u16(bytes, 4)?,
        entry_count: read_u16(bytes, 6)?,
    };
    if !hbi_boot::validate_header(header) {
        return None;
    }
    let count = header.entry_count as usize;
    let total = header_len.checked_add(count.checked_mul(entry_len)?)?;
    if bytes.len() < total {
        return None;
    }
    let mut idx = 0usize;
    while idx < count {
        let base = header_len + idx * entry_len;
        let flags = read_u32(bytes, base + hbi_boot::PATH_BYTES * 2)?;
        if flags == 0 {
            let mut spec = BootDriverSpec::empty();
            let elf = bytes.get(base..base + hbi_boot::PATH_BYTES)?;
            let manifest =
                bytes.get(base + hbi_boot::PATH_BYTES..base + hbi_boot::PATH_BYTES * 2)?;
            spec.elf_path_len = copy_nul_terminated(elf, &mut spec.elf_path);
            spec.manifest_path_len = copy_nul_terminated(manifest, &mut spec.manifest_path);
            if spec.manifest_path() == "/manifests/nvme.hdriver" {
                return Some(spec);
            }
        }
        idx += 1;
    }
    None
}

fn copy_nul_terminated(src: &[u8], dst: &mut [u8]) -> usize {
    let mut len = 0usize;
    while len < src.len() && len < dst.len() && src[len] != 0 {
        dst[len] = src[len];
        len += 1;
    }
    len
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

impl DriverManager {
    /// Create DriverManager state from static manifests.
    pub fn new() -> Self {
        let mut registry = ServiceRegistry::new();
        registry.populate_from_manifests();
        Self {
            registry,
            input_host: None,
            nvme_host: None,
            hxfs_service: None,
            hxfs_failed: false,
            hxfs_ready: false,
            acpi_manager: None,
            acpi_tables: None,
            acpi_broker: None,
            registry_channel: None,
            fs: FileSystemService::new(),
            volume: VolumeManagerService::new(),
            devfs: DevFsService::new(),
            blobfs: BlobFsService::new(),
            heartbeat_count: 0,
            acpi_heartbeat_count: 0,
            nvme_heartbeat_count: 0,
            bootfs_loaded: false,
            storage_boot: None,
            nvme_boot_driver: None,
            pending_resources: [
                PendingResources::empty(),
                PendingResources::empty(),
                PendingResources::empty(),
                PendingResources::empty(),
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
        if self.bootfs_loaded
            && self.input_host.is_none()
            && self.driver_grants_ready(b"input-host")
        {
            self.start_input_host();
        }
        if self.bootfs_loaded
            && self.nvme_host.is_none()
            && self.driver_grants_ready(NVME_DRIVER_NAME)
            && self.nvme_boot_driver.is_some()
            && self.storage_boot_has_nvme()
        {
            self.start_nvme_host();
        }
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

    /// Launch the input DriverHost and wait until mandatory services are ready.
    pub fn start_input_host(&mut self) {
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

    fn install_storage_boot_info(&mut self, vmo: Vmo) {
        let mut bytes = [0u8; storage_boot::MAX_ENCODED_BYTES];
        let read = match vmo.read(0, &mut bytes) {
            Ok(n) => n,
            Err(error) => {
                println!(
                    "[driver-manager] storage boot-info read failed: {}",
                    error.as_str()
                );
                return;
            }
        };
        let Some(info) = storage_boot::decode(&bytes[..read]) else {
            println!("[driver-manager] storage boot-info parse failed");
            return;
        };
        println!(
            "[driver-manager] storage boot-info: dma={:#x}+{:#x} nvme_count={}",
            info.dma_pool.base, info.dma_pool.len, info.nvme_count
        );
        if info.nvme_count > 0 {
            let nvme = info.nvme[0];
            println!(
                "[driver-manager] NVMe PCI function: {:02x}:{:02x}.{} bar0={:#x}+{:#x} irq={} flags={:#x}",
                nvme.bus,
                nvme.device,
                nvme.function,
                nvme.bar0_base,
                nvme.bar0_len,
                nvme.irq_line,
                nvme.flags
            );
        }
        self.storage_boot = Some(info);
        self.try_start_pending_hosts();
    }

    fn storage_boot_has_nvme(&self) -> bool {
        self.storage_boot
            .as_ref()
            .is_some_and(|info| info.nvme_count > 0)
    }

    fn load_boot_driver_manifest(&mut self) {
        if self.nvme_boot_driver.is_some() {
            return;
        }
        let Some(bootfs) = self.fs.bootfs() else {
            return;
        };
        let mut bytes = [0u8; 1024];
        let Ok(n) = bootfs.read_file("/storage/boot-drivers.manifest", &mut bytes) else {
            println!("[driver-manager] no storage boot-driver manifest in BOOTFS");
            return;
        };
        let Some(spec) = parse_nvme_boot_driver_spec(&bytes[..n]) else {
            println!("[driver-manager] storage boot-driver manifest has no NVMe entry");
            return;
        };
        println!(
            "[driver-manager] boot driver manifest: nvme elf={} manifest={}",
            spec.elf_path(),
            spec.manifest_path()
        );
        self.nvme_boot_driver = Some(spec);
        self.try_start_pending_hosts();
    }

    fn start_nvme_host(&mut self) {
        let Some(spec) = self.nvme_boot_driver else {
            return;
        };
        let Some(bootfs) = self.fs.bootfs() else {
            return;
        };
        let Some(vmo) = self.fs.vmo() else {
            return;
        };
        let mut manifest_buf = [0u8; 1024];
        let manifest_path = spec.manifest_path();
        let n = match bootfs.read_file(manifest_path, &mut manifest_buf) {
            Ok(n) => n,
            Err(error) => {
                println!(
                    "[driver-manager] failed to read NVMe manifest {}: {}",
                    manifest_path,
                    error.as_str()
                );
                return;
            }
        };
        let Some(manifest) = crate::manifest::parse_hdriver(&manifest_buf[..n]) else {
            println!("[driver-manager] failed to parse NVMe manifest");
            return;
        };
        if manifest.name_as_str().as_bytes() != NVME_DRIVER_NAME {
            println!("[driver-manager] NVMe manifest name mismatch");
            return;
        }
        let elf_path = spec.elf_path();
        let entry = match bootfs.get_entry(elf_path) {
            Ok(Some(entry)) => entry,
            _ => {
                println!("[driver-manager] NVMe DriverHost ELF missing: {}", elf_path);
                return;
            }
        };
        let launched = libcanvas::process::spawn_elf_from_vmo(
            manifest.name_as_str(),
            vmo,
            entry.offset,
            entry.len,
        );
        match launched {
            Ok((process, bootstrap)) => {
                println!("[driver-manager] launched NVMe DriverHost from HBI BOOTFS");
                self.forward_pending_resources(manifest.name_as_str(), &bootstrap, &process);
                self.nvme_host = Some(ManagedHost { process, bootstrap });
                self.wait_for_nvme_host_ready();
            }
            Err(error) => {
                println!(
                    "[driver-manager] failed to launch NVMe DriverHost: {}",
                    error.as_str()
                );
                self.registry.mark_failed("block:nvme");
            }
        }
    }

    /// Main supervision loop.
    pub fn run(&mut self, init_bootstrap: Channel) -> ! {
        loop {
            self.poll_init_bootstrap(&init_bootstrap);
            self.poll_registry_requests();
            self.fs.poll();
            let nvme_online = self.registry.state("block:nvme") == Some(ServiceState::Online);
            self.volume.poll(
                self.nvme_host.as_ref().map(|host| &host.bootstrap),
                nvme_online,
            );
            self.try_start_hxfs_service(nvme_online);
            self.blobfs.poll(
                &mut self.volume,
                self.nvme_host.as_ref().map(|host| &host.bootstrap),
                nvme_online,
            );
            self.devfs.poll(
                &mut self.volume,
                self.nvme_host.as_ref().map(|host| &host.bootstrap),
                nvme_online,
            );
            self.poll_input_host();
            self.poll_nvme_host();
            self.poll_hxfs_service();
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

    fn try_start_hxfs_service(&mut self, nvme_online: bool) {
        if self.hxfs_service.is_some() || self.hxfs_failed || !nvme_online || !self.bootfs_loaded {
            return;
        }
        let block_channel = match (&self.nvme_host, &mut self.volume) {
            (Some(nvme_host), volume) => {
                volume.open_fs_candidate_channel(&nvme_host.bootstrap, nvme_online)
            }
            (None, _) => return,
        };
        let block_channel = match block_channel {
            Ok(channel) => channel,
            Err(_) => return,
        };
        let Some(bootfs) = self.fs.bootfs() else {
            return;
        };
        let Ok(Some(entry)) = bootfs.get_entry("/services/hxfs.elf") else {
            println!("[driver-manager] Hxfs service ELF missing from BOOTFS");
            self.hxfs_failed = true;
            return;
        };
        let Some(bootfs_vmo) = self.fs.vmo() else {
            return;
        };
        let launched = libcanvas::process::spawn_elf_from_vmo(
            "hxfs-service",
            bootfs_vmo,
            entry.offset,
            entry.len,
        );
        let Ok((process, bootstrap)) = launched else {
            println!("[driver-manager] failed to launch Hxfs service");
            self.hxfs_failed = true;
            return;
        };
        if let Err((error, _handle)) = bootstrap.write_handle(
            protocol::HXFS_BLOCK_DEVICE.as_bytes(),
            block_channel.into_handle(),
        ) {
            println!(
                "[driver-manager] failed to transfer Hxfs block device: {}",
                error.as_str()
            );
            self.hxfs_failed = true;
            return;
        }
        println!("[driver-manager] launched read-only Hxfs service");
        self.hxfs_service = Some(ManagedHost { process, bootstrap });
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
        if let Err((error, handle)) = bootstrap.write_handle(
            protocol::ACPI_MANAGER_TABLES.as_bytes(),
            archive.into_handle(),
        ) {
            println!(
                "[driver-manager] failed to transfer ACPI table archive: {}",
                error.as_str()
            );
            self.acpi_tables = Some(Vmo::from_handle(handle));
            return;
        }
        let Some(broker) = self.acpi_broker.take() else {
            return;
        };
        if let Err((error, broker)) =
            bootstrap.write_handle(protocol::ACPI_MANAGER_BROKER.as_bytes(), broker)
        {
            println!(
                "[driver-manager] failed to transfer ACPI broker capability: {}",
                error.as_str()
            );
            self.acpi_broker = Some(broker);
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

    fn wait_for_nvme_host_ready(&mut self) {
        for _ in 0..20_000 {
            self.poll_nvme_host();
            if self.registry.state("block:nvme") == Some(ServiceState::Online) {
                return;
            }
            libcanvas::process::yield_now();
        }
        println!("[driver-manager] NVMe DriverHost did not report resources in time");
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
        // Optionally consume the pending bucket first so we can still
        // send the transfer-complete sentinel even when the driver
        // declared zero grants — child's `consume_manifest_resources`
        // needs the sentinel to exit its blocking drain either way.
        let bucket = self.take_pending_bucket(driver.as_bytes());
        let mut sent = 0usize;
        let mut total = 0usize;
        if let Some(mut bucket) = bucket {
            total = bucket.count;
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
                    Err((e, _handle)) => println!(
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
        } else {
            println!(
                "[driver-manager] no pending resources for {} (manifest declared none, or already forwarded)",
                driver
            );
        }

        // Sentinel: tell the child that manifest resource delivery
        // is done so it can exit its blocking drain loop. Sent even
        // on the zero-grant path so the child never has to know
        // whether its manifest happened to declare any grants —
        // one deterministic exit condition either way.
        if let Err(e) = child_bootstrap.write(protocol::RESOURCE_TRANSFER_COMPLETE.as_bytes()) {
            println!(
                "[driver-manager] resource:transfer-complete send to {} failed: {}",
                driver,
                e.as_str()
            );
        }
        let _ = (sent, total); // keep local totals visible above the sentinel emit.
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
                    self.load_boot_driver_manifest();
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
                Ok((n, Some(handle))) if &buf[..n] == protocol::STORAGE_BOOT_VMO.as_bytes() => {
                    println!("[driver-manager] received storage boot-info VMO");
                    self.install_storage_boot_info(Vmo::from_handle(handle));
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
                Ok(n) if &buf[..n] == protocol::OPEN_DEVFS.as_bytes() => self.open_devfs_service(),
                Ok(n) if &buf[..n] == protocol::OPEN_BLOBFS.as_bytes() => {
                    self.open_blobfs_service()
                }
                Ok(n) if &buf[..n] == protocol::OPEN_HXFS.as_bytes() => self.open_hxfs_service(),
                Ok(n) if &buf[..n] == protocol::OPEN_BLOCK_NVME.as_bytes() => {
                    self.open_nvme_block_service()
                }
                Ok(n) if &buf[..n] == protocol::OPEN_VOLUME_SYSTEM.as_bytes() => {
                    self.open_system_volume()
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

    fn open_devfs_service(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        self.devfs.open_for_registry(registry);
    }

    fn open_blobfs_service(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        let nvme_online = self.registry.state("block:nvme") == Some(ServiceState::Online);
        let nvme_bootstrap = self.nvme_host.as_ref().map(|host| &host.bootstrap);
        self.blobfs
            .open_for_registry(registry, &mut self.volume, nvme_bootstrap, nvme_online);
    }

    fn open_hxfs_service(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        if !self.hxfs_ready {
            let _ = registry.write(protocol::HXFS_UNAVAILABLE.as_bytes());
            return;
        }
        let Some(hxfs) = self.hxfs_service.as_ref() else {
            let _ = registry.write(protocol::HXFS_UNAVAILABLE.as_bytes());
            return;
        };
        match Channel::pair() {
            Ok((client_end, server_end)) => {
                if let Err((error, _handle)) = hxfs.bootstrap.write_handle(
                    protocol::ATTACH_HXFS_CLIENT.as_bytes(),
                    server_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to attach Hxfs client: {}",
                        error.as_str()
                    );
                    let _ = registry.write(protocol::HXFS_UNAVAILABLE.as_bytes());
                    return;
                }
                if let Err((error, _handle)) = registry
                    .write_handle(protocol::HXFS_CHANNEL.as_bytes(), client_end.into_handle())
                {
                    println!(
                        "[driver-manager] failed to return Hxfs channel: {}",
                        error.as_str()
                    );
                }
            }
            Err(_) => {
                let _ = registry.write(protocol::HXFS_UNAVAILABLE.as_bytes());
            }
        }
    }

    fn open_nvme_block_service(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        if self.registry.state("block:nvme") != Some(ServiceState::Online) {
            let _ = registry.write(protocol::BLOCK_NVME_UNAVAILABLE.as_bytes());
            println!("[driver-manager] NVMe BlockDevice requested before online");
            return;
        }
        let Some(nvme_host) = self.nvme_host.as_ref() else {
            let _ = registry.write(protocol::BLOCK_NVME_UNAVAILABLE.as_bytes());
            return;
        };
        match Channel::pair() {
            Ok((client_end, driver_end)) => {
                if let Err((error, _handle)) = nvme_host.bootstrap.write_handle(
                    protocol::ATTACH_BLOCK_NVME_CLIENT.as_bytes(),
                    driver_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to attach NVMe block client: {}",
                        error.as_str()
                    );
                    let _ = registry.write(protocol::BLOCK_NVME_UNAVAILABLE.as_bytes());
                    return;
                }
                if let Err((error, _handle)) = registry.write_handle(
                    protocol::BLOCK_NVME_CHANNEL.as_bytes(),
                    client_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return NVMe block channel: {}",
                        error.as_str()
                    );
                    return;
                }
                println!("[driver-manager] opened NVMe BlockDevice service channel");
            }
            Err(error) => {
                println!(
                    "[driver-manager] failed to create NVMe block channel: {}",
                    error.as_str()
                );
                let _ = registry.write(protocol::BLOCK_NVME_UNAVAILABLE.as_bytes());
            }
        }
    }

    fn open_system_volume(&mut self) {
        let Some(registry) = self.registry_channel.as_ref() else {
            return;
        };
        let nvme_online = self.registry.state("block:nvme") == Some(ServiceState::Online);
        let nvme_bootstrap = self.nvme_host.as_ref().map(|host| &host.bootstrap);
        self.volume
            .open_system_volume(registry, nvme_bootstrap, nvme_online);
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
                if let Err((e, _handle)) = input_host.bootstrap.write_handle(
                    protocol::ATTACH_KEYBOARD_CLIENT.as_bytes(),
                    driver_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to attach keyboard client: {}",
                        e.as_str()
                    );
                    return;
                }
                if let Err((e, _handle)) = registry.write_handle(
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

    fn poll_nvme_host(&mut self) {
        let mut buf = [0u8; 64];
        loop {
            let Some(host) = self.nvme_host.as_ref() else {
                return;
            };
            let _keep_process_alive = &host.process;
            match host.bootstrap.read_into(&mut buf) {
                Ok(n) => self.handle_nvme_host_message(&buf[..n]),
                Err(ErrorCode::ShouldWait) => return,
                Err(error) => {
                    println!(
                        "[driver-manager] NVMe host channel read failed: {}",
                        error.as_str()
                    );
                    self.registry.mark_failed("block:nvme");
                    return;
                }
            }
        }
    }

    fn poll_hxfs_service(&mut self) {
        let mut buf = [0u8; 64];
        loop {
            let Some(host) = self.hxfs_service.as_ref() else {
                return;
            };
            let _keep_process_alive = &host.process;
            match host.bootstrap.read_into(&mut buf) {
                Ok(n) if &buf[..n] == protocol::HXFS_READY.as_bytes() => {
                    self.hxfs_ready = true;
                    println!("[driver-manager] Hxfs service ready");
                }
                Ok(n) if &buf[..n] == protocol::HXFS_SERVICE_UNAVAILABLE.as_bytes() => {
                    self.hxfs_failed = true;
                    self.hxfs_ready = false;
                    println!("[driver-manager] Hxfs service unavailable");
                }
                Ok(_) => {}
                Err(ErrorCode::ShouldWait) => return,
                Err(error) => {
                    println!(
                        "[driver-manager] Hxfs service channel failed: {}",
                        error.as_str()
                    );
                    self.hxfs_failed = true;
                    self.hxfs_ready = false;
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

    fn handle_nvme_host_message(&mut self, msg: &[u8]) {
        if msg == protocol::NVME_HOST_STARTING.as_bytes() {
            println!("[driver-manager] NVMe DriverHost starting");
        } else if msg == protocol::NVME_HOST_RESOURCES_READY.as_bytes()
            || msg == protocol::NVME_BLOCK_READY.as_bytes()
        {
            let owner = self.registry.owner("block:nvme").unwrap_or("unknown-host");
            println!(
                "[driver-manager] registered Stage-A block:nvme resources from {}",
                owner
            );
        } else if msg == protocol::NVME_BLOCK_IDENTIFIED.as_bytes() {
            let owner = self.registry.owner("block:nvme").unwrap_or("unknown-host");
            println!(
                "[driver-manager] registered identified block:nvme namespace from {}",
                owner
            );
            self.registry.mark_online("block:nvme");
        } else if msg == protocol::NVME_BLOCK_BRINGUP_FAILED.as_bytes() {
            println!("[driver-manager] NVMe controller bring-up failed");
            self.registry.mark_failed("block:nvme");
        } else if msg == protocol::NVME_HOST_READY.as_bytes() {
            println!("[driver-manager] NVMe DriverHost ready (resource-only Stage A)");
        } else if msg == protocol::NVME_HOST_MISSING_RESOURCES.as_bytes() {
            println!("[driver-manager] NVMe DriverHost missing required resources");
            self.registry.mark_failed("block:nvme");
        } else if msg == b"heartbeat:nvme" {
            self.nvme_heartbeat_count = self.nvme_heartbeat_count.wrapping_add(1);
        } else {
            println!("[driver-manager] unknown NVMe-host message");
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
