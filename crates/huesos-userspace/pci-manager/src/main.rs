//! Fail-closed userspace PCI Manager.
//!
//! PCI-9 establishes process isolation, typed bootstrap, readiness,
//! heartbeat, and supervisor restart behavior.
//!
//! AP-9 adds generation-bound delivery of read-only configuration
//! authority: DriverManager may later attach an immutable `HMCF`
//! snapshot and one read-only ECAM capability per HMCF record
//! (canonical order), terminated by an `AuthorityComplete` sentinel.
//! The manager independently decodes and validates the image and maps
//! every window read-only before upgrading its readiness report. No
//! PCI configuration space byte is ever read and no topology is
//! exposed; AML-mediated access lands with AP-10.
//!
//! AP-10 additionally:
//!
//! * accepts one private mediation channel end (label
//!   [`huesos_abi::pci_mediation::MEDIATION_CHANNEL_LABEL`]) once the
//!   configuration authority is granted, and serves fixed-size
//!   [`huesos_abi::pci_mediation::Request`]s on it;
//! * performs the physical configuration access itself — read-only
//!   ECAM mappings for the normal backend, or the legacy CF8/CFC
//!   common subset under the conformance-only `force-legacy` feature;
//! * answers every write attempt with [`huesos_abi::pci_mediation::Status::AccessDenied`]
//!   before any hardware access;
//! * binds requests to both manager generations plus the retained
//!   `HMCF` snapshot identity (stale requests are answered, never
//!   executed);
//! * logs one structured observation line per request (op, status,
//!   latency, backend) with stable `obs key=value` keys for CI.
//!
//! Readiness is two-phase: an immediate fail-closed `Ready` at
//! startup (unchanged contract), then — only after a valid authority
//! burst decodes, validates and maps — a `Ready` with
//! [`Status::ConfigAuthorityReady`].

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use huesos_abi::hmcf;
use huesos_abi::pci::{self as abi_pci, ApertureKind, RootBridgeTable};
use huesos_abi::pci_lease::pack_pci_address;
use huesos_abi::pci_manager::{self, Message, Opcode, Status, MESSAGE_BYTES};
use huesos_abi::pci_mediation::{
    self, Opcode as MediationOpcode, Request, Response, Status as MediationStatus, ValidRequest,
    ValidationError,
};
#[cfg(not(feature = "force-legacy"))]
use huesos_abi::vmar_flags;
use huesos_abi::{rights, ResourceKindAbi};
use huesos_pci::bar_sizing::{self, NoActiveLeases};
use huesos_pci::capability;
use huesos_pci::driver_binding::{
    self, BindingDecision, ClassMatch, DeviceMatchRule, DmaPoolGrant, DriverManifestSpec,
    FunctionIdentity, InterruptAllocatorContext, InterruptMode, IrqPreference, MsiCapabilityInfo,
    MsixCapabilityInfo, PrtRouteInfo,
};
use huesos_pci::inventory::{
    ConfigReader, DiagnosticInventory, FirmwareResourceAvailability, InventoryManager,
};
use huesos_pci::lease::{
    DeviceId, DeviceLeasePolicy, DmaIsolation, LeaseEvent, LeaseGeneration, RelocationClass,
};
use huesos_pci::resource_planner::{self, ResourcePlan};
use huesos_pci::resource_validation::{
    ResourceClass, ResourceRegister, ResourceStatus, RootAperture, ValidationReport,
};
use huesos_pci::topology::RootBus;
use huesos_pci::write_policy::{
    self, ConfigReadWriteTransport, HeaderKind, WriteClass, WritePolicyError, WriteRequest,
    COMMAND_WRITABLE_MASK, OFFSET_COMMAND,
};
use huesos_pci::{ConfigWidth, PciAddress, CONVENTIONAL_CONFIG_BYTES, ENHANCED_CONFIG_BYTES};
use libcanvas::{println, wait_any, Channel, ErrorCode, Handle, Port, Signals, Vmo, WaitItem};

#[cfg(feature = "force-legacy")]
use libcanvas::resource::IoPort;

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

/// Private, per-manager mapping base for the read-only ECAM windows.
/// Each window is mapped at the next page boundary after the previous
/// one; the region is far from the heap and stack reservations.
#[cfg(not(feature = "force-legacy"))]
const CONFIG_WINDOW_VA_BASE: u64 = 0x0000_0001_0000_0000;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: called once at process startup before any allocation or
    // additional thread exists.
    if unsafe { !HEAP.init() } {
        libcanvas::debug::write_str("[pci-manager] hardened heap init failed\n");
        libcanvas::process::exit(-10);
    }
    println!("[pci-manager] userspace service started (configuration disabled)");
    let bootstrap = libcanvas::channel::bootstrap();
    let Some(hello) = receive_hello(&bootstrap) else {
        libcanvas::process::exit(-1);
    };

    // Phase 1 readiness (unchanged contract): alive and fail-closed.
    let ready = Message::ready_without_roots(hello.manager_generation);
    if !send(&bootstrap, ready) {
        libcanvas::process::exit(-2);
    }
    println!("[pci-manager] ready without root descriptors; fail-closed");

    let mut authority = ConfigAuthority::default();
    let mut yields = 0u32;
    loop {
        let mut bytes = [0u8; 64];
        match bootstrap.read_optional_handle(&mut bytes) {
            Ok((length, handle)) => {
                if !handle_authority_message(
                    &bootstrap,
                    &bytes[..length],
                    handle,
                    &mut authority,
                    hello.manager_generation,
                ) {
                    libcanvas::process::exit(0);
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => libcanvas::process::exit(0),
        }
        if authority.authorized {
            serve_mediation(&mut authority, hello.manager_generation);
        }

        yields = yields.wrapping_add(1);
        if yields.is_multiple_of(65_536) {
            let _ = send(
                &bootstrap,
                Message {
                    opcode: Opcode::Heartbeat,
                    manager_generation: hello.manager_generation,
                    status: Status::NoRootsFailClosed,
                    detail: 0,
                },
            );
        }
        libcanvas::process::yield_now();
    }
}

/// Accumulated state of one authority burst.
struct ConfigAuthority {
    hmcf: Option<Vmo>,
    ecam: [Option<Handle>; hmcf::MAX_RECORDS as usize],
    ecam_count: usize,
    /// Retained decoded window table, filled in canonical record order
    /// by `finish_authority`. Never re-decoded; the mapping bases below
    /// are the only valid targets for configuration reads.
    windows: [Option<WindowMapping>; hmcf::MAX_RECORDS as usize],
    windows_len: usize,
    firmware_snapshot_id: u64,
    producer_generation: u64,
    /// Validated `HPCI` root-bridge table forwarded after ACPI init (AP-15).
    roots: Option<RootBridgeTable>,
    /// Diagnostic read-only inventory state (AP-16).
    inventory: InventoryManager,
    /// Live BAR sizing validation report (Stage E.1 / AP-19).
    live_validation: Option<ValidationReport>,
    /// Firmware-preserving resource plan (Stage F.2 / AP-19).
    resource_plan: Option<ResourcePlan>,
    /// Kernel `DeviceLeaseAuthority` capability (AP-20).
    device_lease_authority: Option<Handle>,
    /// Active kernel `DeviceLease` handles per discovered PCI function (AP-20).
    leases: Vec<ActiveDeviceLease>,
    /// Whether the Stage G.3 `DeviceGone` self-check ran for this generation.
    gone_probe_done: bool,
    /// Whether Stage H.3 driver binding and Stage I resource handoff ran.
    binding_published: bool,
    #[cfg_attr(feature = "force-legacy", allow(dead_code))]
    rw_ecam: [Option<Handle>; hmcf::MAX_RECORDS as usize],
    #[cfg_attr(feature = "force-legacy", allow(dead_code))]
    rw_ecam_count: usize,
    writable: bool,
    write_upgrading: bool,
    #[cfg(feature = "force-legacy")]
    legacy_ioport: Option<IoPort>,
    mediation: Option<Channel>,
    /// A fail-closed verdict was already reported; further bursts are
    /// ignored rather than double-reported.
    verdict_sent: bool,
    authorized: bool,
}

/// Retained kernel `DeviceLease` for one discovered PCI function (AP-20).
#[allow(dead_code)]
struct ActiveDeviceLease {
    address: PciAddress,
    device_id: u64,
    generation: u64,
    handle: Handle,
}

/// One retained, mapped configuration window.
struct WindowMapping {
    segment: u16,
    bus_start: u8,
    bus_end: u8,
    /// First byte addressable in the mapped region.
    #[cfg_attr(feature = "force-legacy", allow(dead_code))]
    va_base: u64,
    /// Total mapped span in bytes.
    #[cfg_attr(feature = "force-legacy", allow(dead_code))]
    span_bytes: u64,
    /// Retained Mmio capability handle so RO->RW upgrade can unmap and
    /// release the read-only resource cleanly (AP-17).
    #[cfg(not(feature = "force-legacy"))]
    resource: Option<Handle>,
}

impl Default for ConfigAuthority {
    fn default() -> Self {
        Self {
            hmcf: None,
            ecam: [const { None }; hmcf::MAX_RECORDS as usize],
            ecam_count: 0,
            windows: [const { None }; hmcf::MAX_RECORDS as usize],
            windows_len: 0,
            firmware_snapshot_id: 0,
            producer_generation: 0,
            roots: None,
            inventory: InventoryManager::new(),
            live_validation: None,
            resource_plan: None,
            device_lease_authority: None,
            leases: Vec::new(),
            gone_probe_done: false,
            binding_published: false,
            rw_ecam: [const { None }; hmcf::MAX_RECORDS as usize],
            rw_ecam_count: 0,
            writable: false,
            write_upgrading: false,
            #[cfg(feature = "force-legacy")]
            legacy_ioport: None,
            mediation: None,
            verdict_sent: false,
            authorized: false,
        }
    }
}

/// Consume one message of the authority burst (or a stray control
/// message). Returns `false` when the process should exit fail-closed.
fn handle_authority_message(
    bootstrap: &Channel,
    bytes: &[u8],
    handle: Option<Handle>,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) -> bool {
    if authority.authorized {
        // Post-authority messages: the private mediation channel end,
        // the validated `HPCI` root table, or ACPI crash-freeze signals.
        if let Some(handle) = handle {
            if bytes == huesos_abi::pci_mediation::MEDIATION_CHANNEL_LABEL
                && authority.mediation.is_none()
            {
                authority.mediation = Some(Channel::from_handle(handle));
                println!(
                    "[pci-manager] mediation channel established generation {}",
                    manager_generation
                );
            } else if bytes == pci_manager::ROOT_TABLE_VMO_LABEL {
                accept_root_table(bootstrap, handle, authority, manager_generation);
            } else if bytes == pci_manager::CONFIG_ECAM_RW_LABEL {
                if !authority.writable && authority.rw_ecam_count < authority.rw_ecam.len() {
                    authority.rw_ecam[authority.rw_ecam_count] = Some(handle);
                    authority.rw_ecam_count += 1;
                } else {
                    drop(handle);
                }
            } else if bytes == pci_manager::DEVICE_LEASE_AUTHORITY_LABEL {
                if authority.device_lease_authority.is_none() {
                    authority.device_lease_authority = Some(handle);
                    println!("[pci-manager] received DeviceLeaseAuthority");
                    if authority.resource_plan.is_some() && authority.leases.is_empty() {
                        establish_device_leases(bootstrap, authority, manager_generation);
                    }
                } else {
                    drop(handle);
                }
            } else {
                drop(handle);
            }
        } else if let Some(message) = pci_manager::decode(bytes) {
            if message.manager_generation == manager_generation {
                match message.opcode {
                    Opcode::AcpiGenerationFrozen => {
                        handle_acpi_frozen(
                            bootstrap,
                            authority,
                            manager_generation,
                            message.detail != 0,
                        );
                    }
                    Opcode::PrepareWriteUpgrade => {
                        prepare_write_upgrade(bootstrap, authority, manager_generation);
                    }
                    Opcode::WriteAuthorityComplete => {
                        finish_write_authority(
                            bootstrap,
                            authority,
                            manager_generation,
                            message.detail,
                        );
                    }
                    _ => {}
                }
            }
        }
        return true;
    }
    match handle {
        Some(handle) => {
            #[cfg(feature = "force-legacy")]
            if bytes == pci_manager::LEGACY_IOPORT_LABEL {
                if authority.legacy_ioport.is_some() {
                    println!("[pci-manager] legacy backend rejected: duplicate capability");
                    return reject_authority(bootstrap, authority, manager_generation);
                }
                authority.legacy_ioport = Some(IoPort::from_handle(handle));
                return true;
            }
            if bytes == pci_manager::HMCF_VMO_LABEL {
                if authority.hmcf.is_some() {
                    println!("[pci-manager] HMCF rejected: duplicate snapshot");
                    return reject_authority(bootstrap, authority, manager_generation);
                }
                authority.hmcf = Some(Vmo::from_handle(handle));
                return true;
            }
            if bytes == pci_manager::CONFIG_ECAM_LABEL {
                if authority.ecam_count >= authority.ecam.len() {
                    println!("[pci-manager] HMCF rejected: too many capabilities");
                    return reject_authority(bootstrap, authority, manager_generation);
                }
                authority.ecam[authority.ecam_count] = Some(handle);
                authority.ecam_count += 1;
                return true;
            }
            println!("[pci-manager] HMCF rejected: unexpected capability");
            reject_authority(bootstrap, authority, manager_generation)
        }
        None => {
            let Some(message) = pci_manager::decode(bytes) else {
                println!("[pci-manager] HMCF rejected: unreadable control message");
                return reject_authority(bootstrap, authority, manager_generation);
            };
            if message.manager_generation != manager_generation {
                // Same generation discipline as the heartbeat loop;
                // stale control bytes carry no authority.
                println!("[pci-manager] stale control message ignored");
                return true;
            }
            match message.opcode {
                Opcode::AuthorityComplete => {
                    finish_authority(bootstrap, authority, manager_generation, message.detail)
                }
                Opcode::Heartbeat => true,
                _ => {
                    println!("[pci-manager] HMCF rejected: unexpected control message");
                    reject_authority(bootstrap, authority, manager_generation)
                }
            }
        }
    }
}

fn reject_root_table(bootstrap: &Channel, manager_generation: u64, reason: &str) {
    println!("[pci-manager] rejected HPCI root table: {}", reason);
    let _ = send(
        bootstrap,
        Message {
            opcode: Opcode::RootTableRejected,
            manager_generation,
            status: Status::InvalidRootTable,
            detail: 0,
        },
    );
}

fn accept_root_table(
    bootstrap: &Channel,
    handle: Handle,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) {
    let vmo = Vmo::from_handle(handle);
    if authority.inventory.is_frozen() {
        reject_root_table(
            bootstrap,
            manager_generation,
            "inventory frozen after ACPI failure",
        );
        return;
    }
    if authority.roots.is_some() {
        reject_root_table(bootstrap, manager_generation, "duplicate root table");
        return;
    }
    let Some(hmcf_vmo) = authority.hmcf.as_ref() else {
        reject_root_table(bootstrap, manager_generation, "retained HMCF absent");
        return;
    };
    let mut hmcf_hdr = [0u8; hmcf::HEADER_BYTES];
    if !read_vmo_exact(hmcf_vmo, 0, &mut hmcf_hdr) {
        reject_root_table(bootstrap, manager_generation, "HMCF header unreadable");
        return;
    }
    let Ok(hmcf_declared) = hmcf::declared_size(&hmcf_hdr) else {
        reject_root_table(bootstrap, manager_generation, "HMCF header invalid");
        return;
    };
    let mut hmcf_buf = [0u8; hmcf::MAX_BYTES];
    if !read_vmo_exact(hmcf_vmo, 0, &mut hmcf_buf[..hmcf_declared]) {
        reject_root_table(bootstrap, manager_generation, "HMCF body unreadable");
        return;
    }
    let Ok(hmcf_view) = hmcf::decode(&hmcf_buf[..hmcf_declared]) else {
        reject_root_table(bootstrap, manager_generation, "HMCF decode failed");
        return;
    };

    let mut hpci_hdr = [0u8; abi_pci::HEADER_BYTES];
    if !read_vmo_exact(&vmo, 0, &mut hpci_hdr) {
        reject_root_table(bootstrap, manager_generation, "short HPCI header read");
        return;
    }
    let Ok(declared) = abi_pci::declared_size(&hpci_hdr) else {
        reject_root_table(bootstrap, manager_generation, "malformed HPCI header");
        return;
    };
    let mut hpci_buf = [0u8; abi_pci::MAX_ENCODED_BYTES];
    if !read_vmo_exact(&vmo, 0, &mut hpci_buf[..declared]) {
        reject_root_table(bootstrap, manager_generation, "short HPCI body read");
        return;
    }
    let Ok(table) = abi_pci::decode(&hpci_buf[..declared]) else {
        reject_root_table(bootstrap, manager_generation, "HPCI decode failed");
        return;
    };
    if abi_pci::validate_roots_and_hmcf(&table, &hmcf_view).is_err() {
        reject_root_table(
            bootstrap,
            manager_generation,
            "HPCI failed HMCF consistency validation",
        );
        return;
    }
    for root in &table.roots[..table.root_count] {
        let covered_by_window = authority.windows[..authority.windows_len]
            .iter()
            .flatten()
            .any(|w| {
                w.segment == root.segment
                    && root.start_bus >= w.bus_start
                    && root.end_bus <= w.bus_end
            });
        if !covered_by_window {
            reject_root_table(
                bootstrap,
                manager_generation,
                "HPCI root outside mapped config windows",
            );
            return;
        }
    }

    let root_count = table.root_count;
    let aperture_count = table.aperture_count;
    let prt_count = table.prt_count;
    println!(
        "[pci-manager] accepted HPCI root table: {} root(s), {} aperture(s), {} prt(s)",
        root_count, aperture_count, prt_count
    );
    for idx in 0..root_count {
        let root = table.roots[idx];
        let mut direct_prt = 0usize;
        let mut link_prt = 0usize;
        let mut unresolved_prt = 0usize;
        for entry in table.root_prt(idx) {
            match entry.source_kind {
                abi_pci::PrtSourceKind::DirectGsi => direct_prt += 1,
                abi_pci::PrtSourceKind::PciLinkDevice => link_prt += 1,
                abi_pci::PrtSourceKind::UnresolvedLink => unresolved_prt += 1,
            }
        }
        println!(
            "[pci-manager] root[{}] seg={} bus={}..={} prt(direct={}, link={}, unresolved={}) osc={:?} granted=0x{:x} err=0x{:x}",
            idx,
            root.segment,
            root.start_bus,
            root.end_bus,
            direct_prt,
            link_prt,
            unresolved_prt,
            root.osc_status,
            root.osc_granted_control,
            root.osc_error_flags
        );
    }
    let _ = send(
        bootstrap,
        Message {
            opcode: Opcode::RootTableAccepted,
            manager_generation,
            status: Status::Ok,
            detail: root_count as u32,
        },
    );
    publish_inventory_from_hpci(bootstrap, authority, &table, manager_generation);
    authority.roots = Some(table);
}

struct ReadOnlyTransport<'a> {
    windows: &'a [Option<WindowMapping>],
    windows_len: usize,
    #[cfg(feature = "force-legacy")]
    legacy_ioport: Option<&'a IoPort>,
}

impl<'a> ConfigReader for ReadOnlyTransport<'a> {
    fn read_u32(
        &mut self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
    ) -> Option<u32> {
        read_raw_u32(
            self.windows,
            self.windows_len,
            #[cfg(feature = "force-legacy")]
            self.legacy_ioport,
            segment,
            bus,
            device,
            function,
            offset,
        )
    }
}

fn aperture_class(kind: ApertureKind) -> ResourceClass {
    match kind {
        ApertureKind::Io => ResourceClass::Io,
        ApertureKind::Mmio32 => ResourceClass::Mmio32,
        ApertureKind::Mmio64 => ResourceClass::Mmio64,
        ApertureKind::PrefetchableMemory => ResourceClass::PrefetchableMemory,
    }
}

fn publish_inventory_from_hpci(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    table: &RootBridgeTable,
    manager_generation: u64,
) {
    let mut roots = Vec::new();
    for root in &table.roots[..table.root_count] {
        roots.push(RootBus {
            root_id: root.root_id,
            segment: root.segment,
            start_bus: root.start_bus,
            end_bus: root.end_bus,
        });
    }
    let mut apertures = Vec::new();
    for ap in &table.apertures[..table.aperture_count] {
        let Some(owner) = table.roots.get(usize::from(ap.root_index)) else {
            continue;
        };
        apertures.push(RootAperture {
            root_id: owner.root_id,
            class: aperture_class(ap.kind),
            pci_base: ap.pci_base,
            cpu_base: ap.cpu_base,
            len: ap.len,
        });
    }

    let mut transport = ReadOnlyTransport {
        windows: &authority.windows,
        windows_len: authority.windows_len,
        #[cfg(feature = "force-legacy")]
        legacy_ioport: authority.legacy_ioport.as_ref(),
    };
    match authority
        .inventory
        .publish_from_roots(&mut transport, &roots, &apertures)
    {
        Ok(inv) => {
            log_diagnostic_inventory(inv);
            let _ = send(
                bootstrap,
                Message::inventory_published(
                    manager_generation,
                    inv.snapshot.nodes().len() as u32,
                    inv.availability == FirmwareResourceAvailability::Available,
                ),
            );
        }
        Err(err) => {
            println!(
                "[pci-manager] diagnostic PCI inventory build skipped: {:?}",
                err
            );
        }
    }
}

fn handle_acpi_frozen(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
    no_hpci: bool,
) {
    if let Some(preserved) = authority.inventory.last_good() {
        let gen = preserved.generation;
        let nodes = preserved.snapshot.nodes().len();
        authority.inventory.freeze();
        println!(
            "[pci-manager] ACPI frozen; preserved diagnostic PCI inventory gen={} functions={} config-writes=0",
            gen, nodes
        );
        return;
    }

    if no_hpci && !authority.inventory.is_frozen() {
        let mut fallback_roots = Vec::new();
        for (idx, window) in authority.windows[..authority.windows_len]
            .iter()
            .flatten()
            .enumerate()
        {
            fallback_roots.push(RootBus {
                root_id: (idx as u64) + 1,
                segment: window.segment,
                start_bus: window.bus_start,
                end_bus: window.bus_end,
            });
        }
        let mut transport = ReadOnlyTransport {
            windows: &authority.windows,
            windows_len: authority.windows_len,
            #[cfg(feature = "force-legacy")]
            legacy_ioport: authority.legacy_ioport.as_ref(),
        };
        if let Ok(inv) = authority
            .inventory
            .publish_unavailable(&mut transport, &fallback_roots)
        {
            log_diagnostic_inventory(inv);
            let _ = send(
                bootstrap,
                Message::inventory_published(
                    manager_generation,
                    inv.snapshot.nodes().len() as u32,
                    false,
                ),
            );
        }
    }
    authority.inventory.freeze();
}

fn log_diagnostic_inventory(inv: &DiagnosticInventory) {
    let mut res_valid = 0usize;
    let mut res_unrouteable = 0usize;
    let mut res_conflict = 0usize;
    if let Some(report) = inv.validation.as_ref() {
        for entry in report.resources() {
            match entry.status {
                huesos_pci::resource_validation::ResourceStatus::Valid
                | huesos_pci::resource_validation::ResourceStatus::Fixed => res_valid += 1,
                huesos_pci::resource_validation::ResourceStatus::Unrouteable => {
                    res_unrouteable += 1
                }
                huesos_pci::resource_validation::ResourceStatus::Conflicting => res_conflict += 1,
                _ => {}
            }
        }
    }
    for node in inv.snapshot.nodes() {
        let addr = node.function.address;
        println!(
            "[pci-manager] obs inv-dev gen={} seg={} bdf={:02x}:{:02x}.{} vendor=0x{:04x} dev=0x{:04x} class={:02x}:{:02x}:{:02x} depth={} resources={}",
            inv.generation,
            addr.segment(),
            addr.bus(),
            addr.device(),
            addr.function(),
            node.function.vendor_id,
            node.function.device_id,
            node.function.class_code.class,
            node.function.class_code.subclass,
            node.function.class_code.prog_if,
            node.depth,
            inv.availability.as_str()
        );
    }
    println!(
        "[pci-manager] published diagnostic PCI inventory: gen={} roots={} functions={} resources={} valid-res={} unrouteable-res={} conflict-res={} config-writes={}",
        inv.generation,
        inv.snapshot.roots().len(),
        inv.snapshot.nodes().len(),
        inv.availability.as_str(),
        res_valid,
        res_unrouteable,
        res_conflict,
        inv.config_writes
    );
}

/// Report the fail-closed verdict once per generation.
fn reject_authority(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) -> bool {
    if !authority.verdict_sent {
        authority.verdict_sent = true;
        let _ = send(bootstrap, Message::ready_without_roots(manager_generation));
    }
    true
}

/// Validate the completed burst and map every window read-only.
fn finish_authority(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
    declared_count: u32,
) -> bool {
    let Some(hmcf_view) = authority.hmcf.as_ref() else {
        if authority.ecam_count == 0 && declared_count == 0 {
            println!("[pci-manager] no firmware snapshot");
        } else {
            println!("[pci-manager] HMCF rejected: sentinel without snapshot");
        }
        return reject_authority(bootstrap, authority, manager_generation);
    };

    // Independent decode; the image is tiny and fully validated here.
    let mut header = [0u8; hmcf::HEADER_BYTES];
    if !read_vmo_exact(hmcf_view, 0, &mut header) {
        println!("[pci-manager] HMCF rejected: short header read");
        return reject_authority(bootstrap, authority, manager_generation);
    }
    let declared = match hmcf::declared_size(&header) {
        Ok(total) => total,
        Err(error) => {
            println!("[pci-manager] HMCF rejected: {}", hmcf_error_name(error));
            return reject_authority(bootstrap, authority, manager_generation);
        }
    };
    let mut image = [0u8; hmcf::MAX_BYTES];
    if !read_vmo_exact(hmcf_view, 0, &mut image[..declared]) {
        println!("[pci-manager] HMCF rejected: short image read");
        return reject_authority(bootstrap, authority, manager_generation);
    }
    let view = match hmcf::decode(&image[..declared]) {
        Ok(view) => view,
        Err(error) => {
            println!("[pci-manager] HMCF rejected: {}", hmcf_error_name(error));
            return reject_authority(bootstrap, authority, manager_generation);
        }
    };
    #[cfg_attr(feature = "force-legacy", allow(unused_variables))]
    let record_count = view.record_count();
    #[cfg(feature = "force-legacy")]
    {
        // Forced legacy backend: exactly one IoPort capability
        // (CF8/CFC) is expected, no ECAM windows. The HMCF image is
        // still required: requests are bound to its generations and
        // snapshot identity, and its bus maps bound the common subset.
        if authority.legacy_ioport.is_none() {
            println!("[pci-manager] legacy backend requires the CF8/CFC capability");
            return reject_authority(bootstrap, authority, manager_generation);
        }
        if declared_count != 1 {
            println!(
                "[pci-manager] legacy backend rejected: {} declared capability(ies), expected 1",
                declared_count
            );
            return reject_authority(bootstrap, authority, manager_generation);
        }
        if authority.ecam_count != 0 {
            println!("[pci-manager] legacy backend rejected: ECAM capability in legacy burst");
            return reject_authority(bootstrap, authority, manager_generation);
        }
        // Retain the window table (bus maps and segment ids) without
        // mapping anything; reads go through CF8/CFC.
        let mut windows_len = 0usize;
        for record in view.records() {
            if windows_len >= authority.windows.len() {
                break;
            }
            authority.windows[windows_len] = Some(WindowMapping {
                segment: record.segment,
                bus_start: record.start_bus,
                bus_end: record.end_bus,
                va_base: 0,
                span_bytes: record.span_bytes,
            });
            windows_len += 1;
        }
        authority.windows_len = windows_len;
        authority.firmware_snapshot_id = view.firmware_snapshot_id();
        authority.producer_generation = view.producer_generation();
        authority.authorized = true;
        println!(
            "[pci-manager] legacy CF8/CFC config reads ready: snapshot {}, producer generation {}",
            authority.firmware_snapshot_id, authority.producer_generation
        );
        println!(
            "[pci-manager] obs backend=legacy-cf8-cfc windows={} snapshot={}",
            windows_len, authority.firmware_snapshot_id
        );
        let _ = send(
            bootstrap,
            Message::ready_config_authority(manager_generation, 1),
        );
        true
    }
    #[cfg(not(feature = "force-legacy"))]
    {
        if authority.ecam_count != record_count || declared_count as usize != record_count {
            println!(
                "[pci-manager] HMCF rejected: {} capability(ies) for {} record(s)",
                authority.ecam_count, record_count
            );
            return reject_authority(bootstrap, authority, manager_generation);
        }
    }

    #[cfg(not(feature = "force-legacy"))]
    {
        // Map every window read-only at private virtual addresses. The
        // kernel enforces READ-only (the capability carries no WRITE
        // right), `NO_CACHE` for Mmio resources and no executable mapping;
        // validation here is the cheap userspace half of the contract.
        let mut next_va = CONFIG_WINDOW_VA_BASE;
        let mut mapped = 0usize;
        for (index, record) in view.records().enumerate() {
            if record.ecam_base & 0xF_FFFF != 0 || record.span_bytes & 0xF_FFFF != 0 {
                println!("[pci-manager] HMCF rejected: misaligned window geometry");
                return reject_authority(bootstrap, authority, manager_generation);
            }
            let Some(handle) = authority.ecam[index].take() else {
                println!("[pci-manager] HMCF rejected: capability {} missing", index);
                return reject_authority(bootstrap, authority, manager_generation);
            };
            let window_va = next_va;
            let result = libcanvas::resource::map_self(
                &handle,
                0,
                window_va,
                record.span_bytes,
                vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC,
            );
            if let Err(error) = result {
                drop(handle);
                println!(
                    "[pci-manager] read-only config authority map rejected: {}",
                    error.as_str()
                );
                return reject_authority(bootstrap, authority, manager_generation);
            }
            if mapped < authority.windows.len() {
                authority.windows[mapped] = Some(WindowMapping {
                    segment: record.segment,
                    bus_start: record.start_bus,
                    bus_end: record.end_bus,
                    va_base: window_va,
                    span_bytes: record.span_bytes,
                    resource: Some(handle),
                });
            } else {
                drop(handle);
            }
            mapped += 1;
            next_va = next_va.saturating_add(record.span_bytes);
        }
        authority.windows_len = mapped;
        authority.firmware_snapshot_id = view.firmware_snapshot_id();
        authority.producer_generation = view.producer_generation();

        authority.authorized = true;
        println!(
        "[pci-manager] read-only config authority ready: {} window(s), snapshot {}, producer generation {}",
        mapped,
        view.firmware_snapshot_id(),
        view.producer_generation()
    );
        println!(
            "[pci-manager] obs backend=ecam windows={} snapshot={}",
            mapped,
            view.firmware_snapshot_id()
        );
        let _ = send(
            bootstrap,
            Message::ready_config_authority(manager_generation, mapped as u32),
        );
        true
    }
}

fn prepare_write_upgrade(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) {
    if authority.writable || authority.write_upgrading {
        return;
    }
    #[cfg(feature = "force-legacy")]
    {
        let _ = (bootstrap, manager_generation);
    }
    #[cfg(not(feature = "force-legacy"))]
    {
        let mut unmapped = 0usize;
        for window in authority.windows[..authority.windows_len]
            .iter_mut()
            .flatten()
        {
            let Some(handle) = window.resource.take() else {
                println!("[pci-manager] write upgrade rejected: missing RO capability");
                return;
            };
            if let Err(error) =
                libcanvas::resource::unmap_self(&handle, window.va_base, window.span_bytes)
            {
                println!(
                    "[pci-manager] write upgrade unmap failed: {}",
                    error.as_str()
                );
                window.resource = Some(handle);
                return;
            }
            drop(handle);
            window.va_base = 0;
            unmapped += 1;
        }
        authority.write_upgrading = true;
        authority.rw_ecam_count = 0;
        let _ = send(
            bootstrap,
            Message::write_upgrade_prepared(manager_generation, unmapped as u32),
        );
    }
}

fn finish_write_authority(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
    declared_count: u32,
) {
    if authority.writable {
        return;
    }
    #[cfg(feature = "force-legacy")]
    {
        if authority.legacy_ioport.is_none() || declared_count != 1 {
            println!("[pci-manager] legacy write authority rejected");
            return;
        }
        authority.writable = true;
        authority.write_upgrading = false;
        if verify_b4_write_policy(authority, 1) {
            run_live_bar_inventory_and_planner(bootstrap, authority, manager_generation);
            let _ = send(
                bootstrap,
                Message::write_authority_ready(manager_generation, 1),
            );
        } else {
            authority.writable = false;
        }
    }
    #[cfg(not(feature = "force-legacy"))]
    {
        if !authority.write_upgrading
            || authority.rw_ecam_count != authority.windows_len
            || declared_count as usize != authority.windows_len
        {
            println!(
                "[pci-manager] write authority rejected: {} capability(ies) for {} window(s)",
                authority.rw_ecam_count, authority.windows_len
            );
            return;
        }
        let mut next_va = CONFIG_WINDOW_VA_BASE;
        let mut mapped = 0usize;
        for index in 0..authority.windows_len {
            let Some(window) = authority.windows[index].as_mut() else {
                return;
            };
            let Some(handle) = authority.rw_ecam[index].take() else {
                println!(
                    "[pci-manager] write authority rejected: missing RW handle {}",
                    index
                );
                return;
            };
            let window_va = next_va;
            if let Err(error) = libcanvas::resource::map_self(
                &handle,
                0,
                window_va,
                window.span_bytes,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            ) {
                drop(handle);
                println!(
                    "[pci-manager] write-capable config authority map rejected: {}",
                    error.as_str()
                );
                return;
            }
            window.va_base = window_va;
            window.resource = Some(handle);
            next_va = next_va.saturating_add(window.span_bytes);
            mapped += 1;
        }
        authority.writable = true;
        authority.write_upgrading = false;
        if verify_b4_write_policy(authority, mapped) {
            run_live_bar_inventory_and_planner(bootstrap, authority, manager_generation);
            let _ = send(
                bootstrap,
                Message::write_authority_ready(manager_generation, mapped as u32),
            );
        } else {
            authority.writable = false;
        }
    }
}

struct ReadWriteTransport<'a> {
    windows: &'a [Option<WindowMapping>],
    windows_len: usize,
    writable: bool,
    #[cfg(feature = "force-legacy")]
    legacy_ioport: Option<&'a IoPort>,
}

impl<'a> ConfigReadWriteTransport for ReadWriteTransport<'a> {
    fn read_width(&mut self, address: PciAddress, offset: u16, width: ConfigWidth) -> Option<u32> {
        read_raw_width(
            self.windows,
            self.windows_len,
            #[cfg(feature = "force-legacy")]
            self.legacy_ioport,
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
            offset,
            width,
        )
    }

    fn write_width(
        &mut self,
        address: PciAddress,
        offset: u16,
        width: ConfigWidth,
        value: u32,
    ) -> bool {
        if !self.writable {
            return false;
        }
        write_raw_width(
            self.windows,
            self.windows_len,
            #[cfg(feature = "force-legacy")]
            self.legacy_ioport,
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
            offset,
            width,
            value,
        )
    }
}

fn verify_b4_write_policy(authority: &ConfigAuthority, window_count: usize) -> bool {
    let max_config_bytes = if cfg!(feature = "force-legacy") {
        CONVENTIONAL_CONFIG_BYTES
    } else {
        ENHANCED_CONFIG_BYTES
    };
    let mut transport = ReadWriteTransport {
        windows: &authority.windows,
        windows_len: authority.windows_len,
        writable: authority.writable,
        #[cfg(feature = "force-legacy")]
        legacy_ioport: authority.legacy_ioport.as_ref(),
    };

    // 1. Negative B.4 gates: Forbidden, ReadOnlyIdentity, MissingReadbackMask.
    let forbidden = WriteRequest {
        address: PciAddress::ZERO,
        header_kind: HeaderKind::Type0Endpoint,
        class: WriteClass::Forbidden,
        offset: OFFSET_COMMAND,
        width: ConfigWidth::Word,
        max_config_bytes,
        value: 0,
        write_mask: 0x0001,
        expected_readback_mask: 0x0001,
        allowlist_entry: None,
    };
    if write_policy::execute_checked_write(&mut transport, &forbidden)
        != Err(WritePolicyError::ForbiddenClass)
    {
        println!("[pci-manager] b4-policy negative check failed: Forbidden");
        return false;
    }

    let read_only = WriteRequest {
        class: WriteClass::ReadOnlyIdentity,
        offset: 0x00,
        ..forbidden
    };
    if write_policy::execute_checked_write(&mut transport, &read_only)
        != Err(WritePolicyError::ReadOnlyClass)
    {
        println!("[pci-manager] b4-policy negative check failed: ReadOnlyIdentity");
        return false;
    }

    let missing_mask = WriteRequest {
        class: WriteClass::CommandControl,
        expected_readback_mask: 0,
        ..forbidden
    };
    if write_policy::execute_checked_write(&mut transport, &missing_mask)
        != Err(WritePolicyError::MissingReadbackMask)
    {
        println!("[pci-manager] b4-policy negative check failed: MissingReadbackMask");
        return false;
    }

    // 2. Idempotent CommandControl write + readback check on 00:00.0 (preserves existing bits).
    let Some(current_cmd) =
        transport.read_width(PciAddress::ZERO, OFFSET_COMMAND, ConfigWidth::Word)
    else {
        println!("[pci-manager] b4-policy command read failed");
        return false;
    };
    let idempotent = WriteRequest {
        address: PciAddress::ZERO,
        header_kind: HeaderKind::Type0Endpoint,
        class: WriteClass::CommandControl,
        offset: OFFSET_COMMAND,
        width: ConfigWidth::Word,
        max_config_bytes,
        value: current_cmd & COMMAND_WRITABLE_MASK,
        write_mask: COMMAND_WRITABLE_MASK,
        expected_readback_mask: COMMAND_WRITABLE_MASK,
        allowlist_entry: None,
    };
    match write_policy::execute_checked_write(&mut transport, &idempotent) {
        Ok(record) => {
            println!(
                "[pci-manager] obs b4-write class={} bdf=00:00.0 offset=0x{:02x} width={} before=0x{:04x} written=0x{:04x} readback=0x{:04x} mask=0x{:04x} status=ok",
                record.class.as_str(),
                record.offset,
                record.width.bytes(),
                record.before_value,
                record.written_value,
                record.readback_value,
                record.expected_readback_mask
            );
            println!(
                "[pci-manager] write-capable config authority ready: {} window(s), b4-policy=verified",
                window_count
            );
            true
        }
        Err(error) => {
            println!(
                "[pci-manager] b4-policy idempotent write failed: {}",
                error.as_str()
            );
            false
        }
    }
}

fn resource_class_label(class: ResourceClass) -> &'static str {
    match class {
        ResourceClass::Io => "io",
        ResourceClass::Mmio32 => "mmio32",
        ResourceClass::Mmio64 => "mmio64",
        ResourceClass::PrefetchableMemory => "prefetch",
    }
}

fn resource_status_label(status: ResourceStatus) -> &'static str {
    match status {
        ResourceStatus::Valid => "Valid",
        ResourceStatus::Fixed => "Fixed",
        ResourceStatus::Unassigned => "Unassigned",
        ResourceStatus::Conflicting => "Conflicting",
        ResourceStatus::Unrouteable => "Unrouteable",
        ResourceStatus::Unsupported => "Unsupported",
    }
}

fn run_live_bar_inventory_and_planner(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) {
    let Some(table) = authority.roots.as_ref() else {
        return;
    };
    let Some(inv) = authority.inventory.last_good() else {
        return;
    };
    let snapshot = inv.snapshot.clone();
    let mut apertures = Vec::new();
    for ap in &table.apertures[..table.aperture_count] {
        let Some(owner) = table.roots.get(usize::from(ap.root_index)) else {
            continue;
        };
        apertures.push(RootAperture {
            root_id: owner.root_id,
            class: aperture_class(ap.kind),
            pci_base: ap.pci_base,
            cpu_base: ap.cpu_base,
            len: ap.len,
        });
    }

    let mut transport = ReadWriteTransport {
        windows: &authority.windows,
        windows_len: authority.windows_len,
        writable: authority.writable,
        #[cfg(feature = "force-legacy")]
        legacy_ioport: authority.legacy_ioport.as_ref(),
    };

    let live = match bar_sizing::collect_live_bar_inventory(
        &mut transport,
        &snapshot,
        &apertures,
        &NoActiveLeases,
    ) {
        Ok(live) => live,
        Err(err) => {
            println!("[pci-manager] obs e1-bar status=error detail={:?}", err);
            return;
        }
    };

    for entry in live.validation.resources() {
        let r = entry.resource;
        let reg_kind = match r.register {
            ResourceRegister::Bar(i) => ("bar", i),
            ResourceRegister::BridgeWindow(i) => ("win", i),
        };
        println!(
            "[pci-manager] obs e1-bar bdf={:02x}:{:02x}.{} reg={}{} class={} pci=0x{:x} len=0x{:x} assigned={} status={}",
            r.owner.bus(),
            r.owner.device(),
            r.owner.function(),
            reg_kind.0,
            reg_kind.1,
            resource_class_label(r.class),
            r.pci_base,
            r.len,
            r.assigned,
            resource_status_label(entry.status)
        );
    }

    if !live.validation.is_conflict_free() {
        println!(
            "[pci-manager] obs f2-plan status=skipped reason=validation-not-conflict-free roms={}",
            live.rom_bars.len()
        );
        authority.live_validation = Some(live.validation);
        return;
    }

    let plan =
        match resource_planner::plan_firmware_preserving(&snapshot, &apertures, &live.validation) {
            Ok(plan) => plan,
            Err(err) => {
                println!(
                    "[pci-manager] obs f2-plan status=plan-error detail={:?}",
                    err
                );
                authority.live_validation = Some(live.validation);
                return;
            }
        };

    let commit_plan = match resource_planner::build_commit_plan(&snapshot, &plan, &mut transport) {
        Ok(cp) => cp,
        Err(err) => {
            println!(
                "[pci-manager] obs f2-plan status=commit-build-error detail={:?}",
                err
            );
            authority.live_validation = Some(live.validation);
            authority.resource_plan = Some(plan);
            return;
        }
    };

    let writes_len = commit_plan.writes().len();
    if writes_len > 0 {
        if let Err(err) = resource_planner::execute_commit_plan(&commit_plan, &mut transport) {
            println!(
                "[pci-manager] obs f2-plan status=commit-error detail={:?} writes={}",
                err, writes_len
            );
            return;
        }
    }

    println!(
        "[pci-manager] obs f2-plan status=ok planned={} writes={} roms={}",
        plan.resources().len(),
        writes_len,
        live.rom_bars.len()
    );
    authority.live_validation = Some(live.validation);
    authority.resource_plan = Some(plan);
    establish_device_leases(bootstrap, authority, manager_generation);
}

fn establish_device_leases(
    bootstrap: &Channel,
    authority: &mut ConfigAuthority,
    manager_generation: u64,
) {
    let Some(lease_auth) = authority.device_lease_authority.as_ref() else {
        return;
    };
    let Some(inv) = authority.inventory.last_good() else {
        return;
    };
    let snapshot_id = authority.firmware_snapshot_id;
    if snapshot_id == 0 {
        return;
    }

    if !authority.gone_probe_done {
        authority.gone_probe_done = true;
        run_device_gone_self_check(lease_auth, snapshot_id);
    }

    if authority.leases.is_empty() {
        for node in inv.snapshot.nodes() {
            let addr = node.function.address;
            let Some(packed) =
                pack_pci_address(addr.segment(), addr.bus(), addr.device(), addr.function())
            else {
                continue;
            };
            let device_id = packed | (1u64 << 32);
            let Ok(handle) =
                libcanvas::device_lease::create(lease_auth, device_id, snapshot_id, packed)
            else {
                println!(
                    "[pci-manager] obs g2-lease bdf={:02x}:{:02x}.{} status=create-failed",
                    addr.bus(),
                    addr.device(),
                    addr.function()
                );
                continue;
            };
            let Ok(info) = libcanvas::device_lease::query(&handle) else {
                println!(
                    "[pci-manager] obs g2-lease bdf={:02x}:{:02x}.{} status=query-failed",
                    addr.bus(),
                    addr.device(),
                    addr.function()
                );
                continue;
            };
            println!(
                "[pci-manager] obs g2-lease bdf={:02x}:{:02x}.{} device_id=0x{:x} gen={} snapshot=0x{:016x} status=ok",
                addr.bus(),
                addr.device(),
                addr.function(),
                info.device_id,
                info.generation,
                info.firmware_snapshot_id
            );
            authority.leases.push(ActiveDeviceLease {
                address: addr,
                device_id: info.device_id,
                generation: info.generation,
                handle,
            });
        }
    }

    if !authority.binding_published && !authority.leases.is_empty() {
        authority.binding_published = true;
        run_driver_binding_and_handoff(bootstrap, authority, manager_generation);
    }
}

fn run_driver_binding_and_handoff(
    bootstrap: &Channel,
    authority: &ConfigAuthority,
    manager_generation: u64,
) {
    let Some(inv) = authority.inventory.last_good() else {
        return;
    };
    let Some(plan) = authority.resource_plan.as_ref() else {
        return;
    };
    let Some(validation) = authority.live_validation.as_ref() else {
        return;
    };
    let Some(roots) = authority.roots.as_ref() else {
        return;
    };

    let manifests = [
        DriverManifestSpec {
            driver_name: "nvme-host",
            match_rule: DeviceMatchRule {
                vendor_id: None,
                device_id: None,
                subsystem_vendor_id: None,
                subsystem_id: None,
                revision_id: None,
                class: Some(ClassMatch {
                    base: 0x01,
                    sub: 0x08,
                    prog_if: Some(0x02),
                }),
                required_capability_id: None,
            },
            relocation: RelocationClass::Fixed,
            irq_preference: IrqPreference::MsixThenMsiThenIntx,
            max_vectors: 4,
            allow_polling_fallback: true,
        },
        DriverManifestSpec {
            driver_name: "ahci-host",
            match_rule: DeviceMatchRule {
                vendor_id: None,
                device_id: None,
                subsystem_vendor_id: None,
                subsystem_id: None,
                revision_id: None,
                class: Some(ClassMatch {
                    base: 0x01,
                    sub: 0x06,
                    prog_if: Some(0x01),
                }),
                required_capability_id: None,
            },
            relocation: RelocationClass::Fixed,
            irq_preference: IrqPreference::MsiThenIntx,
            max_vectors: 1,
            allow_polling_fallback: false,
        },
    ];

    let mut transport = ReadWriteTransport {
        windows: &authority.windows,
        windows_len: authority.windows_len,
        writable: authority.writable,
        #[cfg(feature = "force-legacy")]
        legacy_ioport: authority.legacy_ioport.as_ref(),
    };
    let mut bound_count = 0u32;

    for lease in &authority.leases {
        let Some(node) = inv
            .snapshot
            .nodes()
            .iter()
            .find(|n| n.function.address == lease.address)
        else {
            continue;
        };

        let mut cfg = [0u8; 256];
        for dword_idx in 0..64usize {
            let off = (dword_idx * 4) as u16;
            let val = transport
                .read_width(lease.address, off, ConfigWidth::Dword)
                .unwrap_or(0xFFFF_FFFF);
            let bytes = val.to_le_bytes();
            cfg[dword_idx * 4..dword_idx * 4 + 4].copy_from_slice(&bytes);
        }

        let revision_id = cfg[0x08];
        let header_type = cfg[0x0E] & 0x7F;
        let (subsystem_vendor_id, subsystem_id) = if header_type == 0 {
            (
                u16::from_le_bytes([cfg[0x2C], cfg[0x2D]]),
                u16::from_le_bytes([cfg[0x2E], cfg[0x2F]]),
            )
        } else {
            (0, 0)
        };
        let interrupt_pin = cfg[0x3D];
        let current_command = u16::from_le_bytes([cfg[0x04], cfg[0x05]]);
        let caps = capability::parse_conventional(&cfg).unwrap_or_default();

        let ident = FunctionIdentity {
            function: node.function,
            revision_id,
            subsystem_vendor_id,
            subsystem_id,
            interrupt_pin,
            capabilities: &caps,
        };

        let Ok(dev_id) = DeviceId::try_new(lease.device_id) else {
            continue;
        };
        let Ok(gen_id) = LeaseGeneration::try_new(lease.generation) else {
            continue;
        };
        let Ok(mut policy) = DeviceLeasePolicy::try_new(
            dev_id,
            gen_id,
            lease.address,
            RelocationClass::Fixed,
            DmaIsolation::Trusted,
        ) else {
            continue;
        };
        let _ = policy.apply(gen_id, LeaseEvent::Configure);

        let decision = match driver_binding::match_driver(&ident, &policy, gen_id, &manifests) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let fc = node.function.class_code;
        match decision {
            BindingDecision::Unbound => {
                println!(
                    "[pci-manager] obs h3-bind bdf={:02x}:{:02x}.{} vendor=0x{:04x} device=0x{:04x} class={:02x}:{:02x}:{:02x} decision=unbound",
                    lease.address.bus(),
                    lease.address.device(),
                    lease.address.function(),
                    node.function.vendor_id,
                    node.function.device_id,
                    fc.class,
                    fc.subclass,
                    fc.prog_if
                );
            }
            BindingDecision::Matched {
                manifest_index,
                score,
            } => {
                let manifest = &manifests[manifest_index];
                bound_count = bound_count.saturating_add(1);
                println!(
                    "[pci-manager] obs h3-bind bdf={:02x}:{:02x}.{} vendor=0x{:04x} device=0x{:04x} class={:02x}:{:02x}:{:02x} decision=matched driver={} score={}",
                    lease.address.bus(),
                    lease.address.device(),
                    lease.address.function(),
                    node.function.vendor_id,
                    node.function.device_id,
                    fc.class,
                    fc.subclass,
                    fc.prog_if,
                    manifest.driver_name,
                    score
                );

                let mut msix_info: Option<MsixCapabilityInfo> = None;
                let mut msi_info: Option<MsiCapabilityInfo> = None;
                for &cap in &caps {
                    if cap.id == driver_binding::PCI_CAP_ID_MSIX && msix_info.is_none() {
                        msix_info = driver_binding::decode_msix_capability(
                            &mut transport,
                            lease.address,
                            cap,
                        );
                    } else if cap.id == driver_binding::PCI_CAP_ID_MSI && msi_info.is_none() {
                        msi_info = driver_binding::decode_msi_capability(
                            &mut transport,
                            lease.address,
                            cap,
                        );
                    }
                }

                let prt_info = if interrupt_pin > 0 {
                    bar_sizing::root_id_of(&inv.snapshot, lease.address).and_then(|root_id| {
                        let root_idx = roots.roots[..roots.root_count]
                            .iter()
                            .position(|r| r.root_id == root_id)?;
                        roots
                            .root_prt(root_idx)
                            .iter()
                            .find(|e| {
                                e.device == lease.address.device() && e.pin == interrupt_pin - 1
                            })
                            .map(|e| PrtRouteInfo {
                                gsi: e.gsi,
                                triggering: e.triggering,
                                polarity: e.polarity,
                            })
                    })
                } else {
                    None
                };

                let irq_ctx = InterruptAllocatorContext {
                    destination_apic_id: 0,
                    interrupt_remapping_active: false,
                    available_vectors: 16,
                    next_base_vector: 0xD0,
                };
                let Ok(irq_plan) = driver_binding::plan_interrupt_transaction(
                    lease.address,
                    &policy,
                    gen_id,
                    manifest,
                    plan,
                    msix_info,
                    msi_info,
                    prt_info,
                    irq_ctx,
                    current_command,
                ) else {
                    println!(
                        "[pci-manager] obs i1-irq bdf={:02x}:{:02x}.{} status=plan-failed",
                        lease.address.bus(),
                        lease.address.device(),
                        lease.address.function()
                    );
                    continue;
                };

                let all_writes_valid = irq_plan
                    .writes
                    .iter()
                    .all(|w| write_policy::validate_write_request(w).is_ok());

                let mut minted_handles: Vec<Handle> = Vec::new();
                for res in validation.resources() {
                    if res.resource.owner != lease.address {
                        continue;
                    }
                    let Some(cpu_base) = res.cpu_base else {
                        continue;
                    };
                    if res.resource.len == 0 {
                        continue;
                    }
                    let kind = match res.resource.class {
                        ResourceClass::Io => ResourceKindAbi::IoPort,
                        ResourceClass::Mmio32
                        | ResourceClass::Mmio64
                        | ResourceClass::PrefetchableMemory => ResourceKindAbi::Mmio,
                    };
                    if let Ok(h) = libcanvas::device_lease::mint_resource(
                        &lease.handle,
                        kind,
                        lease.generation,
                        cpu_base,
                        res.resource.len,
                        true,
                    ) {
                        minted_handles.push(h);
                    }
                }

                let (mode_str, irq_num) = match irq_plan.mode {
                    InterruptMode::Msix { base_vector, .. } => ("msix", base_vector),
                    InterruptMode::Msi { base_vector, .. } => ("msi", base_vector),
                    InterruptMode::Intx { gsi, .. } => ("intx", gsi),
                    InterruptMode::Polling => ("polling", 0),
                };
                if let InterruptMode::Intx { gsi, .. } = irq_plan.mode {
                    if let Ok(irq_h) = libcanvas::device_lease::mint_resource(
                        &lease.handle,
                        ResourceKindAbi::Irq,
                        lease.generation,
                        u64::from(gsi),
                        1,
                        false,
                    ) {
                        minted_handles.push(irq_h);
                    }
                } else if let InterruptMode::Msi {
                    base_vector,
                    vector_count,
                    ..
                }
                | InterruptMode::Msix {
                    base_vector,
                    vector_count,
                    ..
                } = irq_plan.mode
                {
                    if let Ok(irq_h) = libcanvas::device_lease::mint_resource(
                        &lease.handle,
                        ResourceKindAbi::Irq,
                        lease.generation,
                        u64::from(base_vector),
                        u64::from(vector_count),
                        true,
                    ) {
                        minted_handles.push(irq_h);
                    }
                }

                let mut ro_lease_mint_denied = false;
                if let Ok(ro_lease) = lease.handle.duplicate(rights::READ | rights::TRANSFER) {
                    ro_lease_mint_denied = matches!(
                        libcanvas::device_lease::mint_resource(
                            &ro_lease,
                            ResourceKindAbi::Mmio,
                            lease.generation,
                            0xFEE0_0000,
                            0x1000,
                            true,
                        ),
                        Err(ErrorCode::AccessDenied)
                    );
                    let _ = bootstrap.write_handle(pci_manager::DEVICE_LEASE_RO_LABEL, ro_lease);
                }
                let minted_count = minted_handles.len();
                for res_handle in minted_handles {
                    let _ = bootstrap.write_handle(pci_manager::LEASE_RESOURCE_LABEL, res_handle);
                }

                let dma_desc = DmaPoolGrant::try_new(&policy, gen_id, 0x0, 0x0, 0x1000).ok();
                let isolation_str = dma_desc.map_or("Trusted", |d| d.isolation_label());

                println!(
                    "[pci-manager] obs i1-irq bdf={:02x}:{:02x}.{} mode={} irq={} writes={} valid_b4={} minted={} ro_lease_mint_denied={}",
                    lease.address.bus(),
                    lease.address.device(),
                    lease.address.function(),
                    mode_str,
                    irq_num,
                    irq_plan.writes.len(),
                    all_writes_valid,
                    minted_count,
                    ro_lease_mint_denied
                );
                println!(
                    "[pci-manager] obs i2-dma bdf={:02x}:{:02x}.{} isolation={}",
                    lease.address.bus(),
                    lease.address.device(),
                    lease.address.function(),
                    isolation_str
                );
            }
        }
    }

    let _ = send(
        bootstrap,
        Message::driver_binding_published(manager_generation, bound_count),
    );
}

fn run_device_gone_self_check(lease_auth: &Handle, snapshot_id: u64) {
    let probe_device_id = u64::MAX;
    let Some(packed) = pack_pci_address(0, 0xff, 0x1f, 0x07) else {
        return;
    };
    let Ok(probe_lease) =
        libcanvas::device_lease::create(lease_auth, probe_device_id, snapshot_id, packed)
    else {
        println!("[pci-manager] obs g3-gone probe=create-failed");
        return;
    };
    let Ok(port) = Port::create() else {
        println!("[pci-manager] obs g3-gone probe=port-failed");
        return;
    };
    if libcanvas::device_lease::bind_gone_port(&probe_lease, &port, 0xA920).is_err() {
        println!("[pci-manager] obs g3-gone probe=bind-failed");
        return;
    }
    if libcanvas::device_lease::revoke(&probe_lease, 1, 0).is_err() {
        println!("[pci-manager] obs g3-gone probe=revoke-failed");
        return;
    }
    let Ok(packet) = port.read() else {
        println!("[pci-manager] obs g3-gone probe=missing-packet");
        return;
    };
    let post_revoke = libcanvas::device_lease::mint_resource(
        &probe_lease,
        huesos_abi::ResourceKindAbi::Mmio,
        1,
        0xFEE0_0000,
        0x1000,
        true,
    );
    let post_revoke_ok = matches!(post_revoke, Err(ErrorCode::AccessDenied));
    let packet_ok = packet.key == 0xA920
        && packet.packet_type == libcanvas::PORT_PACKET_DEVICE_GONE
        && packet.data[0] == probe_device_id
        && packet.data[1] == 1
        && packet.data[2] == snapshot_id;
    println!(
        "[pci-manager] obs g3-gone probe={} pkt_type={} dev_id=0x{:x} post_revoke_denied={}",
        if packet_ok && post_revoke_ok {
            "ok"
        } else {
            "failed"
        },
        packet.packet_type,
        packet.data[0],
        post_revoke_ok
    );
}

fn read_vmo_exact(vmo: &Vmo, offset: u64, buf: &mut [u8]) -> bool {
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(cursor) = offset.checked_add(filled as u64) else {
            return false;
        };
        match vmo.read(cursor, &mut buf[filled..]) {
            Ok(0) => return false,
            Ok(read_bytes) => filled += read_bytes,
            Err(_) => return false,
        }
    }
    true
}

fn receive_hello(bootstrap: &Channel) -> Option<Message> {
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    let mut bytes = [0u8; MESSAGE_BYTES];
    loop {
        wait_any(&items, 0).ok()?;
        match bootstrap.read_into(&mut bytes) {
            Ok(length) => {
                let message = pci_manager::decode(&bytes[..length])?;
                if message.opcode == Opcode::Hello && message.status == Status::Ok {
                    return Some(message);
                }
                return None;
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => return None,
        }
    }
}

fn send(bootstrap: &Channel, message: Message) -> bool {
    let mut bytes = [0u8; MESSAGE_BYTES];
    let Some(length) = pci_manager::encode(message, &mut bytes) else {
        return false;
    };
    bootstrap.write(&bytes[..length]).is_ok()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[pci-manager] PANIC\n");
    libcanvas::process::exit(-127);
}

const fn hmcf_error_name(error: hmcf::HmcfError) -> &'static str {
    match error {
        hmcf::HmcfError::Truncated => "truncated image",
        hmcf::HmcfError::Format => "malformed envelope",
        hmcf::HmcfError::Reserved => "reserved field non-zero",
        hmcf::HmcfError::Count => "invalid record count",
        hmcf::HmcfError::Checksum => "checksum mismatch",
        hmcf::HmcfError::BusRange => "invalid bus range",
        hmcf::HmcfError::MisalignedBase => "misaligned ECAM base",
        hmcf::HmcfError::Span => "window span mismatch",
        hmcf::HmcfError::AddressOverflow => "physical span overflow",
        hmcf::HmcfError::NotCanonical => "non-canonical record order",
        hmcf::HmcfError::Overlap => "overlapping windows",
        hmcf::HmcfError::StaleGeneration => "stale producer generation",
        hmcf::HmcfError::SnapshotMismatch => "snapshot mismatch",
    }
}

// ---------------------------------------------------------------------------
// AP-10 mediation serving

const MEDIATION_DRAIN_BUDGET: u32 = 8;
#[cfg(not(feature = "force-legacy"))]
const SPAN_PER_BUS: u64 = 1024 * 1024;

/// Drain a bounded number of queued mediation requests.
fn serve_mediation(authority: &mut ConfigAuthority, manager_generation: u64) {
    if authority.mediation.is_none() || authority.write_upgrading {
        return;
    }
    for _ in 0..MEDIATION_DRAIN_BUDGET {
        let next = {
            let Some(channel) = authority.mediation.as_ref() else {
                break;
            };
            let mut bytes = [0u8; pci_mediation::REQUEST_BYTES];
            channel.read_into(&mut bytes).map(|length| (bytes, length))
        };
        match next {
            Ok((bytes, length)) => {
                let Some(channel) = authority.mediation.as_ref() else {
                    break;
                };
                handle_mediation_request(channel, &bytes[..length], authority, manager_generation);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
            Err(_) => {
                println!("[pci-manager] obs mediation peer-closed");
                authority.mediation = None;
                break;
            }
        }
    }
}

fn respond(channel: &Channel, request: &Request, status: MediationStatus, value: u64) {
    let mut bytes = [0u8; pci_mediation::RESPONSE_BYTES];
    let response = Response::for_request(request, status, value);
    let Some(length) = pci_mediation::encode_response(&response, &mut bytes) else {
        return;
    };
    let _ = channel.write(&bytes[..length]);
}

fn handle_mediation_request(
    channel: &Channel,
    bytes: &[u8],
    authority: &ConfigAuthority,
    manager_generation: u64,
) {
    let start = libcanvas::system::monotonic_ticks().unwrap_or(0);
    let Some(request) = pci_mediation::decode_request(bytes) else {
        let response = Response {
            version: pci_mediation::VERSION,
            reserved: 0,
            status: MediationStatus::InvalidRequest as i32,
            correlation_id: 0,
            pci_generation: manager_generation,
            acpi_generation: 0,
            value: 0,
        };
        let mut out = [0u8; pci_mediation::RESPONSE_BYTES];
        if let Some(length) = pci_mediation::encode_response(&response, &mut out) {
            let _ = channel.write(&out[..length]);
        }
        println!("[pci-manager] obs mediation op=unknown status=invalid-request correlation=0");
        return;
    };
    let valid = match request.validate() {
        Ok(valid) => valid,
        Err(error) => {
            respond(channel, &request, MediationStatus::InvalidRequest, 0);
            println!(
                "[pci-manager] obs mediation op=unknown status=invalid-request correlation={} error={}",
                request.correlation_id,
                validation_error_name(error)
            );
            return;
        }
    };
    // Every write variant is denied before any hardware access.
    if valid.opcode == MediationOpcode::Write {
        respond(channel, &request, MediationStatus::AccessDenied, 0);
        println!(
            "[pci-manager] obs mediation op=write status=denied reason=policy correlation={}",
            valid.correlation_id
        );
        return;
    }
    if valid.pci_generation != manager_generation
        || valid.acpi_generation != authority.producer_generation
    {
        respond(channel, &request, MediationStatus::StaleGeneration, 0);
        println!(
            "[pci-manager] obs mediation op=read status=stale-generation correlation={}",
            valid.correlation_id
        );
        return;
    }
    if valid.firmware_snapshot_id != authority.firmware_snapshot_id {
        respond(channel, &request, MediationStatus::SnapshotMismatch, 0);
        println!(
            "[pci-manager] obs mediation op=read status=snapshot-mismatch correlation={}",
            valid.correlation_id
        );
        return;
    }
    match perform_read(authority, &valid) {
        Ok(value) => {
            respond(channel, &request, MediationStatus::Ok, value);
            let latency = libcanvas::system::monotonic_ticks()
                .unwrap_or(0)
                .saturating_sub(start);
            let absent: u64 = if value == all_ones(valid.width) { 1 } else { 0 };
            println!(
                "[pci-manager] obs mediation op=read status=ok seg={} bus={} dev={} fn={} off=0x{:x} width={} correlation={} absent={} latency-ticks={}",
                valid.segment,
                valid.bus,
                valid.device,
                valid.function,
                valid.offset,
                valid.width,
                valid.correlation_id,
                absent,
                latency
            );
        }
        Err(ReadFailure::NoWindow) => {
            respond(channel, &request, MediationStatus::NotFound, 0);
            println!(
                "[pci-manager] obs mediation op=read status=not-found correlation={}",
                valid.correlation_id
            );
        }
        #[cfg(feature = "force-legacy")]
        Err(ReadFailure::LegacyOutOfSubset) => {
            respond(channel, &request, MediationStatus::NotFound, 0);
            println!(
                "[pci-manager] obs mediation op=read status=not-found reason=common-subset correlation={}",
                valid.correlation_id
            );
        }
        #[cfg(feature = "force-legacy")]
        Err(ReadFailure::BackendUnavailable) => {
            respond(channel, &request, MediationStatus::NotReady, 0);
            println!(
                "[pci-manager] obs mediation op=read status=not-ready correlation={}",
                valid.correlation_id
            );
        }
    }
}

#[derive(Clone, Copy)]
enum ReadFailure {
    NoWindow,
    #[cfg(feature = "force-legacy")]
    LegacyOutOfSubset,
    #[cfg(feature = "force-legacy")]
    BackendUnavailable,
}

/// Whether any retained HMCF record covers `(segment, bus)`.
#[cfg(feature = "force-legacy")]
fn bus_covered(authority: &ConfigAuthority, segment: u16, bus: u8) -> bool {
    authority.windows[..authority.windows_len]
        .iter()
        .flatten()
        .any(|window| window.segment == segment && bus >= window.bus_start && bus <= window.bus_end)
}

fn all_ones(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    }
}

const fn validation_error_name(error: ValidationError) -> &'static str {
    match error {
        ValidationError::Version => "version",
        ValidationError::Opcode => "opcode",
        ValidationError::Reserved => "reserved",
        ValidationError::Width => "width",
        ValidationError::Alignment => "alignment",
        ValidationError::DeviceFunction => "device-function",
        ValidationError::Generation => "generation",
        ValidationError::Snapshot => "snapshot",
    }
}

#[cfg(feature = "force-legacy")]
#[allow(clippy::too_many_arguments)]
fn read_raw_u32(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    legacy_ioport: Option<&IoPort>,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> Option<u32> {
    let legacy = legacy_ioport?;
    let covered = windows[..windows_len].iter().flatten().any(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    });
    if !covered || offset >= 256 || (offset & 3) != 0 || device >= 32 || function >= 8 {
        return None;
    }
    let address = 0x8000_0000u32
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset);
    legacy.write_u32(0x0CF8, address).ok()?;
    legacy.read_u32(0x0CFC).ok()
}

#[cfg(not(feature = "force-legacy"))]
fn read_raw_u32(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> Option<u32> {
    if (offset & 3) != 0 || device >= 32 || function >= 8 {
        return None;
    }
    let window = windows[..windows_len].iter().flatten().find(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    })?;
    let function_offset = (bus - window.bus_start) as u64 * SPAN_PER_BUS
        + (u64::from(device) << 15)
        + (u64::from(function) << 12)
        + u64::from(offset);
    if function_offset + 4 > window.span_bytes {
        return None;
    }
    Some(libcanvas::channel::mmio_load::<u32>(
        window.va_base + function_offset,
    ))
}

#[cfg(feature = "force-legacy")]
fn perform_read(authority: &ConfigAuthority, request: &ValidRequest) -> Result<u64, ReadFailure> {
    let Some(legacy) = authority.legacy_ioport.as_ref() else {
        return Err(ReadFailure::BackendUnavailable);
    };
    if !bus_covered(authority, request.segment, request.bus) {
        return Err(ReadFailure::NoWindow);
    }
    // The legacy mechanism cannot address the extended configuration
    // space; only the 256-byte common subset is served.
    if u64::from(request.offset) + u64::from(request.width) > 256 {
        return Err(ReadFailure::LegacyOutOfSubset);
    }
    let address = 0x8000_0000u32
        | (u32::from(request.bus) << 16)
        | (u32::from(request.device) << 11)
        | (u32::from(request.function) << 8)
        | (u32::from(request.offset) & 0xFC);
    legacy
        .write_u32(0x0CF8, address)
        .map_err(|_| ReadFailure::BackendUnavailable)?;
    let port = 0x0CFC + (request.offset & 0x3);
    match request.width {
        1 => legacy.read_u8(port).map(u64::from),
        2 => legacy.read_u16(port).map(u64::from),
        _ => legacy.read_u32(port).map(u64::from),
    }
    .map_err(|_| ReadFailure::BackendUnavailable)
}

#[cfg(not(feature = "force-legacy"))]
fn perform_read(authority: &ConfigAuthority, request: &ValidRequest) -> Result<u64, ReadFailure> {
    let Some(window) = authority.windows[..authority.windows_len]
        .iter()
        .flatten()
        .find(|window| {
            window.segment == request.segment
                && request.bus >= window.bus_start
                && request.bus <= window.bus_end
        })
    else {
        return Err(ReadFailure::NoWindow);
    };
    let function_offset = (request.bus - window.bus_start) as u64 * SPAN_PER_BUS
        + (u64::from(request.device) << 15)
        + (u64::from(request.function) << 12)
        + u64::from(request.offset);
    if function_offset + u64::from(request.width) > window.span_bytes {
        return Err(ReadFailure::NoWindow);
    }
    let address = window.va_base + function_offset;
    // The mapped window is read-only and NO_CACHE; `function_offset +
    // width` was validated against the window span right above and
    // `offset` is aligned to `width` by the request validator. The load
    // is exactly as wide as the validated request.
    let value = match request.width {
        1 => u64::from(libcanvas::channel::mmio_load::<u8>(address)),
        2 => u64::from(libcanvas::channel::mmio_load::<u16>(address)),
        _ => u64::from(libcanvas::channel::mmio_load::<u32>(address)),
    };
    Ok(value)
}

#[cfg(feature = "force-legacy")]
#[allow(clippy::too_many_arguments)]
fn read_raw_width(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    legacy_ioport: Option<&IoPort>,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    width: ConfigWidth,
) -> Option<u32> {
    let legacy = legacy_ioport?;
    let covered = windows[..windows_len].iter().flatten().any(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    });
    let width_bytes = width.bytes();
    if !covered
        || device >= 32
        || function >= 8
        || (offset & (width_bytes - 1)) != 0
        || u32::from(offset) + u32::from(width_bytes) > 256
    {
        return None;
    }
    let address = 0x8000_0000u32
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | (u32::from(offset) & 0xFC);
    legacy.write_u32(0x0CF8, address).ok()?;
    let port = 0x0CFC + (offset & 0x3);
    match width {
        ConfigWidth::Byte => legacy.read_u8(port).ok().map(u32::from),
        ConfigWidth::Word => legacy.read_u16(port).ok().map(u32::from),
        ConfigWidth::Dword => legacy.read_u32(port).ok(),
    }
}

#[cfg(not(feature = "force-legacy"))]
#[allow(clippy::too_many_arguments)]
fn read_raw_width(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    width: ConfigWidth,
) -> Option<u32> {
    let width_bytes = width.bytes();
    if device >= 32
        || function >= 8
        || (offset & (width_bytes - 1)) != 0
        || u32::from(offset) + u32::from(width_bytes) > 4096
    {
        return None;
    }
    let window = windows[..windows_len].iter().flatten().find(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    })?;
    if window.va_base == 0 {
        return None;
    }
    let function_offset = (bus - window.bus_start) as u64 * SPAN_PER_BUS
        + (u64::from(device) << 15)
        + (u64::from(function) << 12)
        + u64::from(offset);
    if function_offset + u64::from(width_bytes) > window.span_bytes {
        return None;
    }
    let address = window.va_base + function_offset;
    Some(match width {
        ConfigWidth::Byte => u32::from(libcanvas::channel::mmio_load::<u8>(address)),
        ConfigWidth::Word => u32::from(libcanvas::channel::mmio_load::<u16>(address)),
        ConfigWidth::Dword => libcanvas::channel::mmio_load::<u32>(address),
    })
}

#[cfg(feature = "force-legacy")]
#[allow(clippy::too_many_arguments)]
fn write_raw_width(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    legacy_ioport: Option<&IoPort>,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    width: ConfigWidth,
    value: u32,
) -> bool {
    let Some(legacy) = legacy_ioport else {
        return false;
    };
    let covered = windows[..windows_len].iter().flatten().any(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    });
    let width_bytes = width.bytes();
    if !covered
        || device >= 32
        || function >= 8
        || (offset & (width_bytes - 1)) != 0
        || u32::from(offset) + u32::from(width_bytes) > 256
    {
        return false;
    }
    let address = 0x8000_0000u32
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | (u32::from(offset) & 0xFC);
    if legacy.write_u32(0x0CF8, address).is_err() {
        return false;
    }
    let port = 0x0CFC + (offset & 0x3);
    match width {
        ConfigWidth::Byte => legacy.write_u8(port, value as u8).is_ok(),
        ConfigWidth::Word => legacy.write_u16(port, value as u16).is_ok(),
        ConfigWidth::Dword => legacy.write_u32(port, value).is_ok(),
    }
}

#[cfg(not(feature = "force-legacy"))]
#[allow(clippy::too_many_arguments)]
fn write_raw_width(
    windows: &[Option<WindowMapping>],
    windows_len: usize,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    width: ConfigWidth,
    value: u32,
) -> bool {
    let width_bytes = width.bytes();
    if device >= 32
        || function >= 8
        || (offset & (width_bytes - 1)) != 0
        || u32::from(offset) + u32::from(width_bytes) > 4096
    {
        return false;
    }
    let Some(window) = windows[..windows_len].iter().flatten().find(|window| {
        window.segment == segment && bus >= window.bus_start && bus <= window.bus_end
    }) else {
        return false;
    };
    if window.va_base == 0 {
        return false;
    }
    let function_offset = (bus - window.bus_start) as u64 * SPAN_PER_BUS
        + (u64::from(device) << 15)
        + (u64::from(function) << 12)
        + u64::from(offset);
    if function_offset + u64::from(width_bytes) > window.span_bytes {
        return false;
    }
    let address = window.va_base + function_offset;
    match width {
        ConfigWidth::Byte => libcanvas::channel::mmio_store::<u8>(address, value as u8),
        ConfigWidth::Word => libcanvas::channel::mmio_store::<u16>(address, value as u16),
        ConfigWidth::Dword => libcanvas::channel::mmio_store::<u32>(address, value),
    }
    true
}
