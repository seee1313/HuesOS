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
//! Readiness is two-phase: an immediate fail-closed `Ready` at
//! startup (unchanged contract), then — only after a valid authority
//! burst decodes, validates and maps — a `Ready` with
//! [`Status::ConfigAuthorityReady`].

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::hmcf;
use huesos_abi::pci_manager::{self, Message, Opcode, Status, MESSAGE_BYTES};
use huesos_abi::vmar_flags;
use libcanvas::{println, wait_any, Channel, ErrorCode, Handle, Signals, Vmo, WaitItem};

/// Private, per-manager mapping base for the read-only ECAM windows.
/// Each window is mapped at the next page boundary after the previous
/// one; the region is far from the heap and stack reservations.
const CONFIG_WINDOW_VA_BASE: u64 = 0x0000_0001_0000_0000;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
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
        let mut bytes = [0u8; MESSAGE_BYTES];
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
    /// A fail-closed verdict was already reported; further bursts are
    /// ignored rather than double-reported.
    verdict_sent: bool,
    authorized: bool,
}

impl Default for ConfigAuthority {
    fn default() -> Self {
        Self {
            hmcf: None,
            ecam: [const { None }; hmcf::MAX_RECORDS as usize],
            ecam_count: 0,
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
        // Nothing more is accepted once authority is granted; a stray
        // handle must not accumulate.
        if handle.is_some() {
            drop(handle);
        }
        return true;
    }
    match handle {
        Some(handle) => {
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
    let record_count = view.record_count();
    if authority.ecam_count != record_count || declared_count as usize != record_count {
        println!(
            "[pci-manager] HMCF rejected: {} capability(ies) for {} record(s)",
            authority.ecam_count, record_count
        );
        return reject_authority(bootstrap, authority, manager_generation);
    }

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
        let result = libcanvas::resource::map_self(
            &handle,
            0,
            next_va,
            record.span_bytes,
            vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC,
        );
        // The mapping keeps the resource alive via a kernel reference;
        // the userspace handle is safe to drop after mapping.
        drop(handle);
        if let Err(error) = result {
            println!(
                "[pci-manager] read-only config authority map rejected: {}",
                error.as_str()
            );
            return reject_authority(bootstrap, authority, manager_generation);
        }
        mapped += 1;
        next_va = next_va.saturating_add(record.span_bytes);
    }

    authority.authorized = true;
    println!(
        "[pci-manager] read-only config authority ready: {} window(s), snapshot {}, producer generation {}",
        mapped,
        view.firmware_snapshot_id(),
        view.producer_generation()
    );
    let _ = send(
        bootstrap,
        Message::ready_config_authority(manager_generation, mapped as u32),
    );
    true
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
