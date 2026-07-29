//! NVMe DriverHost skeleton.
//!
//! Production design constraints agreed for this driver:
//! - userspace DriverHost, not a kernel storage driver;
//! - resources come from the HBI image / DriverManager bootstrap path;
//! - DMA is a preallocated 64 MiB pool capability;
//! - no heap allocation after initialization;
//! - interrupt-first I/O with MSI-X -> MSI -> polling fallback;
//! - per-CPU queues and async BlockDevice completions in later slices.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::{println, Channel, ErrorCode, Handle};

const REQUIRED_RESOURCES: usize = 3;
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const RESOURCE_TRANSFER_COMPLETE: &[u8] = b"resource:transfer-complete";
const LABEL_CAP: usize = 96;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceSlotKind {
    Mmio,
    Irq,
    DmaPool,
}

impl ResourceSlotKind {
    const fn as_str(&self) -> &'static str {
        match self {
            ResourceSlotKind::Mmio => "mmio",
            ResourceSlotKind::Irq => "irq",
            ResourceSlotKind::DmaPool => "dma",
        }
    }
}

#[derive(Clone, Copy)]
struct ParsedResourceLabel {
    kind: ResourceSlotKind,
    base: u64,
    len: u64,
    exclusive: bool,
}

struct ResourceSlot {
    kind: ResourceSlotKind,
    label: [u8; LABEL_CAP],
    label_len: usize,
    base: u64,
    len: u64,
    exclusive: bool,
    handle: Option<Handle>,
}

impl ResourceSlot {
    const fn empty(kind: ResourceSlotKind) -> Self {
        Self {
            kind,
            label: [0; LABEL_CAP],
            label_len: 0,
            base: 0,
            len: 0,
            exclusive: false,
            handle: None,
        }
    }

    fn is_present(&self) -> bool {
        self.handle.is_some()
    }

    fn fill(&mut self, label: &[u8], parsed: ParsedResourceLabel, handle: Handle) {
        self.label_len = label.len().min(self.label.len());
        self.label[..self.label_len].copy_from_slice(&label[..self.label_len]);
        self.base = parsed.base;
        self.len = parsed.len;
        self.exclusive = parsed.exclusive;
        self.handle = Some(handle);
    }
}

struct NvmeBootstrap {
    slots: [ResourceSlot; REQUIRED_RESOURCES],
}

impl NvmeBootstrap {
    const fn new() -> Self {
        Self {
            slots: [
                ResourceSlot::empty(ResourceSlotKind::Mmio),
                ResourceSlot::empty(ResourceSlotKind::Irq),
                ResourceSlot::empty(ResourceSlotKind::DmaPool),
            ],
        }
    }

    fn record(&mut self, label: &[u8], handle: Handle) {
        let Some(parsed) = parse_resource_label(label) else {
            println!("[driver-host:nvme] dropped malformed resource label");
            drop(handle);
            return;
        };
        let mut fallback = Some(handle);
        for slot in &mut self.slots {
            if slot.kind == parsed.kind && !slot.is_present() {
                if let Some(handle) = fallback.take() {
                    slot.fill(label, parsed, handle);
                }
                break;
            }
        }
        if let Some(duplicate) = fallback {
            println!(
                "[driver-host:nvme] dropped duplicate {} resource",
                parsed.kind.as_str()
            );
            drop(duplicate);
        }
    }

    fn ready(&self) -> bool {
        self.slots.iter().all(ResourceSlot::is_present)
    }

    fn log_summary(&self) {
        for slot in &self.slots {
            if slot.is_present() {
                println!(
                    "[driver-host:nvme] resource {} OK base={:#x} len={:#x}",
                    slot.kind.as_str(),
                    slot.base,
                    slot.len
                );
            } else {
                println!("[driver-host:nvme] resource {} MISSING", slot.kind.as_str());
            }
        }
    }
}

fn parse_resource_label(label: &[u8]) -> Option<ParsedResourceLabel> {
    // Expected label format from init:
    // resource:<driver>:<kind>:0x<base>:0x<len>:<mode>
    let mut parts = label.split(|&byte| byte == b':');
    if parts.next()? != b"resource" {
        return None;
    }
    let driver = parts.next()?;
    if driver.is_empty() {
        return None;
    }
    let kind = match parts.next()? {
        b"mmio" => ResourceSlotKind::Mmio,
        b"irq" => ResourceSlotKind::Irq,
        b"dma" => ResourceSlotKind::DmaPool,
        _ => return None,
    };
    let base = parse_hex_u64(parts.next()?)?;
    let len = parse_hex_u64(parts.next()?)?;
    if len == 0 {
        return None;
    }
    let exclusive = match parts.next()? {
        b"excl" => true,
        b"shared" => false,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(ParsedResourceLabel {
        kind,
        base,
        len,
        exclusive,
    })
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    let digits = bytes.strip_prefix(b"0x")?;
    if digits.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &digit in digits {
        let nibble = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(u64::from(nibble))?;
    }
    Some(value)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-host:nvme] started");
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:nvme:starting");

    let mut state = NvmeBootstrap::new();
    drain_bootstrap_resources(&bootstrap, &mut state);
    state.log_summary();

    if state.ready() {
        println!("[driver-host:nvme] resources: mmio OK, irq OK, dma OK");
        let _ = bootstrap.write(b"driver-host:nvme:resources-ready");
        let _ = bootstrap.write(b"service:block:nvme:ready");
        let _ = bootstrap.write(b"driver-host:nvme:ready");
    } else {
        let _ = bootstrap.write(b"service:block:nvme:missing-resources");
    }

    loop {
        libcanvas::process::yield_now();
    }
}

fn drain_bootstrap_resources(bootstrap: &Channel, state: &mut NvmeBootstrap) {
    let mut buf = [0u8; 96];
    loop {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if buf[..n].starts_with(RESOURCE_LABEL_PREFIX) => {
                state.record(&buf[..n], handle);
            }
            Ok((_n, Some(handle))) => drop(handle),
            Ok((n, None)) if &buf[..n] == RESOURCE_TRANSFER_COMPLETE => return,
            Ok((_n, None)) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(ErrorCode::PeerClosed) => return,
            Err(_) => return,
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-host:nvme] PANIC\n");
    libcanvas::process::exit(-1);
}
