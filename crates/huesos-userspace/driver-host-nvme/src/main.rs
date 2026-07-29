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
const LABEL_CAP: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceSlotKind {
    Mmio,
    Irq,
    DmaPool,
}

struct ResourceSlot {
    kind: ResourceSlotKind,
    label: [u8; LABEL_CAP],
    label_len: usize,
    handle: Option<Handle>,
}

impl ResourceSlot {
    const fn empty(kind: ResourceSlotKind) -> Self {
        Self {
            kind,
            label: [0; LABEL_CAP],
            label_len: 0,
            handle: None,
        }
    }

    fn is_present(&self) -> bool {
        self.handle.is_some()
    }

    fn fill(&mut self, label: &[u8], handle: Handle) {
        self.label_len = label.len().min(self.label.len());
        self.label[..self.label_len].copy_from_slice(&label[..self.label_len]);
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
        let kind = classify_resource(label);
        let mut fallback = Some(handle);
        for slot in &mut self.slots {
            if slot.kind == kind && !slot.is_present() {
                if let Some(handle) = fallback.take() {
                    slot.fill(label, handle);
                }
                break;
            }
        }
        // Unknown/duplicate resources are dropped by Handle's RAII wrapper.
    }

    fn ready(&self) -> bool {
        self.slots.iter().all(ResourceSlot::is_present)
    }
}

fn classify_resource(label: &[u8]) -> ResourceSlotKind {
    if contains(label, b"dma") {
        ResourceSlotKind::DmaPool
    } else if contains(label, b"irq") {
        ResourceSlotKind::Irq
    } else {
        ResourceSlotKind::Mmio
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut index = 0usize;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            return true;
        }
        index += 1;
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-host:nvme] started");
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:nvme:starting");

    let mut state = NvmeBootstrap::new();
    drain_bootstrap_resources(&bootstrap, &mut state);

    if state.ready() {
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
