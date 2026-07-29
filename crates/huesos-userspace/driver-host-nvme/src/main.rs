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

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::ptr::null_mut;
use huesos_nvme::controller::{Controller, ControllerConfig, NvmeError};
use huesos_nvme::device::{BarRegion, DeviceResources, DmaRegion};
use huesos_nvme::pci_transport::PciMmioTransport;
use libcanvas::{println, Channel, ErrorCode, Handle, Interrupt, Port};

const REQUIRED_RESOURCES: usize = 3;
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const RESOURCE_TRANSFER_COMPLETE: &[u8] = b"resource:transfer-complete";
const LABEL_CAP: usize = 96;
const MMIO_MAP_ADDR: u64 = 0x0000_7000_0000_0000;
const DMA_MAP_ADDR: u64 = 0x0000_7100_0000_0000;
const MSI_VECTOR_BASE: u64 = 0xD0;
const MAX_BOUND_INTERRUPTS: usize = 16;

struct NoHeapAllocator;

// SAFETY: this DriverHost intentionally has no heap. Returning null for every
// allocation request makes accidental heap use fail immediately instead of
// silently violating the no-heap-after-init NVMe policy. `dealloc` is a no-op
// because this allocator never hands out memory.
unsafe impl GlobalAlloc for NoHeapAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: NoHeapAllocator = NoHeapAllocator;

struct InterruptSlot {
    handle: Option<Interrupt>,
}

impl InterruptSlot {
    const fn empty() -> Self {
        Self { handle: None }
    }
}

struct InterruptState {
    port: Port,
    slots: [InterruptSlot; MAX_BOUND_INTERRUPTS],
    count: usize,
}

impl InterruptState {
    fn keepalive_marker(&self) -> usize {
        let mut live = usize::from(self.port.handle().raw() != 0);
        for slot in &self.slots {
            if slot.handle.is_some() {
                live += 1;
            }
        }
        live
    }
}

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

    fn handle(&self) -> Option<&Handle> {
        self.handle.as_ref()
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

    fn slot(&self, kind: ResourceSlotKind) -> Option<&ResourceSlot> {
        self.slots.iter().find(|slot| slot.kind == kind)
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

    let mut interrupt_state: Option<InterruptState> = None;
    if state.ready() {
        println!("[driver-host:nvme] resources: mmio OK, irq OK, dma OK");
        let _ = bootstrap.write(b"driver-host:nvme:resources-ready");
        match bring_up_controller(&state) {
            Ok(irq_state) => {
                interrupt_state = Some(irq_state);
                let _ = bootstrap.write(b"service:block:nvme:identified");
                let _ = bootstrap.write(b"driver-host:nvme:ready");
            }
            Err(error) => {
                println!("[driver-host:nvme] controller bring-up failed: {}", error);
                let _ = bootstrap.write(b"service:block:nvme:bringup-failed");
            }
        }
    } else {
        let _ = bootstrap.write(b"service:block:nvme:missing-resources");
    }

    loop {
        if let Some(irq_state) = interrupt_state.as_ref() {
            let _keep_irq_handles_alive = irq_state.keepalive_marker();
        }
        libcanvas::process::yield_now();
    }
}

fn bring_up_controller(state: &NvmeBootstrap) -> Result<InterruptState, &'static str> {
    let mmio = state.slot(ResourceSlotKind::Mmio).ok_or("mmio-slot")?;
    let irq = state.slot(ResourceSlotKind::Irq).ok_or("irq-slot")?;
    let dma = state.slot(ResourceSlotKind::DmaPool).ok_or("dma-slot")?;
    let Some(mmio_handle) = mmio.handle() else {
        return Err("mmio-handle");
    };
    let Some(dma_handle) = dma.handle() else {
        return Err("dma-handle");
    };
    let flags = libcanvas::vmar_flags::USER
        | libcanvas::vmar_flags::SPECIFIC
        | libcanvas::vmar_flags::READ
        | libcanvas::vmar_flags::WRITE;
    libcanvas::resource::map_self(mmio_handle, 0, MMIO_MAP_ADDR, mmio.len, flags)
        .map_err(|_| "map-mmio")?;
    libcanvas::resource::map_self(dma_handle, 0, DMA_MAP_ADDR, dma.len, flags)
        .map_err(|_| "map-dma")?;

    let resources = DeviceResources {
        reg_bar: BarRegion {
            index: 0,
            phys: mmio.base,
            virt: MMIO_MAP_ADDR,
            size: mmio.len,
            is_memory: true,
            prefetchable: false,
        },
        dma: DmaRegion {
            phys: dma.base,
            virt: DMA_MAP_ADDR,
            size: dma.len,
        },
    };
    let interrupt_state = bind_interrupts(irq)?;
    let interrupt_first = interrupt_state.count != 0;
    let transport = PciMmioTransport::new(resources);
    let mut controller = Controller::new(transport, dma.base, dma.len);
    let cpu_count = match libcanvas::system::cpu_count() {
        Ok(count) => count.max(1),
        Err(_) => 1,
    };
    let config = ControllerConfig {
        cpu_count,
        msix_available: interrupt_first && irq.len > 1,
        msi_available: interrupt_first && irq.len == 1,
    };
    let info = controller
        .init_with_config(config)
        .map_err(nvme_error_label)?;
    println!(
        "[driver-host:nvme] identified nsid={} block_size={} block_count={} max_request={} queues={} irq={:#x}+{:#x} bound_irqs={}",
        info.namespace.nsid,
        info.namespace.block_size,
        info.namespace.block_count,
        info.controller.max_request_bytes,
        info.io_queue_count,
        irq.base,
        irq.len,
        interrupt_state.count
    );
    Ok(interrupt_state)
}

fn bind_interrupts(irq: &ResourceSlot) -> Result<InterruptState, &'static str> {
    let Some(irq_handle) = irq.handle() else {
        return Err("irq-handle");
    };
    let port = Port::create().map_err(|_| "irq-port")?;
    let mut state = InterruptState {
        port,
        slots: [const { InterruptSlot::empty() }; MAX_BOUND_INTERRUPTS],
        count: 0,
    };
    if irq.base < MSI_VECTOR_BASE {
        println!(
            "[driver-host:nvme] no MSI/MSI-X vectors programmed; polling fallback irq={:#x}+{:#x}",
            irq.base, irq.len
        );
        return Ok(state);
    }
    let bind_count = (irq.len as usize).min(MAX_BOUND_INTERRUPTS);
    let mut idx = 0usize;
    while idx < bind_count {
        let vector = irq.base + idx as u64;
        let interrupt =
            Interrupt::create_from_resource(irq_handle, vector as u32).map_err(|_| "irq-create")?;
        interrupt
            .bind_port(&state.port, vector)
            .map_err(|_| "irq-bind")?;
        state.slots[idx].handle = Some(interrupt);
        state.count += 1;
        idx += 1;
    }
    println!(
        "[driver-host:nvme] bound {} MSI/MSI-X vector(s) at {:#x}",
        state.count, irq.base
    );
    Ok(state)
}

fn nvme_error_label(error: NvmeError) -> &'static str {
    match error {
        NvmeError::OutOfDma => "out-of-dma",
        NvmeError::NotReady => "not-ready",
        NvmeError::CommandFailed { .. } => "command-failed",
        NvmeError::Timeout => "timeout",
        NvmeError::InvalidArgs => "invalid-args",
        NvmeError::OutOfRange => "out-of-range",
        NvmeError::BufferTooSmall => "buffer-too-small",
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
