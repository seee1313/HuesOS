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
use huesos_abi::block::{
    completion_data, AsyncBlockInfo, AsyncBlockOp, AsyncBlockRequest, AsyncBlockStatus,
};
use huesos_nvme::controller::{Controller, ControllerConfig, NvmeError};
use huesos_nvme::device::{BarRegion, DeviceResources, DmaRegion};
use huesos_nvme::pci_transport::PciMmioTransport;
use libcanvas::{println, Channel, ErrorCode, Handle, Interrupt, Port, Vmo};

const REQUIRED_RESOURCES: usize = 3;
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const RESOURCE_TRANSFER_COMPLETE: &[u8] = b"resource:transfer-complete";
const LABEL_CAP: usize = 96;
const MMIO_MAP_ADDR: u64 = 0x0000_7000_0000_0000;
const DMA_MAP_ADDR: u64 = 0x0000_7100_0000_0000;
const MSI_VECTOR_BASE: u64 = 0xD0;
const MAX_BOUND_INTERRUPTS: usize = 16;
const MAX_BLOCK_CLIENTS: usize = 4;
const MAX_CLIENT_BUFFERS: usize = 8;
const TRANSFER_CHUNK_BYTES: usize = 4096;

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

struct ClientBuffer {
    id: u32,
    vmo: Vmo,
}

struct BlockClient {
    channel: Channel,
    completion_port: Option<Port>,
    buffers: [Option<ClientBuffer>; MAX_CLIENT_BUFFERS],
}

impl BlockClient {
    fn new(channel: Channel) -> Self {
        Self {
            channel,
            completion_port: None,
            buffers: [const { None }; MAX_CLIENT_BUFFERS],
        }
    }

    fn upsert_buffer(&mut self, id: u32, vmo: Vmo) -> Result<(), ()> {
        for slot in &mut self.buffers {
            if slot.as_ref().is_some_and(|buffer| buffer.id == id) {
                *slot = Some(ClientBuffer { id, vmo });
                return Ok(());
            }
        }
        let Some(slot) = self.buffers.iter_mut().find(|slot| slot.is_none()) else {
            return Err(());
        };
        *slot = Some(ClientBuffer { id, vmo });
        Ok(())
    }

    fn buffer(&self, id: u32) -> Option<&Vmo> {
        self.buffers
            .iter()
            .flatten()
            .find(|buffer| buffer.id == id)
            .map(|buffer| &buffer.vmo)
    }
}

struct DriverRuntime {
    controller: Controller<PciMmioTransport>,
    interrupt_state: InterruptState,
    clients: [Option<BlockClient>; MAX_BLOCK_CLIENTS],
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

    let mut runtime: Option<DriverRuntime> = None;
    if state.ready() {
        println!("[driver-host:nvme] resources: mmio OK, irq OK, dma OK");
        let _ = bootstrap.write(b"driver-host:nvme:resources-ready");
        match bring_up_controller(&state) {
            Ok(driver_runtime) => {
                runtime = Some(driver_runtime);
                let _ = bootstrap.write(b"service:block:nvme:identified");
                let _ = bootstrap.write(b"driver-host:nvme:ready");
            }
            Err((error, detail)) => {
                match detail {
                    Some(reason) => {
                        println!(
                            "[driver-host:nvme] controller bring-up failed: {} ({})",
                            error, reason
                        );
                    }
                    None => {
                        println!("[driver-host:nvme] controller bring-up failed: {}", error);
                    }
                }
                let _ = bootstrap.write(b"service:block:nvme:bringup-failed");
            }
        }
    } else {
        let _ = bootstrap.write(b"service:block:nvme:missing-resources");
    }

    loop {
        if let Some(runtime) = runtime.as_mut() {
            runtime.poll(&bootstrap);
        }
        libcanvas::process::yield_now();
    }
}

fn bring_up_controller(
    state: &NvmeBootstrap,
) -> Result<DriverRuntime, (&'static str, Option<&'static str>)> {
    let mmio = state
        .slot(ResourceSlotKind::Mmio)
        .ok_or(("mmio-slot", None))?;
    let irq = state
        .slot(ResourceSlotKind::Irq)
        .ok_or(("irq-slot", None))?;
    let dma = state
        .slot(ResourceSlotKind::DmaPool)
        .ok_or(("dma-slot", None))?;
    let Some(mmio_handle) = mmio.handle() else {
        return Err(("mmio-handle", None));
    };
    let Some(dma_handle) = dma.handle() else {
        return Err(("dma-handle", None));
    };
    let flags = libcanvas::vmar_flags::USER
        | libcanvas::vmar_flags::SPECIFIC
        | libcanvas::vmar_flags::READ
        | libcanvas::vmar_flags::WRITE;
    libcanvas::resource::map_self(mmio_handle, 0, MMIO_MAP_ADDR, mmio.len, flags)
        .map_err(|_| ("map-mmio", None))?;
    libcanvas::resource::map_self(dma_handle, 0, DMA_MAP_ADDR, dma.len, flags)
        .map_err(|_| ("map-dma", None))?;

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
    let interrupt_state = bind_interrupts(irq).map_err(|label| (label, None))?;
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
    let info = controller.init_with_config(config).map_err(|error| {
        let detail = match error {
            NvmeError::InvalidIdentifyController | NvmeError::InvalidIdentifyNamespace => {
                Some(controller.last_identify_error().unwrap_or("unknown"))
            }
            _ => None,
        };
        (nvme_error_label(error), detail)
    })?;
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
    Ok(DriverRuntime {
        controller,
        interrupt_state,
        clients: [const { None }; MAX_BLOCK_CLIENTS],
    })
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

impl DriverRuntime {
    fn poll(&mut self, bootstrap: &Channel) {
        let _keep_irq_handles_alive = self.interrupt_state.keepalive_marker();
        self.poll_bootstrap(bootstrap);
        self.drain_interrupt_port();
        let mut index = 0usize;
        while index < self.clients.len() {
            self.poll_client(index);
            index += 1;
        }
    }

    fn poll_bootstrap(&mut self, bootstrap: &Channel) {
        let mut buf = [0u8; 64];
        loop {
            match bootstrap.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"block:nvme-client" => {
                    self.attach_client(Channel::from_handle(handle));
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(_) => return,
            }
        }
    }

    fn attach_client(&mut self, channel: Channel) {
        let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) else {
            println!("[driver-host:nvme] block client table full");
            drop(channel);
            return;
        };
        *slot = Some(BlockClient::new(channel));
        println!("[driver-host:nvme] attached block client");
    }

    fn drain_interrupt_port(&self) {
        loop {
            match self.interrupt_state.port.read() {
                Ok(_packet) => {}
                Err(ErrorCode::ShouldWait) => return,
                Err(_) => return,
            }
        }
    }

    fn poll_client(&mut self, index: usize) {
        let mut buf = [0u8; 96];
        loop {
            let Some(client) = self.clients[index].as_mut() else {
                return;
            };
            match client.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"block:completion-port" => {
                    client.completion_port = Some(Port::from_handle(handle));
                }
                Ok((n, Some(handle))) if buf[..n].starts_with(b"block:buffer:0x") => {
                    let id = parse_hex_u32(&buf[b"block:buffer:0x".len()..n]);
                    if let Some(id) = id {
                        if client.upsert_buffer(id, Vmo::from_handle(handle)).is_err() {
                            println!("[driver-host:nvme] client buffer table full");
                        }
                    } else {
                        drop(handle);
                    }
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) => self.handle_block_request(index, &buf[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    return;
                }
                Err(error) => {
                    println!(
                        "[driver-host:nvme] block client read failed: {}",
                        error.as_str()
                    );
                    return;
                }
            }
        }
    }

    fn handle_block_request(&mut self, index: usize, bytes: &[u8]) {
        let Some(request) = AsyncBlockRequest::decode(bytes) else {
            return;
        };
        let status = self.execute_block_request(index, request);
        let bytes = transferred_bytes(&self.controller, status, request);
        self.complete(index, request.request_id, status, bytes, 0);
    }

    fn execute_block_request(
        &mut self,
        index: usize,
        request: AsyncBlockRequest,
    ) -> AsyncBlockStatus {
        if request.namespace_id != 1 {
            return AsyncBlockStatus::InvalidArgs;
        }
        match request.op {
            AsyncBlockOp::Info => self.send_info(index),
            AsyncBlockOp::Flush => match self.controller.flush() {
                Ok(()) => AsyncBlockStatus::Ok,
                Err(_) => AsyncBlockStatus::IoError,
            },
            AsyncBlockOp::Read => self.read_request(index, request),
            AsyncBlockOp::Write => self.write_request(index, request),
        }
    }

    fn send_info(&mut self, index: usize) -> AsyncBlockStatus {
        let info = AsyncBlockInfo {
            namespace_id: 1,
            block_size: self.controller.lba_size(),
            block_count: self.controller.namespace_size(),
            max_request_bytes: self.controller.mdts(),
        };
        let Some(client) = self.clients[index].as_ref() else {
            return AsyncBlockStatus::NoResources;
        };
        if client.channel.write(&info.encode()).is_err() {
            return AsyncBlockStatus::IoError;
        }
        AsyncBlockStatus::Ok
    }

    fn read_request(&mut self, index: usize, request: AsyncBlockRequest) -> AsyncBlockStatus {
        let Some(block_size) = block_size_usize(&self.controller) else {
            return AsyncBlockStatus::InvalidArgs;
        };
        let total_bytes = request.block_count as usize * block_size;
        if total_bytes as u64 > self.controller.mdts() as u64 {
            return AsyncBlockStatus::InvalidArgs;
        }
        let mut scratch = [0u8; TRANSFER_CHUNK_BYTES];
        let mut done_blocks = 0u32;
        while done_blocks < request.block_count {
            let chunk_blocks = ((TRANSFER_CHUNK_BYTES / block_size) as u32)
                .max(1)
                .min(request.block_count - done_blocks);
            let chunk_bytes = chunk_blocks as usize * block_size;
            if self
                .controller
                .read(
                    request.lba + u64::from(done_blocks),
                    chunk_blocks as u16,
                    &mut scratch[..chunk_bytes],
                )
                .is_err()
            {
                return AsyncBlockStatus::IoError;
            }
            let Some(client) = self.clients[index].as_ref() else {
                return AsyncBlockStatus::NoResources;
            };
            let Some(vmo) = client.buffer(request.buffer_id) else {
                return AsyncBlockStatus::InvalidArgs;
            };
            let offset = u64::from(done_blocks) * block_size as u64;
            match vmo.write(offset, &scratch[..chunk_bytes]) {
                Ok(written) if written == chunk_bytes => {}
                _ => return AsyncBlockStatus::IoError,
            }
            done_blocks += chunk_blocks;
        }
        AsyncBlockStatus::Ok
    }

    fn write_request(&mut self, index: usize, request: AsyncBlockRequest) -> AsyncBlockStatus {
        let Some(block_size) = block_size_usize(&self.controller) else {
            return AsyncBlockStatus::InvalidArgs;
        };
        let total_bytes = request.block_count as usize * block_size;
        if total_bytes as u64 > self.controller.mdts() as u64 {
            return AsyncBlockStatus::InvalidArgs;
        }
        let mut scratch = [0u8; TRANSFER_CHUNK_BYTES];
        let mut done_blocks = 0u32;
        while done_blocks < request.block_count {
            let chunk_blocks = ((TRANSFER_CHUNK_BYTES / block_size) as u32)
                .max(1)
                .min(request.block_count - done_blocks);
            let chunk_bytes = chunk_blocks as usize * block_size;
            let Some(client) = self.clients[index].as_ref() else {
                return AsyncBlockStatus::NoResources;
            };
            let Some(vmo) = client.buffer(request.buffer_id) else {
                return AsyncBlockStatus::InvalidArgs;
            };
            let offset = u64::from(done_blocks) * block_size as u64;
            match vmo.read(offset, &mut scratch[..chunk_bytes]) {
                Ok(read) if read == chunk_bytes => {}
                _ => return AsyncBlockStatus::IoError,
            }
            if self
                .controller
                .write(
                    request.lba + u64::from(done_blocks),
                    chunk_blocks as u16,
                    &scratch[..chunk_bytes],
                )
                .is_err()
            {
                return AsyncBlockStatus::IoError;
            }
            done_blocks += chunk_blocks;
        }
        AsyncBlockStatus::Ok
    }

    fn complete(
        &self,
        index: usize,
        request_id: u64,
        status: AsyncBlockStatus,
        bytes: u64,
        nvme_status: u16,
    ) {
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        let Some(port) = client.completion_port.as_ref() else {
            return;
        };
        let packet = libcanvas::PortPacket {
            key: request_id,
            packet_type: libcanvas::PORT_PACKET_BLOCK_COMPLETION,
            status: 0,
            data: completion_data(request_id, status, bytes, nvme_status),
        };
        let _ = port.queue(&packet);
    }
}

fn block_size_usize(controller: &Controller<PciMmioTransport>) -> Option<usize> {
    let block_size = controller.lba_size() as usize;
    if block_size == 0 || block_size > TRANSFER_CHUNK_BYTES {
        None
    } else {
        Some(block_size)
    }
}

fn transferred_bytes(
    controller: &Controller<PciMmioTransport>,
    status: AsyncBlockStatus,
    request: AsyncBlockRequest,
) -> u64 {
    if status != AsyncBlockStatus::Ok {
        return 0;
    }
    match request.op {
        AsyncBlockOp::Read | AsyncBlockOp::Write => {
            u64::from(request.block_count).saturating_mul(u64::from(controller.lba_size()))
        }
        AsyncBlockOp::Flush => 0,
        AsyncBlockOp::Info => huesos_abi::block::ASYNC_INFO_RESPONSE_BYTES as u64,
    }
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    u32::try_from(parse_hex_u64_raw(bytes)?).ok()
}

fn parse_hex_u64_raw(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &digit in bytes {
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

fn nvme_error_label(error: NvmeError) -> &'static str {
    match error {
        NvmeError::OutOfDma => "out-of-dma",
        NvmeError::NotReady => "not-ready",
        NvmeError::CommandFailed { .. } => "command-failed",
        NvmeError::Timeout => "timeout",
        NvmeError::InvalidArgs => "invalid-args",
        NvmeError::InvalidQueuePlan => "invalid-queue-plan",
        NvmeError::InvalidIdentifyController => "invalid-identify-controller",
        NvmeError::InvalidIdentifyNamespace => "invalid-identify-namespace",
        NvmeError::InvalidPrp => "invalid-prp",
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
