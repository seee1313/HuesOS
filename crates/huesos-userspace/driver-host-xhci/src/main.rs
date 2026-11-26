//! Zero-heap Ring-3 Asynchronous USB 3.x (`xHCI` 1.x) DriverHost.
//!
//! Responsibilities:
//! - Owns one isolated xHCI controller (`BAR0` MMIO, MSI-X/MSI `Interrupt`,
//!   `4 MiB` `< 4 GiB` `DmaPool`, and `DeviceLease` under Intel VT-d).
//! - Enforces zero heap allocation (`NoHeapAllocator`) and drives asynchronous
//!   Command, Control, Hub, HID, and Bulk-Only Transport (`BOT` / SCSI) TRB
//!   state machines via `hues-async` + `huesos-usb`.
//! - Streams normalized `[b'k', pressed, key]` and `[b'm', buttons, dx, dy, wheel]`
//!   input events to `driver-manager`, serves `AsyncBlockRequest` over
//!   `/dev/block/usb0`, and publishes zero-bus-traffic `HUSB` inventory VMOs.

#![no_std]
#![no_main]

mod controller;
mod mmio;

use controller::{InputEventSink, XhciController, BOT_DATA_MAX_BYTES, BOT_DATA_OFF};
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::ptr::null_mut;
use hues_async::backend::UserBackend;
use hues_async::Executor;
use huesos_abi::block::{
    completion_data, AsyncBlockInfo, AsyncBlockOp, AsyncBlockRequest, AsyncBlockStatus,
    ASYNC_INFO_RESPONSE_BYTES,
};
use huesos_abi::pci_iommu::IommuMode;
use huesos_abi::pci_manager::DEVICE_LEASE_XHCI_RO_LABEL;
use huesos_abi::rights;
use huesos_abi::usb;
use libcanvas::{
    println, wait_any, Channel, ErrorCode, Handle, Interrupt, Port, PortPacket, Signals, Vmo,
    WaitItem, PORT_PACKET_BLOCK_COMPLETION, PORT_PACKET_DEVICE_GONE,
};
use mmio::MappedWin;

const REQUIRED_RESOURCES: usize = 3;
const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
const RESOURCE_TRANSFER_COMPLETE: &[u8] = b"resource:transfer-complete";
const MMIO_MAP_ADDR: u64 = 0x0000_7300_0000_0000;
const DMA_MAP_ADDR: u64 = 0x0000_7310_0000_0000;
const MSI_VECTOR_BASE: u64 = 0xD0;
const MAX_BOUND_INTERRUPTS: usize = 8;
const MAX_BLOCK_CLIENTS: usize = 8;
const MAX_CLIENT_BUFFERS: usize = 8;
const IO_CHUNK_BYTES: usize = 32 * 1024;

struct NoHeapAllocator;

// SAFETY: `driver-host-xhci` intentionally runs with zero heap allocation.
// Any accidental `alloc` attempt returns null immediately rather than breaking
// the zero-heap Ring-3 driver guarantee.
unsafe impl GlobalAlloc for NoHeapAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: NoHeapAllocator = NoHeapAllocator;

fn park_yield() {
    libcanvas::process::yield_now();
}

fn wake_noop(_slot: u32) {}

fn monotonic_ticks_now() -> u64 {
    libcanvas::system::monotonic_ticks().unwrap_or(0)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceSlotKind {
    Mmio,
    Irq,
    DmaPool,
}

impl ResourceSlotKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mmio => "mmio",
            Self::Irq => "irq",
            Self::DmaPool => "dma",
        }
    }
}

#[derive(Clone, Copy)]
struct ParsedResourceLabel {
    kind: ResourceSlotKind,
    base: u64,
    len: u64,
}

struct ResourceSlot {
    kind: ResourceSlotKind,
    base: u64,
    len: u64,
    handle: Option<Handle>,
}

impl ResourceSlot {
    const fn empty(kind: ResourceSlotKind) -> Self {
        Self {
            kind,
            base: 0,
            len: 0,
            handle: None,
        }
    }

    fn is_present(&self) -> bool {
        self.handle.is_some()
    }
}

struct XhciBootstrap {
    slots: [ResourceSlot; REQUIRED_RESOURCES],
    lease: Option<Handle>,
    gone_port: Option<Port>,
    bdf_packed: u32,
}

impl XhciBootstrap {
    const fn new() -> Self {
        Self {
            slots: [
                ResourceSlot::empty(ResourceSlotKind::Mmio),
                ResourceSlot::empty(ResourceSlotKind::Irq),
                ResourceSlot::empty(ResourceSlotKind::DmaPool),
            ],
            lease: None,
            gone_port: None,
            bdf_packed: 0,
        }
    }

    fn record_lease(&mut self, handle: Handle) {
        if self.lease.is_some() {
            drop(handle);
            return;
        }
        let Ok(info) = libcanvas::device_lease::query(&handle) else {
            drop(handle);
            return;
        };
        if let Ok(port) = Port::create() {
            if libcanvas::device_lease::bind_gone_port(&handle, &port, 0x5848).is_ok() {
                self.gone_port = Some(port);
            }
        }
        self.bdf_packed = info.pci_address_packed as u32;
        self.lease = Some(handle);
        println!(
            "[driver-host:xhci] read-only DeviceLease bound bdf={:#x}",
            self.bdf_packed
        );
    }

    fn record_resource(&mut self, label: &[u8], handle: Handle) {
        let Some(parsed) = parse_resource_label(label) else {
            drop(handle);
            return;
        };
        let mut rem = Some(handle);
        for slot in &mut self.slots {
            if slot.kind == parsed.kind && !slot.is_present() {
                slot.base = parsed.base;
                slot.len = parsed.len;
                slot.handle = rem.take();
                break;
            }
        }
        if let Some(dup) = rem {
            drop(dup);
        }
    }

    fn ready(&self) -> bool {
        self.slots.iter().all(ResourceSlot::is_present)
    }

    fn slot(&self, kind: ResourceSlotKind) -> Option<&ResourceSlot> {
        self.slots.iter().find(|s| s.kind == kind)
    }

    fn log_summary(&self) {
        for slot in &self.slots {
            if slot.is_present() {
                println!(
                    "[driver-host:xhci] resource {} OK base={:#x} len={:#x}",
                    slot.kind.as_str(),
                    slot.base,
                    slot.len
                );
            } else {
                println!("[driver-host:xhci] resource {} MISSING", slot.kind.as_str());
            }
        }
    }
}

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
    fn drain(&self) {
        loop {
            match self.port.read() {
                Ok(_pkt) => {}
                Err(ErrorCode::ShouldWait) => return,
                Err(_) => return,
            }
        }
    }

    fn wait_brief(&self, timeout_ticks: u64) {
        let items = [WaitItem::new(
            self.port.handle().raw(),
            Signals::READABLE,
            1,
        )];
        let _ = wait_any(&items, timeout_ticks);
        self.drain();
    }
}

struct InputChannels {
    keyboard: Option<Channel>,
    mouse: Option<Channel>,
}

impl InputChannels {
    const fn new() -> Self {
        Self {
            keyboard: None,
            mouse: None,
        }
    }
}

impl InputEventSink for InputChannels {
    fn on_key(&mut self, wire: [u8; 3]) {
        if let Some(ch) = self.keyboard.as_ref() {
            if ch.write(&wire) == Err(ErrorCode::PeerClosed) {
                self.keyboard = None;
            }
        }
    }

    fn on_mouse(&mut self, wire: [u8; 5]) {
        if let Some(ch) = self.mouse.as_ref() {
            if ch.write(&wire) == Err(ErrorCode::PeerClosed) {
                self.mouse = None;
            }
        }
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
            if slot.as_ref().is_some_and(|b| b.id == id) {
                *slot = Some(ClientBuffer { id, vmo });
                return Ok(());
            }
        }
        let Some(slot) = self.buffers.iter_mut().find(|s| s.is_none()) else {
            return Err(());
        };
        *slot = Some(ClientBuffer { id, vmo });
        Ok(())
    }

    fn buffer(&self, id: u32) -> Option<&Vmo> {
        self.buffers
            .iter()
            .flatten()
            .find(|b| b.id == id)
            .map(|b| &b.vmo)
    }
}

struct DriverRuntime {
    ctrl: Option<XhciController>,
    irq: InterruptState,
    executor: Executor<8, 256, UserBackend>,
    input: InputChannels,
    block_clients: [Option<BlockClient>; MAX_BLOCK_CLIENTS],
    bot_announced: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-host:xhci] started");
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:xhci:starting");

    let mut boot = XhciBootstrap::new();
    drain_bootstrap_resources(&bootstrap, &mut boot);
    boot.log_summary();

    let mut runtime: Option<DriverRuntime> = None;
    if boot.ready() {
        let _ = bootstrap.write(b"driver-host:xhci:resources-ready");
        match bring_up(&boot) {
            Ok(mut rt) => {
                // Exercise zero-heap `hues_async::Executor` slot scheduling at bring-up.
                let _ = rt.executor.spawn(hues_async::yield_now());
                let _ = rt.executor.poll();

                // Enumerate all boot-attached root-hub & downstream USB Hub devices.
                if let Some(ctrl) = rt.ctrl.as_ref() {
                    let irq_ref = &rt.irq;
                    ctrl.process_topology(&mut rt.input, || irq_ref.wait_brief(1));
                }
                publish_husb_if_needed(&bootstrap, &mut rt);
                let _ = bootstrap.write(b"service:usb:hid:ready");
                if rt
                    .ctrl
                    .as_ref()
                    .and_then(XhciController::first_bot_geometry)
                    .is_some()
                {
                    rt.bot_announced = true;
                    let _ = bootstrap.write(b"service:block:usb:ready");
                }
                let _ = bootstrap.write(b"driver-host:xhci:ready");
                runtime = Some(rt);
            }
            Err(reason) => {
                println!("[driver-host:xhci] bring-up failed: {}", reason);
                let _ = bootstrap.write(b"service:usb:bringup-failed");
            }
        }
    } else {
        let _ = bootstrap.write(b"service:usb:missing-resources");
    }

    loop {
        if let Some(port) = boot.gone_port.as_ref() {
            if let Ok(pkt) = port.read() {
                if pkt.packet_type == PORT_PACKET_DEVICE_GONE {
                    println!("[driver-host:xhci] DeviceGone received; quiescing xHCI");
                    runtime = None;
                    let _ = bootstrap.write(b"service:usb:device-gone");
                }
            }
        }
        if let Some(rt) = runtime.as_mut() {
            rt.poll_step(&bootstrap);
            rt.wait_until_active(&bootstrap, boot.gone_port.as_ref(), 2);
        } else {
            let items = [WaitItem::new(
                bootstrap.handle().raw(),
                Signals::READABLE | Signals::PEER_CLOSED,
                0,
            )];
            let _ = wait_any(&items, 10);
        }
    }
}

fn bring_up(boot: &XhciBootstrap) -> Result<DriverRuntime, &'static str> {
    let mmio_slot = boot.slot(ResourceSlotKind::Mmio).ok_or("mmio-slot")?;
    let irq_slot = boot.slot(ResourceSlotKind::Irq).ok_or("irq-slot")?;
    let dma_slot = boot.slot(ResourceSlotKind::DmaPool).ok_or("dma-slot")?;
    let mmio_h = mmio_slot.handle.as_ref().ok_or("mmio-handle")?;
    let dma_h = dma_slot.handle.as_ref().ok_or("dma-handle")?;

    let flags = libcanvas::vmar_flags::USER
        | libcanvas::vmar_flags::SPECIFIC
        | libcanvas::vmar_flags::READ
        | libcanvas::vmar_flags::WRITE;
    libcanvas::resource::map_self(mmio_h, 0, MMIO_MAP_ADDR, mmio_slot.len, flags)
        .map_err(|_| "map-mmio")?;
    libcanvas::resource::map_self(dma_h, 0, DMA_MAP_ADDR, dma_slot.len, flags)
        .map_err(|_| "map-dma")?;

    let irq = bind_interrupts(irq_slot)?;
    let msi_active = irq.count > 0;
    let iommu_isolated = libcanvas::device_lease::system_iommu_status()
        .map(|st| st.active_mode == IommuMode::Isolated as u8 && boot.lease.is_some())
        .unwrap_or(false);

    let backend = UserBackend::new(park_yield, wake_noop, monotonic_ticks_now);
    let mut rt = DriverRuntime {
        ctrl: None,
        irq,
        executor: Executor::new_with(backend),
        input: InputChannels::new(),
        block_clients: [const { None }; MAX_BLOCK_CLIENTS],
        bot_announced: false,
    };

    XhciController::init_in_place(
        &mut rt.ctrl,
        MappedWin::new(MMIO_MAP_ADDR as usize, mmio_slot.len as usize),
        MappedWin::new(DMA_MAP_ADDR as usize, dma_slot.len as usize),
        dma_slot.base,
        boot.bdf_packed,
        iommu_isolated,
        msi_active,
    )
    .map_err(|e| e.as_str())?;

    Ok(rt)
}

fn bind_interrupts(irq: &ResourceSlot) -> Result<InterruptState, &'static str> {
    let irq_handle = irq.handle.as_ref().ok_or("irq-handle")?;
    let port = Port::create().map_err(|_| "irq-port")?;
    let mut state = InterruptState {
        port,
        slots: [const { InterruptSlot::empty() }; MAX_BOUND_INTERRUPTS],
        count: 0,
    };
    if irq.base < MSI_VECTOR_BASE {
        println!(
            "[driver-host:xhci] legacy/polling interrupt mode irq={:#x}+{:#x}",
            irq.base, irq.len
        );
        return Ok(state);
    }
    let bind_count = (irq.len as usize).min(MAX_BOUND_INTERRUPTS);
    let mut idx = 0usize;
    while idx < bind_count {
        let vector = irq.base + idx as u64;
        let intr = Interrupt::create_from_resource(irq_handle, vector as u32)
            .map_err(|_| "irq-create")?;
        intr.bind_port(&state.port, vector).map_err(|_| "irq-bind")?;
        state.slots[idx].handle = Some(intr);
        state.count += 1;
        idx += 1;
    }
    println!(
        "[driver-host:xhci] bound {} MSI/MSI-X vector(s) at {:#x}",
        state.count, irq.base
    );
    Ok(state)
}

impl DriverRuntime {
    fn poll_step(&mut self, bootstrap: &Channel) {
        self.poll_bootstrap(bootstrap);
        self.irq.drain();
        let _ = self.executor.poll();

        if let Some(ctrl) = self.ctrl.as_ref() {
            let _ = ctrl.pump_events(&mut self.input);
            if ctrl.has_pending_topology_work() {
                let irq_ref = &self.irq;
                ctrl.process_topology(&mut self.input, || irq_ref.wait_brief(1));
            }
            if !self.bot_announced && ctrl.first_bot_geometry().is_some() {
                self.bot_announced = true;
                let _ = bootstrap.write(b"service:block:usb:ready");
            }
        }

        let mut c_idx = 0usize;
        while c_idx < MAX_BLOCK_CLIENTS {
            self.poll_block_client(c_idx);
            c_idx += 1;
        }

        publish_husb_if_needed(bootstrap, self);
    }

    fn wait_until_active(&self, bootstrap: &Channel, gone_port: Option<&Port>, timeout_ticks: u64) {
        let mut items = [WaitItem::new(0, Signals::NONE, 0); 14];
        let sig = Signals::READABLE | Signals::PEER_CLOSED;
        items[0] = WaitItem::new(bootstrap.handle().raw(), sig, 0);
        items[1] = WaitItem::new(self.irq.port.handle().raw(), Signals::READABLE, 1);
        let mut count = 2usize;
        if let Some(gp) = gone_port {
            items[count] = WaitItem::new(gp.handle().raw(), Signals::READABLE, 2);
            count += 1;
        }
        for client in self.block_clients.iter().flatten() {
            if count >= items.len() {
                break;
            }
            items[count] = WaitItem::new(client.channel.handle().raw(), sig, count as u64);
            count += 1;
        }
        let _ = wait_any(&items[..count], timeout_ticks);
    }

    fn poll_bootstrap(&mut self, bootstrap: &Channel) {
        let mut buf = [0u8; 64];
        let mut budget = 0usize;
        while budget < 16 {
            budget += 1;
            match bootstrap.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"keyboard-client" => {
                    self.input.keyboard = Some(Channel::from_handle(handle));
                    println!("[driver-host:xhci] attached keyboard client");
                }
                Ok((n, Some(handle))) if &buf[..n] == b"mouse-client" => {
                    self.input.mouse = Some(Channel::from_handle(handle));
                    println!("[driver-host:xhci] attached mouse client");
                }
                Ok((n, Some(handle))) if &buf[..n] == b"block:usb-client" => {
                    self.attach_block_client(Channel::from_handle(handle));
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if &buf[..n] == b"usb:refresh-vmo" => {
                    if let Some(ctrl) = self.ctrl.as_ref() {
                        ctrl.mark_inventory_dirty();
                    }
                }
                Ok((_n, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(_) => return,
            }
        }
    }

    fn attach_block_client(&mut self, channel: Channel) {
        let Some(slot) = self.block_clients.iter_mut().find(|s| s.is_none()) else {
            drop(channel);
            return;
        };
        *slot = Some(BlockClient::new(channel));
        println!("[driver-host:xhci] attached USB BOT block client");
    }

    fn poll_block_client(&mut self, index: usize) {
        let mut buf = [0u8; 96];
        let mut budget = 0usize;
        while budget < 16 {
            budget += 1;
            let Some(client) = self.block_clients[index].as_mut() else {
                return;
            };
            match client.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"block:completion-port" => {
                    client.completion_port = Some(Port::from_handle(handle));
                }
                Ok((n, Some(handle))) if buf[..n].starts_with(b"block:buffer:0x") => {
                    if let Some(id) = parse_hex_u32(&buf[b"block:buffer:0x".len()..n]) {
                        let _ = client.upsert_buffer(id, Vmo::from_handle(handle));
                    } else {
                        drop(handle);
                    }
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) => self.handle_block_request(index, &buf[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.block_clients[index] = None;
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn handle_block_request(&mut self, index: usize, raw: &[u8]) {
        let Some(req) = AsyncBlockRequest::decode(raw) else {
            return;
        };
        let (status, xfer_bytes) = self.execute_block_request(index, req);
        let Some(client) = self.block_clients[index].as_ref() else {
            return;
        };
        let Some(port) = client.completion_port.as_ref() else {
            return;
        };
        let pkt = PortPacket {
            key: req.request_id,
            packet_type: PORT_PACKET_BLOCK_COMPLETION,
            status: 0,
            data: completion_data(req.request_id, status, xfer_bytes, 0),
        };
        let _ = port.queue(&pkt);
    }

    fn execute_block_request(
        &mut self,
        index: usize,
        req: AsyncBlockRequest,
    ) -> (AsyncBlockStatus, u64) {
        if req.namespace_id != 1 {
            return (AsyncBlockStatus::InvalidArgs, 0);
        }
        let Some(ctrl) = self.ctrl.as_ref() else {
            return (AsyncBlockStatus::NoResources, 0);
        };
        let Some((slot_id, block_size, total_blocks)) = ctrl.first_bot_geometry() else {
            return (AsyncBlockStatus::NoResources, 0);
        };
        match req.op {
            AsyncBlockOp::Info => {
                let mut serial = [b' '; 20];
                let mut model = [b' '; 40];
                serial[..8].copy_from_slice(b"USB3BOT0");
                model[..19].copy_from_slice(b"HuesOS USB BOT Disk");
                let info = AsyncBlockInfo {
                    namespace_id: 1,
                    block_size,
                    block_count: total_blocks,
                    max_request_bytes: BOT_DATA_MAX_BYTES as u32,
                    serial,
                    model,
                };
                let Some(client) = self.block_clients[index].as_ref() else {
                    return (AsyncBlockStatus::NoResources, 0);
                };
                if client.channel.write(&info.encode()).is_err() {
                    return (AsyncBlockStatus::IoError, 0);
                }
                (AsyncBlockStatus::Ok, ASYNC_INFO_RESPONSE_BYTES as u64)
            }
            AsyncBlockOp::Flush => {
                let irq_ref = &self.irq;
                match ctrl.execute_bot_flush(slot_id, &mut self.input, || irq_ref.wait_brief(1)) {
                    Ok(()) => (AsyncBlockStatus::Ok, 0),
                    Err(_) => (AsyncBlockStatus::IoError, 0),
                }
            }
            AsyncBlockOp::Read => {
                self.bot_transfer_vmo(index, req, slot_id, block_size as usize, false)
            }
            AsyncBlockOp::Write => {
                self.bot_transfer_vmo(index, req, slot_id, block_size as usize, true)
            }
        }
    }

    fn bot_transfer_vmo(
        &mut self,
        index: usize,
        req: AsyncBlockRequest,
        slot_id: u8,
        block_size: usize,
        is_write: bool,
    ) -> (AsyncBlockStatus, u64) {
        if block_size == 0 || block_size > IO_CHUNK_BYTES {
            return (AsyncBlockStatus::InvalidArgs, 0);
        }
        let Some(total_bytes) = (req.block_count as usize).checked_mul(block_size) else {
            return (AsyncBlockStatus::InvalidArgs, 0);
        };
        if total_bytes > BOT_DATA_MAX_BYTES {
            return (AsyncBlockStatus::InvalidArgs, 0);
        }
        let Some(ctrl) = self.ctrl.as_ref() else {
            return (AsyncBlockStatus::NoResources, 0);
        };
        let dma = ctrl.dma_win();
        let mut bounce = [0u8; 4096];
        let max_chunk_blocks = (IO_CHUNK_BYTES / block_size) as u32;
        let mut done_blocks = 0u32;

        while done_blocks < req.block_count {
            let chunk_blocks = (req.block_count - done_blocks).min(max_chunk_blocks.max(1));
            let chunk_bytes = (chunk_blocks as usize) * block_size;
            let vmo_base_off = u64::from(done_blocks) * (block_size as u64);

            if is_write {
                let Some(client) = self.block_clients[index].as_ref() else {
                    return (AsyncBlockStatus::NoResources, 0);
                };
                let Some(vmo) = client.buffer(req.buffer_id) else {
                    return (AsyncBlockStatus::InvalidArgs, 0);
                };
                let mut copied = 0usize;
                while copied < chunk_bytes {
                    let step = (chunk_bytes - copied).min(bounce.len());
                    if vmo.read(vmo_base_off + copied as u64, &mut bounce[..step]) != Ok(step) {
                        return (AsyncBlockStatus::IoError, 0);
                    }
                    dma.copy_in(BOT_DATA_OFF + copied, &bounce[..step]);
                    copied += step;
                }
            }

            let irq_ref = &self.irq;
            if ctrl
                .execute_bot_io(
                    slot_id,
                    is_write,
                    req.lba + u64::from(done_blocks),
                    chunk_blocks as u16,
                    &mut self.input,
                    || irq_ref.wait_brief(1),
                )
                .is_err()
            {
                return (AsyncBlockStatus::IoError, 0);
            }

            if !is_write {
                let Some(client) = self.block_clients[index].as_ref() else {
                    return (AsyncBlockStatus::NoResources, 0);
                };
                let Some(vmo) = client.buffer(req.buffer_id) else {
                    return (AsyncBlockStatus::InvalidArgs, 0);
                };
                let mut copied = 0usize;
                while copied < chunk_bytes {
                    let step = (chunk_bytes - copied).min(bounce.len());
                    dma.copy_out(BOT_DATA_OFF + copied, &mut bounce[..step]);
                    if vmo.write(vmo_base_off + copied as u64, &bounce[..step]) != Ok(step) {
                        return (AsyncBlockStatus::IoError, 0);
                    }
                    copied += step;
                }
            }

            done_blocks += chunk_blocks;
        }
        (AsyncBlockStatus::Ok, total_bytes as u64)
    }
}

fn publish_husb_if_needed(bootstrap: &Channel, rt: &mut DriverRuntime) {
    let Some(ctrl) = rt.ctrl.as_ref() else {
        return;
    };
    if !ctrl.take_inventory_dirty() {
        return;
    }
    let mut encoded = [0u8; usb::MAX_BYTES];
    let Some(written) = ctrl.encode_husb_snapshot(&mut encoded) else {
        return;
    };
    let Ok(vmo) = Vmo::create(written as u64) else {
        return;
    };
    if vmo.write(0, &encoded[..written]) != Ok(written) {
        return;
    }
    let ro_rights = rights::READ | rights::DUPLICATE | rights::TRANSFER;
    let Ok(ro_vmo) = vmo.duplicate(ro_rights) else {
        return;
    };
    drop(vmo);
    let _ = bootstrap.write_handle(b"service:usb:inventory-vmo", ro_vmo.into_handle());
}

fn drain_bootstrap_resources(bootstrap: &Channel, boot: &mut XhciBootstrap) {
    let mut buf = [0u8; 96];
    loop {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if buf[..n].starts_with(RESOURCE_LABEL_PREFIX) => {
                boot.record_resource(&buf[..n], handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == DEVICE_LEASE_XHCI_RO_LABEL => {
                boot.record_lease(handle);
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

fn parse_resource_label(label: &[u8]) -> Option<ParsedResourceLabel> {
    let mut parts = label.split(|&b| b == b':');
    if parts.next()? != b"resource" {
        return None;
    }
    if parts.next()?.is_empty() {
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
    let mode = parts.next()?;
    if mode != b"excl" && mode != b"shared" {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(ParsedResourceLabel { kind, base, len })
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    parse_hex_u64_raw(bytes.strip_prefix(b"0x")?)
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    u32::try_from(parse_hex_u64_raw(bytes)?).ok()
}

fn parse_hex_u64_raw(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    let mut val = 0u64;
    for &d in digits {
        let nib = match d {
            b'0'..=b'9' => d - b'0',
            b'a'..=b'f' => d - b'a' + 10,
            b'A'..=b'F' => d - b'A' + 10,
            _ => return None,
        };
        val = val.checked_mul(16)?.checked_add(u64::from(nib))?;
    }
    Some(val)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-host:xhci] PANIC\n");
    libcanvas::process::exit(-1);
}
