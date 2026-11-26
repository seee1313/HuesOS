//! Asynchronous Ring-3 xHCI 1.x controller, USB 2.0/3.x Hub, HID Boot Keyboard/Mouse,
//! and Bulk-Only Transport (`BOT` / SCSI) Mass Storage state machines.

use crate::mmio::MappedWin;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use hues_async::block_on;
use huesos_abi::usb::{
    self, UsbDeviceRole, UsbInventoryDevice, UsbInventoryHeader, UsbSpeedAbi, MAX_MANUFACTURER_LEN,
    MAX_PRODUCT_LEN, USB_FLAG_BIOS_HANDOFF_DONE, USB_FLAG_IOMMU_ISOLATED, USB_FLAG_MSI_ACTIVE,
};
use huesos_usb::async_io::{TrbCompletionTable, TrbOutcome, TrbWaitFuture, WaitTicket};
use huesos_usb::bot::{
    CommandBlockWrapper, CommandStatusWrapper, CswStatus, ScsiCapacity, CBW_BYTES, CSW_BYTES,
};
use huesos_usb::ch9::{
    decode_usb_string_ascii, ConfigurationDescriptor, DescriptorIter, DeviceDescriptor,
    EndpointDescriptor, ParsedDescriptor, SetupPacket, DESC_CONFIGURATION, DESC_DEVICE,
    DESC_STRING, HID_PROTO_KEYBOARD, HID_PROTO_MOUSE, MSC_PROTO_BULK_ONLY, MSC_SUBCLASS_SCSI,
    USB_CLASS_HID, USB_CLASS_HUB, USB_CLASS_MASS_STORAGE,
};
use huesos_usb::hid::{HidBootKeyboard, HidKeyEvent, HidMouseEvent, MAX_HID_KEY_EVENTS};
use huesos_usb::hub::{
    append_route_port, HubDescriptor, HubPortStatus, HUB_FEAT_C_BH_PORT_RESET,
    HUB_FEAT_C_PORT_CONNECTION, HUB_FEAT_C_PORT_ENABLE, HUB_FEAT_C_PORT_RESET, HUB_FEAT_PORT_POWER,
    HUB_FEAT_PORT_RESET,
};
use huesos_usb::xhci::{
    default_ep0_mps, init_input_context, portsc_preserve_rw, portsc_speed,
    set_input_endpoint_context, usb_interval_to_xhci, CompletionCode, ControlTransferType,
    DecodedEvent, EndpointContextParams, EventRingConsumer, PortProtocolRange, ProducerRing,
    SlotContextParams, Trb, XhciCapabilities, XhciEndpointType, ERDP_EHB, IMAN_IE, IMAN_IP,
    IR_ERDP, IR_ERSTBA, IR_ERSTSZ, IR_IMAN, IR_IMOD, OP_CONFIG, OP_CRCR, OP_DCBAAP, OP_PAGESIZE,
    OP_PORT_BASE, OP_PORT_STRIDE, OP_USBCMD, OP_USBSTS, PORTSC_CCS, PORTSC_CHANGE_BITS, PORTSC_PED,
    PORTSC_PP, PORTSC_PR, PORTSC_PRC, RT_IR0_BASE, USBCMD_HCRST, USBCMD_HSEE, USBCMD_INTE,
    USBCMD_RS, USBLEGSUP_BIOS_OWNED, USBLEGSUP_OS_OWNED, USBSTS_CNR, USBSTS_EINT, USBSTS_HCH,
    USBSTS_HSE, USBSTS_PCD, XECP_ID_LEGACY, XECP_ID_PROTOCOL,
};
use libcanvas::println;

// ---- Static 4 MiB DMA Pool Offsets (`[0x0000_0000 .. 0x0040_0000)`) ----
const MIN_DMA_POOL_BYTES: usize = 0x0024_0000;
const DCBAA_OFF: usize = 0x0000_0000; // 4 KiB
const SCRATCHPAD_ARR_OFF: usize = 0x0000_1000; // 4 KiB
const SCRATCHPAD_PAGES_OFF: usize = 0x0000_2000; // 32 * 4 KiB = 0x20000
const MAX_SCRATCHPADS: usize = 32;
const CMD_RING_OFF: usize = 0x0002_2000; // 4 KiB
const EVT_RING_OFF: usize = 0x0002_3000; // 4 KiB
const ERST_OFF: usize = 0x0002_4000; // 4 KiB
const OUT_CTX_BASE_OFF: usize = 0x0002_5000; // 32 * 4 KiB = 0x20000
const IN_CTX_BASE_OFF: usize = 0x0004_5000; // 32 * 4 KiB = 0x20000
const XFER_RING_BASE_OFF: usize = 0x0006_5000; // 64 * 4 KiB = 0x40000
const SLOT_BUF_BASE_OFF: usize = 0x000A_5000; // 32 * 4 KiB = 0x20000
pub const BOT_DATA_OFF: usize = 0x0010_0000; // 1 MiB contiguous BOT data window
pub const BOT_DATA_MAX_BYTES: usize = 0x0004_0000; // 256 KiB MDTS per request

const SLOT_CTRL_BUF_OFF: usize = 0x000; // 2048 B Control / Descriptor / CBW+CSW
const SLOT_INTR0_BUF_OFF: usize = 0x800; // 256 B Interrupt IN #0 (Kbd / Hub)
const SLOT_INTR1_BUF_OFF: usize = 0x900; // 256 B Interrupt IN #1 (Mouse)

const MAX_SLOTS: usize = 32;
const CMD_RING_TRBS: usize = 64;
const EVT_RING_TRBS: usize = 256;
const MAX_XFER_RINGS: usize = 64;
const XFER_RING_TRBS: usize = 64;
const MAX_COMPLETION_WAITERS: usize = 32;
const EVENT_DRAIN_BUDGET: usize = 128;

const CMD_TIMEOUT_TICKS: u64 = 150; // 1.5 s at 100 Hz
const XFER_TIMEOUT_TICKS: u64 = 300; // 3.0 s at 100 Hz

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbError {
    MmioInvalid,
    ControllerTimeout,
    NoSlots,
    NoRings,
    NoWaiters,
    TrbFailed(CompletionCode),
    DescriptorInvalid,
    BotFailed,
    DeviceGone,
}

impl UsbError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MmioInvalid => "mmio-invalid",
            Self::ControllerTimeout => "controller-timeout",
            Self::NoSlots => "no-slots",
            Self::NoRings => "no-rings",
            Self::NoWaiters => "no-waiters",
            Self::TrbFailed(_) => "trb-failed",
            Self::DescriptorInvalid => "descriptor-invalid",
            Self::BotFailed => "bot-failed",
            Self::DeviceGone => "device-gone",
        }
    }
}

/// Callback sink receiving decoded USB HID keyboard & mouse wire packets.
pub trait InputEventSink {
    fn on_key(&mut self, wire: [u8; 3]);
    fn on_mouse(&mut self, wire: [u8; 5]);
}

#[derive(Clone, Copy)]
struct XferRingSlot {
    in_use: bool,
    owner_slot: u8,
    owner_dci: u8,
    ring: ProducerRing,
}

impl XferRingSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            owner_slot: 0,
            owner_dci: 0,
            ring: ProducerRing::new(0, XFER_RING_TRBS),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IntrPipeKind {
    None,
    HidKeyboard,
    HidMouse,
    HubChange,
}

#[derive(Clone, Copy)]
struct IntrPipe {
    kind: IntrPipeKind,
    dci: u8,
    ring_idx: u8,
    buf_off: usize,
    xfer_len: u16,
}

impl IntrPipe {
    const EMPTY: Self = Self {
        kind: IntrPipeKind::None,
        dci: 0,
        ring_idx: 0,
        buf_off: 0,
        xfer_len: 0,
    };
}

#[derive(Clone, Copy)]
pub struct BotPipeState {
    pub active: bool,
    pub interface_num: u8,
    pub lun: u8,
    pub bulk_in_ep_addr: u8,
    pub bulk_in_dci: u8,
    pub bulk_in_ring: u8,
    pub bulk_out_ep_addr: u8,
    pub bulk_out_dci: u8,
    pub bulk_out_ring: u8,
    pub block_size: u32,
    pub total_blocks: u64,
    pub next_tag: u32,
}

impl BotPipeState {
    const EMPTY: Self = Self {
        active: false,
        interface_num: 0,
        lun: 0,
        bulk_in_ep_addr: 0,
        bulk_in_dci: 0,
        bulk_in_ring: 0,
        bulk_out_ep_addr: 0,
        bulk_out_dci: 0,
        bulk_out_ring: 0,
        block_size: 0,
        total_blocks: 0,
        next_tag: 1,
    };
}

#[derive(Clone, Copy)]
struct DeviceSlot {
    active: bool,
    slot_id: u8,
    root_port: u8,
    parent_slot_id: u8,
    parent_port: u8,
    route_string: u32,
    tier_depth: u8,
    tt_hub_slot_id: u8,
    tt_port_number: u8,
    speed: UsbSpeedAbi,
    ep0_ring_idx: u8,
    ep0_mps: u16,
    intr0: IntrPipe,
    intr1: IntrPipe,
    kbd_state: HidBootKeyboard,
    is_hub: bool,
    hub_ports: u8,
    hub_is_ss: bool,
    hub_child_slots: [u8; 16],
    bot: BotPipeState,
    inv: UsbInventoryDevice,
}

impl DeviceSlot {
    const EMPTY: Self = Self {
        active: false,
        slot_id: 0,
        root_port: 0,
        parent_slot_id: 0,
        parent_port: 0,
        route_string: 0,
        tier_depth: 0,
        tt_hub_slot_id: 0,
        tt_port_number: 0,
        speed: UsbSpeedAbi::Unknown,
        ep0_ring_idx: 0,
        ep0_mps: 8,
        intr0: IntrPipe::EMPTY,
        intr1: IntrPipe::EMPTY,
        kbd_state: HidBootKeyboard::new(),
        is_hub: false,
        hub_ports: 0,
        hub_is_ss: false,
        hub_child_slots: [0; 16],
        bot: BotPipeState::EMPTY,
        inv: UsbInventoryDevice::ZERO,
    };
}

struct HwState {
    cmd_ring: ProducerRing,
    evt_consumer: EventRingConsumer,
    xfer_rings: [XferRingSlot; MAX_XFER_RINGS],
    devices: [DeviceSlot; MAX_SLOTS],
    root_port_slots: [u8; 64],
    usb3_port_mask: u64,
    root_dirty_mask: u64,
    hub_dirty_mask: u32,
    completed_trbs: u64,
    hid_events: u64,
    bot_blocks_io: u64,
    generation: u64,
}

/// Zero-heap asynchronous xHCI 1.x controller instance.
pub struct XhciController {
    mmio: MappedWin,
    dma: MappedWin,
    dma_phys: u64,
    caps: XhciCapabilities,
    op_off: usize,
    ir0_off: usize,
    db_off: usize,
    active_max_slots: u8,
    active_max_ports: u8,
    bdf_packed: u32,
    iommu_isolated: bool,
    msi_active: bool,
    bios_handoff_done: bool,
    completions: TrbCompletionTable<MAX_COMPLETION_WAITERS>,
    hw: RefCell<HwState>,
    inventory_dirty: Cell<bool>,
}

impl XhciController {
    /// Bring up the xHCI 1.x controller (`USBLEGSUP` BIOS handoff, `HCRST`, `DCBAA`,
    /// Scratchpads, Command/Event Rings, Interrupter 0, and root port power).
    pub fn init_in_place(
        dst: &mut Option<Self>,
        mmio: MappedWin,
        dma: MappedWin,
        dma_phys: u64,
        bdf_packed: u32,
        iommu_isolated: bool,
        msi_active: bool,
    ) -> Result<(), UsbError> {
        if dma.len < MIN_DMA_POOL_BYTES || mmio.len < 0x100 {
            return Err(UsbError::MmioInvalid);
        }
        let Some(caps) = XhciCapabilities::parse(
            mmio.read32(0x00),
            mmio.read32(0x04),
            mmio.read32(0x08),
            mmio.read32(0x10),
            mmio.read32(0x14),
            mmio.read32(0x18),
        ) else {
            return Err(UsbError::MmioInvalid);
        };
        let op_off = usize::from(caps.cap_length);
        let db_off = caps.dboff;
        let ir0_off = caps.rtsoff + RT_IR0_BASE;
        if op_off + OP_PORT_BASE + 0x40 > mmio.len
            || db_off + 256 > mmio.len
            || ir0_off + 0x20 > mmio.len
        {
            return Err(UsbError::MmioInvalid);
        }

        let (bios_handoff_done, usb3_port_mask) =
            perform_bios_handoff_and_port_scan(&mmio, &caps);

        if !wait_mmio_mask(&mmio, op_off + OP_USBSTS, USBSTS_CNR, false, 200) {
            return Err(UsbError::ControllerTimeout);
        }

        // Stop controller (`RS = 0`) and wait for `HCH = 1`.
        let cmd0 = mmio.read32(op_off + OP_USBCMD);
        if (cmd0 & USBCMD_RS) != 0 {
            mmio.write32(op_off + OP_USBCMD, cmd0 & !USBCMD_RS);
            if !wait_mmio_mask(&mmio, op_off + OP_USBSTS, USBSTS_HCH, true, 100) {
                return Err(UsbError::ControllerTimeout);
            }
        }

        // Issue Host Controller Reset (`HCRST = 1`) and wait for `HCRST == 0` & `CNR == 0`.
        mmio.write32(op_off + OP_USBCMD, USBCMD_HCRST);
        if !wait_mmio_mask(&mmio, op_off + OP_USBCMD, USBCMD_HCRST, false, 200)
            || !wait_mmio_mask(&mmio, op_off + OP_USBSTS, USBSTS_CNR, false, 200)
        {
            return Err(UsbError::ControllerTimeout);
        }

        if (mmio.read32(op_off + OP_PAGESIZE) & 1) == 0 {
            return Err(UsbError::MmioInvalid);
        }

        let active_max_slots = caps.max_slots.min(MAX_SLOTS as u8);
        let active_max_ports = caps.max_ports.min(63);

        dma.zero_range(0, SLOT_BUF_BASE_OFF + MAX_SLOTS * 0x1000);

        let scratch_cnt = usize::from(caps.max_scratchpad_bufs).min(MAX_SCRATCHPADS);
        if scratch_cnt > 0 {
            let mut s = 0usize;
            while s < scratch_cnt {
                let page_phys = dma_phys + (SCRATCHPAD_PAGES_OFF + s * 0x1000) as u64;
                dma.write64_dma(SCRATCHPAD_ARR_OFF + s * 8, page_phys);
                s += 1;
            }
            dma.write64_dma(DCBAA_OFF, dma_phys + SCRATCHPAD_ARR_OFF as u64);
        }

        mmio.write32(op_off + OP_CONFIG, u32::from(active_max_slots));
        mmio.write64_split(op_off + OP_DCBAAP, dma_phys + DCBAA_OFF as u64);

        let cmd_ring_phys = dma_phys + CMD_RING_OFF as u64;
        let cmd_ring = ProducerRing::new(cmd_ring_phys, CMD_RING_TRBS);
        mmio.write64_split(op_off + OP_CRCR, cmd_ring.current_iova_with_cycle());

        let evt_ring_phys = dma_phys + EVT_RING_OFF as u64;
        let erst_phys = dma_phys + ERST_OFF as u64;
        let evt_consumer = EventRingConsumer::new(evt_ring_phys, EVT_RING_TRBS);
        dma.write64_dma(ERST_OFF, evt_ring_phys);
        dma.write32(ERST_OFF + 8, EVT_RING_TRBS as u32);
        dma.write32(ERST_OFF + 12, 0);

        mmio.write32(ir0_off + IR_IMOD, 160);
        mmio.write32(ir0_off + IR_ERSTSZ, 1);
        mmio.write64_split(ir0_off + IR_ERDP, evt_consumer.erdp_with_ehb());
        mmio.write64_split(ir0_off + IR_ERSTBA, erst_phys);
        mmio.write32(ir0_off + IR_IMAN, IMAN_IP | IMAN_IE);

        mmio.write32(
            op_off + OP_USBSTS,
            USBSTS_EINT | USBSTS_PCD | USBSTS_HSE,
        );
        mmio.write32(
            op_off + OP_USBCMD,
            USBCMD_RS | USBCMD_INTE | USBCMD_HSEE,
        );
        if !wait_mmio_mask(&mmio, op_off + OP_USBSTS, USBSTS_HCH, false, 100) {
            return Err(UsbError::ControllerTimeout);
        }

        // Ensure Port Power (`PP`) is enabled across all root ports without clobbering RW1C bits.
        let mut p = 1u8;
        while p <= active_max_ports {
            let poff = op_off + port_sc_offset(p);
            let raw = mmio.read32(poff);
            if (raw & PORTSC_PP) == 0 {
                mmio.write32(poff, portsc_preserve_rw(raw) | PORTSC_PP);
            }
            p += 1;
        }
        libcanvas::system::sleep_ms(20);

        let all_ports_mask = if active_max_ports >= 63 {
            !1u64
        } else {
            ((1u64 << (active_max_ports + 1)) - 1) & !1u64
        };

        *dst = Some(Self {
            mmio,
            dma,
            dma_phys,
            caps,
            op_off,
            ir0_off,
            db_off,
            active_max_slots,
            active_max_ports,
            bdf_packed,
            iommu_isolated,
            msi_active,
            bios_handoff_done,
            completions: TrbCompletionTable::new(),
            hw: RefCell::new(HwState {
                cmd_ring,
                evt_consumer,
                xfer_rings: [const { XferRingSlot::empty() }; MAX_XFER_RINGS],
                devices: [DeviceSlot::EMPTY; MAX_SLOTS],
                root_port_slots: [0; 64],
                usb3_port_mask,
                root_dirty_mask: all_ports_mask,
                hub_dirty_mask: 0,
                completed_trbs: 0,
                hid_events: 0,
                bot_blocks_io: 0,
                generation: 1,
            }),
            inventory_dirty: Cell::new(true),
        });

        println!(
            "[driver-host:xhci] controller online hci={:#06x} slots={} ports={} csz={}B scratch={} bios_handoff={} iommu={}",
            caps.hci_version,
            active_max_slots,
            active_max_ports,
            caps.context_size,
            scratch_cnt,
            bios_handoff_done,
            iommu_isolated
        );
        Ok(())
    }

    pub fn take_inventory_dirty(&self) -> bool {
        self.inventory_dirty.replace(false)
    }

    pub fn mark_inventory_dirty(&self) {
        self.inventory_dirty.set(true);
    }

    pub fn has_pending_topology_work(&self) -> bool {
        let hw = self.hw.borrow();
        hw.root_dirty_mask != 0 || hw.hub_dirty_mask != 0
    }

    pub fn first_bot_geometry(&self) -> Option<(u8, u32, u64)> {
        let hw = self.hw.borrow();
        let mut i = 0usize;
        while i < MAX_SLOTS {
            let d = &hw.devices[i];
            if d.active && d.bot.active && d.bot.block_size > 0 {
                return Some((d.slot_id, d.bot.block_size, d.bot.total_blocks));
            }
            i += 1;
        }
        None
    }

    pub fn dma_win(&self) -> MappedWin {
        self.dma
    }

    /// Encode the current zero-bus-traffic `HUSB` v1 snapshot into `out`.
    pub fn encode_husb_snapshot(&self, out: &mut [u8]) -> Option<usize> {
        let mut hw = self.hw.borrow_mut();
        hw.generation = hw.generation.saturating_add(1);
        let mut records = [UsbInventoryDevice::ZERO; usb::MAX_DEVICES];
        let mut count = 0usize;
        let mut i = 0usize;
        while i < MAX_SLOTS && count < usb::MAX_DEVICES {
            if hw.devices[i].active {
                records[count] = hw.devices[i].inv;
                count += 1;
            }
            i += 1;
        }
        let mut flags = 0u8;
        if self.iommu_isolated {
            flags |= USB_FLAG_IOMMU_ISOLATED;
        }
        if self.msi_active {
            flags |= USB_FLAG_MSI_ACTIVE;
        }
        if self.bios_handoff_done {
            flags |= USB_FLAG_BIOS_HANDOFF_DONE;
        }
        let hdr = UsbInventoryHeader {
            generation: hw.generation,
            controller_bdf_packed: self.bdf_packed,
            controller_vendor_id: 0,
            controller_device_id: 0,
            hci_version: self.caps.hci_version,
            max_slots: self.active_max_slots,
            max_ports: self.active_max_ports,
            device_count: count as u8,
            flags,
            completed_trbs: hw.completed_trbs,
            hid_events: hw.hid_events,
            bot_blocks_io: hw.bot_blocks_io,
        };
        usb::encode(&hdr, &records[..count], out).ok()
    }

    /// Drain pending xHCI Event Ring TRBs, waking any awaiting futures in
    /// [`TrbCompletionTable`] and dispatching HID / Hub periodic Interrupt IN events.
    pub fn pump_events(&self, sink: &mut dyn InputEventSink) -> usize {
        let sts = self.mmio.read32(self.op_off + OP_USBSTS);
        if (sts & (USBSTS_EINT | USBSTS_PCD | USBSTS_HSE)) != 0 {
            self.mmio.write32(
                self.op_off + OP_USBSTS,
                sts & (USBSTS_EINT | USBSTS_PCD | USBSTS_HSE),
            );
        }
        let iman = self.mmio.read32(self.ir0_off + IR_IMAN);
        if (iman & IMAN_IP) != 0 {
            self.mmio
                .write32(self.ir0_off + IR_IMAN, iman | IMAN_IP | IMAN_IE);
        }

        let mut drained = 0usize;
        let mut erdp_to_write: Option<u64> = None;

        while drained < EVENT_DRAIN_BUDGET {
            let popped = {
                let mut hw = self.hw.borrow_mut();
                let idx = hw.evt_consumer.dequeue_index();
                let raw_trb = self.dma.read_trb(EVT_RING_OFF, idx);
                hw.evt_consumer
                    .try_consume(raw_trb)
                    .map(|ev| (ev, hw.evt_consumer.erdp_with_ehb()))
            };
            let Some((ev, erdp)) = popped else {
                break;
            };
            erdp_to_write = Some(erdp);
            drained += 1;

            match ev {
                DecodedEvent::CommandCompletion {
                    cmd_trb_iova,
                    code,
                    slot_id,
                } => {
                    self.hw.borrow_mut().completed_trbs += 1;
                    let _ = self.completions.complete_by_trb(
                        cmd_trb_iova,
                        TrbOutcome {
                            code,
                            residual_len: 0,
                            slot_id,
                            dci: 0,
                        },
                    );
                }
                DecodedEvent::TransferEvent {
                    trb_iova,
                    code,
                    residual_len,
                    dci,
                    slot_id,
                } => {
                    self.hw.borrow_mut().completed_trbs += 1;
                    if !self.try_handle_periodic_intr(slot_id, dci, code, residual_len, sink) {
                        let _ = self.completions.complete_by_trb(
                            trb_iova,
                            TrbOutcome {
                                code,
                                residual_len,
                                slot_id,
                                dci,
                            },
                        );
                    }
                }
                DecodedEvent::PortStatusChange { port_id, .. } => {
                    if port_id > 0 && port_id <= self.active_max_ports {
                        self.hw.borrow_mut().root_dirty_mask |= 1u64 << port_id;
                    }
                }
                DecodedEvent::Other { .. } => {}
            }
        }

        if let Some(erdp) = erdp_to_write {
            self.mmio.write64_split(self.ir0_off + IR_ERDP, erdp);
        }
        drained
    }

    fn try_handle_periodic_intr(
        &self,
        slot_id: u8,
        dci: u8,
        code: CompletionCode,
        residual: u32,
        sink: &mut dyn InputEventSink,
    ) -> bool {
        if slot_id == 0 || usize::from(slot_id) > MAX_SLOTS {
            return false;
        }
        let d_idx = usize::from(slot_id - 1);
        let pipe = {
            let hw = self.hw.borrow();
            let dev = &hw.devices[d_idx];
            if !dev.active {
                return false;
            }
            if dev.intr0.kind != IntrPipeKind::None && dev.intr0.dci == dci {
                dev.intr0
            } else if dev.intr1.kind != IntrPipeKind::None && dev.intr1.dci == dci {
                dev.intr1
            } else {
                return false;
            }
        };

        if code.is_ok() {
            let actual = usize::from(pipe.xfer_len).saturating_sub(residual as usize);
            let mut raw = [0u8; 16];
            let copy_len = actual.min(raw.len());
            if copy_len > 0 {
                self.dma.copy_out(pipe.buf_off, &mut raw[..copy_len]);
            }
            match pipe.kind {
                IntrPipeKind::HidKeyboard if copy_len >= 8 => {
                    let mut events = [HidKeyEvent {
                        key: 0,
                        pressed: false,
                    }; MAX_HID_KEY_EVENTS];
                    let count = {
                        let mut hw = self.hw.borrow_mut();
                        let n = hw.devices[d_idx]
                            .kbd_state
                            .feed_report(&raw[..8], &mut events);
                        hw.hid_events = hw.hid_events.saturating_add(n as u64);
                        n
                    };
                    let mut saw_release = false;
                    let mut k = 0usize;
                    while k < count {
                        if !events[k].pressed {
                            saw_release = true;
                        }
                        sink.on_key(events[k].to_wire());
                        k += 1;
                    }
                    if saw_release {
                        self.inventory_dirty.set(true);
                    }
                }
                IntrPipeKind::HidMouse if copy_len >= 3 => {
                    if let Some(m) = HidMouseEvent::decode(&raw[..copy_len]) {
                        self.hw.borrow_mut().hid_events += 1;
                        sink.on_mouse(m.to_wire());
                    }
                }
                IntrPipeKind::HubChange => {
                    self.hw.borrow_mut().hub_dirty_mask |= 1u32 << d_idx;
                }
                _ => {}
            }
        }

        self.arm_interrupt_pipe(slot_id, pipe);
        true
    }

    fn arm_interrupt_pipe(&self, slot_id: u8, pipe: IntrPipe) {
        let mut hw = self.hw.borrow_mut();
        let d_idx = usize::from(slot_id.saturating_sub(1));
        if d_idx >= MAX_SLOTS || !hw.devices[d_idx].active {
            return;
        }
        let r_idx = usize::from(pipe.ring_idx);
        if r_idx >= MAX_XFER_RINGS || !hw.xfer_rings[r_idx].in_use {
            return;
        }
        let buf_phys = self.dma_phys + pipe.buf_off as u64;
        let trb = Trb::xfer_normal(buf_phys, u32::from(pipe.xfer_len), true, true, false);
        let _ = enqueue_xfer_trb(&self.dma, &mut hw.xfer_rings[r_idx], r_idx, trb);
        drop(hw);
        self.ring_doorbell(slot_id, pipe.dci);
    }

    fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let off = self.db_off + usize::from(slot_id) * 4;
        self.mmio.write32(off, u32::from(target));
    }

    /// Drive all pending root-port and downstream USB Hub port enumerations
    /// asynchronously via `hues_async::block_on` + `TrbCompletionTable`.
    pub fn process_topology<F>(&self, sink: &mut dyn InputEventSink, mut wait_irq: F)
    where
        F: FnMut(),
    {
        block_on(self.process_topology_async(), || {
            if self.pump_events(sink) == 0 {
                wait_irq();
                let _ = self.pump_events(sink);
            }
        });
    }

    /// Execute one Bulk-Only Transport (`BOT`) SCSI Read/Write operation
    /// asynchronously via `hues_async::block_on` + `TrbCompletionTable`.
    pub fn execute_bot_io<F>(
        &self,
        slot_id: u8,
        is_write: bool,
        lba: u64,
        blocks: u16,
        sink: &mut dyn InputEventSink,
        mut wait_irq: F,
    ) -> Result<(), UsbError>
    where
        F: FnMut(),
    {
        block_on(
            self.bot_rw_blocks_async(slot_id, is_write, lba, blocks),
            || {
                if self.pump_events(sink) == 0 {
                    wait_irq();
                    let _ = self.pump_events(sink);
                }
            },
        )
    }

    pub fn execute_bot_flush<F>(
        &self,
        slot_id: u8,
        sink: &mut dyn InputEventSink,
        mut wait_irq: F,
    ) -> Result<(), UsbError>
    where
        F: FnMut(),
    {
        block_on(self.bot_sync_cache_async(slot_id), || {
            if self.pump_events(sink) == 0 {
                wait_irq();
                let _ = self.pump_events(sink);
            }
        })
    }

    async fn process_topology_async(&self) {
        let root_mask = {
            let mut hw = self.hw.borrow_mut();
            let m = hw.root_dirty_mask;
            hw.root_dirty_mask = 0;
            m
        };
        if root_mask != 0 {
            let mut port = 1u8;
            while port <= self.active_max_ports {
                if (root_mask & (1u64 << port)) != 0 {
                    self.inspect_root_port(port).await;
                }
                port += 1;
            }
        }

        let hub_mask = {
            let mut hw = self.hw.borrow_mut();
            let m = hw.hub_dirty_mask;
            hw.hub_dirty_mask = 0;
            m
        };
        if hub_mask != 0 {
            let mut d_idx = 0usize;
            while d_idx < MAX_SLOTS {
                if (hub_mask & (1u32 << d_idx)) != 0 {
                    let slot_id = (d_idx + 1) as u8;
                    self.scan_hub_ports(slot_id).await;
                }
                d_idx += 1;
            }
        }
    }

    async fn inspect_root_port(&self, port: u8) {
        let poff = self.op_off + port_sc_offset(port);
        let raw0 = self.mmio.read32(poff);
        if (raw0 & PORTSC_CHANGE_BITS) != 0 {
            self.mmio
                .write32(poff, portsc_preserve_rw(raw0) | (raw0 & PORTSC_CHANGE_BITS));
        }

        let connected = (raw0 & PORTSC_CCS) != 0;
        let existing_slot = self.hw.borrow().root_port_slots[usize::from(port)];
        if !connected {
            if existing_slot != 0 {
                println!(
                    "[driver-host:xhci] root port {} disconnected (slot={})",
                    port, existing_slot
                );
                self.teardown_device_tree(existing_slot).await;
                self.hw.borrow_mut().root_port_slots[usize::from(port)] = 0;
                self.inventory_dirty.set(true);
            }
            return;
        }
        if existing_slot != 0 {
            return;
        }

        let mut raw = self.mmio.read32(poff);
        if (raw & PORTSC_PED) == 0 {
            self.mmio.write32(poff, portsc_preserve_rw(raw) | PORTSC_PR);
            let mut tries = 0u32;
            while tries < 30 {
                libcanvas::system::sleep_ms(10);
                raw = self.mmio.read32(poff);
                if (raw & PORTSC_PR) == 0 && (raw & PORTSC_PED) != 0 {
                    break;
                }
                tries += 1;
            }
            if (raw & PORTSC_PRC) != 0 {
                self.mmio
                    .write32(poff, portsc_preserve_rw(raw) | PORTSC_PRC);
            }
        }

        raw = self.mmio.read32(poff);
        if (raw & (PORTSC_CCS | PORTSC_PED)) != (PORTSC_CCS | PORTSC_PED) {
            return;
        }
        let mut speed = portsc_speed(raw);
        if speed == UsbSpeedAbi::Unknown {
            let is_usb3 = (self.hw.borrow().usb3_port_mask & (1u64 << port)) != 0;
            speed = if is_usb3 {
                UsbSpeedAbi::Super
            } else {
                UsbSpeedAbi::High
            };
        }

        match self.enumerate_device(port, 0, 0, 0, 0, 0, 0, speed).await {
            Ok(slot_id) => {
                self.hw.borrow_mut().root_port_slots[usize::from(port)] = slot_id;
                self.inventory_dirty.set(true);
                let is_hub = self.hw.borrow().devices[usize::from(slot_id - 1)].is_hub;
                if is_hub {
                    self.scan_hub_ports(slot_id).await;
                }
            }
            Err(err) => {
                println!(
                    "[driver-host:xhci] root port {} enumeration failed: {}",
                    port,
                    err.as_str()
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn enumerate_device(
        &self,
        root_port: u8,
        parent_slot_id: u8,
        parent_port: u8,
        route_string: u32,
        tier_depth: u8,
        tt_hub_slot_id: u8,
        tt_port_number: u8,
        speed: UsbSpeedAbi,
    ) -> Result<u8, UsbError> {
        let enable_out = self.submit_command(Trb::cmd_enable_slot()).await?;
        let slot_id = enable_out.slot_id;
        if slot_id == 0 || usize::from(slot_id) > usize::from(self.active_max_slots) {
            return Err(UsbError::NoSlots);
        }
        let d_idx = usize::from(slot_id - 1);

        let Some(ep0_ring_idx) = self.alloc_xfer_ring(slot_id, 1) else {
            let _ = self.submit_command(Trb::cmd_disable_slot(slot_id)).await;
            return Err(UsbError::NoRings);
        };
        let init_mps = if speed == UsbSpeedAbi::Full {
            8
        } else {
            default_ep0_mps(speed)
        };

        let out_ctx_off = OUT_CTX_BASE_OFF + d_idx * 0x1000;
        let in_ctx_off = IN_CTX_BASE_OFF + d_idx * 0x1000;
        self.dma.zero_range(out_ctx_off, 0x1000);
        self.dma.zero_range(in_ctx_off, 0x1000);
        self.dma.write64_dma(
            DCBAA_OFF + usize::from(slot_id) * 8,
            self.dma_phys + out_ctx_off as u64,
        );

        let ep0_ring_iova = self.xfer_ring_phys(ep0_ring_idx) | 1;
        let csz = self.caps.context_size;
        {
            let mut in_buf = [0u8; 33 * 64];
            let slot_params = SlotContextParams {
                route_string,
                speed,
                context_entries: 1,
                root_hub_port: root_port,
                is_hub: false,
                num_ports: 0,
                tt_hub_slot_id,
                tt_port_number,
            };
            let _ = init_input_context(&mut in_buf, csz, 0, 0x3, &slot_params);
            let ep0_params = EndpointContextParams {
                dci: 1,
                ep_type: XhciEndpointType::ControlBiDir,
                max_packet_size: init_mps,
                max_burst: 0,
                interval: 0,
                tr_dequeue_ptr_with_dcs: ep0_ring_iova,
                avg_trb_len: 8,
            };
            let _ = set_input_endpoint_context(&mut in_buf, csz, &ep0_params);
            self.dma.copy_in(in_ctx_off, &in_buf[..csz * 3]);
        }

        {
            let mut hw = self.hw.borrow_mut();
            let mut dev = DeviceSlot::EMPTY;
            dev.active = true;
            dev.slot_id = slot_id;
            dev.root_port = root_port;
            dev.parent_slot_id = parent_slot_id;
            dev.parent_port = parent_port;
            dev.route_string = route_string;
            dev.tier_depth = tier_depth;
            dev.tt_hub_slot_id = tt_hub_slot_id;
            dev.tt_port_number = tt_port_number;
            dev.speed = speed;
            dev.ep0_ring_idx = ep0_ring_idx;
            dev.ep0_mps = init_mps;
            hw.devices[d_idx] = dev;
        }

        let in_ctx_phys = self.dma_phys + in_ctx_off as u64;
        if let Err(err) = self
            .submit_command(Trb::cmd_address_device(in_ctx_phys, slot_id, false))
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }
        libcanvas::system::sleep_ms(10);

        let mut dev_buf = [0u8; 18];
        if let Err(err) = self
            .control_in(
                slot_id,
                SetupPacket::get_descriptor(DESC_DEVICE, 0, 0, 8),
                &mut dev_buf[..8],
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }
        let prelim_mps = if speed.is_superspeed() {
            512u16
        } else {
            match dev_buf[7] {
                8 | 16 | 32 | 64 => u16::from(dev_buf[7]),
                _ => init_mps,
            }
        };
        if prelim_mps != init_mps {
            let _ = self.evaluate_ep0_mps(slot_id, prelim_mps).await;
        }

        if let Err(err) = self
            .control_in(
                slot_id,
                SetupPacket::get_descriptor(DESC_DEVICE, 0, 0, 18),
                &mut dev_buf,
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }
        let Some(dev_desc) = DeviceDescriptor::parse(&dev_buf) else {
            self.teardown_single_slot(slot_id).await;
            return Err(UsbError::DescriptorInvalid);
        };
        let actual_mps = dev_desc.ep0_max_packet_size();
        if actual_mps != self.hw.borrow().devices[d_idx].ep0_mps {
            let _ = self.evaluate_ep0_mps(slot_id, actual_mps).await;
        }

        let mut manufacturer = [0u8; MAX_MANUFACTURER_LEN];
        let mut product = [0u8; MAX_PRODUCT_LEN];
        let mut mfg_len = 0usize;
        let mut prod_len = 0usize;
        if dev_desc.manufacturer_str_idx != 0 || dev_desc.product_str_idx != 0 {
            let lang_id = self.fetch_lang_id(slot_id).await.unwrap_or(0x0409);
            if dev_desc.manufacturer_str_idx != 0 {
                mfg_len = self
                    .fetch_usb_string(
                        slot_id,
                        dev_desc.manufacturer_str_idx,
                        lang_id,
                        &mut manufacturer,
                    )
                    .await;
            }
            if dev_desc.product_str_idx != 0 {
                prod_len = self
                    .fetch_usb_string(slot_id, dev_desc.product_str_idx, lang_id, &mut product)
                    .await;
            }
        }

        let mut cfg_hdr_buf = [0u8; 9];
        if let Err(err) = self
            .control_in(
                slot_id,
                SetupPacket::get_descriptor(DESC_CONFIGURATION, 0, 0, 9),
                &mut cfg_hdr_buf,
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }
        let Some(cfg_hdr) = ConfigurationDescriptor::parse_header(&cfg_hdr_buf) else {
            self.teardown_single_slot(slot_id).await;
            return Err(UsbError::DescriptorInvalid);
        };
        let cfg_total = usize::from(cfg_hdr.total_length).min(512);
        let mut cfg_blob = [0u8; 512];
        if let Err(err) = self
            .control_in(
                slot_id,
                SetupPacket::get_descriptor(DESC_CONFIGURATION, 0, 0, cfg_total as u16),
                &mut cfg_blob[..cfg_total],
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }

        if let Err(err) = self
            .control_no_data(
                slot_id,
                SetupPacket::set_configuration(cfg_hdr.configuration_value),
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }

        if let Err(err) = self
            .configure_device_classes(
                slot_id,
                &dev_desc,
                &cfg_hdr,
                &cfg_blob[..cfg_total],
                &manufacturer[..mfg_len],
                &product[..prod_len],
            )
            .await
        {
            self.teardown_single_slot(slot_id).await;
            return Err(err);
        }

        let inv_snap = self.hw.borrow().devices[d_idx].inv;
        println!(
            "[driver-host:xhci] slot={} port={}.{} {:04x}:{:04x} speed={} role={} prod=\"{}\"",
            slot_id,
            root_port,
            parent_port,
            inv_snap.vendor_id,
            inv_snap.product_id,
            inv_snap.speed.as_str(),
            inv_snap.role.as_str(),
            inv_snap.product_str()
        );
        Ok(slot_id)
    }

    async fn evaluate_ep0_mps(&self, slot_id: u8, new_mps: u16) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let out_ctx_off = OUT_CTX_BASE_OFF + d_idx * 0x1000;
        let in_ctx_off = IN_CTX_BASE_OFF + d_idx * 0x1000;
        let csz = self.caps.context_size;

        self.dma.zero_range(in_ctx_off, 0x1000);
        let mut ctx_copy = [0u8; 256];
        self.dma.copy_out(out_ctx_off, &mut ctx_copy[csz..csz * 3]);
        ctx_copy[4..8].copy_from_slice(&(1u32 << 1).to_le_bytes());
        let ep0_d1_off = csz * 2 + 4;
        let old_d1 = u32::from_le_bytes([
            ctx_copy[ep0_d1_off],
            ctx_copy[ep0_d1_off + 1],
            ctx_copy[ep0_d1_off + 2],
            ctx_copy[ep0_d1_off + 3],
        ]);
        let new_d1 = (old_d1 & 0x0000_FFFF) | (u32::from(new_mps) << 16);
        ctx_copy[ep0_d1_off..ep0_d1_off + 4].copy_from_slice(&new_d1.to_le_bytes());
        self.dma.copy_in(in_ctx_off, &ctx_copy[..csz * 3]);

        self.submit_command(Trb::cmd_evaluate_context(
            self.dma_phys + in_ctx_off as u64,
            slot_id,
        ))
        .await?;
        self.hw.borrow_mut().devices[d_idx].ep0_mps = new_mps;
        Ok(())
    }

    async fn fetch_lang_id(&self, slot_id: u8) -> Option<u16> {
        let mut buf = [0u8; 8];
        self.control_in(
            slot_id,
            SetupPacket::get_descriptor(DESC_STRING, 0, 0, 4),
            &mut buf[..4],
        )
        .await
        .ok()?;
        if buf[0] >= 4 && buf[1] == DESC_STRING {
            Some(u16::from_le_bytes([buf[2], buf[3]]))
        } else {
            None
        }
    }

    async fn fetch_usb_string(
        &self,
        slot_id: u8,
        str_idx: u8,
        lang_id: u16,
        out_ascii: &mut [u8],
    ) -> usize {
        let mut raw = [0u8; 128];
        if self
            .control_in(
                slot_id,
                SetupPacket::get_descriptor(DESC_STRING, str_idx, lang_id, raw.len() as u16),
                &mut raw,
            )
            .await
            .is_err()
        {
            return 0;
        }
        decode_usb_string_ascii(&raw, out_ascii)
    }

    async fn configure_device_classes(
        &self,
        slot_id: u8,
        dev_desc: &DeviceDescriptor,
        cfg_hdr: &ConfigurationDescriptor,
        cfg_blob: &[u8],
        mfg_ascii: &[u8],
        prod_ascii: &[u8],
    ) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let speed = self.hw.borrow().devices[d_idx].speed;

        let mut primary_iface = None;
        let mut cur_iface = None;
        let mut hub_ep: Option<(EndpointDescriptor, u8)> = None;
        let mut kbd_ep: Option<(u8, EndpointDescriptor, u8)> = None;
        let mut mouse_ep: Option<(u8, EndpointDescriptor, u8)> = None;
        let mut bot_iface: Option<u8> = None;
        let mut bot_in: Option<(EndpointDescriptor, u8)> = None;
        let mut bot_out: Option<(EndpointDescriptor, u8)> = None;
        let mut total_eps = 0u8;

        let iter = DescriptorIter::new(cfg_blob);
        let mut last_target: u8 = 0;
        for item in iter {
            match item {
                ParsedDescriptor::Interface(iface) => {
                    if iface.alternate_setting == 0 {
                        if primary_iface.is_none() {
                            primary_iface = Some(iface);
                        }
                        cur_iface = Some(iface);
                    } else {
                        cur_iface = None;
                    }
                    last_target = 0;
                }
                ParsedDescriptor::Endpoint(ep) => {
                    let Some(iface) = cur_iface else {
                        continue;
                    };
                    total_eps = total_eps.saturating_add(1);
                    last_target = 0;
                    if (iface.interface_class == USB_CLASS_HUB
                        || dev_desc.device_class == USB_CLASS_HUB)
                        && ep.xhci_ep_type() == Some(XhciEndpointType::InterruptIn)
                        && hub_ep.is_none()
                    {
                        hub_ep = Some((ep, 0));
                        last_target = 1;
                    } else if iface.interface_class == USB_CLASS_HID
                        && ep.xhci_ep_type() == Some(XhciEndpointType::InterruptIn)
                    {
                        if iface.interface_protocol == HID_PROTO_KEYBOARD && kbd_ep.is_none() {
                            kbd_ep = Some((iface.interface_number, ep, 0));
                            last_target = 2;
                        } else if iface.interface_protocol == HID_PROTO_MOUSE && mouse_ep.is_none()
                        {
                            mouse_ep = Some((iface.interface_number, ep, 0));
                            last_target = 3;
                        } else if kbd_ep.is_none() {
                            kbd_ep = Some((iface.interface_number, ep, 0));
                            last_target = 2;
                        }
                    } else if iface.interface_class == USB_CLASS_MASS_STORAGE
                        && iface.interface_subclass == MSC_SUBCLASS_SCSI
                        && iface.interface_protocol == MSC_PROTO_BULK_ONLY
                    {
                        bot_iface = Some(iface.interface_number);
                        match ep.xhci_ep_type() {
                            Some(XhciEndpointType::BulkIn) if bot_in.is_none() => {
                                bot_in = Some((ep, 0));
                                last_target = 4;
                            }
                            Some(XhciEndpointType::BulkOut) if bot_out.is_none() => {
                                bot_out = Some((ep, 0));
                                last_target = 5;
                            }
                            _ => {}
                        }
                    }
                }
                ParsedDescriptor::SsCompanion { max_burst } => match last_target {
                    1 => {
                        if let Some(h) = hub_ep.as_mut() {
                            h.1 = max_burst;
                        }
                    }
                    2 => {
                        if let Some(k) = kbd_ep.as_mut() {
                            k.2 = max_burst;
                        }
                    }
                    3 => {
                        if let Some(m) = mouse_ep.as_mut() {
                            m.2 = max_burst;
                        }
                    }
                    4 => {
                        if let Some(bi) = bot_in.as_mut() {
                            bi.1 = max_burst;
                        }
                    }
                    5 => {
                        if let Some(bo) = bot_out.as_mut() {
                            bo.1 = max_burst;
                        }
                    }
                    _ => {}
                },
            }
        }

        let mut hub_desc_opt: Option<HubDescriptor> = None;
        if hub_ep.is_some() || dev_desc.device_class == USB_CLASS_HUB {
            let mut hbuf = [0u8; 16];
            let try_ss = speed.is_superspeed();
            if self
                .control_in(
                    slot_id,
                    SetupPacket::hub_get_descriptor(try_ss, 12),
                    &mut hbuf[..12],
                )
                .await
                .is_ok()
            {
                hub_desc_opt = HubDescriptor::parse(&hbuf[..12]);
            }
            if hub_desc_opt.is_none()
                && self
                    .control_in(
                        slot_id,
                        SetupPacket::hub_get_descriptor(false, 12),
                        &mut hbuf[..12],
                    )
                    .await
                    .is_ok()
            {
                hub_desc_opt = HubDescriptor::parse(&hbuf[..12]);
            }
        }

        let in_ctx_off = IN_CTX_BASE_OFF + d_idx * 0x1000;
        let csz = self.caps.context_size;
        let mut in_ctx = [0u8; 33 * 64];
        let mut add_flags: u32 = 1 << 0; // `A0 = 1`, `A1 = 0` per xHCI §4.6.6
        let mut max_dci: u8 = 1;

        let slot_buf_base = SLOT_BUF_BASE_OFF + d_idx * 0x1000;
        let mut intr0_pipe = IntrPipe::EMPTY;
        let mut intr1_pipe = IntrPipe::EMPTY;
        let mut bot_state = BotPipeState::EMPTY;

        if let (Some((ep, burst)), Some(_hub_desc)) = (hub_ep, hub_desc_opt) {
            if let Some((dci, r_idx)) = self.prepare_ep_ctx(
                slot_id,
                speed,
                ep,
                burst,
                &mut in_ctx,
                csz,
                &mut add_flags,
                &mut max_dci,
            ) {
                intr0_pipe = IntrPipe {
                    kind: IntrPipeKind::HubChange,
                    dci,
                    ring_idx: r_idx,
                    buf_off: slot_buf_base + SLOT_INTR0_BUF_OFF,
                    xfer_len: ep.base_packet_size().clamp(1, 8),
                };
            }
        } else {
            if let Some((_iface_num, ep, burst)) = kbd_ep {
                if let Some((dci, r_idx)) = self.prepare_ep_ctx(
                    slot_id,
                    speed,
                    ep,
                    burst,
                    &mut in_ctx,
                    csz,
                    &mut add_flags,
                    &mut max_dci,
                ) {
                    intr0_pipe = IntrPipe {
                        kind: IntrPipeKind::HidKeyboard,
                        dci,
                        ring_idx: r_idx,
                        buf_off: slot_buf_base + SLOT_INTR0_BUF_OFF,
                        xfer_len: ep.base_packet_size().clamp(8, 16),
                    };
                }
            }
            if let Some((_iface_num, ep, burst)) = mouse_ep {
                if let Some((dci, r_idx)) = self.prepare_ep_ctx(
                    slot_id,
                    speed,
                    ep,
                    burst,
                    &mut in_ctx,
                    csz,
                    &mut add_flags,
                    &mut max_dci,
                ) {
                    intr1_pipe = IntrPipe {
                        kind: IntrPipeKind::HidMouse,
                        dci,
                        ring_idx: r_idx,
                        buf_off: slot_buf_base + SLOT_INTR1_BUF_OFF,
                        xfer_len: ep.base_packet_size().clamp(3, 8),
                    };
                }
            }
        }

        if let (Some(iface_num), Some((ep_in, burst_in)), Some((ep_out, burst_out))) =
            (bot_iface, bot_in, bot_out)
        {
            let in_prep = self.prepare_ep_ctx(
                slot_id,
                speed,
                ep_in,
                burst_in,
                &mut in_ctx,
                csz,
                &mut add_flags,
                &mut max_dci,
            );
            let out_prep = self.prepare_ep_ctx(
                slot_id,
                speed,
                ep_out,
                burst_out,
                &mut in_ctx,
                csz,
                &mut add_flags,
                &mut max_dci,
            );
            if let (Some((in_dci, in_ring)), Some((out_dci, out_ring))) = (in_prep, out_prep) {
                bot_state = BotPipeState {
                    active: true,
                    interface_num: iface_num,
                    lun: 0,
                    bulk_in_ep_addr: ep_in.endpoint_address,
                    bulk_in_dci: in_dci,
                    bulk_in_ring: in_ring,
                    bulk_out_ep_addr: ep_out.endpoint_address,
                    bulk_out_dci: out_dci,
                    bulk_out_ring: out_ring,
                    block_size: 0,
                    total_blocks: 0,
                    next_tag: 1,
                };
            }
        }

        if add_flags != (1 << 0) {
            let dev_copy = self.hw.borrow().devices[d_idx];
            let slot_params = SlotContextParams {
                route_string: dev_copy.route_string,
                speed: dev_copy.speed,
                context_entries: max_dci,
                root_hub_port: dev_copy.root_port,
                is_hub: hub_desc_opt.is_some(),
                num_ports: hub_desc_opt.map_or(0, |h| h.num_ports),
                tt_hub_slot_id: dev_copy.tt_hub_slot_id,
                tt_port_number: dev_copy.tt_port_number,
            };
            // Write Input Control + Slot Context without wiping Endpoint Contexts `[csz*2..)`.
            let mut hdr_ctx = [0u8; 33 * 64];
            let _ = init_input_context(&mut hdr_ctx, csz, 0, add_flags, &slot_params);
            in_ctx[..csz * 2].copy_from_slice(&hdr_ctx[..csz * 2]);

            let copy_bytes = usize::from(max_dci + 2) * csz;
            self.dma.zero_range(in_ctx_off, 0x1000);
            self.dma.copy_in(in_ctx_off, &in_ctx[..copy_bytes]);
            self.submit_command(Trb::cmd_configure_endpoint(
                self.dma_phys + in_ctx_off as u64,
                slot_id,
            ))
            .await?;
        }

        let mut role = UsbDeviceRole::Generic;
        if let Some(hub_desc) = hub_desc_opt {
            role = UsbDeviceRole::Hub;
            let depth = self.hw.borrow().devices[d_idx].tier_depth;
            if hub_desc.is_superspeed {
                let _ = self
                    .control_no_data(slot_id, SetupPacket::ss_hub_set_depth(u16::from(depth)))
                    .await;
            }
            let mut p = 1u8;
            while p <= hub_desc.num_ports {
                let _ = self
                    .control_no_data(
                        slot_id,
                        SetupPacket::hub_set_port_feature(HUB_FEAT_PORT_POWER, p),
                    )
                    .await;
                p += 1;
            }
            let settle_ms = u64::from(hub_desc.power_good_2ms).saturating_mul(2).max(25);
            libcanvas::system::sleep_ms(settle_ms);
            {
                let mut hw = self.hw.borrow_mut();
                hw.devices[d_idx].is_hub = true;
                hw.devices[d_idx].hub_ports = hub_desc.num_ports;
                hw.devices[d_idx].hub_is_ss = hub_desc.is_superspeed;
            }
        }

        if let Some((iface_num, _, _)) = kbd_ep {
            let _ = self
                .control_no_data(slot_id, SetupPacket::hid_set_protocol(iface_num, false))
                .await;
            let _ = self
                .control_no_data(slot_id, SetupPacket::hid_set_idle(iface_num, 0, 0))
                .await;
            if role == UsbDeviceRole::Generic {
                role = UsbDeviceRole::HidKeyboard;
            }
        }
        if let Some((iface_num, _, _)) = mouse_ep {
            let _ = self
                .control_no_data(slot_id, SetupPacket::hid_set_protocol(iface_num, false))
                .await;
            let _ = self
                .control_no_data(slot_id, SetupPacket::hid_set_idle(iface_num, 0, 0))
                .await;
            if role == UsbDeviceRole::Generic {
                role = UsbDeviceRole::HidMouse;
            }
        }

        {
            let mut hw = self.hw.borrow_mut();
            let dev = &mut hw.devices[d_idx];
            dev.intr0 = intr0_pipe;
            dev.intr1 = intr1_pipe;
            dev.bot = bot_state;
        }

        if bot_state.active {
            if self.bring_up_bot_device(slot_id).await.is_ok() {
                role = UsbDeviceRole::MassStorageBot;
            } else {
                self.hw.borrow_mut().devices[d_idx].bot.active = false;
            }
        }

        {
            let mut hw = self.hw.borrow_mut();
            let dev = &mut hw.devices[d_idx];
            let mut inv = UsbInventoryDevice::ZERO;
            inv.slot_id = slot_id;
            inv.root_port = dev.root_port;
            inv.parent_slot_id = dev.parent_slot_id;
            inv.parent_port = dev.parent_port;
            inv.speed = dev.speed;
            inv.role = role;
            inv.usb_bcd = dev_desc.usb_bcd;
            inv.vendor_id = dev_desc.vendor_id;
            inv.product_id = dev_desc.product_id;
            inv.device_class = dev_desc.device_class;
            inv.device_subclass = dev_desc.device_subclass;
            inv.device_protocol = dev_desc.device_protocol;
            if let Some(iface) = primary_iface {
                inv.interface_class = iface.interface_class;
                inv.interface_subclass = iface.interface_subclass;
                inv.interface_protocol = iface.interface_protocol;
            }
            inv.num_configurations = dev_desc.num_configurations;
            inv.config_value = cfg_hdr.configuration_value;
            inv.endpoint_count = total_eps;
            inv.hub_ports = dev.hub_ports;
            inv.bot_block_size = dev.bot.block_size;
            inv.bot_total_blocks = dev.bot.total_blocks;
            inv.manufacturer_len = mfg_ascii.len() as u8;
            inv.manufacturer[..mfg_ascii.len()].copy_from_slice(mfg_ascii);
            inv.product_len = prod_ascii.len() as u8;
            inv.product[..prod_ascii.len()].copy_from_slice(prod_ascii);
            dev.inv = inv;
        }

        if intr0_pipe.kind != IntrPipeKind::None {
            self.arm_interrupt_pipe(slot_id, intr0_pipe);
        }
        if intr1_pipe.kind != IntrPipeKind::None {
            self.arm_interrupt_pipe(slot_id, intr1_pipe);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_ep_ctx(
        &self,
        slot_id: u8,
        speed: UsbSpeedAbi,
        ep: EndpointDescriptor,
        max_burst: u8,
        in_ctx: &mut [u8],
        csz: usize,
        add_flags: &mut u32,
        max_dci: &mut u8,
    ) -> Option<(u8, u8)> {
        let dci = ep.xhci_dci()?;
        let ep_type = ep.xhci_ep_type()?;
        let r_idx = self.alloc_xfer_ring(slot_id, dci)?;
        let is_intr = matches!(
            ep_type,
            XhciEndpointType::InterruptIn | XhciEndpointType::InterruptOut
        );
        let mps = ep.base_packet_size().max(if is_intr { 1 } else { 64 });
        let params = EndpointContextParams {
            dci,
            ep_type,
            max_packet_size: mps,
            max_burst,
            interval: usb_interval_to_xhci(speed, ep.interval, is_intr),
            tr_dequeue_ptr_with_dcs: self.xfer_ring_phys(r_idx) | 1,
            avg_trb_len: if is_intr { mps.min(16) } else { 1024 },
        };
        if !set_input_endpoint_context(in_ctx, csz, &params) {
            return None;
        }
        *add_flags |= 1u32 << dci;
        if dci > *max_dci {
            *max_dci = dci;
        }
        Some((dci, r_idx))
    }

    async fn scan_hub_ports(&self, hub_slot_id: u8) {
        let d_idx = usize::from(hub_slot_id.saturating_sub(1));
        if d_idx >= MAX_SLOTS {
            return;
        }
        let dev_snap = self.hw.borrow().devices[d_idx];
        if !dev_snap.active || !dev_snap.is_hub || dev_snap.tier_depth >= 5 {
            return;
        }

        let mut port = 1u8;
        while port <= dev_snap.hub_ports && port <= 15 {
            let p_idx = usize::from(port);
            let mut raw = [0u8; 4];
            if self
                .control_in(
                    hub_slot_id,
                    SetupPacket::hub_get_port_status(port),
                    &mut raw,
                )
                .await
                .is_err()
            {
                port += 1;
                continue;
            }
            let st0 = HubPortStatus::decode(raw, dev_snap.hub_is_ss);
            if st0.change != 0 {
                let _ = self
                    .control_no_data(
                        hub_slot_id,
                        SetupPacket::hub_clear_port_feature(HUB_FEAT_C_PORT_CONNECTION, port),
                    )
                    .await;
                let _ = self
                    .control_no_data(
                        hub_slot_id,
                        SetupPacket::hub_clear_port_feature(HUB_FEAT_C_PORT_ENABLE, port),
                    )
                    .await;
            }

            let existing_child = self.hw.borrow().devices[d_idx].hub_child_slots[p_idx];
            if !st0.connected {
                if existing_child != 0 {
                    println!(
                        "[driver-host:xhci] hub slot={} port={} disconnected (child_slot={})",
                        hub_slot_id, port, existing_child
                    );
                    self.teardown_device_tree(existing_child).await;
                    self.hw.borrow_mut().devices[d_idx].hub_child_slots[p_idx] = 0;
                    self.inventory_dirty.set(true);
                }
                port += 1;
                continue;
            }
            if existing_child != 0 {
                port += 1;
                continue;
            }

            if self
                .control_no_data(
                    hub_slot_id,
                    SetupPacket::hub_set_port_feature(HUB_FEAT_PORT_RESET, port),
                )
                .await
                .is_err()
            {
                port += 1;
                continue;
            }

            let mut final_st = st0;
            let mut tries = 0u32;
            while tries < 25 {
                libcanvas::system::sleep_ms(12);
                if self
                    .control_in(
                        hub_slot_id,
                        SetupPacket::hub_get_port_status(port),
                        &mut raw,
                    )
                    .await
                    .is_ok()
                {
                    final_st = HubPortStatus::decode(raw, dev_snap.hub_is_ss);
                    if !final_st.resetting && final_st.enabled {
                        break;
                    }
                }
                tries += 1;
            }
            let _ = self
                .control_no_data(
                    hub_slot_id,
                    SetupPacket::hub_clear_port_feature(HUB_FEAT_C_PORT_RESET, port),
                )
                .await;
            if dev_snap.hub_is_ss {
                let _ = self
                    .control_no_data(
                        hub_slot_id,
                        SetupPacket::hub_clear_port_feature(HUB_FEAT_C_BH_PORT_RESET, port),
                    )
                    .await;
            }
            if !final_st.connected || !final_st.enabled {
                port += 1;
                continue;
            }

            let Some(child_route) = append_route_port(dev_snap.route_string, port) else {
                port += 1;
                continue;
            };
            let (child_tt_slot, child_tt_port) =
                if matches!(final_st.speed, UsbSpeedAbi::Low | UsbSpeedAbi::Full) {
                    if dev_snap.speed == UsbSpeedAbi::High {
                        (hub_slot_id, port)
                    } else {
                        (dev_snap.tt_hub_slot_id, dev_snap.tt_port_number)
                    }
                } else {
                    (0, 0)
                };

            if let Ok(child_slot) = self
                .enumerate_device(
                    dev_snap.root_port,
                    hub_slot_id,
                    port,
                    child_route,
                    dev_snap.tier_depth + 1,
                    child_tt_slot,
                    child_tt_port,
                    final_st.speed,
                )
                .await
            {
                self.hw.borrow_mut().devices[d_idx].hub_child_slots[p_idx] = child_slot;
                self.inventory_dirty.set(true);
                let c_idx = usize::from(child_slot - 1);
                let child_is_hub = self.hw.borrow().devices[c_idx].is_hub;
                if child_is_hub {
                    self.hw.borrow_mut().hub_dirty_mask |= 1u32 << c_idx;
                }
            }
            port += 1;
        }
    }

    async fn bring_up_bot_device(&self, slot_id: u8) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let iface = self.hw.borrow().devices[d_idx].bot.interface_num;

        let mut max_lun = [0u8; 1];
        if self
            .control_in(slot_id, SetupPacket::msc_get_max_lun(iface), &mut max_lun)
            .await
            .is_err()
        {
            let _ = self
                .control_no_data(slot_id, SetupPacket::clear_endpoint_halt(0))
                .await;
        }

        let tag_inq = self.next_bot_tag(d_idx);
        let mut inq_buf = [0u8; 36];
        self.bot_command_in(
            slot_id,
            CommandBlockWrapper::scsi_inquiry(tag_inq, 0, 36),
            &mut inq_buf,
        )
        .await?;

        let mut ready = false;
        let mut attempt = 0u8;
        while attempt < 5 {
            let tag_tur = self.next_bot_tag(d_idx);
            if self
                .bot_command_no_data(
                    slot_id,
                    CommandBlockWrapper::scsi_test_unit_ready(tag_tur, 0),
                )
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            let tag_sense = self.next_bot_tag(d_idx);
            let mut sense = [0u8; 18];
            let _ = self
                .bot_command_in(
                    slot_id,
                    CommandBlockWrapper::scsi_request_sense(tag_sense, 0, 18),
                    &mut sense,
                )
                .await;
            libcanvas::system::sleep_ms(10);
            attempt += 1;
        }
        if !ready {
            return Err(UsbError::BotFailed);
        }

        let tag_cap10 = self.next_bot_tag(d_idx);
        let mut cap10_buf = [0u8; 8];
        self.bot_command_in(
            slot_id,
            CommandBlockWrapper::scsi_read_capacity10(tag_cap10, 0),
            &mut cap10_buf,
        )
        .await?;
        let capacity = if let Some(cap) = ScsiCapacity::from_read_capacity10(&cap10_buf) {
            cap
        } else {
            let tag_cap16 = self.next_bot_tag(d_idx);
            let mut cap16_buf = [0u8; 32];
            self.bot_command_in(
                slot_id,
                CommandBlockWrapper::scsi_read_capacity16(tag_cap16, 0),
                &mut cap16_buf,
            )
            .await?;
            ScsiCapacity::from_read_capacity16(&cap16_buf).ok_or(UsbError::BotFailed)?
        };

        {
            let mut hw = self.hw.borrow_mut();
            hw.devices[d_idx].bot.block_size = capacity.block_size;
            hw.devices[d_idx].bot.total_blocks = capacity.total_blocks;
        }

        // Perform a 1-block DMA read probe of LBA 0 into `BOT_DATA_OFF` to prove live
        // Bulk-OUT + Bulk-IN DMA under Intel VT-d at attach time!
        if capacity.total_blocks > 0 && capacity.block_size <= 4096 {
            self.bot_rw_blocks_async(slot_id, false, 0, 1).await?;
        }

        println!(
            "[driver-host:xhci] BOT storage online slot={} blocks={} block_size={}",
            slot_id, capacity.total_blocks, capacity.block_size
        );
        Ok(())
    }

    async fn bot_rw_blocks_async(
        &self,
        slot_id: u8,
        is_write: bool,
        lba: u64,
        blocks: u16,
    ) -> Result<(), UsbError> {
        if blocks == 0 {
            return Ok(());
        }
        let d_idx = usize::from(slot_id.saturating_sub(1));
        if d_idx >= MAX_SLOTS {
            return Err(UsbError::DeviceGone);
        }
        let (bot, lba32) = {
            let hw = self.hw.borrow();
            let dev = &hw.devices[d_idx];
            if !dev.active || !dev.bot.active {
                return Err(UsbError::DeviceGone);
            }
            if lba.saturating_add(u64::from(blocks)) > dev.bot.total_blocks {
                return Err(UsbError::BotFailed);
            }
            let Ok(l32) = u32::try_from(lba) else {
                return Err(UsbError::BotFailed);
            };
            (dev.bot, l32)
        };
        let total_bytes = usize::from(blocks).saturating_mul(bot.block_size as usize);
        if total_bytes == 0 || total_bytes > BOT_DATA_MAX_BYTES {
            return Err(UsbError::BotFailed);
        }

        let tag = self.next_bot_tag(d_idx);
        let cbw = if is_write {
            CommandBlockWrapper::scsi_write10(tag, bot.lun, lba32, blocks, bot.block_size)
        } else {
            CommandBlockWrapper::scsi_read10(tag, bot.lun, lba32, blocks, bot.block_size)
        }
        .ok_or(UsbError::BotFailed)?;

        let ctrl_scratch_off = SLOT_BUF_BASE_OFF + d_idx * 0x1000 + SLOT_CTRL_BUF_OFF;
        self.dma.copy_in(ctrl_scratch_off, &cbw.to_bytes());
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_out_dci,
            bot.bulk_out_ring,
            ctrl_scratch_off,
            CBW_BYTES,
        )
        .await?;

        let data_res = if is_write {
            self.bulk_xfer_dma(
                slot_id,
                bot.bulk_out_dci,
                bot.bulk_out_ring,
                BOT_DATA_OFF,
                total_bytes,
            )
            .await
        } else {
            self.bulk_xfer_dma(
                slot_id,
                bot.bulk_in_dci,
                bot.bulk_in_ring,
                BOT_DATA_OFF,
                total_bytes,
            )
            .await
        };
        if let Err(UsbError::TrbFailed(CompletionCode::StallError)) = data_res {
            let ep_addr = if is_write {
                bot.bulk_out_ep_addr
            } else {
                bot.bulk_in_ep_addr
            };
            let ep_dci = if is_write {
                bot.bulk_out_dci
            } else {
                bot.bulk_in_dci
            };
            let ep_ring = if is_write {
                bot.bulk_out_ring
            } else {
                bot.bulk_in_ring
            };
            let _ = self
                .clear_stalled_bulk_ep(slot_id, ep_addr, ep_dci, ep_ring)
                .await;
        } else {
            data_res?;
        }

        let csw_off = ctrl_scratch_off + 64;
        self.dma.zero_range(csw_off, CSW_BYTES);
        if let Err(err) = self
            .bulk_xfer_dma(
                slot_id,
                bot.bulk_in_dci,
                bot.bulk_in_ring,
                csw_off,
                CSW_BYTES,
            )
            .await
        {
            if err == UsbError::TrbFailed(CompletionCode::StallError) {
                self.clear_stalled_bulk_ep(
                    slot_id,
                    bot.bulk_in_ep_addr,
                    bot.bulk_in_dci,
                    bot.bulk_in_ring,
                )
                .await?;
                self.bulk_xfer_dma(
                    slot_id,
                    bot.bulk_in_dci,
                    bot.bulk_in_ring,
                    csw_off,
                    CSW_BYTES,
                )
                .await?;
            } else {
                return Err(err);
            }
        }

        let mut csw_raw = [0u8; CSW_BYTES];
        self.dma.copy_out(csw_off, &mut csw_raw);
        let Some(csw) = CommandStatusWrapper::decode(&csw_raw, tag) else {
            self.bot_reset_recovery(slot_id, bot).await;
            return Err(UsbError::BotFailed);
        };
        match csw.status {
            CswStatus::Passed => {
                self.hw.borrow_mut().bot_blocks_io += u64::from(blocks);
                self.inventory_dirty.set(true);
                Ok(())
            }
            CswStatus::Failed => Err(UsbError::BotFailed),
            CswStatus::PhaseError => {
                self.bot_reset_recovery(slot_id, bot).await;
                Err(UsbError::BotFailed)
            }
        }
    }

    async fn bot_sync_cache_async(&self, slot_id: u8) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id.saturating_sub(1));
        if d_idx >= MAX_SLOTS {
            return Err(UsbError::DeviceGone);
        }
        let lun = self.hw.borrow().devices[d_idx].bot.lun;
        let tag = self.next_bot_tag(d_idx);
        let _ = self
            .bot_command_no_data(slot_id, CommandBlockWrapper::scsi_sync_cache10(tag, lun))
            .await;
        Ok(())
    }

    async fn bot_command_no_data(
        &self,
        slot_id: u8,
        cbw: CommandBlockWrapper,
    ) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let bot = self.hw.borrow().devices[d_idx].bot;
        let scratch = SLOT_BUF_BASE_OFF + d_idx * 0x1000 + SLOT_CTRL_BUF_OFF;
        self.dma.copy_in(scratch, &cbw.to_bytes());
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_out_dci,
            bot.bulk_out_ring,
            scratch,
            CBW_BYTES,
        )
        .await?;

        let csw_off = scratch + 64;
        self.dma.zero_range(csw_off, CSW_BYTES);
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_in_dci,
            bot.bulk_in_ring,
            csw_off,
            CSW_BYTES,
        )
        .await?;
        let mut csw_raw = [0u8; CSW_BYTES];
        self.dma.copy_out(csw_off, &mut csw_raw);
        let Some(csw) = CommandStatusWrapper::decode(&csw_raw, cbw.tag) else {
            return Err(UsbError::BotFailed);
        };
        if csw.status == CswStatus::Passed {
            Ok(())
        } else {
            Err(UsbError::BotFailed)
        }
    }

    async fn bot_command_in(
        &self,
        slot_id: u8,
        cbw: CommandBlockWrapper,
        dst: &mut [u8],
    ) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let bot = self.hw.borrow().devices[d_idx].bot;
        let scratch = SLOT_BUF_BASE_OFF + d_idx * 0x1000 + SLOT_CTRL_BUF_OFF;
        self.dma.copy_in(scratch, &cbw.to_bytes());
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_out_dci,
            bot.bulk_out_ring,
            scratch,
            CBW_BYTES,
        )
        .await?;

        let data_off = scratch + 128;
        self.dma.zero_range(data_off, dst.len());
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_in_dci,
            bot.bulk_in_ring,
            data_off,
            dst.len(),
        )
        .await?;
        self.dma.copy_out(data_off, dst);

        let csw_off = scratch + 64;
        self.dma.zero_range(csw_off, CSW_BYTES);
        self.bulk_xfer_dma(
            slot_id,
            bot.bulk_in_dci,
            bot.bulk_in_ring,
            csw_off,
            CSW_BYTES,
        )
        .await?;
        let mut csw_raw = [0u8; CSW_BYTES];
        self.dma.copy_out(csw_off, &mut csw_raw);
        let Some(csw) = CommandStatusWrapper::decode(&csw_raw, cbw.tag) else {
            return Err(UsbError::BotFailed);
        };
        if csw.status == CswStatus::Passed {
            Ok(())
        } else {
            Err(UsbError::BotFailed)
        }
    }

    async fn clear_stalled_bulk_ep(
        &self,
        slot_id: u8,
        ep_addr: u8,
        ep_dci: u8,
        ring_idx: u8,
    ) -> Result<(), UsbError> {
        let _ = self
            .submit_command(Trb::cmd_reset_endpoint(slot_id, ep_dci))
            .await;
        let deq_with_dcs = self.hw.borrow().xfer_rings[usize::from(ring_idx)]
            .ring
            .current_iova_with_cycle();
        let _ = self
            .submit_command(Trb::cmd_set_tr_dequeue(
                deq_with_dcs & !0xF,
                (deq_with_dcs & 1) != 0,
                slot_id,
                ep_dci,
            ))
            .await;
        let _ = self
            .control_no_data(slot_id, SetupPacket::clear_endpoint_halt(ep_addr))
            .await;
        Ok(())
    }

    async fn bot_reset_recovery(&self, slot_id: u8, bot: BotPipeState) {
        let _ = self
            .control_no_data(slot_id, SetupPacket::msc_bulk_only_reset(bot.interface_num))
            .await;
        let _ = self
            .clear_stalled_bulk_ep(
                slot_id,
                bot.bulk_in_ep_addr,
                bot.bulk_in_dci,
                bot.bulk_in_ring,
            )
            .await;
        let _ = self
            .clear_stalled_bulk_ep(
                slot_id,
                bot.bulk_out_ep_addr,
                bot.bulk_out_dci,
                bot.bulk_out_ring,
            )
            .await;
    }

    fn next_bot_tag(&self, d_idx: usize) -> u32 {
        let mut hw = self.hw.borrow_mut();
        let t = hw.devices[d_idx].bot.next_tag;
        hw.devices[d_idx].bot.next_tag = t.wrapping_add(1).max(1);
        t
    }

    async fn bulk_xfer_dma(
        &self,
        slot_id: u8,
        dci: u8,
        ring_idx: u8,
        dma_off: usize,
        total_len: usize,
    ) -> Result<(), UsbError> {
        const CHUNK: usize = 32 * 1024;
        let ticket = {
            let mut hw = self.hw.borrow_mut();
            let r = &mut hw.xfer_rings[usize::from(ring_idx)];
            let mut rem = total_len;
            let mut cur_off = dma_off;
            let mut last_phys = 0u64;
            while rem > 0 {
                let step = rem.min(CHUNK);
                let more = rem > step;
                let trb = Trb::xfer_normal(
                    self.dma_phys + cur_off as u64,
                    step as u32,
                    !more,
                    !more,
                    more,
                );
                last_phys = enqueue_xfer_trb(&self.dma, r, usize::from(ring_idx), trb);
                cur_off += step;
                rem -= step;
            }
            self.completions
                .register(last_phys, slot_id)
                .ok_or(UsbError::NoWaiters)?
        };
        self.ring_doorbell(slot_id, dci);
        let out = self.await_ticket(ticket, XFER_TIMEOUT_TICKS).await?;
        if out.is_transfer_ok() {
            Ok(())
        } else {
            Err(UsbError::TrbFailed(out.code))
        }
    }

    async fn control_no_data(&self, slot_id: u8, setup: SetupPacket) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let ticket = {
            let mut hw = self.hw.borrow_mut();
            let r_idx = usize::from(hw.devices[d_idx].ep0_ring_idx);
            let r = &mut hw.xfer_rings[r_idx];
            let _ = enqueue_xfer_trb(
                &self.dma,
                r,
                r_idx,
                Trb::xfer_setup(setup.to_le_u64(), ControlTransferType::NoData),
            );
            let status_phys = enqueue_xfer_trb(&self.dma, r, r_idx, Trb::xfer_status(true));
            self.completions
                .register(status_phys, slot_id)
                .ok_or(UsbError::NoWaiters)?
        };
        self.ring_doorbell(slot_id, 1);
        let out = self.await_ticket(ticket, XFER_TIMEOUT_TICKS).await?;
        if out.is_transfer_ok() {
            Ok(())
        } else {
            Err(UsbError::TrbFailed(out.code))
        }
    }

    async fn control_in(
        &self,
        slot_id: u8,
        setup: SetupPacket,
        dst: &mut [u8],
    ) -> Result<(), UsbError> {
        let d_idx = usize::from(slot_id - 1);
        let buf_off = SLOT_BUF_BASE_OFF + d_idx * 0x1000 + SLOT_CTRL_BUF_OFF;
        let xfer_len = dst.len().min(1024);
        self.dma.zero_range(buf_off, xfer_len);
        let ticket = {
            let mut hw = self.hw.borrow_mut();
            let r_idx = usize::from(hw.devices[d_idx].ep0_ring_idx);
            let r = &mut hw.xfer_rings[r_idx];
            let trt = if setup.w_length == 0 {
                ControlTransferType::NoData
            } else if (setup.bm_request_type & 0x80) != 0 {
                ControlTransferType::InData
            } else {
                ControlTransferType::OutData
            };
            let _ = enqueue_xfer_trb(&self.dma, r, r_idx, Trb::xfer_setup(setup.to_le_u64(), trt));
            let _ = enqueue_xfer_trb(
                &self.dma,
                r,
                r_idx,
                Trb::xfer_data(self.dma_phys + buf_off as u64, xfer_len as u32, true),
            );
            let status_phys = enqueue_xfer_trb(&self.dma, r, r_idx, Trb::xfer_status(false));
            self.completions
                .register(status_phys, slot_id)
                .ok_or(UsbError::NoWaiters)?
        };
        self.ring_doorbell(slot_id, 1);
        let out = self.await_ticket(ticket, XFER_TIMEOUT_TICKS).await?;
        if out.is_transfer_ok() {
            self.dma.copy_out(buf_off, &mut dst[..xfer_len]);
            Ok(())
        } else {
            Err(UsbError::TrbFailed(out.code))
        }
    }

    async fn submit_command(&self, cmd_trb: Trb) -> Result<TrbOutcome, UsbError> {
        let ticket = {
            let mut hw = self.hw.borrow_mut();
            let step = hw.cmd_ring.enqueue(cmd_trb);
            let cmd_phys = self.dma.commit_enqueued(CMD_RING_OFF, step);
            self.completions
                .register(cmd_phys, 0)
                .ok_or(UsbError::NoWaiters)?
        };
        self.ring_doorbell(0, 0);
        let out = self.await_ticket(ticket, CMD_TIMEOUT_TICKS).await?;
        if out.is_cmd_ok() {
            Ok(out)
        } else {
            Err(UsbError::TrbFailed(out.code))
        }
    }

    async fn teardown_device_tree(&self, root_slot_id: u8) {
        let mut stack = [0u8; MAX_SLOTS];
        let mut order = [0u8; MAX_SLOTS];
        let mut sp = 0usize;
        let mut count = 0usize;
        if root_slot_id != 0 && usize::from(root_slot_id) <= MAX_SLOTS {
            stack[sp] = root_slot_id;
            sp += 1;
        }
        while sp > 0 && count < MAX_SLOTS {
            sp -= 1;
            let sid = stack[sp];
            order[count] = sid;
            count += 1;
            let hw = self.hw.borrow();
            let dev = &hw.devices[usize::from(sid - 1)];
            if dev.active && dev.is_hub {
                let mut p = 1usize;
                while p <= 15 {
                    let c = dev.hub_child_slots[p];
                    if c != 0 && sp < MAX_SLOTS {
                        stack[sp] = c;
                        sp += 1;
                    }
                    p += 1;
                }
            }
        }
        while count > 0 {
            count -= 1;
            self.teardown_single_slot(order[count]).await;
        }
    }

    async fn teardown_single_slot(&self, slot_id: u8) {
        if slot_id == 0 || usize::from(slot_id) > MAX_SLOTS {
            return;
        }
        let d_idx = usize::from(slot_id - 1);
        self.completions
            .abort_device_slot(slot_id, CompletionCode::Other(0xFF));
        let _ = self.submit_command(Trb::cmd_disable_slot(slot_id)).await;
        self.dma
            .write64_dma(DCBAA_OFF + usize::from(slot_id) * 8, 0);
        let mut hw = self.hw.borrow_mut();
        hw.devices[d_idx] = DeviceSlot::EMPTY;
        let mut r = 0usize;
        while r < MAX_XFER_RINGS {
            if hw.xfer_rings[r].in_use && hw.xfer_rings[r].owner_slot == slot_id {
                hw.xfer_rings[r].in_use = false;
                hw.xfer_rings[r].owner_slot = 0;
                hw.xfer_rings[r].owner_dci = 0;
            }
            r += 1;
        }
    }

    fn alloc_xfer_ring(&self, slot_id: u8, dci: u8) -> Option<u8> {
        let mut hw = self.hw.borrow_mut();
        let mut idx = 0usize;
        while idx < MAX_XFER_RINGS {
            if !hw.xfer_rings[idx].in_use {
                let ring_off = XFER_RING_BASE_OFF + idx * 0x1000;
                let ring_phys = self.dma_phys + ring_off as u64;
                self.dma.zero_range(ring_off, 0x1000);
                hw.xfer_rings[idx] = XferRingSlot {
                    in_use: true,
                    owner_slot: slot_id,
                    owner_dci: dci,
                    ring: ProducerRing::new(ring_phys, XFER_RING_TRBS),
                };
                return Some(idx as u8);
            }
            idx += 1;
        }
        None
    }

    fn xfer_ring_phys(&self, ring_idx: u8) -> u64 {
        self.dma_phys + (XFER_RING_BASE_OFF + usize::from(ring_idx) * 0x1000) as u64
    }

    fn await_ticket(&self, ticket: WaitTicket, timeout_ticks: u64) -> TimedTrbWait<'_> {
        let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
        TimedTrbWait {
            inner: self.completions.wait(ticket),
            deadline_ticks: now.saturating_add(timeout_ticks),
        }
    }
}

struct TimedTrbWait<'a> {
    inner: TrbWaitFuture<'a, MAX_COMPLETION_WAITERS>,
    deadline_ticks: u64,
}

impl Future for TimedTrbWait<'_> {
    type Output = Result<TrbOutcome, UsbError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(Some(outcome)) => Poll::Ready(Ok(outcome)),
            Poll::Ready(None) => Poll::Ready(Err(UsbError::DeviceGone)),
            Poll::Pending => {
                let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                if now >= self.deadline_ticks {
                    Poll::Ready(Err(UsbError::ControllerTimeout))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

const fn port_sc_offset(port_1based: u8) -> usize {
    OP_PORT_BASE + (port_1based.saturating_sub(1) as usize) * OP_PORT_STRIDE
}

fn enqueue_xfer_trb(dma: &MappedWin, slot: &mut XferRingSlot, ring_idx: usize, trb: Trb) -> u64 {
    let ring_off = XFER_RING_BASE_OFF + ring_idx * 0x1000;
    let step = slot.ring.enqueue(trb);
    dma.commit_enqueued(ring_off, step)
}

fn wait_mmio_mask(
    mmio: &MappedWin,
    off: usize,
    mask: u32,
    want_nonzero: bool,
    max_ms: u64,
) -> bool {
    let mut waited = 0u64;
    loop {
        let v = mmio.read32(off);
        let is_set = (v & mask) != 0;
        if is_set == want_nonzero {
            return true;
        }
        if waited >= max_ms {
            return false;
        }
        libcanvas::system::sleep_ms(2);
        waited += 2;
    }
}

/// Walk xHCI Extended Capabilities (`HCCPARAMS1.xECP`), performing `USBLEGSUP`
/// BIOS-to-OS Ownership Handoff (Cap ID `1`) and discovering USB 3.x root hub
/// port ranges (Cap ID `2`, `"USB "`).
fn perform_bios_handoff_and_port_scan(mmio: &MappedWin, caps: &XhciCapabilities) -> (bool, u64) {
    let mut bios_done = false;
    let mut usb3_mask = 0u64;
    let mut ext_off = caps.xecp_offset;
    if ext_off == 0 {
        return (true, 0);
    }
    let mut guard = 0usize;
    while ext_off != 0 && ext_off + 8 <= mmio.len && guard < 64 {
        let hdr = mmio.read32(ext_off);
        if hdr == 0xFFFF_FFFF || hdr == 0 {
            break;
        }
        let cap_id = (hdr & 0xFF) as u8;
        let next_dwords = ((hdr >> 8) & 0xFF) as usize;

        if cap_id == XECP_ID_LEGACY {
            let leg = mmio.read32(ext_off);
            mmio.write32(ext_off, leg | USBLEGSUP_OS_OWNED);
            let _ = wait_mmio_mask(mmio, ext_off, USBLEGSUP_BIOS_OWNED, false, 1000);
            let ctl = mmio.read32(ext_off + 4);
            mmio.write32(ext_off + 4, ctl & 0xE000_0000);
            bios_done = true;
        } else if cap_id == XECP_ID_PROTOCOL && ext_off + 12 <= mmio.len {
            let name_dw1 = mmio.read32(ext_off + 4);
            let dw2 = mmio.read32(ext_off + 8);
            if let Some(proto) = PortProtocolRange::parse(hdr, name_dw1, dw2) {
                if proto.revision_major >= 3 {
                    let mut i = 0u8;
                    while i < proto.port_count {
                        let p = proto.first_port.saturating_add(i);
                        if p < 64 {
                            usb3_mask |= 1u64 << p;
                        }
                        i += 1;
                    }
                }
            }
        }

        if next_dwords == 0 {
            break;
        }
        ext_off = ext_off.saturating_add(next_dwords * 4);
        guard += 1;
    }
    if !bios_done {
        bios_done = true;
    }
    (bios_done, usb3_mask)
}
