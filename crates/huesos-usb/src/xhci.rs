//! xHCI 1.x register decoders, TRB codecs, ring state machines, and 32B/64B
//! Slot/Endpoint Context builders.

use huesos_abi::usb::UsbSpeedAbi;

/// Byte size of one xHCI Transfer/Command/Event Request Block.
pub const TRB_BYTES: usize = 16;

// Operational register offsets from `op_base = cap_base + CAPLENGTH`.
/// USB Command register (`u32`).
pub const OP_USBCMD: usize = 0x00;
/// USB Status register (`u32`, RW1C status bits).
pub const OP_USBSTS: usize = 0x04;
/// Supported page size register (`u32`).
pub const OP_PAGESIZE: usize = 0x08;
/// Device Notification Control register (`u32`).
pub const OP_DNCTRL: usize = 0x14;
/// Command Ring Control register (`u64`).
pub const OP_CRCR: usize = 0x18;
/// Device Context Base Address Array Pointer (`u64`).
pub const OP_DCBAAP: usize = 0x30;
/// Configure register (`u32`, `MaxSlotsEn` in bits `7:0`).
pub const OP_CONFIG: usize = 0x38;
/// Base offset of Port Register Set (`PORTSC` at `+0x00` per 16-byte port).
pub const OP_PORT_BASE: usize = 0x400;
/// Byte stride between adjacent root-hub port register sets.
pub const OP_PORT_STRIDE: usize = 0x10;

// `USBCMD` bits.
/// Run/Stop (`1` = run, `0` = halt).
pub const USBCMD_RS: u32 = 1 << 0;
/// Host Controller Reset.
pub const USBCMD_HCRST: u32 = 1 << 1;
/// Interrupter Enable.
pub const USBCMD_INTE: u32 = 1 << 2;
/// Host System Error Enable.
pub const USBCMD_HSEE: u32 = 1 << 3;

// `USBSTS` bits.
/// Host Controller Halted (`1` when stopped).
pub const USBSTS_HCH: u32 = 1 << 0;
/// Host System Error (`RW1C`).
pub const USBSTS_HSE: u32 = 1 << 2;
/// Event Interrupt (`RW1C`).
pub const USBSTS_EINT: u32 = 1 << 3;
/// Port Change Detect (`RW1C`).
pub const USBSTS_PCD: u32 = 1 << 4;
/// Controller Not Ready (`1` while reset in progress).
pub const USBSTS_CNR: u32 = 1 << 11;

// `PORTSC` bits.
/// Current Connect Status (`ROS`).
pub const PORTSC_CCS: u32 = 1 << 0;
/// Port Enabled/Disabled (`RW1C` — writing `1` DISABLES the port!).
pub const PORTSC_PED: u32 = 1 << 1;
/// Port Reset (`RW1S`).
pub const PORTSC_PR: u32 = 1 << 4;
/// Port Link State shift (`bits 8:5`).
pub const PORTSC_PLS_SHIFT: u32 = 5;
/// Port Power (`RWS`).
pub const PORTSC_PP: u32 = 1 << 9;
/// Port Speed shift (`bits 13:10`).
pub const PORTSC_SPEED_SHIFT: u32 = 10;
/// Link State Write Strobe (`bit 16`).
pub const PORTSC_LWS: u32 = 1 << 16;
/// Connect Status Change (`RW1C`).
pub const PORTSC_CSC: u32 = 1 << 17;
/// Port Enabled/Disabled Change (`RW1C`).
pub const PORTSC_PEC: u32 = 1 << 18;
/// Warm Port Reset Change (`RW1C`).
pub const PORTSC_WRC: u32 = 1 << 19;
/// Over-current Change (`RW1C`).
pub const PORTSC_OCC: u32 = 1 << 20;
/// Port Reset Change (`RW1C`).
pub const PORTSC_PRC: u32 = 1 << 21;
/// Port Link State Change (`RW1C`).
pub const PORTSC_PLC: u32 = 1 << 22;
/// Port Config Error Change (`RW1C`).
pub const PORTSC_CEC: u32 = 1 << 23;
/// Warm Port Reset (`RW1S`, USB3 only).
pub const PORTSC_WPR: u32 = 1 << 31;
/// All `PORTSC` `RW1C` status-change bits (`17..=23`).
pub const PORTSC_CHANGE_BITS: u32 = PORTSC_CSC
    | PORTSC_PEC
    | PORTSC_WRC
    | PORTSC_OCC
    | PORTSC_PRC
    | PORTSC_PLC
    | PORTSC_CEC;
/// Safe read-modify-write mask preserving `RWS` bits (`PP`, `PIC`, `WCE/WDE/WOE`)
/// while zeroing `PED` (`RW1C`) and all `17..=23` `RW1C` change bits.
pub const PORTSC_RW_PRESERVE_MASK: u32 = PORTSC_PP | (0x3 << 14) | (0x7 << 25);

// Runtime Interrupter 0 register offsets from `rt_base + 0x20`.
/// Offset of Interrupter Register Set 0 inside Runtime Registers.
pub const RT_IR0_BASE: usize = 0x20;
/// Interrupter Management (`IP` bit 0 `RW1C`, `IE` bit 1 `RW`).
pub const IR_IMAN: usize = 0x00;
/// Interrupter Moderation (`IMODI` bits `15:0`, `IMODC` bits `31:16`).
pub const IR_IMOD: usize = 0x04;
/// Event Ring Segment Table Size (`u32`, bits `15:0`).
pub const IR_ERSTSZ: usize = 0x08;
/// Event Ring Segment Table Base Address (`u64`, 64-byte aligned).
pub const IR_ERSTBA: usize = 0x10;
/// Event Ring Dequeue Pointer (`u64`, `EHB` bit 3 `RW1C`).
pub const IR_ERDP: usize = 0x18;
/// `IMAN.IP` Interrupt Pending (`RW1C`).
pub const IMAN_IP: u32 = 1 << 0;
/// `IMAN.IE` Interrupt Enable (`RW`).
pub const IMAN_IE: u32 = 1 << 1;
/// `ERDP.EHB` Event Handler Busy (`RW1C`).
pub const ERDP_EHB: u64 = 1 << 3;

// Extended Capability IDs.
/// USB Legacy Support (`BIOS`/`OS` ownership semaphore).
pub const XECP_ID_LEGACY: u8 = 1;
/// Supported Protocol Capability (`"USB "` 2.0 / 3.x port map).
pub const XECP_ID_PROTOCOL: u8 = 2;
/// `USBLEGSUP` BIOS Owned Semaphore (`bit 16`).
pub const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
/// `USBLEGSUP` OS Owned Semaphore (`bit 24`).
pub const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

// TRB Type IDs (`bits 15:10` of `control` dword `d3`).
/// Normal Transfer TRB.
pub const TRB_TYPE_NORMAL: u8 = 1;
/// Setup Stage Control TRB.
pub const TRB_TYPE_SETUP_STAGE: u8 = 2;
/// Data Stage Control TRB.
pub const TRB_TYPE_DATA_STAGE: u8 = 3;
/// Status Stage Control TRB.
pub const TRB_TYPE_STATUS_STAGE: u8 = 4;
/// Link TRB (ring wrap).
pub const TRB_TYPE_LINK: u8 = 6;
/// Enable Slot Command TRB.
pub const TRB_TYPE_ENABLE_SLOT: u8 = 9;
/// Disable Slot Command TRB.
pub const TRB_TYPE_DISABLE_SLOT: u8 = 10;
/// Address Device Command TRB.
pub const TRB_TYPE_ADDRESS_DEVICE: u8 = 11;
/// Configure Endpoint Command TRB.
pub const TRB_TYPE_CONFIGURE_ENDPOINT: u8 = 12;
/// Evaluate Context Command TRB.
pub const TRB_TYPE_EVALUATE_CONTEXT: u8 = 13;
/// Reset Endpoint Command TRB.
pub const TRB_TYPE_RESET_ENDPOINT: u8 = 14;
/// Stop Endpoint Command TRB.
pub const TRB_TYPE_STOP_ENDPOINT: u8 = 15;
/// Set TR Dequeue Pointer Command TRB.
pub const TRB_TYPE_SET_TR_DEQUEUE: u8 = 16;
/// No-Op Command TRB.
pub const TRB_TYPE_NOOP_CMD: u8 = 23;
/// Transfer Event TRB.
pub const TRB_TYPE_TRANSFER_EVENT: u8 = 32;
/// Command Completion Event TRB.
pub const TRB_TYPE_CMD_COMPLETION: u8 = 33;
/// Port Status Change Event TRB.
pub const TRB_TYPE_PORT_STATUS_CHANGE: u8 = 34;

// Common TRB control flags (`d3`).
const TRB_C: u32 = 1 << 0;
const TRB_TC: u32 = 1 << 1;
const TRB_ISP: u32 = 1 << 2;
const TRB_CH: u32 = 1 << 4;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_DIR_IN: u32 = 1 << 16;

/// Control Setup Stage Transfer Type (`TRT` in `d3[17:16]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlTransferType {
    /// No Data Stage (`TRT = 0`).
    NoData = 0,
    /// Host-to-device OUT Data Stage (`TRT = 2`).
    OutData = 2,
    /// Device-to-host IN Data Stage (`TRT = 3`).
    InData = 3,
}

/// Decoded xHCI Capability Register snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XhciCapabilities {
    /// Byte offset from BAR0 to Operational Registers (`CAPLENGTH`).
    pub cap_length: u8,
    /// BCD interface version (`HCIVERSION`, e.g. `0x0100`).
    pub hci_version: u16,
    /// Maximum Device Slots (`HCSPARAMS1[7:0]`).
    pub max_slots: u8,
    /// Maximum Interrupters (`HCSPARAMS1[18:8]`).
    pub max_interrupters: u16,
    /// Maximum Root Hub Ports (`HCSPARAMS1[31:24]`).
    pub max_ports: u8,
    /// Required 4 KiB Scratchpad Buffers (`HCSPARAMS2` hi `25:21` | lo `31:27`).
    pub max_scratchpad_bufs: u16,
    /// `64`-bit Addressing Capability (`HCCPARAMS1[0]`).
    pub addr64: bool,
    /// Context Size (`64` bytes when `HCCPARAMS1[2] == 1`, else `32` bytes).
    pub context_size: usize,
    /// Extended Capabilities byte offset from BAR0 (`HCCPARAMS1[31:16] * 4`).
    pub xecp_offset: usize,
    /// Doorbell Array byte offset from BAR0 (`DBOFF & !0x3`).
    pub dboff: usize,
    /// Runtime Register Space byte offset from BAR0 (`RTSOFF & !0x1F`).
    pub rtsoff: usize,
}

impl XhciCapabilities {
    /// Parse the architectural xHCI capability registers read from BAR0.
    pub const fn parse(
        cap_len_ver: u32,
        hcsparams1: u32,
        hcsparams2: u32,
        hccparams1: u32,
        dboff: u32,
        rtsoff: u32,
    ) -> Option<Self> {
        let cap_length = (cap_len_ver & 0xFF) as u8;
        let hci_version = (cap_len_ver >> 16) as u16;
        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_interrupters = ((hcsparams1 >> 8) & 0x7FF) as u16;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        if cap_length < 0x20 || max_slots == 0 || max_ports == 0 {
            return None;
        }
        let sp_hi = (hcsparams2 >> 21) & 0x1F;
        let sp_lo = (hcsparams2 >> 27) & 0x1F;
        let max_scratchpad_bufs = ((sp_hi << 5) | sp_lo) as u16;
        let addr64 = (hccparams1 & 1) != 0;
        let context_size = if (hccparams1 & (1 << 2)) != 0 { 64 } else { 32 };
        let xecp_offset = (((hccparams1 >> 16) & 0xFFFF) as usize) * 4;
        let db = (dboff & !0x3) as usize;
        let rts = (rtsoff & !0x1F) as usize;
        if db < cap_length as usize || rts < cap_length as usize {
            return None;
        }
        Some(Self {
            cap_length,
            hci_version,
            max_slots,
            max_interrupters,
            max_ports,
            max_scratchpad_bufs,
            addr64,
            context_size,
            xecp_offset,
            dboff: db,
            rtsoff: rts,
        })
    }
}

/// Root-port protocol assignment parsed from xHCI `Supported Protocol` capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortProtocolRange {
    /// BCD revision (`0x0200` for USB 2.0, `0x0300`/`0x0310`/`0x0320` for USB 3.x).
    pub revision_major: u8,
    /// Minor BCD revision.
    pub revision_minor: u8,
    /// 1-based first root port covered by this range.
    pub first_port: u8,
    /// Number of consecutive root ports covered.
    pub port_count: u8,
}

impl PortProtocolRange {
    /// Parse two 32-bit dwords (`dw0`, `dw2`) of a Supported Protocol Extended Capability.
    pub const fn parse(dw0: u32, name_dw1: u32, dw2: u32) -> Option<Self> {
        if (dw0 & 0xFF) != XECP_ID_PROTOCOL as u32 || name_dw1 != 0x2042_5355 {
            return None;
        }
        let rev_minor = ((dw0 >> 16) & 0xFF) as u8;
        let rev_major = ((dw0 >> 24) & 0xFF) as u8;
        let first_port = (dw2 & 0xFF) as u8;
        let port_count = ((dw2 >> 8) & 0xFF) as u8;
        if first_port == 0 || port_count == 0 {
            return None;
        }
        Some(Self {
            revision_major: rev_major,
            revision_minor: rev_minor,
            first_port,
            port_count,
        })
    }

    /// Return `true` if 1-based `port` falls inside this capability range.
    pub const fn contains_port(&self, port: u8) -> bool {
        let end = self.first_port.saturating_add(self.port_count);
        port >= self.first_port && port < end
    }
}

/// Mask `PORTSC` safely for read-modify-write without clearing `PED` or `RW1C` bits.
pub const fn portsc_preserve_rw(raw: u32) -> u32 {
    raw & PORTSC_RW_PRESERVE_MASK
}

/// Extract negotiated [`UsbSpeedAbi`] from `PORTSC[13:10]`.
pub const fn portsc_speed(raw: u32) -> UsbSpeedAbi {
    match (raw >> PORTSC_SPEED_SHIFT) & 0xF {
        1 => UsbSpeedAbi::Full,
        2 => UsbSpeedAbi::Low,
        3 => UsbSpeedAbi::High,
        4 => UsbSpeedAbi::Super,
        5..=15 => UsbSpeedAbi::SuperPlus,
        _ => UsbSpeedAbi::Unknown,
    }
}

/// Default Control Endpoint 0 Max Packet Size for a newly reset USB speed.
pub const fn default_ep0_mps(speed: UsbSpeedAbi) -> u16 {
    match speed {
        UsbSpeedAbi::Low => 8,
        UsbSpeedAbi::Full | UsbSpeedAbi::High => 64,
        UsbSpeedAbi::Super | UsbSpeedAbi::SuperPlus => 512,
        UsbSpeedAbi::Unknown => 8,
    }
}

/// xHCI TRB completion code (`bits 31:24` of Event `status` dword `d2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionCode {
    /// Operation completed without error (`1`).
    Success,
    /// Short packet (`13`) — valid for variable-length IN transfers.
    ShortPacket,
    /// Endpoint returned STALL handshake (`6`).
    StallError,
    /// Data buffer overrun/underrun (`2`).
    DataBufferError,
    /// Babble detected (`3`).
    BabbleDetected,
    /// USB bus transaction timeout/CRC error (`4`).
    UsbTransactionError,
    /// Malformed TRB (`5`).
    TrbError,
    /// No free hardware device slots (`9`).
    NoSlotsAvailable,
    /// Slot or endpoint not in expected state (`11` / `12`).
    InvalidState(u8),
    /// Any other architectural or vendor completion code.
    Other(u8),
}

impl CompletionCode {
    /// Decode raw 8-bit completion code.
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Success,
            2 => Self::DataBufferError,
            3 => Self::BabbleDetected,
            4 => Self::UsbTransactionError,
            5 => Self::TrbError,
            6 => Self::StallError,
            9 => Self::NoSlotsAvailable,
            11 | 12 => Self::InvalidState(raw),
            13 => Self::ShortPacket,
            other => Self::Other(other),
        }
    }

    /// True if the transfer succeeded (`Success` or `ShortPacket`).
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Success | Self::ShortPacket)
    }
}

/// Raw 16-byte xHCI TRB (`4 x u32` little-endian).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Trb {
    /// Parameter low dword (`0x00`).
    pub d0: u32,
    /// Parameter high dword (`0x04`).
    pub d1: u32,
    /// Status dword (`0x08`).
    pub d2: u32,
    /// Control dword (`0x0C`, bit 0 = Cycle).
    pub d3: u32,
}

impl Trb {
    /// Zeroed TRB.
    pub const ZERO: Self = Self {
        d0: 0,
        d1: 0,
        d2: 0,
        d3: 0,
    };

    /// Encode to 16 little-endian bytes for writing into a DMA ring slot.
    pub const fn to_le_bytes(self) -> [u8; TRB_BYTES] {
        let b0 = self.d0.to_le_bytes();
        let b1 = self.d1.to_le_bytes();
        let b2 = self.d2.to_le_bytes();
        let b3 = self.d3.to_le_bytes();
        [
            b0[0], b0[1], b0[2], b0[3], b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3],
            b3[0], b3[1], b3[2], b3[3],
        ]
    }

    /// Decode 16 little-endian bytes read from an Event Ring slot.
    pub const fn from_le_bytes(b: [u8; TRB_BYTES]) -> Self {
        Self {
            d0: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            d1: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            d2: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            d3: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }

    /// Cycle bit (`d3[0]`).
    pub const fn cycle(self) -> bool {
        (self.d3 & TRB_C) != 0
    }

    /// Return a copy with Cycle bit set to `cycle`.
    pub const fn with_cycle(mut self, cycle: bool) -> Self {
        if cycle {
            self.d3 |= TRB_C;
        } else {
            self.d3 &= !TRB_C;
        }
        self
    }

    /// 6-bit TRB Type (`d3[15:10]`).
    pub const fn trb_type(self) -> u8 {
        ((self.d3 >> 10) & 0x3F) as u8
    }

    /// 64-bit parameter (`(d1 << 32) | d0`).
    pub const fn param_u64(self) -> u64 {
        (self.d1 as u64) << 32 | (self.d0 as u64)
    }

    /// Construct a Link TRB wrapping back to `ring_base_iova` with `ToggleCycle = 1`.
    pub const fn link(ring_base_iova: u64, toggle_cycle: bool) -> Self {
        let tc = if toggle_cycle { TRB_TC } else { 0 };
        Self {
            d0: ring_base_iova as u32,
            d1: (ring_base_iova >> 32) as u32,
            d2: 0,
            d3: ((TRB_TYPE_LINK as u32) << 10) | tc,
        }
    }

    /// Construct an `Enable Slot` Command TRB.
    pub const fn cmd_enable_slot() -> Self {
        Self {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: (TRB_TYPE_ENABLE_SLOT as u32) << 10,
        }
    }

    /// Construct a `Disable Slot` Command TRB.
    pub const fn cmd_disable_slot(slot_id: u8) -> Self {
        Self {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: ((TRB_TYPE_DISABLE_SLOT as u32) << 10) | ((slot_id as u32) << 24),
        }
    }

    /// Construct an `Address Device` Command TRB (`BSR = 0` sends `SET_ADDRESS`).
    pub const fn cmd_address_device(input_ctx_iova: u64, slot_id: u8, bsr: bool) -> Self {
        let bsr_bit = if bsr { 1 << 9 } else { 0 };
        Self {
            d0: input_ctx_iova as u32,
            d1: (input_ctx_iova >> 32) as u32,
            d2: 0,
            d3: ((TRB_TYPE_ADDRESS_DEVICE as u32) << 10) | bsr_bit | ((slot_id as u32) << 24),
        }
    }

    /// Construct a `Configure Endpoint` Command TRB.
    pub const fn cmd_configure_endpoint(input_ctx_iova: u64, slot_id: u8) -> Self {
        Self {
            d0: input_ctx_iova as u32,
            d1: (input_ctx_iova >> 32) as u32,
            d2: 0,
            d3: ((TRB_TYPE_CONFIGURE_ENDPOINT as u32) << 10) | ((slot_id as u32) << 24),
        }
    }

    /// Construct an `Evaluate Context` Command TRB (e.g. updating EP0 MaxPacketSize).
    pub const fn cmd_evaluate_context(input_ctx_iova: u64, slot_id: u8) -> Self {
        Self {
            d0: input_ctx_iova as u32,
            d1: (input_ctx_iova >> 32) as u32,
            d2: 0,
            d3: ((TRB_TYPE_EVALUATE_CONTEXT as u32) << 10) | ((slot_id as u32) << 24),
        }
    }

    /// Construct a `Reset Endpoint` Command TRB (`TSP = 0` clears halted endpoint).
    pub const fn cmd_reset_endpoint(slot_id: u8, dci: u8) -> Self {
        Self {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: ((TRB_TYPE_RESET_ENDPOINT as u32) << 10)
                | ((dci as u32) << 16)
                | ((slot_id as u32) << 24),
        }
    }

    /// Construct a `Set TR Dequeue Pointer` Command TRB (`new_deq_iova | dcs`).
    pub const fn cmd_set_tr_dequeue(new_deq_iova: u64, dcs: bool, slot_id: u8, dci: u8) -> Self {
        let ptr = (new_deq_iova & !0xF) | (dcs as u64);
        Self {
            d0: ptr as u32,
            d1: (ptr >> 32) as u32,
            d2: 0,
            d3: ((TRB_TYPE_SET_TR_DEQUEUE as u32) << 10)
                | ((dci as u32) << 16)
                | ((slot_id as u32) << 24),
        }
    }

    /// Construct a Control `Setup Stage` TRB (`IDT = 1`, 8-byte Setup immediate).
    pub const fn xfer_setup(setup_packet_le: u64, trt: ControlTransferType) -> Self {
        Self {
            d0: setup_packet_le as u32,
            d1: (setup_packet_le >> 32) as u32,
            d2: 8,
            d3: ((TRB_TYPE_SETUP_STAGE as u32) << 10) | TRB_IDT | ((trt as u32) << 16),
        }
    }

    /// Construct a Control `Data Stage` TRB (`IOC = 0`, `ISP = 0`; completion fires on Status Stage).
    pub const fn xfer_data(buf_iova: u64, len: u32, dir_in: bool) -> Self {
        let dir = if dir_in { TRB_DIR_IN } else { 0 };
        Self {
            d0: buf_iova as u32,
            d1: (buf_iova >> 32) as u32,
            d2: len & 0x1FFFF,
            d3: ((TRB_TYPE_DATA_STAGE as u32) << 10) | dir,
        }
    }

    /// Construct a Control `Status Stage` TRB (`IOC = 1`).
    pub const fn xfer_status(status_dir_in: bool) -> Self {
        let dir = if status_dir_in { TRB_DIR_IN } else { 0 };
        Self {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: ((TRB_TYPE_STATUS_STAGE as u32) << 10) | dir | TRB_IOC,
        }
    }

    /// Construct a `Normal` Transfer TRB for Bulk or Interrupt endpoints.
    pub const fn xfer_normal(buf_iova: u64, len: u32, ioc: bool, isp: bool, chain: bool) -> Self {
        let mut flags = (TRB_TYPE_NORMAL as u32) << 10;
        if ioc {
            flags |= TRB_IOC;
        }
        if isp {
            flags |= TRB_ISP;
        }
        if chain {
            flags |= TRB_CH;
        }
        Self {
            d0: buf_iova as u32,
            d1: (buf_iova >> 32) as u32,
            d2: len & 0x1FFFF,
            d3: flags,
        }
    }
}

/// Decoded Event Ring TRB notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedEvent {
    /// Command Completion Event (`type 33`).
    CommandCompletion {
        /// IOVA of the completed Command TRB.
        cmd_trb_iova: u64,
        /// Hardware completion status.
        code: CompletionCode,
        /// Slot ID returned (e.g. by `Enable Slot`).
        slot_id: u8,
    },
    /// Transfer Event (`type 32`).
    TransferEvent {
        /// IOVA of the generating Transfer TRB.
        trb_iova: u64,
        /// Hardware completion status.
        code: CompletionCode,
        /// Un-transferred residual byte count (`bits 23:0` of `d2`).
        residual_len: u32,
        /// Endpoint DCI (`1..=31`).
        dci: u8,
        /// Device Slot ID.
        slot_id: u8,
    },
    /// Port Status Change Event (`type 34`).
    PortStatusChange {
        /// 1-based Root Hub Port ID (`d0[31:24]`).
        port_id: u8,
        /// Completion code (`Success`).
        code: CompletionCode,
    },
    /// Unhandled or informational xHCI event TRB.
    Other {
        /// Raw 6-bit TRB type.
        trb_type: u8,
    },
}

impl DecodedEvent {
    /// Decode an Event TRB whose Cycle bit has already been verified.
    pub const fn from_trb(trb: Trb) -> Self {
        let code = CompletionCode::from_raw((trb.d2 >> 24) as u8);
        match trb.trb_type() {
            TRB_TYPE_CMD_COMPLETION => Self::CommandCompletion {
                cmd_trb_iova: trb.param_u64() & !0xF,
                code,
                slot_id: (trb.d3 >> 24) as u8,
            },
            TRB_TYPE_TRANSFER_EVENT => Self::TransferEvent {
                trb_iova: trb.param_u64() & !0xF,
                code,
                residual_len: trb.d2 & 0x00FF_FFFF,
                dci: ((trb.d3 >> 16) & 0x1F) as u8,
                slot_id: (trb.d3 >> 24) as u8,
            },
            TRB_TYPE_PORT_STATUS_CHANGE => Self::PortStatusChange {
                port_id: (trb.d0 >> 24) as u8,
                code,
            },
            other => Self::Other { trb_type: other },
        }
    }
}

/// One write step produced by [`ProducerRing::enqueue`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnqueuedTrb {
    /// Optional Link TRB write `(slot_index, trb)` when wrapping from `cap - 1` to `0`.
    pub wrap_link: Option<(usize, Trb)>,
    /// Ring slot index where the payload TRB must be written.
    pub slot_index: usize,
    /// Payload TRB stamped with the active Producer Cycle State (`PCS`).
    pub trb: Trb,
    /// Physical/IOVA address of the payload TRB (`base_iova + slot_index * 16`).
    pub trb_iova: u64,
}

/// Pure single-segment xHCI Producer Ring state machine (`Command` or `Transfer` ring).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerRing {
    base_iova: u64,
    capacity: usize,
    enqueue_idx: usize,
    pcs: bool,
}

impl ProducerRing {
    /// Initialize an empty producer ring at `base_iova` with `capacity` total TRB slots
    /// (`capacity >= 4`; slot `capacity - 1` is reserved for the wrap `Link` TRB).
    pub const fn new(base_iova: u64, capacity: usize) -> Self {
        Self {
            base_iova,
            capacity,
            enqueue_idx: 0,
            pcs: true,
        }
    }

    /// Base physical/IOVA address of slot `0`.
    pub const fn base_iova(&self) -> u64 {
        self.base_iova
    }

    /// Current Producer Cycle State (`PCS`).
    pub const fn cycle(&self) -> bool {
        self.pcs
    }

    /// Current dequeue/enqueue pointer value suitable for `CRCR` or `TR Dequeue Pointer` (`| DCS`).
    pub const fn current_iova_with_cycle(&self) -> u64 {
        let addr = self.base_iova + (self.enqueue_idx as u64) * (TRB_BYTES as u64);
        addr | (self.pcs as u64)
    }

    /// Stamp `payload` into the next usable slot, automatically emitting a `Link`
    /// TRB with `ToggleCycle = 1` when wrapping at `capacity - 1`.
    pub fn enqueue(&mut self, payload: Trb) -> EnqueuedTrb {
        let mut wrap_link = None;
        if self.enqueue_idx >= self.capacity - 1 {
            let link_idx = self.capacity - 1;
            let link = Trb::link(self.base_iova, true).with_cycle(self.pcs);
            wrap_link = Some((link_idx, link));
            self.enqueue_idx = 0;
            self.pcs = !self.pcs;
        }
        let idx = self.enqueue_idx;
        let stamped = payload.with_cycle(self.pcs);
        let trb_iova = self.base_iova + (idx as u64) * (TRB_BYTES as u64);
        self.enqueue_idx += 1;
        if self.enqueue_idx >= self.capacity - 1 {
            // Wrap eagerly or on next enqueue; keeping wrap on next enqueue preserves
            // contiguous multi-TRB bursts unless idx hits capacity - 1.
        }
        EnqueuedTrb {
            wrap_link,
            slot_index: idx,
            trb: stamped,
            trb_iova,
        }
    }
}

/// Pure single-segment xHCI Event Ring consumer state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRingConsumer {
    base_iova: u64,
    capacity: usize,
    dequeue_idx: usize,
    ccs: bool,
}

impl EventRingConsumer {
    /// Initialize an Event Ring consumer at `base_iova` with `capacity` TRB slots (`CCS = 1`).
    pub const fn new(base_iova: u64, capacity: usize) -> Self {
        Self {
            base_iova,
            capacity,
            dequeue_idx: 0,
            ccs: true,
        }
    }

    /// Current slot index to inspect next.
    pub const fn dequeue_index(&self) -> usize {
        self.dequeue_idx
    }

    /// Expected Consumer Cycle State (`CCS`).
    pub const fn cycle(&self) -> bool {
        self.ccs
    }

    /// Inspect `slot_trb` at `self.dequeue_index()`; if its Cycle bit matches `CCS`,
    /// advance the consumer and return [`DecodedEvent`].
    pub fn try_consume(&mut self, slot_trb: Trb) -> Option<DecodedEvent> {
        if slot_trb.cycle() != self.ccs {
            return None;
        }
        self.dequeue_idx += 1;
        if self.dequeue_idx >= self.capacity {
            self.dequeue_idx = 0;
            self.ccs = !self.ccs;
        }
        Some(DecodedEvent::from_trb(slot_trb))
    }

    /// Value to write to `ERDP` (`current_dequeue_iova | ERDP_EHB`).
    pub const fn erdp_with_ehb(&self) -> u64 {
        let addr = self.base_iova + (self.dequeue_idx as u64) * (TRB_BYTES as u64);
        (addr & !0xF) | ERDP_EHB
    }
}

/// Endpoint type field (`EP Type` in `EndpointContext` `dw1[5:3]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XhciEndpointType {
    /// Bulk OUT (`2`).
    BulkOut = 2,
    /// Interrupt OUT (`3`).
    InterruptOut = 3,
    /// Bidirectional Control Endpoint 0 (`4`).
    ControlBiDir = 4,
    /// Bulk IN (`6`).
    BulkIn = 6,
    /// Interrupt IN (`7`).
    InterruptIn = 7,
}

/// Parameters for populating an Input Context (`32`B or `64`B `context_size`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotContextParams {
    /// 20-bit xHCI Route String (`0` for root-hub-attached devices).
    pub route_string: u32,
    /// Negotiated link speed.
    pub speed: UsbSpeedAbi,
    /// Highest enabled Endpoint Context index (`1` for EP0 only, up to `31`).
    pub context_entries: u8,
    /// 1-based Root Hub Port Number.
    pub root_hub_port: u8,
    /// True if this device is a USB Hub (`SlotContext` `Hub` bit 26).
    pub is_hub: bool,
    /// Downstream port count when `is_hub` is `true`.
    pub num_ports: u8,
    /// Parent High-Speed Hub Slot ID when an FS/LS device sits behind an HS hub (`TT`).
    pub tt_hub_slot_id: u8,
    /// Parent Hub Port Number when `tt_hub_slot_id != 0`.
    pub tt_port_number: u8,
}

/// Parameters for populating one Endpoint Context inside an Input Context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointContextParams {
    /// Endpoint Context index (`DCI`, `1..=31`).
    pub dci: u8,
    /// xHCI endpoint type (`ControlBiDir`, `InterruptIn`, `BulkIn`, `BulkOut`).
    pub ep_type: XhciEndpointType,
    /// Maximum packet size (`0..=65535`).
    pub max_packet_size: u16,
    /// SuperSpeed `bMaxBurst` (`0` for USB 2.0 or non-burst endpoints).
    pub max_burst: u8,
    /// Encoded xHCI polling interval exponent (`0` for Control/Bulk).
    pub interval: u8,
    /// Initial `TR Dequeue Pointer | DCS` (`ring_base_iova | 1`).
    pub tr_dequeue_ptr_with_dcs: u64,
    /// Average TRB length hint (`8` for Control, `max_packet_size` for Intr, `3072` for Bulk).
    pub avg_trb_len: u16,
}

/// Write `Input Control Context` (`drop_flags`, `add_flags`) and `Slot Context` into `buf`
/// (`buf.len() >= 33 * context_size`, zeroed before writing).
pub fn init_input_context(
    buf: &mut [u8],
    context_size: usize,
    drop_flags: u32,
    add_flags: u32,
    slot: &SlotContextParams,
) -> bool {
    if (context_size != 32 && context_size != 64) || buf.len() < 33 * context_size {
        return false;
    }
    buf[..33 * context_size].fill(0);
    // Input Control Context at index 0.
    buf[0..4].copy_from_slice(&drop_flags.to_le_bytes());
    buf[4..8].copy_from_slice(&add_flags.to_le_bytes());

    // Slot Context at index 1 (`offset = context_size`).
    let speed_raw: u32 = match slot.speed {
        UsbSpeedAbi::Full => 1,
        UsbSpeedAbi::Low => 2,
        UsbSpeedAbi::High => 3,
        UsbSpeedAbi::Super => 4,
        UsbSpeedAbi::SuperPlus => 5,
        UsbSpeedAbi::Unknown => 0,
    };
    let hub_bit = if slot.is_hub { 1u32 << 26 } else { 0 };
    let mtt_bit = 0u32;
    let dw0 = (slot.route_string & 0x000F_FFFF)
        | (speed_raw << 20)
        | mtt_bit
        | hub_bit
        | (u32::from(slot.context_entries & 0x1F) << 27);
    let dw1 = (u32::from(slot.root_hub_port) << 16) | (u32::from(slot.num_ports) << 24);
    let dw2 = u32::from(slot.tt_hub_slot_id) | (u32::from(slot.tt_port_number) << 8);

    let s_off = context_size;
    buf[s_off..s_off + 4].copy_from_slice(&dw0.to_le_bytes());
    buf[s_off + 4..s_off + 8].copy_from_slice(&dw1.to_le_bytes());
    buf[s_off + 8..s_off + 12].copy_from_slice(&dw2.to_le_bytes());
    true
}

/// Populate one Endpoint Context (`DCI = params.dci`, Input Context index `dci + 1`).
pub fn set_input_endpoint_context(
    buf: &mut [u8],
    context_size: usize,
    params: &EndpointContextParams,
) -> bool {
    let dci = usize::from(params.dci);
    if !(1..=31).contains(&dci)
        || (context_size != 32 && context_size != 64)
        || buf.len() < (dci + 2) * context_size
    {
        return false;
    }
    let off = (dci + 1) * context_size;
    let cerr: u32 = 3;
    let dw0 = u32::from(params.interval) << 16;
    let dw1 = (cerr << 1)
        | ((params.ep_type as u32) << 3)
        | (u32::from(params.max_burst) << 8)
        | (u32::from(params.max_packet_size) << 16);
    let dw2 = params.tr_dequeue_ptr_with_dcs as u32;
    let dw3 = (params.tr_dequeue_ptr_with_dcs >> 32) as u32;
    let dw4 = u32::from(params.avg_trb_len);

    buf[off..off + 4].copy_from_slice(&dw0.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&dw1.to_le_bytes());
    buf[off + 8..off + 12].copy_from_slice(&dw2.to_le_bytes());
    buf[off + 12..off + 16].copy_from_slice(&dw3.to_le_bytes());
    buf[off + 16..off + 20].copy_from_slice(&dw4.to_le_bytes());
    true
}

/// Convert USB descriptor `bInterval` into xHCI `EndpointContext.Interval` (`125 us` exponent).
pub const fn usb_interval_to_xhci(speed: UsbSpeedAbi, raw_b_interval: u8, is_intr: bool) -> u8 {
    if !is_intr {
        return 0;
    }
    match speed {
        UsbSpeedAbi::High | UsbSpeedAbi::Super | UsbSpeedAbi::SuperPlus => {
            let clamped = if raw_b_interval == 0 {
                1
            } else if raw_b_interval > 16 {
                16
            } else {
                raw_b_interval
            };
            clamped - 1
        }
        UsbSpeedAbi::Full | UsbSpeedAbi::Low | UsbSpeedAbi::Unknown => {
            // Convert ms (`1..=255`) to nearest `2^n * 125 us` (`n in 3..=10`).
            let frames = if raw_b_interval == 0 {
                10u32
            } else {
                raw_b_interval as u32
            };
            let microframes = frames * 8;
            let log2 = 31u32.saturating_sub(microframes.leading_zeros());
            if log2 < 3 {
                3
            } else if log2 > 10 {
                10
            } else {
                log2 as u8
            }
        }
    }
}
