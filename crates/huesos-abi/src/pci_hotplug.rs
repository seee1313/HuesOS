//! Live PCI hotplug notification wire format (Stages K.2/M.2, AP-24).
//!
//! Ring-3 `acpi-manager` observes ACPI `Notify()` values raised by firmware
//! on PCI/PCIe hotplug slots (delivered through the SCI + GPE path, see
//! `docs/ACPI_RING3.md`) and re-emits a bounded, fixed-size wire event to
//! `pci-manager` over the private `pci-hotplug-events` channel minted by
//! DriverManager. The event carries just enough topology to select the
//! affected subtree; it deliberately carries no configuration registers —
//! `pci-manager` re-reads the subtree over its own config authority.
//!
//! A spurious or forged event cannot create authority by itself: the
//! channel is delivered only by DriverManager and `pci-manager` coalesces
//! and bounds events with `huesos_pci::hotplug::HotplugEventQueue` before
//! any subtree rescan or insertion is planned.

use crate::pci_lease::{pack_pci_address, unpack_pci_address};

/// Wire magic: ASCII `HPHG` in little endian.
pub const MAGIC: u32 = 0x4748_5048;
/// Current wire format version.
pub const VERSION: u16 = 1;
/// Fixed encoded event bytes.
///
/// Offsets 28..36 carry the complete little-endian `root_id`; bytes 36..40
/// are reserved and must remain zero. The explicit tail keeps the event
/// naturally extensible without changing the channel message size.
pub const MESSAGE_BYTES: usize = 40;

/// Label used by DriverManager when delivering one end of the private
/// `pci-hotplug-events` channel pair to `acpi-manager` and the other end
/// to `pci-manager`. Both managers must accept the label before the pair
/// is created; the pair is rebuilt on every relaunch of either manager.
pub const HOTPLUG_EVENTS_LABEL: &[u8] = b"pci-hotplug-events";
/// Label used by the optional ring-3 syscall-98 integration probe when
/// DriverManager lends it a duplicate write endpoint for the same private
/// event channel. Keeping this wire label in the ABI prevents the probe and
/// supervisor from silently drifting apart.
pub const HOTPLUG_TEST_CHANNEL_LABEL: &[u8] = b"pci-hotplug-test-channel";

/// ACPI `Notify()` value: bus check (`0x00`).
pub const NOTIFY_BUS_CHECK: u32 = 0x00;
/// ACPI `Notify()` value: device check (`0x01`).
pub const NOTIFY_DEVICE_CHECK: u32 = 0x01;
/// ACPI `Notify()` value: eject request (`0x03`).
pub const NOTIFY_EJECT_REQUEST: u32 = 0x03;
/// ACPI `Notify()` value used by PCIe native hotplug for presence-detect
/// changes when firmware does not grant native control (`0x80`).
pub const NOTIFY_PCIE_PRESENCE_DETECT: u32 = 0x80;
/// ACPI `Notify()` value used by PCIe native hotplug for eject requests
/// when firmware does not grant native control (`0x81`).
pub const NOTIFY_PCIE_EJECT_REQUEST: u32 = 0x81;
/// ACPI `Notify()` value used by PCIe native hotplug for surprise
/// removal / link-down when firmware does not grant native control (`0x82`).
pub const NOTIFY_PCIE_SURPRISE_REMOVAL: u32 = 0x82;

/// Bounded wire classification of an ACPI `Notify()` value that can affect
/// PCI topology.
///
/// `Ignored` values carry no hotplug meaning for this track (AER, device
/// wake, power-budget changes, ...); the producer still records them for
/// observability, but `pci-manager` never turns them into a rescan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HotplugNotifyKind {
    /// `BusCheck` / `DeviceCheck` / presence-detect: rescan the subtree.
    RescanSubtree = 1,
    /// Eject request: drain and eject the slot in an orderly way.
    OrderlyEject = 2,
    /// Surprise removal or link-down: revoke authority immediately.
    SurpriseLinkDown = 3,
}

/// Classify an ACPI `Notify()` value into a bounded hotplug kind.
///
/// Returns `None` for values that carry no topology meaning (or are out of
/// scope for the hotplug track); the caller must drop them.
pub const fn acpi_notify_kind(value: u32) -> Option<HotplugNotifyKind> {
    match value {
        NOTIFY_BUS_CHECK | NOTIFY_DEVICE_CHECK | NOTIFY_PCIE_PRESENCE_DETECT => {
            Some(HotplugNotifyKind::RescanSubtree)
        }
        NOTIFY_EJECT_REQUEST | NOTIFY_PCIE_EJECT_REQUEST => Some(HotplugNotifyKind::OrderlyEject),
        NOTIFY_PCIE_SURPRISE_REMOVAL => Some(HotplugNotifyKind::SurpriseLinkDown),
        _ => None,
    }
}

/// Scope of the affected subtree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HotplugTargetKind {
    /// Entire host bridge root (identified by its `HYMU`/HPCI `root_id`).
    Root = 1,
    /// Subtree below a hotplug-capable Type-1 bridge port (BDF).
    BridgePort = 2,
    /// One specific function (orderly/surprise removal).
    Function = 3,
}

/// One fixed-size hotplug notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotplugWireEvent {
    /// Wire magic ([`MAGIC`]).
    pub magic: u32,
    /// Wire version ([`VERSION`]).
    pub version: u16,
    /// Reserved, must be zero.
    pub reserved: u16,
    /// Bounded classification of the raw `Notify()` value (`0` when the
    /// value is not meaningful for topology; such events must not be acted
    /// on, but may still be printed for observability).
    pub kind: HotplugNotifyKind,
    /// Target scope.
    pub target: HotplugTargetKind,
    /// Segment of the target bridge/function (`0` for [`HotplugTargetKind::Root`]).
    pub segment: u16,
    /// Bus of the target bridge/function (`0` for [`HotplugTargetKind::Root`]).
    pub bus: u8,
    /// Device of the target bridge/function (`0` for [`HotplugTargetKind::Root`]).
    pub device: u8,
    /// Function of the target bridge/function (`0` for [`HotplugTargetKind::Root`]).
    pub function: u8,
    /// Raw ACPI `Notify()` value the event was derived from.
    pub notify_value: u32,
    /// HPCI `root_id` of the affected root when `target == Root`, else `0`.
    pub root_id: u64,
}

impl HotplugWireEvent {
    /// Construct a rescan request for one firmware root.
    ///
    /// A zero `root_id` is a deliberate test-only wildcard: the PCI Manager
    /// resolves it to the sole root when the platform exposes one root.
    pub const fn root_rescan(root_id: u64, notify_value: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind: HotplugNotifyKind::RescanSubtree,
            target: HotplugTargetKind::Root,
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            notify_value,
            root_id,
        }
    }

    /// Construct a rescan request for a bridge port's subtree.
    pub const fn bridge_port_rescan(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind: HotplugNotifyKind::RescanSubtree,
            target: HotplugTargetKind::BridgePort,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id: 0,
        }
    }

    const fn bridge_port_action(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        kind: HotplugNotifyKind,
        notify_value: u32,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind,
            target: HotplugTargetKind::BridgePort,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id: 0,
        }
    }

    /// Construct an orderly eject request for a bridge port subtree.
    pub const fn bridge_port_eject(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self::bridge_port_action(
            segment,
            bus,
            device,
            function,
            HotplugNotifyKind::OrderlyEject,
            notify_value,
        )
    }

    /// Construct a surprise-removal request for a bridge port subtree.
    pub const fn bridge_port_surprise_removal(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self::bridge_port_action(
            segment,
            bus,
            device,
            function,
            HotplugNotifyKind::SurpriseLinkDown,
            notify_value,
        )
    }

    const fn root_action(root_id: u64, kind: HotplugNotifyKind, notify_value: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind,
            target: HotplugTargetKind::Root,
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            notify_value,
            root_id,
        }
    }

    /// Construct an orderly eject request for a firmware root.
    pub const fn root_eject(root_id: u64, notify_value: u32) -> Self {
        Self::root_action(root_id, HotplugNotifyKind::OrderlyEject, notify_value)
    }

    /// Construct a surprise-removal request for a firmware root.
    pub const fn root_surprise_removal(root_id: u64, notify_value: u32) -> Self {
        Self::root_action(root_id, HotplugNotifyKind::SurpriseLinkDown, notify_value)
    }

    /// Construct a rescan request for one specific function node.
    pub const fn function_rescan(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind: HotplugNotifyKind::RescanSubtree,
            target: HotplugTargetKind::Function,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id: 0,
        }
    }

    /// Construct an orderly eject request for a function.
    pub const fn function_eject(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind: HotplugNotifyKind::OrderlyEject,
            target: HotplugTargetKind::Function,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id: 0,
        }
    }

    /// Construct a surprise-removal indication for a function.
    pub const fn function_surprise_removal(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        notify_value: u32,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            reserved: 0,
            kind: HotplugNotifyKind::SurpriseLinkDown,
            target: HotplugTargetKind::Function,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id: 0,
        }
    }

    /// Encode to the fixed wire layout.
    pub fn encode(&self) -> [u8; MESSAGE_BYTES] {
        let mut out = [0u8; MESSAGE_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.reserved.to_le_bytes());
        out[8..12].copy_from_slice(&(self.kind as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(self.target as u32).to_le_bytes());
        out[16..18].copy_from_slice(&self.segment.to_le_bytes());
        out[18] = self.bus;
        out[19] = self.device;
        out[20] = self.function;
        out[24..28].copy_from_slice(&self.notify_value.to_le_bytes());
        out[28..36].copy_from_slice(&self.root_id.to_le_bytes());
        out
    }

    /// Decode and validate one event. Rejects any magic/version/reserved
    /// mismatch and any unknown `kind`/`target` discriminant.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MESSAGE_BYTES {
            return None;
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
        let reserved = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
        let kind_raw = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let target_raw = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let segment = u16::from_le_bytes(bytes[16..18].try_into().ok()?);
        let bus = bytes[18];
        let device = bytes[19];
        let function = bytes[20];
        let notify_value = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
        let root_id = u64::from_le_bytes(bytes[28..36].try_into().ok()?);
        if magic != MAGIC
            || version != VERSION
            || reserved != 0
            || bytes[21..24] != [0; 3]
            || bytes[36..40] != [0; 4]
        {
            return None;
        }
        let kind = match kind_raw {
            1 => HotplugNotifyKind::RescanSubtree,
            2 => HotplugNotifyKind::OrderlyEject,
            3 => HotplugNotifyKind::SurpriseLinkDown,
            _ => return None,
        };
        let target = match target_raw {
            1 => HotplugTargetKind::Root,
            2 => HotplugTargetKind::BridgePort,
            3 => HotplugTargetKind::Function,
            _ => return None,
        };
        if acpi_notify_kind(notify_value) != Some(kind)
            || device > 31
            || function > 7
            || (target == HotplugTargetKind::Root
                && (segment != 0 || bus != 0 || device != 0 || function != 0))
            || (target != HotplugTargetKind::Root && root_id != 0)
        {
            return None;
        }
        Some(Self {
            magic,
            version,
            reserved,
            kind,
            target,
            segment,
            bus,
            device,
            function,
            notify_value,
            root_id,
        })
    }

    /// Canonical packed BDF of the target (segment:bus:device:function).
    pub const fn bdf_packed(&self) -> Option<u64> {
        pack_pci_address(self.segment, self.bus, self.device, self.function)
    }
}

/// Userspace argument for [`crate::Syscall::PciHotplugTrigger`].
///
/// The syscall consumes the channel capability and a pre-encoded event as one
/// bounded operation. The channel itself is the authority: only the test
/// ring-3 program receiving the private endpoint can request an event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciHotplugTriggerArgs {
    /// Write-capable endpoint whose peer is owned by `pci-manager`.
    pub channel: crate::HandleValue,
    /// Zero padding for stable alignment and future flags.
    pub reserved: [u8; 4],
    /// One [`HotplugWireEvent`] encoded with [`HotplugWireEvent::encode`].
    pub event: [u8; MESSAGE_BYTES],
}

impl PciHotplugTriggerArgs {
    /// Construct a syscall argument from a private channel and event.
    pub fn new(channel: crate::HandleValue, event: HotplugWireEvent) -> Self {
        Self {
            channel,
            reserved: [0; 4],
            event: event.encode(),
        }
    }
}

/// Fixed bytes for the PCI Manager ↔ DriverManager live handoff control
/// message. Resource messages carry their physical range in the same bounded
/// record, while the actual authority remains in the transferred handle.
pub const HANDOFF_MESSAGE_BYTES: usize = 80;
/// Wire magic: ASCII `HPHB` in little endian.
pub const HANDOFF_MAGIC: u32 = 0x4248_5048;
/// Current handoff wire version.
pub const HANDOFF_VERSION: u16 = 1;

/// Driver family selected by PCI Manager's bounded manifest matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HotplugDriverKind {
    /// No supported live driver was selected.
    Unknown = 0,
    /// NVMe block DriverHost.
    Nvme = 1,
    /// VirtIO network service.
    Net = 2,
    /// WLAN service.
    Wlan = 3,
    /// xHCI DriverHost.
    Xhci = 4,
}

impl HotplugDriverKind {
    fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            0 => Self::Unknown,
            1 => Self::Nvme,
            2 => Self::Net,
            3 => Self::Wlan,
            4 => Self::Xhci,
            _ => return None,
        })
    }
}

/// Handoff operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HotplugHandoffOp {
    /// PCI Manager asks DriverManager to bind one configured lease.
    BindRequest = 1,
    /// DriverManager reports the bind result and optional DriverHost KOID.
    BindResponse = 2,
    /// PCI Manager asks DriverManager to withdraw a bound lease.
    RemoveRequest = 3,
    /// DriverManager acknowledges withdrawal.
    RemoveResponse = 4,
    /// One lease-bound resource follows a bind request.
    BindResource = 5,
    /// All resources for a bind request have been transferred.
    BindComplete = 6,
}

impl HotplugHandoffOp {
    fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            1 => Self::BindRequest,
            2 => Self::BindResponse,
            3 => Self::RemoveRequest,
            4 => Self::RemoveResponse,
            5 => Self::BindResource,
            6 => Self::BindComplete,
            _ => return None,
        })
    }
}

/// Kind of resource attached to a bind request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HotplugResourceKind {
    /// No resource; used by control records.
    None = 0,
    /// The write-capable DeviceLease transferred with `BindRequest`.
    Lease = 1,
    /// Endpoint BAR resource.
    Mmio = 2,
    /// Interrupt or polling descriptor.
    Irq = 3,
    /// Isolated DMA pool resource.
    DmaPool = 4,
}

impl HotplugResourceKind {
    fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            0 => Self::None,
            1 => Self::Lease,
            2 => Self::Mmio,
            3 => Self::Irq,
            4 => Self::DmaPool,
            _ => return None,
        })
    }
}

/// Bounded result of a DriverManager handoff decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HotplugHandoffStatus {
    /// Request/response is valid and the driver may proceed.
    Ok = 0,
    /// No live binding is available for this endpoint.
    Unsupported = 1,
    /// The selected DriverHost already owns a different fixed device.
    Busy = 2,
    /// The request was stale or did not match the transferred lease.
    Stale = 3,
    /// Capability or protocol validation failed.
    Invalid = 4,
    /// Driver launch or readiness failed.
    Failed = 5,
}

impl HotplugHandoffStatus {
    fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::Unsupported,
            2 => Self::Busy,
            3 => Self::Stale,
            4 => Self::Invalid,
            5 => Self::Failed,
            _ => return None,
        })
    }
}

/// Fixed-size identity, resource, and result message for one live handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotplugHandoff {
    /// Wire magic.
    pub magic: u32,
    /// Wire version.
    pub version: u16,
    /// Operation.
    pub op: HotplugHandoffOp,
    /// PCI Manager generation.
    pub manager_generation: u64,
    /// Stable kernel DeviceLease identity.
    pub device_id: u64,
    /// Current lease generation.
    pub lease_generation: u64,
    /// Packed segment:BDF identity.
    pub bdf: u64,
    /// Driver family selected by PCI Manager.
    pub driver: HotplugDriverKind,
    /// Result status (`Ok` for a bind/remove request).
    pub status: HotplugHandoffStatus,
    /// DriverHost process KOID on a successful bind response.
    pub process_koid: u64,
    /// Resource kind carried by a handle on `BindRequest`/`BindResource`.
    pub resource_kind: HotplugResourceKind,
    /// Whether the resource range is exclusive.
    pub resource_exclusive: bool,
    /// Physical base of a resource record.
    pub resource_base: u64,
    /// Physical length of a resource record.
    pub resource_len: u64,
}

impl HotplugHandoff {
    const fn control(
        op: HotplugHandoffOp,
        manager_generation: u64,
        device_id: u64,
        lease_generation: u64,
        bdf: u64,
        driver: HotplugDriverKind,
    ) -> Self {
        Self {
            magic: HANDOFF_MAGIC,
            version: HANDOFF_VERSION,
            op,
            manager_generation,
            device_id,
            lease_generation,
            bdf,
            driver,
            status: HotplugHandoffStatus::Ok,
            process_koid: 0,
            resource_kind: HotplugResourceKind::None,
            resource_exclusive: false,
            resource_base: 0,
            resource_len: 0,
        }
    }

    /// Construct a bind request. Its transferred handle is the write-capable
    /// `DeviceLease`; the manager must validate every identity field before
    /// retaining it.
    pub const fn bind_request(
        manager_generation: u64,
        device_id: u64,
        lease_generation: u64,
        bdf: u64,
        driver: HotplugDriverKind,
    ) -> Self {
        let mut request = Self::control(
            HotplugHandoffOp::BindRequest,
            manager_generation,
            device_id,
            lease_generation,
            bdf,
            driver,
        );
        request.resource_kind = HotplugResourceKind::Lease;
        request
    }

    /// Construct one resource-transfer record.
    pub const fn bind_resource(
        request: Self,
        resource_kind: HotplugResourceKind,
        base: u64,
        len: u64,
        exclusive: bool,
    ) -> Self {
        let mut message = Self::control(
            HotplugHandoffOp::BindResource,
            request.manager_generation,
            request.device_id,
            request.lease_generation,
            request.bdf,
            request.driver,
        );
        message.resource_kind = resource_kind;
        message.resource_base = base;
        message.resource_len = len;
        message.resource_exclusive = exclusive;
        message
    }

    /// Construct the end-of-resources record.
    pub const fn bind_complete(request: Self) -> Self {
        Self::control(
            HotplugHandoffOp::BindComplete,
            request.manager_generation,
            request.device_id,
            request.lease_generation,
            request.bdf,
            request.driver,
        )
    }

    /// Construct a removal request.
    pub const fn remove_request(request: Self) -> Self {
        Self::control(
            HotplugHandoffOp::RemoveRequest,
            request.manager_generation,
            request.device_id,
            request.lease_generation,
            request.bdf,
            request.driver,
        )
    }

    /// Construct a response for a previously received handoff request.
    pub const fn response(request: Self, status: HotplugHandoffStatus, process_koid: u64) -> Self {
        let mut response = Self::control(
            match request.op {
                HotplugHandoffOp::RemoveRequest | HotplugHandoffOp::RemoveResponse => {
                    HotplugHandoffOp::RemoveResponse
                }
                _ => HotplugHandoffOp::BindResponse,
            },
            request.manager_generation,
            request.device_id,
            request.lease_generation,
            request.bdf,
            request.driver,
        );
        response.status = status;
        response.process_koid = process_koid;
        response
    }

    /// Encode a handoff message.
    pub fn encode(&self) -> [u8; HANDOFF_MESSAGE_BYTES] {
        let mut out = [0u8; HANDOFF_MESSAGE_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&(self.op as u16).to_le_bytes());
        out[8..16].copy_from_slice(&self.manager_generation.to_le_bytes());
        out[16..24].copy_from_slice(&self.device_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.lease_generation.to_le_bytes());
        out[32..40].copy_from_slice(&self.bdf.to_le_bytes());
        out[40..44].copy_from_slice(&(self.driver as u32).to_le_bytes());
        out[44..48].copy_from_slice(&(self.status as u32).to_le_bytes());
        out[48..56].copy_from_slice(&self.process_koid.to_le_bytes());
        out[56..60].copy_from_slice(&(self.resource_kind as u32).to_le_bytes());
        out[60..64].copy_from_slice(&u32::from(self.resource_exclusive).to_le_bytes());
        out[64..72].copy_from_slice(&self.resource_base.to_le_bytes());
        out[72..80].copy_from_slice(&self.resource_len.to_le_bytes());
        out
    }

    /// Decode a fixed-size handoff message and reject malformed identities.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HANDOFF_MESSAGE_BYTES {
            return None;
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
        let op = HotplugHandoffOp::from_raw(u16::from_le_bytes(bytes[6..8].try_into().ok()?))?;
        let manager_generation = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let device_id = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let lease_generation = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let bdf = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let driver =
            HotplugDriverKind::from_raw(u32::from_le_bytes(bytes[40..44].try_into().ok()?))?;
        let status =
            HotplugHandoffStatus::from_raw(u32::from_le_bytes(bytes[44..48].try_into().ok()?))?;
        let process_koid = u64::from_le_bytes(bytes[48..56].try_into().ok()?);
        let resource_kind =
            HotplugResourceKind::from_raw(u32::from_le_bytes(bytes[56..60].try_into().ok()?))?;
        let exclusive = u32::from_le_bytes(bytes[60..64].try_into().ok()?);
        let resource_base = u64::from_le_bytes(bytes[64..72].try_into().ok()?);
        let resource_len = u64::from_le_bytes(bytes[72..80].try_into().ok()?);
        let resource_exclusive = match exclusive {
            0 => false,
            1 => true,
            _ => return None,
        };
        if magic != HANDOFF_MAGIC
            || version != HANDOFF_VERSION
            || manager_generation == 0
            || device_id == 0
            || lease_generation == 0
            || unpack_pci_address(bdf).is_none()
            || (matches!(
                op,
                HotplugHandoffOp::BindRequest | HotplugHandoffOp::RemoveRequest
            ) && status != HotplugHandoffStatus::Ok)
            || (!matches!(
                op,
                HotplugHandoffOp::BindResponse | HotplugHandoffOp::RemoveResponse
            ) && process_koid != 0)
            || (matches!(
                op,
                HotplugHandoffOp::BindResource | HotplugHandoffOp::BindComplete
            ) && status != HotplugHandoffStatus::Ok)
            || (matches!(op, HotplugHandoffOp::BindResponse)
                && ((status == HotplugHandoffStatus::Ok && process_koid == 0)
                    || (status != HotplugHandoffStatus::Ok && process_koid != 0)))
            || (matches!(op, HotplugHandoffOp::RemoveResponse) && process_koid != 0)
            || (matches!(op, HotplugHandoffOp::BindRequest)
                && resource_kind != HotplugResourceKind::Lease)
            || (matches!(op, HotplugHandoffOp::BindResource)
                && (resource_kind == HotplugResourceKind::None
                    || resource_kind == HotplugResourceKind::Lease
                    || resource_len == 0
                    || resource_base.checked_add(resource_len).is_none()))
            || (!matches!(op, HotplugHandoffOp::BindResource)
                && !matches!(op, HotplugHandoffOp::BindRequest)
                && (resource_kind != HotplugResourceKind::None
                    || resource_exclusive
                    || resource_base != 0
                    || resource_len != 0))
            || (matches!(op, HotplugHandoffOp::BindRequest)
                && (resource_exclusive || resource_base != 0 || resource_len != 0))
        {
            return None;
        }
        Some(Self {
            magic,
            version,
            op,
            manager_generation,
            device_id,
            lease_generation,
            bdf,
            driver,
            status,
            process_koid,
            resource_kind,
            resource_exclusive,
            resource_base,
            resource_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_map_is_total_and_fail_closed() {
        assert_eq!(
            acpi_notify_kind(0x00),
            Some(HotplugNotifyKind::RescanSubtree)
        );
        assert_eq!(
            acpi_notify_kind(0x01),
            Some(HotplugNotifyKind::RescanSubtree)
        );
        assert_eq!(
            acpi_notify_kind(0x03),
            Some(HotplugNotifyKind::OrderlyEject)
        );
        assert_eq!(
            acpi_notify_kind(0x80),
            Some(HotplugNotifyKind::RescanSubtree)
        );
        assert_eq!(
            acpi_notify_kind(0x81),
            Some(HotplugNotifyKind::OrderlyEject)
        );
        assert_eq!(
            acpi_notify_kind(0x82),
            Some(HotplugNotifyKind::SurpriseLinkDown)
        );
        // AER / wake / power: never a topology event.
        assert_eq!(acpi_notify_kind(0x84), None);
        assert_eq!(acpi_notify_kind(0x02), None);
        assert_eq!(acpi_notify_kind(0xFF), None);
    }

    #[test]
    fn event_round_trip() {
        let event = HotplugWireEvent::bridge_port_rescan(0, 0, 0x16, 0, NOTIFY_BUS_CHECK);
        let bytes = event.encode();
        assert_eq!(HotplugWireEvent::decode(&bytes), Some(event));
        let eject = HotplugWireEvent::function_eject(0, 2, 1, 0, NOTIFY_EJECT_REQUEST);
        assert_eq!(HotplugWireEvent::decode(&eject.encode()), Some(eject));
        let bridge_eject = HotplugWireEvent::bridge_port_eject(0, 0, 0x16, 0, 0x81);
        assert_eq!(
            HotplugWireEvent::decode(&bridge_eject.encode()),
            Some(bridge_eject)
        );
        let root_surprise = HotplugWireEvent::root_surprise_removal(7, 0x82);
        assert_eq!(
            HotplugWireEvent::decode(&root_surprise.encode()),
            Some(root_surprise)
        );
        let surprise = HotplugWireEvent::function_surprise_removal(0, 2, 1, 0, 0x82);
        assert_eq!(HotplugWireEvent::decode(&surprise.encode()), Some(surprise));
    }

    #[test]
    fn decode_rejects_corruption() {
        let event = HotplugWireEvent::bridge_port_rescan(0, 0, 0x16, 0, 0x00);
        let bytes = event.encode();
        let mut bad = bytes;
        bad[0] ^= 0xFF;
        assert_eq!(HotplugWireEvent::decode(&bad), None);
        let mut bad = bytes;
        bad[8] = 9;
        assert_eq!(HotplugWireEvent::decode(&bad), None);
        let mut bad = bytes;
        bad[12] = 7;
        assert_eq!(HotplugWireEvent::decode(&bad), None);
        let mut bad = bytes;
        bad[21] = 1;
        assert_eq!(HotplugWireEvent::decode(&bad), None);
        assert_eq!(HotplugWireEvent::decode(&bytes[..16]), None);
    }

    #[test]
    fn handoff_round_trip_requires_real_success_identity() {
        let request = HotplugHandoff::bind_request(
            9,
            0x1234,
            7,
            0x0000_0000_0001_0000,
            HotplugDriverKind::Nvme,
        );
        assert_eq!(HotplugHandoff::decode(&request.encode()), Some(request));
        let response = HotplugHandoff::response(request, HotplugHandoffStatus::Ok, 0x55);
        assert_eq!(HotplugHandoff::decode(&response.encode()), Some(response));
        let mut bad = response.encode();
        bad[48..56].fill(0);
        assert_eq!(HotplugHandoff::decode(&bad), None);
        let resource = HotplugHandoff::bind_resource(
            request,
            HotplugResourceKind::Mmio,
            0xfee0_0000,
            0x1000,
            true,
        );
        assert_eq!(HotplugHandoff::decode(&resource.encode()), Some(resource));
        let mut bad = resource.encode();
        bad[60] = 2;
        assert_eq!(HotplugHandoff::decode(&bad), None);
        let mut bad = resource.encode();
        bad[44..48].copy_from_slice(&(HotplugHandoffStatus::Failed as u32).to_le_bytes());
        assert_eq!(HotplugHandoff::decode(&bad), None);
        let complete = HotplugHandoff::bind_complete(request);
        let mut bad = complete.encode();
        bad[44..48].copy_from_slice(&(HotplugHandoffStatus::Failed as u32).to_le_bytes());
        assert_eq!(HotplugHandoff::decode(&bad), None);
        let mut bad = request.encode();
        bad[56] = 2;
        assert_eq!(HotplugHandoff::decode(&bad), None);
    }
}
