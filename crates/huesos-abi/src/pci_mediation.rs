//! Dedicated ACPI ↔ PCI configuration read mediation protocol (AP-10).
//!
//! Ring 3 AML (once a namespace is loaded) never reaches configuration
//! space by itself. The isolated ACPI manager encodes each access as a
//! [`Request`] on a private brokered channel; the supervised PCI Manager
//! — the only process holding read-only authority for the firmware's
//! ECAM windows (AP-9) or the legacy CF8/CFC authority (AP-8 mint
//! kind 2) — performs the physical access and answers with a
//! [`Response`]. The channel itself is the capability: the kernel gives
//! it to DriverManager only, and DriverManager hands one end to each of
//! the two supervised managers.
//!
//! ## Freshness discipline
//!
//! Every request carries *both* manager generations and the firmware
//! snapshot identity retained from the `HMCF` pipeline. The PCI Manager
//! answers a request only when:
//!
//! 1. `pci_generation` equals its own generation;
//! 2. `acpi_generation` equals the producer generation recorded in its
//!    validated `HMCF` image;
//! 3. `firmware_snapshot_id` equals the image's snapshot identity.
//!
//! Anything else is answered with [`Status::StaleGeneration`] or
//! [`Status::SnapshotMismatch`] and touches no hardware. The mediation
//! channel is additionally re-created by DriverManager on every relaunch
//! of either manager, so a stale peer holds a closed channel rather than
//! a live one.
//!
//! ## Write discipline
//!
//! [`Opcode::Write`] decodes (append-only) so a peer can be answered,
//! but it is *always* denied with [`Status::AccessDenied`] before any
//! hardware access, and it carries no write path in this module. The old
//! ACPI broker PCI opcodes remain decodable in
//! [`crate::acpi_broker`] but are likewise never authorizable.
//!
//! ## Opaque region handles
//!
//! [`PciConfigRegions`] implements the open/read/close lifecycle the
//! uACPI address-space handler will drive in AP-13: opening a region
//! yields a small opaque [`RegionHandle`] (never a pointer), reads name
//! the region by handle, closing releases it. Stale handles are
//! rejected by a per-slot generation counter. No raw configuration
//! pointer is ever stored, minted, or derived.

/// Current mediation protocol version.
pub const VERSION: u16 = 1;
/// Encoded request size in bytes.
pub const REQUEST_BYTES: usize = 48;
/// Encoded response size in bytes.
pub const RESPONSE_BYTES: usize = 40;
/// Label under which DriverManager transfers one end of the mediation
/// channel to each supervised manager.
pub const MEDIATION_CHANNEL_LABEL: &[u8] = b"pci-config-read";
/// Plain ASCII announcement (`pci-config-read-gen:<decimal generation>`)
/// DriverManager writes to the ACPI manager's bootstrap channel right
/// before handing it the mediation channel, so the requester knows the
/// PCI Manager generation to bind into its requests.
pub const MEDIATION_GENERATION_PREFIX: &[u8] = b"pci-config-read-gen:";
/// Largest offset addressable by a request (extended configuration
/// space is 4 KiB).
pub const MAX_OFFSET: u16 = 4095;
/// Default bound for [`PciConfigRegions`].
pub const MAX_REGIONS: usize = 16;

/// Mediation operation.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    /// Read `width` bytes at `offset` of one configuration space.
    Read = 1,
    /// Decodable so peers can be answered; *never* executed. Always
    /// denied with [`Status::AccessDenied`] before any hardware access.
    Write = 2,
}

impl Opcode {
    /// Decode a wire value without constructing an invalid enum.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            _ => None,
        }
    }
}

/// Mediation outcome.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// The read completed; `value` carries it.
    Ok = 0,
    /// Request bytes were malformed, or a field was out of bounds.
    InvalidRequest = -1,
    /// Write variant, or a read that policy denied. Never touches hardware.
    AccessDenied = -2,
    /// No configuration window covers the requested segment:bus, or the
    /// legacy backend cannot reach the (extended) offset.
    NotFound = -3,
    /// `pci_generation` or `acpi_generation` is stale for this manager.
    StaleGeneration = -4,
    /// `firmware_snapshot_id` does not match the retained `HMCF` image.
    SnapshotMismatch = -5,
    /// Authority for configuration access has not been granted yet
    /// (fresh manager, burst not complete, or settle sentinel received).
    NotReady = -6,
}

impl Status {
    /// Decode a wire value without constructing an invalid enum.
    pub const fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            -1 => Some(Self::InvalidRequest),
            -2 => Some(Self::AccessDenied),
            -3 => Some(Self::NotFound),
            -4 => Some(Self::StaleGeneration),
            -5 => Some(Self::SnapshotMismatch),
            -6 => Some(Self::NotReady),
            _ => None,
        }
    }
}

/// One fixed mediation request.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u16,
    /// Raw [`Opcode`] value; decoded explicitly by [`Request::validate`].
    pub opcode: u16,
    /// Exact access width in bytes: 1, 2, or 4.
    pub width: u8,
    /// Reserved; must be zero.
    pub reserved: [u8; 3],
    /// Generation of the requesting ACPI manager.
    pub acpi_generation: u64,
    /// Generation of the PCI manager the request expects to serve it.
    pub pci_generation: u64,
    /// Firmware snapshot identity retained from the `HMCF` pipeline.
    pub firmware_snapshot_id: u64,
    /// PCI segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number, `0..=31`.
    pub device: u8,
    /// Function number, `0..=7`.
    pub function: u8,
    /// Reserved; must be zero.
    pub reserved2: u8,
    /// Configuration offset, `0..=4095`, aligned to `width`.
    pub offset: u16,
    /// Caller-selected correlation identifier copied into the response.
    pub correlation_id: u64,
}

/// A structurally validated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidRequest {
    /// Decoded operation.
    pub opcode: Opcode,
    /// Exact access width in bytes.
    pub width: u8,
    /// Generation of the requesting ACPI manager.
    pub acpi_generation: u64,
    /// Generation of the expected PCI manager.
    pub pci_generation: u64,
    /// Firmware snapshot identity.
    pub firmware_snapshot_id: u64,
    /// PCI segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number.
    pub device: u8,
    /// Function number.
    pub function: u8,
    /// Configuration offset.
    pub offset: u16,
    /// Correlation identifier.
    pub correlation_id: u64,
}

/// Structural validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Unsupported protocol version.
    Version,
    /// Unknown opcode number.
    Opcode,
    /// Reserved bytes were non-zero.
    Reserved,
    /// Width was not 1, 2, or 4.
    Width,
    /// Offset was not aligned to the width, exceeded [`MAX_OFFSET`], or
    /// `offset + width` exceeded the 4 KiB space.
    Alignment,
    /// `device` exceeded 31 or `function` exceeded 7.
    DeviceFunction,
    /// A generation was zero.
    Generation,
    /// `firmware_snapshot_id` was zero.
    Snapshot,
}

impl Request {
    /// Build a read request. The parameter count mirrors the wire format
    /// one-to-one; grouping them into a struct would only re-shuffle the
    /// same fields at every call site.
    #[allow(clippy::too_many_arguments)]
    pub const fn read(
        acpi_generation: u64,
        pci_generation: u64,
        firmware_snapshot_id: u64,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        width: u8,
        correlation_id: u64,
    ) -> Self {
        Self {
            version: VERSION,
            opcode: Opcode::Read as u16,
            width,
            reserved: [0; 3],
            acpi_generation,
            pci_generation,
            firmware_snapshot_id,
            segment,
            bus,
            device,
            function,
            reserved2: 0,
            offset,
            correlation_id,
        }
    }

    /// Build a write request. The PCI manager always answers it with
    /// [`Status::AccessDenied`] before any hardware access; it exists so
    /// a confused or adversarial peer gets an explicit denial instead of
    /// an ambiguous decode failure.
    #[allow(clippy::too_many_arguments)]
    pub const fn write(
        acpi_generation: u64,
        pci_generation: u64,
        firmware_snapshot_id: u64,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        width: u8,
        correlation_id: u64,
    ) -> Self {
        Self {
            version: VERSION,
            opcode: Opcode::Write as u16,
            width,
            reserved: [0; 3],
            acpi_generation,
            pci_generation,
            firmware_snapshot_id,
            segment,
            bus,
            device,
            function,
            reserved2: 0,
            offset,
            correlation_id,
        }
    }

    /// Validate structure without performing any I/O.
    pub fn validate(self) -> Result<ValidRequest, ValidationError> {
        if self.version != VERSION {
            return Err(ValidationError::Version);
        }
        let Some(opcode) = Opcode::from_raw(self.opcode) else {
            return Err(ValidationError::Opcode);
        };
        if self.reserved != [0; 3] || self.reserved2 != 0 {
            return Err(ValidationError::Reserved);
        }
        if !matches!(self.width, 1 | 2 | 4) {
            return Err(ValidationError::Width);
        }
        let offset = u64::from(self.offset);
        if offset > u64::from(MAX_OFFSET)
            || offset & (u64::from(self.width) - 1) != 0
            || offset + u64::from(self.width) > 4096
        {
            return Err(ValidationError::Alignment);
        }
        if self.device > 31 || self.function > 7 {
            return Err(ValidationError::DeviceFunction);
        }
        if self.acpi_generation == 0 || self.pci_generation == 0 {
            return Err(ValidationError::Generation);
        }
        if self.firmware_snapshot_id == 0 {
            return Err(ValidationError::Snapshot);
        }
        Ok(ValidRequest {
            opcode,
            width: self.width,
            acpi_generation: self.acpi_generation,
            pci_generation: self.pci_generation,
            firmware_snapshot_id: self.firmware_snapshot_id,
            segment: self.segment,
            bus: self.bus,
            device: self.device,
            function: self.function,
            offset: self.offset,
            correlation_id: self.correlation_id,
        })
    }
}

/// One fixed mediation response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Response {
    /// [`VERSION`].
    pub version: u16,
    /// Reserved; must be zero.
    pub reserved: u16,
    /// Raw [`Status`] value.
    pub status: i32,
    /// Copied from the request.
    pub correlation_id: u64,
    /// Generation of the answering PCI manager (echoes the request).
    pub pci_generation: u64,
    /// Generation of the requesting ACPI manager (echoes the request).
    pub acpi_generation: u64,
    /// Read value; zero unless `status == Ok`.
    pub value: u64,
}

impl Response {
    /// Build the response to one request.
    pub const fn for_request(request: &Request, status: Status, value: u64) -> Self {
        Self {
            version: VERSION,
            reserved: 0,
            status: status as i32,
            correlation_id: request.correlation_id,
            pci_generation: request.pci_generation,
            acpi_generation: request.acpi_generation,
            value,
        }
    }
}

/// Encode one request.
pub fn encode_request(request: &Request, output: &mut [u8]) -> Option<usize> {
    if output.len() < REQUEST_BYTES {
        return None;
    }
    output[..REQUEST_BYTES].fill(0);
    u16_le(output, 0, request.version);
    u16_le(output, 2, request.opcode);
    output[4] = request.width;
    output[5..8].copy_from_slice(&request.reserved);
    u64_le(output, 8, request.acpi_generation);
    u64_le(output, 16, request.pci_generation);
    u64_le(output, 24, request.firmware_snapshot_id);
    u16_le(output, 32, request.segment);
    output[34] = request.bus;
    output[35] = request.device;
    output[36] = request.function;
    output[37] = request.reserved2;
    u16_le(output, 38, request.offset);
    u64_le(output, 40, request.correlation_id);
    Some(REQUEST_BYTES)
}

/// Decode one request.
pub fn decode_request(bytes: &[u8]) -> Option<Request> {
    if bytes.len() != REQUEST_BYTES {
        return None;
    }
    let mut reserved = [0u8; 3];
    reserved.copy_from_slice(&bytes[5..8]);
    Some(Request {
        version: u16_at(bytes, 0)?,
        opcode: u16_at(bytes, 2)?,
        width: bytes[4],
        reserved,
        acpi_generation: u64_at(bytes, 8)?,
        pci_generation: u64_at(bytes, 16)?,
        firmware_snapshot_id: u64_at(bytes, 24)?,
        segment: u16_at(bytes, 32)?,
        bus: bytes[34],
        device: bytes[35],
        function: bytes[36],
        reserved2: bytes[37],
        offset: u16_at(bytes, 38)?,
        correlation_id: u64_at(bytes, 40)?,
    })
}

/// Encode one response.
pub fn encode_response(response: &Response, output: &mut [u8]) -> Option<usize> {
    if output.len() < RESPONSE_BYTES {
        return None;
    }
    output[..RESPONSE_BYTES].fill(0);
    u16_le(output, 0, response.version);
    u16_le(output, 2, response.reserved);
    output[4..8].copy_from_slice(&response.status.to_le_bytes());
    u64_le(output, 8, response.correlation_id);
    u64_le(output, 16, response.pci_generation);
    u64_le(output, 24, response.acpi_generation);
    u64_le(output, 32, response.value);
    Some(RESPONSE_BYTES)
}

/// Decode one response.
pub fn decode_response(bytes: &[u8]) -> Option<Response> {
    if bytes.len() != RESPONSE_BYTES {
        return None;
    }
    if u16_at(bytes, 0)? != VERSION || u16_at(bytes, 2)? != 0 {
        return None;
    }
    let status_raw = i32::from_le_bytes(bytes[4..8].try_into().ok()?);
    Status::from_raw(status_raw)?;
    Some(Response {
        version: VERSION,
        reserved: 0,
        status: status_raw,
        correlation_id: u64_at(bytes, 8)?,
        pci_generation: u64_at(bytes, 16)?,
        acpi_generation: u64_at(bytes, 24)?,
        value: u64_at(bytes, 32)?,
    })
}

fn u16_le(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Opaque region handle minted by [`PciConfigRegions::attach`].
///
/// Bits `[7:0]` carry `index + 1`; bits `[31:8]` carry a per-slot
/// generation counter that increments on every attach and detach, so a
/// handle captured before a close is stale forever afterwards.
/// The value is a small integer, never a pointer.
pub type RegionHandle = u32;

/// One attached configuration region binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionBinding {
    /// PCI segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number, `0..=31`.
    pub device: u8,
    /// Function number, `0..=7`.
    pub function: u8,
    /// Region base offset within the configuration space.
    pub base_offset: u16,
    /// Region length in bytes (`1..=4096`).
    pub length: u16,
}

impl RegionBinding {
    /// Whether the binding is internally consistent.
    pub fn is_valid(&self) -> bool {
        self.device <= 31
            && self.function <= 7
            && self.length >= 1
            && self
                .base_offset
                .checked_add(self.length)
                .is_some_and(|end| end <= 4096)
    }
}

/// Open/read/close state machine for the uACPI address-space handler
/// (wired in AP-13 once the namespace loads).
///
/// `N` bounds the number of simultaneously attached regions. All
/// operations are allocation-free and total: invalid or stale handles
/// yield `None`/`false`, never a panic, never a pointer.
pub struct PciConfigRegions<const N: usize = MAX_REGIONS> {
    slots: [RegionSlot; N],
}

#[derive(Clone, Copy)]
struct RegionSlot {
    /// Per-slot generation, bumped on attach and detach. Zero means the
    /// slot was never attached and is not handed out.
    generation: u32,
    binding: Option<RegionBinding>,
}

const EMPTY_SLOT: RegionSlot = RegionSlot {
    generation: 0,
    binding: None,
};

impl<const N: usize> Default for PciConfigRegions<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PciConfigRegions<N> {
    /// Empty table; every handle rejected until [`attach`](Self::attach).
    pub const fn new() -> Self {
        Self {
            slots: [EMPTY_SLOT; N],
        }
    }

    /// Open one region. Returns the opaque handle, or `None` when the
    /// binding is invalid or the table is full.
    pub fn attach(&mut self, binding: RegionBinding) -> Option<RegionHandle> {
        if !binding.is_valid() {
            return None;
        }
        for index in 0..N {
            if self.slots[index].binding.is_none() {
                let generation = self.slots[index].generation.checked_add(1)?;
                self.slots[index].generation = generation;
                self.slots[index].binding = Some(binding);
                return Some((generation << 8) | (index as u32 + 1));
            }
        }
        None
    }

    /// Close one region. Returns whether a live region was closed.
    /// The freed slot's generation advances, invalidating any handle
    /// captured before the close.
    pub fn detach(&mut self, handle: RegionHandle) -> bool {
        let Some(slot) = self.slot_mut(handle) else {
            return false;
        };
        slot.binding = None;
        slot.generation = slot.generation.wrapping_add(1);
        true
    }

    /// Resolve a live handle to its binding. `None` for stale, closed,
    /// or never-minted handles.
    pub fn resolve(&self, handle: RegionHandle) -> Option<RegionBinding> {
        let index = (handle & 0xff) as usize;
        let generation = handle >> 8;
        if index == 0 || index > N || generation == 0 {
            return None;
        }
        let slot = &self.slots[index - 1];
        if slot.generation != generation {
            return None;
        }
        slot.binding
    }

    fn slot_mut(&mut self, handle: RegionHandle) -> Option<&mut RegionSlot> {
        let index = (handle & 0xff) as usize;
        let generation = handle >> 8;
        if index == 0 || index > N || generation == 0 {
            return None;
        }
        let slot = &mut self.slots[index - 1];
        if slot.generation != generation || slot.binding.is_none() {
            return None;
        }
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwrap an `Option` inside a test without growing the unsafe or
    /// panic-adjacent call surface; absence is a hard test failure.
    fn or_fail<T>(value: Option<T>, what: &str) -> T {
        match value {
            Some(v) => v,
            None => {
                assert!(false, "{what}");
                unreachable!()
            }
        }
    }

    fn read_request() -> Request {
        Request::read(1, 7, 0xA5A5, 0, 0, 0, 0, 0x10, 4, 0xDEAD_BEEF)
    }

    #[test]
    fn read_request_round_trips_and_validates() {
        let request = read_request();
        let mut bytes = [0u8; REQUEST_BYTES];
        assert_eq!(encode_request(&request, &mut bytes), Some(REQUEST_BYTES));
        let decoded = or_fail(decode_request(&bytes), "decode_request");
        assert_eq!(decoded, request);
        let valid = or_fail(decoded.validate().ok(), "validate");
        assert_eq!(valid.opcode, Opcode::Read);
        assert_eq!(valid.width, 4);
        assert_eq!(valid.correlation_id, 0xDEAD_BEEF);
    }

    #[test]
    fn write_request_decodes_but_is_denied_marker_only() {
        let request = Request::write(1, 7, 0xA5A5, 0, 0, 0, 0, 0x04, 4, 9);
        let mut bytes = [0u8; REQUEST_BYTES];
        assert_eq!(encode_request(&request, &mut bytes), Some(REQUEST_BYTES));
        let decoded = or_fail(decode_request(&bytes), "decode_request");
        assert_eq!(decoded.validate().map(|v| v.opcode), Ok(Opcode::Write));
        assert_eq!(Opcode::from_raw(3), None);
        assert_eq!(Opcode::from_raw(0xffff), None);
    }

    #[test]
    fn rejects_bad_version_reserved_width_alignment_bounds() {
        let mut bytes = [0u8; REQUEST_BYTES];
        let request = read_request();
        assert_eq!(encode_request(&request, &mut bytes), Some(REQUEST_BYTES));

        let mut bumped = request;
        bumped.version = 2;
        assert_eq!(bumped.validate(), Err(ValidationError::Version));

        let mut reserved = request;
        reserved.reserved = [0, 1, 0];
        assert_eq!(reserved.validate(), Err(ValidationError::Reserved));

        let mut reserved2 = request;
        reserved2.reserved2 = 1;
        assert_eq!(reserved2.validate(), Err(ValidationError::Reserved));

        let mut width = request;
        width.width = 3;
        assert_eq!(width.validate(), Err(ValidationError::Width));

        let mut unaligned = request;
        unaligned.offset = 2; // not aligned to 4
        assert_eq!(unaligned.validate(), Err(ValidationError::Alignment));

        let mut edge = request;
        edge.offset = 4092; // 4092 + 4 == 4096: the last legal dword
        assert!(edge.validate().is_ok());

        let mut overflow = request;
        overflow.offset = 4096; // one past the end
        assert_eq!(overflow.validate(), Err(ValidationError::Alignment));

        let mut extended = request;
        extended.offset = 0x100; // extended config space is fine when aligned
        assert!(extended.validate().is_ok());

        let mut too_wide = request;
        too_wide.width = 2;
        too_wide.offset = 4096;
        assert_eq!(too_wide.validate(), Err(ValidationError::Alignment));
    }

    #[test]
    fn rejects_bad_device_function_generations_snapshot() {
        let mut device = read_request();
        device.device = 32;
        assert_eq!(device.validate(), Err(ValidationError::DeviceFunction));

        let mut function = read_request();
        function.function = 8;
        assert_eq!(function.validate(), Err(ValidationError::DeviceFunction));

        let mut acpi = read_request();
        acpi.acpi_generation = 0;
        assert_eq!(acpi.validate(), Err(ValidationError::Generation));

        let mut pci = read_request();
        pci.pci_generation = 0;
        assert_eq!(pci.validate(), Err(ValidationError::Generation));

        let mut snapshot = read_request();
        snapshot.firmware_snapshot_id = 0;
        assert_eq!(snapshot.validate(), Err(ValidationError::Snapshot));
    }

    #[test]
    fn response_round_trips_and_echoes() {
        let request = read_request();
        let response = Response::for_request(&request, Status::Ok, 0x1234_8086);
        let mut bytes = [0u8; RESPONSE_BYTES];
        assert_eq!(encode_response(&response, &mut bytes), Some(RESPONSE_BYTES));
        let decoded = or_fail(decode_response(&bytes), "decode_response");
        assert_eq!(decoded, response);
        assert_eq!(decoded.correlation_id, request.correlation_id);
        assert_eq!(decoded.pci_generation, request.pci_generation);
        assert_eq!(decoded.value, 0x1234_8086);

        let denied = Response::for_request(&request, Status::AccessDenied, 0);
        assert_eq!(denied.status, Status::AccessDenied as i32);
        assert_eq!(Status::from_raw(0), Some(Status::Ok));
        assert_eq!(Status::from_raw(-6), Some(Status::NotReady));
        assert_eq!(Status::from_raw(-7), None);
    }

    fn binding() -> RegionBinding {
        RegionBinding {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            base_offset: 0,
            length: 256,
        }
    }

    #[test]
    fn regions_open_read_close_cycle() {
        let mut table = PciConfigRegions::<4>::new();
        let first = or_fail(table.attach(binding()), "attach");
        assert_ne!(first, 0);
        assert_eq!(table.resolve(first), Some(binding()));
        assert!(table.detach(first));
        assert_eq!(table.resolve(first), None);
        assert!(!table.detach(first));
    }

    #[test]
    fn regions_reject_invalid_bindings() {
        let mut table = PciConfigRegions::<2>::new();
        let mut device = binding();
        device.device = 32;
        assert_eq!(table.attach(device), None);

        let mut zero = binding();
        zero.length = 0;
        assert_eq!(table.attach(zero), None);

        let mut overflow = binding();
        overflow.base_offset = 4090;
        overflow.length = 16;
        assert_eq!(table.attach(overflow), None);

        let mut extended = binding();
        extended.base_offset = 256;
        extended.length = 3840;
        assert!(table.attach(extended).is_some());
    }

    #[test]
    fn regions_stale_handles_die_on_detach_and_reattach() {
        let mut table = PciConfigRegions::<1>::new();
        let first = or_fail(table.attach(binding()), "first attach");
        assert!(table.detach(first));
        // Same slot, new generation: the old handle must stay dead.
        let second = or_fail(table.attach(binding()), "reattach");
        assert_ne!(first, second);
        assert_eq!(table.resolve(first), None);
        assert_eq!(table.resolve(second), Some(binding()));
        assert!(!table.detach(first));
    }

    #[test]
    fn regions_exhaustion_is_total() {
        let mut table = PciConfigRegions::<2>::new();
        assert!(table.attach(binding()).is_some());
        assert!(table.attach(binding()).is_some());
        assert_eq!(table.attach(binding()), None);
    }
}
