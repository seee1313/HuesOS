//! PCI Manager bootstrap/lifecycle control protocol.
//!
//! Hardware configuration and topology payloads use separate bounded formats.
//! This fixed control message establishes supervisor/manager liveness and keeps
//! the initial no-root skeleton fail-closed without text parsing.

/// Wire magic: ASCII `HPCM` in little endian.
pub const MAGIC: u32 = 0x4d43_5048;
/// Current control protocol version.
pub const VERSION: u16 = 1;
/// Fixed encoded message bytes.
pub const MESSAGE_BYTES: usize = 24;
/// Future VMO-handle label carrying `huesos_abi::pci::RootBridgeTable` bytes.
pub const ROOT_TABLE_VMO_LABEL: &[u8] = b"pci-roots-vmo";
/// Label carrying the bounded, immutable `huesos_abi::hmcf` snapshot to
/// one PCI Manager generation. The VMO grants `READ | TRANSFER` only;
/// DriverManager transfers a duplicate, never its retained origin, and
/// the receiver must treat it as immutable.
pub const HMCF_VMO_LABEL: &[u8] = b"pci-hmcf-vmo";
/// Label carrying one read-only ECAM capability (`Mmio`, `READ |
/// TRANSFER` rights). One message per `huesos_abi::hmcf` record, sent
/// in canonical record order; the receiver matches the `i`-th
/// `CONFIG_ECAM_LABEL` handle to the `i`-th HMCF record.
pub const CONFIG_ECAM_LABEL: &[u8] = b"pci-config-ecam";
/// Label carrying one upgraded read-write ECAM capability (`Mmio`,
/// `READ | WRITE | TRANSFER` rights) after validated `HPCI` roots and
/// B.4 write-policy enforcement (AP-17).
pub const CONFIG_ECAM_RW_LABEL: &[u8] = b"pci-config-ecam-rw";
/// Label carrying the legacy CF8/CFC `IoPort` capability (`READ | WRITE |
/// TRANSFER`) minted for PCI segment 0. Sent only when the supervisor
/// requests the legacy backend with [`HELLO_FLAG_FORCE_LEGACY`]; never
/// sent otherwise.
pub const LEGACY_IOPORT_LABEL: &[u8] = b"pci-legacy-ioport";
/// Label carrying the `DeviceLeaseAuthority` capability from DriverManager to
/// PCI Manager (AP-20). Must stay `<= MESSAGE_BYTES` (24 bytes).
pub const DEVICE_LEASE_AUTHORITY_LABEL: &[u8] = b"pci-lease-auth";
/// Label carrying a read-only `DeviceLease` handle (`READ | TRANSFER`)
/// from PCI Manager to DriverManager / DriverHost (AP-21).
pub const DEVICE_LEASE_RO_LABEL: &[u8] = b"pci-lease-ro";
/// Label carrying the read-only `DeviceLease` handle bound specifically to
/// `driver-host-nvme` (Stage J.2 / AP-22).
pub const DEVICE_LEASE_NVME_RO_LABEL: &[u8] = b"pci-lease-ro:nvme";
/// Label carrying a narrow lease-bound `Resource` handle (`Mmio`, `IoPort`,
/// `Irq`, or `DmaPool`) minted via `DeviceLeaseMintResource` (AP-21).
pub const LEASE_RESOURCE_LABEL: &[u8] = b"pci-lease-res";

/// Configuration override: serve configuration reads through the
/// legacy CF8/CFC mechanism (#1) even though ECAM authority is mapped.
/// Intended for conformance testing of the legacy common subset; the
/// manager still requires the legacy `IoPort` capability to be granted
/// with this flag, otherwise reads answer `NotReady`.
pub const HELLO_FLAG_FORCE_LEGACY: u32 = 1 << 0;
/// Kill-switch flag: `init.storage=off` was active, so PCI Manager must
/// leave NVMe controllers unbound and unconfigured (AP-22).
pub const HELLO_FLAG_STORAGE_OFF: u32 = 1 << 1;
/// All hello flags known by version 1.
pub const HELLO_FLAGS_V1: u32 = HELLO_FLAG_FORCE_LEGACY | HELLO_FLAG_STORAGE_OFF;

/// Control operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Opcode {
    /// DriverManager starts one manager generation.
    Hello = 1,
    /// PCI Manager completed fail-closed bootstrap.
    Ready = 2,
    /// Periodic liveness notification.
    Heartbeat = 3,
    /// Future root-table VMO was accepted.
    RootTableAccepted = 4,
    /// Future root-table VMO was rejected.
    RootTableRejected = 5,
    /// DriverManager ends the config-authority transfer burst with
    /// this message. `detail` carries the number of read-only ECAM
    /// capabilities that preceded it (`0` when no authority could be
    /// minted — the manager must stay fail-closed). Sent at most
    /// once per manager generation, only after a `Hello`.
    AuthorityComplete = 6,
    /// DriverManager freezes new inventory generations when ACPI crashes,
    /// restarts, or fails initialization (`detail=1` when no HPCI roots
    /// were ever published).
    AcpiGenerationFrozen = 7,
    /// PCI Manager published one immutable read-only diagnostic inventory
    /// snapshot (`detail` carries discovered function count).
    InventoryPublished = 8,
    /// DriverManager instructs PCI Manager to unmap and release its read-only
    /// ECAM windows before minting write-capable ECAM capabilities (AP-17).
    PrepareWriteUpgrade = 9,
    /// PCI Manager unmapped and released its read-only ECAM windows (AP-17).
    WriteUpgradePrepared = 10,
    /// DriverManager ends the write-capable ECAM capability burst (`detail`
    /// carries window count) (AP-17).
    WriteAuthorityComplete = 11,
    /// PCI Manager mapped write-capable config authority and verified B.4
    /// write policy (`detail` carries window count) (AP-17).
    WriteAuthorityReady = 12,
    /// PCI Manager completed H.3 manifest driver binding and Stage I narrow
    /// lease-bound resource minting (`detail` carries bound device count) (AP-21).
    DriverBindingPublished = 13,
}

impl Opcode {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Hello),
            2 => Some(Self::Ready),
            3 => Some(Self::Heartbeat),
            4 => Some(Self::RootTableAccepted),
            5 => Some(Self::RootTableRejected),
            6 => Some(Self::AuthorityComplete),
            7 => Some(Self::AcpiGenerationFrozen),
            8 => Some(Self::InventoryPublished),
            9 => Some(Self::PrepareWriteUpgrade),
            10 => Some(Self::WriteUpgradePrepared),
            11 => Some(Self::WriteAuthorityComplete),
            12 => Some(Self::WriteAuthorityReady),
            13 => Some(Self::DriverBindingPublished),
            _ => None,
        }
    }
}

/// Manager status carried by a control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Status {
    /// Operation completed normally.
    Ok = 0,
    /// Manager is alive but has no root descriptors/config authority; every
    /// physical PCI operation remains disabled.
    NoRootsFailClosed = 1,
    /// Bootstrap/control bytes were malformed.
    InvalidMessage = -1,
    /// Root descriptor table was rejected.
    InvalidRootTable = -2,
    /// Manager completed fail-closed bootstrap **and** accepted the
    /// read-only config authority handoff (HMCF decoded, ECAM
    /// capabilities received and mapped read-only). Distinguished
    /// from [`Status::NoRootsFailClosed`] so supervisors can record
    /// the upgrade; every PCI configuration read still requires the
    /// AP-10 mediation protocol.
    ConfigAuthorityReady = 2,
    /// Diagnostic inventory was built without complete validated ACPI
    /// roots/apertures (`FirmwareResourcesUnavailable`).
    FirmwareResourcesUnavailable = 3,
    /// Manager upgraded to write-capable configuration authority under
    /// `huesos-pci::write_policy` enforcement (AP-17).
    WriteAuthorityReady = 4,
}

impl Status {
    fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::NoRootsFailClosed),
            -1 => Some(Self::InvalidMessage),
            -2 => Some(Self::InvalidRootTable),
            2 => Some(Self::ConfigAuthorityReady),
            3 => Some(Self::FirmwareResourcesUnavailable),
            4 => Some(Self::WriteAuthorityReady),
            _ => None,
        }
    }
}

/// Decoded fixed control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    /// Operation.
    pub opcode: Opcode,
    /// Non-zero process incarnation selected by DriverManager.
    pub manager_generation: u64,
    /// Status.
    pub status: Status,
    /// Operation-specific bounded detail (for example root count).
    pub detail: u32,
}

impl Message {
    /// Supervisor hello for one manager process incarnation.
    pub const fn hello(manager_generation: u64) -> Self {
        Self::hello_with_flags(manager_generation, 0)
    }

    /// Hello with explicit configuration override flags (`HELLO_FLAGS_V1`).
    pub const fn hello_with_flags(manager_generation: u64, flags: u32) -> Self {
        Self {
            opcode: Opcode::Hello,
            manager_generation,
            status: Status::Ok,
            detail: flags,
        }
    }

    /// Fail-closed ready response used before live roots are wired.
    pub const fn ready_without_roots(manager_generation: u64) -> Self {
        Self {
            opcode: Opcode::Ready,
            manager_generation,
            status: Status::NoRootsFailClosed,
            detail: 0,
        }
    }

    /// Ready response sent after the read-only config authority
    /// handoff validated: `window_count` ECAM capabilities are mapped
    /// read-only. PCI configuration reads remain mediation-only.
    pub const fn ready_config_authority(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::Ready,
            manager_generation,
            status: Status::ConfigAuthorityReady,
            detail: window_count,
        }
    }

    /// End-of-authority-burst sentinel; `window_count` ECAM
    /// capabilities (`0` = none, stay fail-closed).
    pub const fn authority_complete(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::AuthorityComplete,
            manager_generation,
            status: Status::Ok,
            detail: window_count,
        }
    }

    /// Notify PCI Manager to freeze new inventory generations while preserving
    /// its last-good diagnostic snapshot.
    pub const fn acpi_generation_frozen(manager_generation: u64, no_hpci: bool) -> Self {
        Self {
            opcode: Opcode::AcpiGenerationFrozen,
            manager_generation,
            status: if no_hpci {
                Status::FirmwareResourcesUnavailable
            } else {
                Status::Ok
            },
            detail: if no_hpci { 1 } else { 0 },
        }
    }

    /// Report that diagnostic read-only PCI inventory was published.
    pub const fn inventory_published(
        manager_generation: u64,
        function_count: u32,
        resources_available: bool,
    ) -> Self {
        Self {
            opcode: Opcode::InventoryPublished,
            manager_generation,
            status: if resources_available {
                Status::Ok
            } else {
                Status::FirmwareResourcesUnavailable
            },
            detail: function_count,
        }
    }

    /// Ask PCI Manager to unmap and drop its read-only ECAM windows before
    /// minting write-capable ECAM capabilities (AP-17).
    pub const fn prepare_write_upgrade(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::PrepareWriteUpgrade,
            manager_generation,
            status: Status::Ok,
            detail: window_count,
        }
    }

    /// Acknowledge that read-only ECAM windows have been unmapped and dropped.
    pub const fn write_upgrade_prepared(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::WriteUpgradePrepared,
            manager_generation,
            status: Status::Ok,
            detail: window_count,
        }
    }

    /// End-of-write-upgrade-burst sentinel (`window_count` RW ECAM capabilities,
    /// or `1` for already-RW legacy CF8/CFC).
    pub const fn write_authority_complete(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::WriteAuthorityComplete,
            manager_generation,
            status: Status::Ok,
            detail: window_count,
        }
    }

    /// Report that H.3 driver binding and Stage I narrow resource minting completed.
    pub const fn driver_binding_published(manager_generation: u64, bound_count: u32) -> Self {
        Self {
            opcode: Opcode::DriverBindingPublished,
            manager_generation,
            status: Status::Ok,
            detail: bound_count,
        }
    }

    /// Report that write-capable configuration authority is active under B.4
    /// write policy (`window_count` windows).
    pub const fn write_authority_ready(manager_generation: u64, window_count: u32) -> Self {
        Self {
            opcode: Opcode::WriteAuthorityReady,
            manager_generation,
            status: Status::WriteAuthorityReady,
            detail: window_count,
        }
    }
}

/// Bounded linear-backoff state for one restartable manager service.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RestartBackoff {
    failures: u8,
    deadline: u64,
}

impl RestartBackoff {
    /// Empty state; the first launch is immediately allowed.
    pub const fn new() -> Self {
        Self {
            failures: 0,
            deadline: 0,
        }
    }

    /// Consecutive failed incarnations.
    pub const fn failures(self) -> u8 {
        self.failures
    }

    /// Earliest monotonic tick at which another attempt may start.
    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// Whether another launch is admitted now.
    pub const fn can_attempt(self, now: u64, max_attempts: u8) -> bool {
        self.failures < max_attempts && now >= self.deadline
    }

    /// Record one failure. Returns whether another attempt remains.
    pub fn record_failure(&mut self, now: u64, max_attempts: u8, base_delay: u64) -> bool {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= max_attempts {
            self.deadline = u64::MAX;
            return false;
        }
        self.deadline = now.saturating_add(base_delay.saturating_mul(u64::from(self.failures)));
        true
    }

    /// Permanently exhaust this policy instance.
    pub fn exhaust(&mut self) {
        self.failures = u8::MAX;
        self.deadline = u64::MAX;
    }

    /// A ready incarnation resets the consecutive-failure budget.
    pub fn record_ready(&mut self) {
        self.failures = 0;
        self.deadline = 0;
    }
}

/// Encode one control message.
pub fn encode(message: Message, out: &mut [u8]) -> Option<usize> {
    if out.len() < MESSAGE_BYTES
        || message.manager_generation == 0
        || (message.opcode == Opcode::Hello && message.detail & !HELLO_FLAGS_V1 != 0)
    {
        return None;
    }
    out[..MESSAGE_BYTES].fill(0);
    write_u32(out, 0, MAGIC)?;
    write_u16(out, 4, VERSION)?;
    write_u16(out, 6, message.opcode as u16)?;
    write_u64(out, 8, message.manager_generation)?;
    write_i32(out, 16, message.status as i32)?;
    write_u32(out, 20, message.detail)?;
    Some(MESSAGE_BYTES)
}

/// Decode and validate one exact control message.
pub fn decode(bytes: &[u8]) -> Option<Message> {
    if bytes.len() != MESSAGE_BYTES
        || read_u32(bytes, 0)? != MAGIC
        || read_u16(bytes, 4)? != VERSION
    {
        return None;
    }
    let opcode = Opcode::from_raw(read_u16(bytes, 6)?)?;
    let manager_generation = read_u64(bytes, 8)?;
    let status = Status::from_raw(read_i32(bytes, 16)?)?;
    let detail = read_u32(bytes, 20)?;
    if manager_generation == 0 || (opcode == Opcode::Hello && detail & !HELLO_FLAGS_V1 != 0) {
        return None;
    }
    Some(Message {
        opcode,
        manager_generation,
        status,
        detail,
    })
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) -> Option<()> {
    out.get_mut(offset..offset + 2)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) -> Option<()> {
    out.get_mut(offset..offset + 4)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_i32(out: &mut [u8], offset: usize, value: i32) -> Option<()> {
    out.get_mut(offset..offset + 4)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) -> Option<()> {
    out.get_mut(offset..offset + 8)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let value = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_rejects_unknown_flags() {
        let mut bytes = [0u8; MESSAGE_BYTES];
        assert!(encode(Message::hello_with_flags(7, 1 << 4), &mut bytes).is_none());
        let mut raw = [0u8; MESSAGE_BYTES];
        assert!(encode(Message::hello(7), &mut raw).is_some());
        raw[20] = 0x10; // poke an unknown flag bit into detail
        assert_eq!(decode(&raw), None);
        assert!(decode(&encode_or_fail(Message::hello_with_flags(
            7,
            HELLO_FLAG_FORCE_LEGACY
        )))
        .is_some());
    }

    fn encode_or_fail(message: Message) -> [u8; MESSAGE_BYTES] {
        let mut bytes = [0u8; MESSAGE_BYTES];
        assert!(encode(message, &mut bytes).is_some());
        bytes
    }

    #[test]
    fn hello_and_fail_closed_ready_round_trip() {
        for message in [
            Message::hello(7),
            Message::ready_without_roots(7),
            Message::ready_config_authority(7, 2),
            Message::authority_complete(7, 2),
            Message::authority_complete(7, 0),
            Message::hello_with_flags(7, HELLO_FLAG_FORCE_LEGACY),
        ] {
            let mut bytes = [0u8; MESSAGE_BYTES];
            let Some(length) = encode(message, &mut bytes) else {
                assert!(false, "valid message should encode");
                return;
            };
            assert_eq!(length, MESSAGE_BYTES);
            assert_eq!(decode(&bytes), Some(message));
        }
    }

    #[test]
    fn rejects_zero_generation_unknown_values_and_wrong_length() {
        let mut bytes = [0u8; MESSAGE_BYTES];
        assert_eq!(encode(Message::hello(0), &mut bytes), None);
        assert_eq!(decode(&bytes[..MESSAGE_BYTES - 1]), None);

        let Some(_) = encode(Message::hello(1), &mut bytes) else {
            assert!(false, "hello should encode");
            return;
        };
        bytes[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode(&bytes), None);

        let Some(_) = encode(Message::hello(1), &mut bytes) else {
            assert!(false, "hello should encode");
            return;
        };
        bytes[16..20].copy_from_slice(&123i32.to_le_bytes());
        assert_eq!(decode(&bytes), None);
    }

    #[test]
    fn rejects_small_output_without_partial_success() {
        let mut bytes = [0xa5u8; MESSAGE_BYTES - 1];
        assert_eq!(encode(Message::hello(1), &mut bytes), None);
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn restart_backoff_is_bounded_linear_and_resettable() {
        let mut state = RestartBackoff::new();
        assert!(state.can_attempt(0, 3));
        assert!(state.record_failure(10, 3, 100));
        assert_eq!(state.failures(), 1);
        assert_eq!(state.deadline(), 110);
        assert!(!state.can_attempt(109, 3));
        assert!(state.can_attempt(110, 3));
        assert!(state.record_failure(110, 3, 100));
        assert_eq!(state.deadline(), 310);
        assert!(!state.record_failure(310, 3, 100));
        assert_eq!(state.deadline(), u64::MAX);
        assert!(!state.can_attempt(u64::MAX, 3));
        state.record_ready();
        assert_eq!(state, RestartBackoff::new());
    }

    #[test]
    fn restart_backoff_saturates_and_can_fail_closed_permanently() {
        let mut state = RestartBackoff::new();
        assert!(state.record_failure(u64::MAX - 5, 2, 100));
        assert_eq!(state.deadline(), u64::MAX);
        state.exhaust();
        assert_eq!(state.failures(), u8::MAX);
        assert!(!state.can_attempt(u64::MAX, u8::MAX));
    }

    #[test]
    fn ap16_inventory_and_freeze_messages_round_trip() {
        for msg in [
            Message::acpi_generation_frozen(4, false),
            Message::acpi_generation_frozen(4, true),
            Message::inventory_published(4, 12, true),
            Message::inventory_published(4, 3, false),
            Message::prepare_write_upgrade(4, 1),
            Message::write_upgrade_prepared(4, 1),
            Message::write_authority_complete(4, 1),
            Message::write_authority_ready(4, 1),
        ] {
            let mut bytes = [0u8; MESSAGE_BYTES];
            assert_eq!(encode(msg, &mut bytes), Some(MESSAGE_BYTES));
            assert_eq!(decode(&bytes), Some(msg));
        }
    }
}
