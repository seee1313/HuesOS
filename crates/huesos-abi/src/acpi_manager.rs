//! Generation-safe ACPI Manager lifecycle and supervision protocol.

/// Wire magic: ASCII `HACM` in little endian.
pub const MAGIC: u32 = 0x4d43_4148;
/// Current append-only protocol version.
pub const VERSION: u16 = 1;
/// Fixed control message bytes.
pub const MESSAGE_BYTES: usize = 24;
/// DriverManager transfers the immutable archive with this label.
pub const TABLES_VMO_LABEL: &[u8] = b"acpi-tables-vmo";
/// DriverManager transfers the deny-by-default broker with this label.
pub const BROKER_LABEL: &[u8] = b"acpi-broker";
/// DriverManager transfers the child process's own root VMAR with this label.
pub const SELF_VMAR_LABEL: &[u8] = b"acpi-self-vmar";
/// Test-only hello detail: generation one exits before readiness.
pub const HELLO_FLAG_INJECT_PRE_READY_EXIT: u32 = 1 << 0;
/// All hello flags known by version 1.
pub const HELLO_FLAGS_V1: u32 = HELLO_FLAG_INJECT_PRE_READY_EXIT;

/// Lifecycle control operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Opcode {
    /// DriverManager starts one process generation.
    Hello = 1,
    /// ACPI Manager accepted archive, broker, and self-VMAR capabilities.
    Ready = 2,
    /// Periodic liveness marker.
    Heartbeat = 3,
    /// Manager reports a structured bootstrap/runtime failure.
    Failed = 4,
}

impl Opcode {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Hello),
            2 => Some(Self::Ready),
            3 => Some(Self::Heartbeat),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Status {
    /// Operation completed normally.
    Ok = 0,
    /// Archive, broker, and mapping authority are validated and retained.
    ArchiveBrokerReady = 1,
    /// Message bytes or generation were invalid.
    InvalidMessage = -1,
    /// Archive validation failed.
    InvalidArchive = -2,
    /// Broker self-test failed.
    BrokerDenied = -3,
    /// One mandatory capability was absent or malformed.
    MissingCapability = -4,
}

impl Status {
    fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::ArchiveBrokerReady),
            -1 => Some(Self::InvalidMessage),
            -2 => Some(Self::InvalidArchive),
            -3 => Some(Self::BrokerDenied),
            -4 => Some(Self::MissingCapability),
            _ => None,
        }
    }
}

/// One fixed lifecycle message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    /// Control operation.
    pub opcode: Opcode,
    /// Non-zero process incarnation selected by DriverManager.
    pub manager_generation: u64,
    /// Operation status.
    pub status: Status,
    /// Operation detail: hello flags, table count, or failure code.
    pub detail: u32,
}

impl Message {
    /// Construct a supervisor hello.
    pub const fn hello(manager_generation: u64, flags: u32) -> Self {
        Self {
            opcode: Opcode::Hello,
            manager_generation,
            status: Status::Ok,
            detail: flags,
        }
    }

    /// Construct readiness after archive/broker validation.
    pub const fn ready(manager_generation: u64, table_count: u32) -> Self {
        Self {
            opcode: Opcode::Ready,
            manager_generation,
            status: Status::ArchiveBrokerReady,
            detail: table_count,
        }
    }
}

/// Bounded linear restart-backoff state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RestartBackoff {
    failures: u8,
    deadline: u64,
}

impl RestartBackoff {
    /// Empty state; immediate first launch.
    pub const fn new() -> Self {
        Self {
            failures: 0,
            deadline: 0,
        }
    }

    /// Consecutive failed generations.
    pub const fn failures(self) -> u8 {
        self.failures
    }

    /// Earliest monotonic tick for another attempt.
    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// Whether a launch is admitted now.
    pub const fn can_attempt(self, now: u64, max_attempts: u8) -> bool {
        self.failures < max_attempts && now >= self.deadline
    }

    /// Record one failed generation and return whether a retry remains.
    pub fn record_failure(&mut self, now: u64, max_attempts: u8, base_delay: u64) -> bool {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= max_attempts {
            self.deadline = u64::MAX;
            return false;
        }
        self.deadline = now.saturating_add(base_delay.saturating_mul(u64::from(self.failures)));
        true
    }

    /// Reset consecutive failure state after readiness.
    pub fn record_ready(&mut self) {
        self.failures = 0;
        self.deadline = 0;
    }

    /// Permanently exhaust this instance.
    pub fn exhaust(&mut self) {
        self.failures = u8::MAX;
        self.deadline = u64::MAX;
    }
}

/// Availability/freeze policy independent from process and IPC mechanisms.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AvailabilityPolicy {
    runtime_ready: bool,
    last_good_snapshot: bool,
    frozen: bool,
}

impl AvailabilityPolicy {
    /// Initial fail-closed state.
    pub const fn new() -> Self {
        Self {
            runtime_ready: false,
            last_good_snapshot: false,
            frozen: true,
        }
    }

    /// Record runtime readiness. New lifecycle work remains blocked until a
    /// future HMCF/HPCI stage records one validated snapshot.
    pub fn record_runtime_ready(&mut self) {
        self.runtime_ready = true;
        self.frozen = !self.last_good_snapshot;
    }

    /// Record publication of a validated last-good firmware snapshot.
    pub fn record_snapshot(&mut self) {
        self.last_good_snapshot = true;
        self.frozen = !self.runtime_ready;
    }

    /// Freeze new lifecycle work after runtime failure while retaining data.
    pub fn record_runtime_failure(&mut self) {
        self.runtime_ready = false;
        self.frozen = true;
    }

    /// Existing non-ACPI-dependent devices may use last-good data.
    pub const fn existing_devices_may_continue(self) -> bool {
        self.last_good_snapshot
    }

    /// New leases/topology/hotplug require both a ready runtime and snapshot.
    pub const fn new_lifecycle_allowed(self) -> bool {
        self.runtime_ready && self.last_good_snapshot && !self.frozen
    }

    /// Whether the system is explicitly frozen for new lifecycle operations.
    pub const fn frozen(self) -> bool {
        self.frozen
    }
}

/// Encode one exact control message.
pub fn encode(message: Message, output: &mut [u8]) -> Option<usize> {
    if output.len() < MESSAGE_BYTES
        || message.manager_generation == 0
        || (message.opcode == Opcode::Hello && message.detail & !HELLO_FLAGS_V1 != 0)
    {
        return None;
    }
    output[..MESSAGE_BYTES].fill(0);
    output[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&(message.opcode as u16).to_le_bytes());
    output[8..16].copy_from_slice(&message.manager_generation.to_le_bytes());
    output[16..20].copy_from_slice(&(message.status as i32).to_le_bytes());
    output[20..24].copy_from_slice(&message.detail.to_le_bytes());
    Some(MESSAGE_BYTES)
}

/// Decode one exact control message.
pub fn decode(bytes: &[u8]) -> Option<Message> {
    if bytes.len() != MESSAGE_BYTES || u32_at(bytes, 0)? != MAGIC || u16_at(bytes, 4)? != VERSION {
        return None;
    }
    let opcode = Opcode::from_raw(u16_at(bytes, 6)?)?;
    let manager_generation = u64_at(bytes, 8)?;
    let status = Status::from_raw(i32_at(bytes, 16)?)?;
    let detail = u32_at(bytes, 20)?;
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

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let value = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_messages_round_trip_and_reject_stale_shapes() {
        for message in [Message::hello(7, 0), Message::ready(7, 12)] {
            let mut bytes = [0u8; MESSAGE_BYTES];
            assert_eq!(encode(message, &mut bytes), Some(MESSAGE_BYTES));
            assert_eq!(decode(&bytes), Some(message));
        }
        let mut bytes = [0u8; MESSAGE_BYTES];
        assert_eq!(encode(Message::hello(0, 0), &mut bytes), None);
        assert_eq!(encode(Message::hello(1, u32::MAX), &mut bytes), None);
        assert_eq!(decode(&bytes[..MESSAGE_BYTES - 1]), None);
    }

    #[test]
    fn restart_backoff_is_bounded_and_saturating() {
        let mut backoff = RestartBackoff::new();
        assert!(backoff.record_failure(10, 3, 100));
        assert_eq!(backoff.deadline(), 110);
        assert!(!backoff.can_attempt(109, 3));
        assert!(backoff.record_failure(u64::MAX - 1, 3, 100));
        assert_eq!(backoff.deadline(), u64::MAX);
        assert!(!backoff.record_failure(u64::MAX, 3, 100));
        backoff.record_ready();
        assert_eq!(backoff, RestartBackoff::new());
        backoff.exhaust();
        assert!(!backoff.can_attempt(u64::MAX, u8::MAX));
    }

    #[test]
    fn failure_freezes_new_work_but_preserves_last_good_devices() {
        let mut policy = AvailabilityPolicy::new();
        policy.record_runtime_ready();
        assert!(policy.frozen());
        policy.record_snapshot();
        assert!(policy.new_lifecycle_allowed());
        policy.record_runtime_failure();
        assert!(policy.frozen());
        assert!(policy.existing_devices_may_continue());
        assert!(!policy.new_lifecycle_allowed());
        policy.record_runtime_ready();
        assert!(policy.new_lifecycle_allowed());
    }
}
