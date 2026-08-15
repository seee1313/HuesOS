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
}

impl Opcode {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Hello),
            2 => Some(Self::Ready),
            3 => Some(Self::Heartbeat),
            4 => Some(Self::RootTableAccepted),
            5 => Some(Self::RootTableRejected),
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
}

impl Status {
    fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::NoRootsFailClosed),
            -1 => Some(Self::InvalidMessage),
            -2 => Some(Self::InvalidRootTable),
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
        Self {
            opcode: Opcode::Hello,
            manager_generation,
            status: Status::Ok,
            detail: 0,
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
    if out.len() < MESSAGE_BYTES || message.manager_generation == 0 {
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
    if manager_generation == 0 {
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
    fn hello_and_fail_closed_ready_round_trip() {
        for message in [Message::hello(7), Message::ready_without_roots(7)] {
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
}
