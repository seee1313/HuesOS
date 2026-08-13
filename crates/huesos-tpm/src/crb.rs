//! TPM 2.0 CRB (Command Response Buffer) transport.
//!
//! CRB is the modern MMIO interface defined by the TCG PC Client
//! Platform TPM Profile: the driver requests locality, writes the
//! command into a shared buffer, sets `start`, polls until the TPM
//! clears it, then reads the response out of the same buffer. QEMU's
//! `tpm-crb` device implements it, which is what the swtpm-backed
//! tests drive.
//!
//! CRB rather than TIS: TIS is the older FIFO interface and needs a
//! byte-at-a-time state machine with far more polling states to get
//! right. CRB moves the data through a single mapped buffer, so the
//! part that has to be correct is the handshake, not the transfer.
//!
//! The MMIO itself lives behind the [`CrbTransport`] trait. The
//! command layer above it is then pure byte manipulation, testable on
//! the host against a simulated TPM, which is where all the
//! marshalling and bounds-checking bugs actually get caught.

use crate::{parse_response_header, response_code, ResponseHeader, HEADER_BYTES};

/// CRB register offsets from the interface base (TCG PTP, table 12).
pub mod reg {
    /// `TPM_LOC_STATE_x`: locality state, read-only.
    pub const LOC_STATE: usize = 0x0000;
    /// `TPM_LOC_CTRL_x`: locality request/relinquish.
    pub const LOC_CTRL: usize = 0x0008;
    /// `TPM_LOC_STS_x`: locality grant status.
    pub const LOC_STS: usize = 0x000C;
    /// `TPM_CRB_CTRL_REQ_x`: command ready / go idle request.
    pub const CTRL_REQ: usize = 0x0040;
    /// `TPM_CRB_CTRL_STS_x`: interface status.
    pub const CTRL_STS: usize = 0x0044;
    /// `TPM_CRB_CTRL_CANCEL_x`: cancel the current command.
    pub const CTRL_CANCEL: usize = 0x0048;
    /// `TPM_CRB_CTRL_START_x`: start command execution.
    pub const CTRL_START: usize = 0x004C;
}

/// `TPM_LOC_CTRL` bits.
pub mod loc_ctrl {
    /// Request locality.
    pub const REQUEST_ACCESS: u32 = 1 << 0;
    /// Relinquish locality.
    pub const RELINQUISH: u32 = 1 << 1;
}

/// `TPM_LOC_STS` bits.
pub mod loc_sts {
    /// Locality has been granted to the requester.
    pub const GRANTED: u32 = 1 << 0;
}

/// `TPM_CRB_CTRL_REQ` bits.
pub mod ctrl_req {
    /// Ask the TPM to enter the Ready state.
    pub const COMMAND_READY: u32 = 1 << 0;
    /// Ask the TPM to return to Idle.
    pub const GO_IDLE: u32 = 1 << 1;
}

/// `TPM_CRB_CTRL_STS` bits.
pub mod ctrl_sts {
    /// The TPM reported a fatal error; the interface must be reset.
    pub const TPM_STS_ERROR: u32 = 1 << 0;
    /// The TPM is idle.
    pub const TPM_IDLE: u32 = 1 << 1;
}

/// `TPM_CRB_CTRL_START` bit: set by the driver, cleared by the TPM
/// when the response is ready.
pub const CTRL_START_GO: u32 = 1 << 0;

/// Transport-level failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrbError {
    /// Locality was never granted.
    LocalityDenied,
    /// The TPM did not reach the Ready state in the allotted polls.
    NotReady,
    /// The TPM did not clear `start` in the allotted polls.
    ///
    /// Reported rather than waited on forever: a wedged TPM must not
    /// hang the boot path, and an encrypted volume that cannot be
    /// unsealed should fail to mount, not hang the machine.
    Timeout,
    /// The interface reported a fatal error.
    InterfaceError,
    /// The command does not fit the device's command buffer.
    CommandTooLarge,
    /// The response does not fit the caller's buffer.
    ResponseTooLarge,
}

/// Command-layer failure, covering both transport and protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpmCommandError {
    /// The transport failed.
    Transport(CrbError),
    /// The response was shorter than a TPM header.
    ShortResponse,
    /// The response header was internally inconsistent.
    MalformedResponse,
    /// The TPM returned a non-zero response code.
    Tpm(u32),
    /// A response field was outside the response body.
    TruncatedField,
    /// A caller-provided buffer was too small.
    BufferTooSmall,
    /// A parameter was out of range before anything was sent.
    InvalidArgument,
}

impl From<CrbError> for TpmCommandError {
    fn from(error: CrbError) -> Self {
        Self::Transport(error)
    }
}

/// A CRB-capable TPM.
///
/// Implementors provide register access and the command buffer; the
/// handshake sequencing lives in [`execute`], so the real driver and
/// the test double cannot drift apart in how they talk to the device.
pub trait CrbTransport {
    /// Read a 32-bit CRB register.
    fn read_reg(&self, offset: usize) -> u32;
    /// Write a 32-bit CRB register.
    fn write_reg(&mut self, offset: usize, value: u32);
    /// Copy a command into the device command buffer.
    fn write_command(&mut self, bytes: &[u8]) -> Result<(), CrbError>;
    /// Copy the response out of the device response buffer.
    fn read_response(&mut self, out: &mut [u8]) -> Result<usize, CrbError>;
    /// Advance simulated time / yield. Real hardware yields to the
    /// scheduler; the simulator uses it to run the command.
    fn poll_tick(&mut self);
}

/// How many polls each wait stage allows before giving up.
///
/// A TPM 2.0 `Create` on real hardware can take well over a second, so
/// the budget is generous -- but it is a budget. Unbounded polling in
/// the storage bring-up path turns a broken TPM into a hung boot.
pub const POLL_BUDGET: u32 = 1_000_000;

/// Acquire locality 0.
pub fn request_locality<T: CrbTransport>(transport: &mut T) -> Result<(), CrbError> {
    if transport.read_reg(reg::LOC_STS) & loc_sts::GRANTED != 0 {
        return Ok(());
    }
    transport.write_reg(reg::LOC_CTRL, loc_ctrl::REQUEST_ACCESS);
    let mut budget = POLL_BUDGET;
    while budget > 0 {
        if transport.read_reg(reg::LOC_STS) & loc_sts::GRANTED != 0 {
            return Ok(());
        }
        transport.poll_tick();
        budget -= 1;
    }
    Err(CrbError::LocalityDenied)
}

/// Release locality 0.
pub fn relinquish_locality<T: CrbTransport>(transport: &mut T) {
    transport.write_reg(reg::LOC_CTRL, loc_ctrl::RELINQUISH);
}

/// Drive one command/response exchange.
///
/// Sequence: request Ready, write the command, set `start`, poll until
/// the TPM clears it, read the response, return to Idle. The TPM's own
/// response code is *not* interpreted here -- callers that expect a
/// specific failure (a PCR policy mismatch, say) need to see it.
pub fn execute<T: CrbTransport>(
    transport: &mut T,
    command: &[u8],
    response: &mut [u8],
) -> Result<(ResponseHeader, usize), TpmCommandError> {
    if command.len() < HEADER_BYTES {
        return Err(TpmCommandError::InvalidArgument);
    }
    if transport.read_reg(reg::CTRL_STS) & ctrl_sts::TPM_STS_ERROR != 0 {
        return Err(CrbError::InterfaceError.into());
    }

    // Ask for Ready and wait for the TPM to leave Idle.
    transport.write_reg(reg::CTRL_REQ, ctrl_req::COMMAND_READY);
    let mut budget = POLL_BUDGET;
    loop {
        if transport.read_reg(reg::CTRL_STS) & ctrl_sts::TPM_IDLE == 0 {
            break;
        }
        if budget == 0 {
            return Err(CrbError::NotReady.into());
        }
        transport.poll_tick();
        budget -= 1;
    }

    transport.write_command(command)?;
    transport.write_reg(reg::CTRL_START, CTRL_START_GO);

    // The TPM clears `start` when the response is ready.
    let mut budget = POLL_BUDGET;
    loop {
        if transport.read_reg(reg::CTRL_START) & CTRL_START_GO == 0 {
            break;
        }
        if transport.read_reg(reg::CTRL_STS) & ctrl_sts::TPM_STS_ERROR != 0 {
            return Err(CrbError::InterfaceError.into());
        }
        if budget == 0 {
            // Cancel so the device is not left mid-command with the
            // next caller's Ready request racing this one.
            transport.write_reg(reg::CTRL_CANCEL, 1);
            transport.write_reg(reg::CTRL_REQ, ctrl_req::GO_IDLE);
            return Err(CrbError::Timeout.into());
        }
        transport.poll_tick();
        budget -= 1;
    }

    let read = transport.read_response(response)?;
    transport.write_reg(reg::CTRL_REQ, ctrl_req::GO_IDLE);
    let header = parse_response_header(&response[..read])?;
    Ok((header, read))
}

/// Execute and require `TPM_RC_SUCCESS`, returning the response body
/// (everything after the header).
pub fn execute_ok<'a, T: CrbTransport>(
    transport: &mut T,
    command: &[u8],
    response: &'a mut [u8],
) -> Result<&'a [u8], TpmCommandError> {
    let (header, read) = execute(transport, command, response)?;
    if header.code != response_code::SUCCESS {
        return Err(TpmCommandError::Tpm(header.code));
    }
    Ok(&response[HEADER_BYTES..read])
}
