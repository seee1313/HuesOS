//! Safe client for the dedicated ACPI ↔ PCI mediation channel (AP-10).
//!
//! The channel carries fixed-size [`huesos_abi::pci_mediation`] messages;
//! this wrapper owns one endpoint and a bounded retry/timeout budget for
//! the synchronous request/response exchange. It never names a physical
//! address and never performs any access beyond writing the request and
//! reading the response on the channel.

use crate::{Channel, ErrorCode};
use huesos_abi::pci_mediation::{self, Opcode, Request, Status, RESPONSE_BYTES};

/// Default bounded wait for one mediation round trip, in monotonic
/// ticks (10 ms per tick — 100 ms). The PCI Manager drains the
/// mediation channel on every scheduling iteration, so a healthy peer
/// answers long before this bound; the bound exists so a stuck or
/// dead peer degrades to an error instead of a hung caller.
pub const DEFAULT_TIMEOUT_TICKS: u64 = 10;

/// One endpoint of the mediation channel, with the requester's identity
/// baked in so callers cannot forge generations ad hoc.
pub struct MediationRequester {
    channel: Channel,
    acpi_generation: u64,
    pci_generation: Option<u64>,
    firmware_snapshot_id: u64,
}

impl MediationRequester {
    /// Wrap a channel end transferred by DriverManager.
    pub fn new(channel: Channel, acpi_generation: u64, firmware_snapshot_id: u64) -> Self {
        Self {
            channel,
            acpi_generation,
            pci_generation: None,
            firmware_snapshot_id,
        }
    }

    /// Record the PCI Manager generation announced by DriverManager
    /// (`pci-config-read-gen:<n>` on the bootstrap channel).
    pub fn set_pci_generation(&mut self, pci_generation: u64) {
        if pci_generation != 0 {
            self.pci_generation = Some(pci_generation);
        }
    }

    /// Whether the peer generation announcement arrived.
    pub fn pci_generation(&self) -> Option<u64> {
        self.pci_generation
    }

    /// Whether the underlying peer is gone (e.g. PCI Manager restarted).
    pub fn is_peer_closed(&self) -> bool {
        // Zero-capacity read probes liveness without consuming a message.
        matches!(
            self.channel.read_etc(&mut [], &mut []),
            Err(ErrorCode::PeerClosed)
        )
    }

    /// Mediated configuration read. `width` ∈ {1, 2, 4}.
    pub fn read(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        width: u8,
    ) -> Result<u64, AccessError> {
        self.call(
            Opcode::Read,
            segment,
            bus,
            device,
            function,
            offset,
            width,
            0,
        )
    }

    /// Mediated write attempt. Always answered [`Status::AccessDenied`]
    /// by the PCI Manager before any hardware access; provided so AML
    /// paths get an explicit denial instead of an open-coded stub.
    pub fn write_denied(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        width: u8,
    ) -> Result<(), AccessError> {
        match self.call(
            Opcode::Write,
            segment,
            bus,
            device,
            function,
            offset,
            width,
            0,
        ) {
            Err(AccessError::Denied) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(AccessError::Internal),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        opcode: Opcode,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        width: u8,
        correlation_id: u64,
    ) -> Result<u64, AccessError> {
        let pci_generation = self.pci_generation.ok_or(AccessError::NotReady)?;
        let request = match opcode {
            Opcode::Read => Request::read(
                self.acpi_generation,
                pci_generation,
                self.firmware_snapshot_id,
                segment,
                bus,
                device,
                function,
                offset,
                width,
                correlation_id,
            ),
            Opcode::Write => Request::write(
                self.acpi_generation,
                pci_generation,
                self.firmware_snapshot_id,
                segment,
                bus,
                device,
                function,
                offset,
                width,
                correlation_id,
            ),
        };
        let mut request_bytes = [0u8; pci_mediation::REQUEST_BYTES];
        let Some(length) = pci_mediation::encode_request(&request, &mut request_bytes) else {
            return Err(AccessError::Internal);
        };
        self.channel
            .write(&request_bytes[..length])
            .map_err(|_| AccessError::PeerClosed)?;

        let mut response_bytes = [0u8; RESPONSE_BYTES];
        let read = self
            .channel
            .read_into_timeout(&mut response_bytes, DEFAULT_TIMEOUT_TICKS)
            .map_err(|error| match error {
                ErrorCode::TimedOut | ErrorCode::ShouldWait => AccessError::Timeout,
                ErrorCode::PeerClosed => AccessError::PeerClosed,
                _ => AccessError::Internal,
            })?;
        let Some(response) = pci_mediation::decode_response(&response_bytes[..read]) else {
            return Err(AccessError::Internal);
        };
        if response.correlation_id != correlation_id
            || response.pci_generation != pci_generation
            || response.acpi_generation != self.acpi_generation
        {
            return Err(AccessError::StaleGeneration);
        }
        match Status::from_raw(response.status).unwrap_or(Status::InvalidRequest) {
            Status::Ok => Ok(response.value),
            Status::InvalidRequest => Err(AccessError::InvalidRequest),
            Status::AccessDenied => Err(AccessError::Denied),
            Status::NotFound => Err(AccessError::NotFound),
            Status::StaleGeneration => Err(AccessError::StaleGeneration),
            Status::SnapshotMismatch => Err(AccessError::SnapshotMismatch),
            Status::NotReady => Err(AccessError::NotReady),
        }
    }
}

/// Structured failure of one mediation round trip. Stable variants; new
/// ones may be appended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// The peer generation announcement has not arrived yet.
    NotReady,
    /// The PCI Manager is not granting configuration authority yet.
    NotAuthorized,
    /// The read timed out waiting for the peer.
    Timeout,
    /// The peer endpoint is closed.
    PeerClosed,
    /// The peer answered with a request that failed validation.
    InvalidRequest,
    /// The request was denied by policy (all writes, and any read the
    /// manager refuses).
    Denied,
    /// No window covers the requested segment:bus, or the legacy backend
    /// cannot address the (extended) offset.
    NotFound,
    /// Generations are stale for this manager incarnation.
    StaleGeneration,
    /// Snapshot identity does not match the retained `HMCF` image.
    SnapshotMismatch,
    /// A protocol invariant failed locally.
    Internal,
}

impl AccessError {
    /// Stable lowercase name for structured observations.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::NotAuthorized => "not_authorized",
            Self::Timeout => "timeout",
            Self::PeerClosed => "peer_closed",
            Self::InvalidRequest => "invalid_request",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::StaleGeneration => "stale_generation",
            Self::SnapshotMismatch => "snapshot_mismatch",
            Self::Internal => "internal",
        }
    }
}
