//! Async BlockDevice client-side request tracking helpers.
//!
//! This module is transport-independent. A userspace client submits
//! [`AsyncBlockRequest`](crate::block_async::AsyncBlockRequest) messages over a
//! Channel and receives Port completions; the fixed table here tracks request ids
//! and validates matching completions without heap allocation.

use crate::block_async::{decode_completion_data, AsyncBlockStatus};

/// Maximum outstanding requests tracked by the first client helper.
pub const MAX_CLIENT_REQUESTS: usize = 256;

/// One live client request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientRequest {
    /// Request id echoed by the DriverHost completion.
    pub request_id: u64,
    /// Buffer slot submitted with the request.
    pub buffer_id: u32,
    /// Expected byte count for sanity checks.
    pub expected_bytes: u64,
}

/// Completion matched to a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedCompletion {
    /// Completed request.
    pub request: ClientRequest,
    /// DriverHost status.
    pub status: AsyncBlockStatus,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Raw NVMe status field.
    pub nvme_status: u16,
}

/// Failure while tracking requests/completions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTrackerError {
    /// Table full.
    Full,
    /// Request id already live.
    Duplicate,
    /// Completion references an unknown request id.
    UnknownRequest,
    /// Completion payload is malformed.
    MalformedCompletion,
}

/// Fixed-capacity request tracker.
pub struct ClientRequestTracker {
    slots: [Option<ClientRequest>; MAX_CLIENT_REQUESTS],
    next_request_id: u64,
}

impl ClientRequestTracker {
    /// Create an empty tracker.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_CLIENT_REQUESTS],
            next_request_id: 1,
        }
    }

    /// Allocate a monotonic non-zero request id.
    pub fn alloc_request_id(&mut self) -> u64 {
        let id = self.next_request_id.max(1);
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        id
    }

    /// Insert one outstanding request.
    pub fn insert(&mut self, request: ClientRequest) -> Result<(), ClientTrackerError> {
        if self
            .slots
            .iter()
            .flatten()
            .any(|live| live.request_id == request.request_id)
        {
            return Err(ClientTrackerError::Duplicate);
        }
        for slot in &mut self.slots {
            if slot.is_none() {
                *slot = Some(request);
                return Ok(());
            }
        }
        Err(ClientTrackerError::Full)
    }

    /// Match a raw Port `data` payload and remove the corresponding request.
    pub fn complete(&mut self, data: [u64; 4]) -> Result<MatchedCompletion, ClientTrackerError> {
        let (request_id, status, bytes_transferred, nvme_status) =
            decode_completion_data(data).ok_or(ClientTrackerError::MalformedCompletion)?;
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|request| request.request_id == request_id))
        else {
            return Err(ClientTrackerError::UnknownRequest);
        };
        let Some(request) = self.slots[index].take() else {
            return Err(ClientTrackerError::UnknownRequest);
        };
        Ok(MatchedCompletion {
            request,
            status,
            bytes_transferred,
            nvme_status,
        })
    }

    /// Number of live requests.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// True when no requests are live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ClientRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_async::{completion_data, AsyncBlockStatus};

    #[test]
    fn request_ids_are_nonzero_and_monotonic() {
        let mut tracker = ClientRequestTracker::new();
        assert_eq!(tracker.alloc_request_id(), 1);
        assert_eq!(tracker.alloc_request_id(), 2);
    }

    #[test]
    fn completion_matches_and_removes_request() {
        let mut tracker = ClientRequestTracker::new();
        let request = ClientRequest {
            request_id: 7,
            buffer_id: 3,
            expected_bytes: 4096,
        };
        assert_eq!(tracker.insert(request), Ok(()));
        let data = completion_data(7, AsyncBlockStatus::Ok, 4096, 0);
        let matched = tracker.complete(data);
        assert_eq!(
            matched,
            Ok(MatchedCompletion {
                request,
                status: AsyncBlockStatus::Ok,
                bytes_transferred: 4096,
                nvme_status: 0,
            })
        );
        assert!(tracker.is_empty());
    }

    #[test]
    fn rejects_duplicate_and_unknown_completion() {
        let mut tracker = ClientRequestTracker::new();
        let request = ClientRequest {
            request_id: 1,
            buffer_id: 0,
            expected_bytes: 512,
        };
        assert_eq!(tracker.insert(request), Ok(()));
        assert_eq!(tracker.insert(request), Err(ClientTrackerError::Duplicate));
        assert_eq!(
            tracker.complete(completion_data(99, AsyncBlockStatus::Ok, 0, 0)),
            Err(ClientTrackerError::UnknownRequest)
        );
    }
}
