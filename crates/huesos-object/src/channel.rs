//! Channel IPC objects.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::wait::{self, WaitQueue};
use crate::{alloc_koid, Handle, KernelObject, Koid, ObjectType};
use huesos_quota::{Limits, Quota, Resource, UNLIMITED};

/// Maximum number of messages retained in one channel inbox.
pub const MAX_CHANNEL_QUEUE_MESSAGES: usize = 256;
/// Maximum aggregate byte payload retained in one channel inbox.
pub const MAX_CHANNEL_QUEUE_BYTES: u64 = 1024 * 1024;
/// Maximum aggregate transferred handles retained in one channel inbox.
pub const MAX_CHANNEL_QUEUE_HANDLES: u64 = 256;

/// A channel pair (created together via [`Channel::pair`]) shares two
/// bounded message queues: writes on endpoint A enqueue onto the queue that
/// endpoint B reads from, and vice versa. Each endpoint keeps an `Arc` to its
/// peer's inbox so the pair keeps working even after one side's `Channel`
/// object handle is dropped independently.
pub struct Channel {
    koid: Koid,
    /// Queue this endpoint *reads from* (the peer writes into it).
    inbox: Arc<Mutex<MessageQueue>>,
    /// Queue this endpoint *writes to* (the peer reads from it).
    outbox: Arc<Mutex<MessageQueue>>,
    /// Waiters blocked in a read on this endpoint (shared with peer's
    /// `peer_readers` so `send` can wake them).
    readers: Arc<WaitQueue>,
    /// Peer's reader wait queue.
    peer_readers: Arc<WaitQueue>,
    /// Liveness of this endpoint.
    local_alive: Arc<AtomicBool>,
    /// Liveness of the peer endpoint.
    peer_alive: Arc<AtomicBool>,
}

struct MessageQueue {
    messages: VecDeque<ChannelMessage>,
    quota: Quota,
}

impl MessageQueue {
    fn new() -> Result<Self, ChannelCreateError> {
        let mut messages = VecDeque::new();
        messages
            .try_reserve_exact(MAX_CHANNEL_QUEUE_MESSAGES)
            .map_err(|_| ChannelCreateError::OutOfMemory)?;
        Ok(Self {
            messages,
            quota: Quota::new(Limits {
                max_memory: MAX_CHANNEL_QUEUE_BYTES,
                max_handles: MAX_CHANNEL_QUEUE_HANDLES,
                max_cpu_ticks: UNLIMITED,
            }),
        })
    }

    fn enqueue(&mut self, msg: ChannelMessage) -> Result<(), ChannelSendError> {
        let bytes = msg.data.len() as u64;
        let handles = msg.handles.len() as u64;
        if self.messages.len() >= MAX_CHANNEL_QUEUE_MESSAGES
            || !self.quota.fits(Resource::Memory, bytes)
            || !self.quota.fits(Resource::Handles, handles)
        {
            return Err(ChannelSendError::new(msg, ChannelSendFailure::QuotaExceeded));
        }

        // Queue storage is preallocated during channel creation. Never grow
        // it from a send path; a capacity mismatch is a normal admission
        // failure rather than a reason to allocate or panic.
        if self.messages.capacity() <= self.messages.len() {
            return Err(ChannelSendError::new(msg, ChannelSendFailure::OutOfMemory));
        }
        let _ = self.quota.try_acquire(Resource::Memory, bytes);
        let _ = self.quota.try_acquire(Resource::Handles, handles);
        self.messages.push_back(msg);
        Ok(())
    }

    fn dequeue(&mut self) -> Option<ChannelMessage> {
        let msg = self.messages.pop_front()?;
        self.quota
            .release(Resource::Memory, msg.data.len() as u64);
        self.quota
            .release(Resource::Handles, msg.handles.len() as u64);
        Some(msg)
    }
}

/// Failure returned when a channel message cannot be admitted to its bounded
/// peer queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelSendFailure {
    /// The queue's message, byte, or transferred-handle quota is exhausted.
    QuotaExceeded,
    /// The queue could not reserve its bounded slot.
    OutOfMemory,
    /// The peer endpoint was closed before the send linearized.
    PeerClosed,
}

/// A failed send together with the untouched message, allowing the syscall
/// layer to restore moved handles transactionally.
pub struct ChannelSendError {
    message: ChannelMessage,
    reason: ChannelSendFailure,
}

impl ChannelSendError {
    fn new(message: ChannelMessage, reason: ChannelSendFailure) -> Self {
        Self { message, reason }
    }

    /// Split the failure into its reason and original message.
    pub fn into_parts(self) -> (ChannelMessage, ChannelSendFailure) {
        (self.message, self.reason)
    }
}

/// A message sent over a channel.
pub struct ChannelMessage {
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Handles transferred with the message.
    pub handles: Vec<Handle>,
}

impl Drop for ChannelMessage {
    fn drop(&mut self) {
        // If the message is discarded (peer closed, buffer dropped), release
        // the handle-count holds that kept objects alive in flight.
        for h in self.handles.drain(..) {
            crate::note_handle_close(h.koid);
        }
    }
}

/// Reason a channel message could not be received into caller-provided buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelRecvError {
    /// Byte buffer is too small for the next queued message.
    BytesTooSmall,
    /// Handle buffer is too small for the next queued message.
    HandlesTooSmall,
    /// The peer endpoint is closed and the queue is empty.
    PeerClosed,
}

/// Failure while allocating the bounded channel queues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelCreateError {
    /// The fixed queue storage could not be allocated.
    OutOfMemory,
}

impl Channel {
    /// Create a connected pair of channel endpoints. Writing to one and
    /// reading from the other (or vice versa) delivers messages correctly.
    pub fn pair() -> Result<(Arc<Self>, Arc<Self>), ChannelCreateError> {
        let q1 = Arc::new(Mutex::new(MessageQueue::new()?));
        let q2 = Arc::new(Mutex::new(MessageQueue::new()?));
        let readers_a = Arc::new(WaitQueue::new());
        let readers_b = Arc::new(WaitQueue::new());
        let alive_a = Arc::new(AtomicBool::new(true));
        let alive_b = Arc::new(AtomicBool::new(true));

        let a = Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::clone(&q1),
            outbox: Arc::clone(&q2),
            readers: Arc::clone(&readers_a),
            peer_readers: Arc::clone(&readers_b),
            local_alive: Arc::clone(&alive_a),
            peer_alive: Arc::clone(&alive_b),
        });
        let b = Arc::new(Self {
            koid: alloc_koid(),
            inbox: q2,
            outbox: q1,
            readers: readers_b,
            peer_readers: readers_a,
            local_alive: alive_b,
            peer_alive: alive_a,
        });
        Ok((a, b))
    }

    /// Create a standalone channel endpoint with no peer. Sends fail with
    /// [`ChannelSendFailure::PeerClosed`]; real producers should use
    /// [`Channel::pair`]. Mainly useful for tests.
    pub fn new() -> Result<Arc<Self>, ChannelCreateError> {
        let readers = Arc::new(WaitQueue::new());
        Ok(Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::new(Mutex::new(MessageQueue::new()?)),
            outbox: Arc::new(Mutex::new(MessageQueue::new()?)),
            readers: Arc::clone(&readers),
            peer_readers: readers,
            local_alive: Arc::new(AtomicBool::new(true)),
            peer_alive: Arc::new(AtomicBool::new(false)),
        }))
    }

    /// Send a message to the peer endpoint (enqueued FIFO) and wake one reader.
    /// The message is returned unchanged on failure.
    pub fn send(&self, msg: ChannelMessage) -> Result<(), ChannelSendError> {
        // The atomic check is the send/close linearization point. A close that
        // happens after this check is ordered after the send and may discard
        // the unread message, which is the normal endpoint-close semantics.
        if !self.peer_alive.load(Ordering::Acquire) {
            return Err(ChannelSendError::new(msg, ChannelSendFailure::PeerClosed));
        }
        let mut outbox = self.outbox.lock();
        match outbox.enqueue(msg) {
            Ok(()) => {
                drop(outbox);
                self.peer_readers.wake_one();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Whether the peer endpoint has been closed.
    pub fn peer_closed(&self) -> bool {
        !self.peer_alive.load(Ordering::Acquire)
    }

    /// Receive a message, distinguishing an empty live queue from a closed
    /// peer.
    pub fn recv_status(&self) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        if let Some(msg) = self.inbox.lock().dequeue() {
            return Ok(Some(msg));
        }
        if self.peer_closed() {
            Err(ChannelRecvError::PeerClosed)
        } else {
            Ok(None)
        }
    }

    /// Receive a message sent by the peer endpoint (non-blocking, FIFO).
    /// This compatibility helper hides peer closure; syscall paths use
    /// [`Self::recv_status`] so closure is observable at the ABI.
    pub fn recv(&self) -> Option<ChannelMessage> {
        self.recv_status().ok().flatten()
    }

    /// Blocking receive with peer-close reporting.
    pub fn recv_blocking_status(&self) -> Result<ChannelMessage, ChannelRecvError> {
        loop {
            match self.recv_status()? {
                Some(msg) => return Ok(msg),
                None => wait::park_on(self.readers.as_ref()),
            }
        }
    }

    /// Blocking receive: park until a message is available or the peer closes.
    pub fn recv_blocking(&self) -> Result<ChannelMessage, ChannelRecvError> {
        self.recv_blocking_status()
    }

    /// Blocking receive with timeout and peer-close reporting.
    pub fn recv_blocking_timeout_status(
        &self,
        timeout_ticks: u64,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        use wait::ParkResult;
        if timeout_ticks == 0 {
            return self.recv_blocking_status().map(Some);
        }
        loop {
            if let Some(msg) = self.recv_status()? {
                return Ok(Some(msg));
            }
            match wait::park_on_timeout(self.readers.as_ref(), timeout_ticks) {
                ParkResult::Woken => continue,
                ParkResult::TimedOut => return self.recv_status(),
            }
        }
    }

    /// Blocking receive with timeout in scheduler ticks (`0` = forever).
    /// Returns `None` if the timeout expires, and reports peer closure.
    pub fn recv_blocking_timeout(
        &self,
        timeout_ticks: u64,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        self.recv_blocking_timeout_status(timeout_ticks)
    }

    /// Receive only if the caller-provided byte/handle capacities can hold
    /// the next queued message. The message remains queued on size errors.
    pub fn recv_if_fits(
        &self,
        byte_capacity: usize,
        handle_capacity: usize,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        let mut q = self.inbox.lock();
        let Some(msg) = q.messages.front() else {
            return if self.peer_closed() {
                Err(ChannelRecvError::PeerClosed)
            } else {
                Ok(None)
            };
        };
        if msg.data.len() > byte_capacity {
            return Err(ChannelRecvError::BytesTooSmall);
        }
        if msg.handles.len() > handle_capacity {
            return Err(ChannelRecvError::HandlesTooSmall);
        }
        Ok(q.dequeue())
    }

    /// Blocking variant of [`Self::recv_if_fits`].
    pub fn recv_if_fits_blocking(
        &self,
        byte_capacity: usize,
        handle_capacity: usize,
    ) -> Result<ChannelMessage, ChannelRecvError> {
        loop {
            match self.recv_if_fits(byte_capacity, handle_capacity) {
                Ok(Some(msg)) => return Ok(msg),
                Ok(None) => wait::park_on(self.readers.as_ref()),
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.local_alive.store(false, Ordering::Release);
        // Wake readers so a blocking syscall can observe PeerClosed instead of
        // sleeping forever after the last endpoint disappears.
        self.peer_readers.wake_all();
    }
}

impl KernelObject for Channel {
    fn object_type(&self) -> ObjectType {
        ObjectType::Channel
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
