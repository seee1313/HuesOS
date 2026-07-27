//! Channel IPC objects.

use crate::irq_guard::IrqSafeMutex;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

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
    inbox: Arc<IrqSafeMutex<MessageQueue>>,
    /// Queue this endpoint *writes to* (the peer reads from it).
    outbox: Arc<IrqSafeMutex<MessageQueue>>,
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
    /// Monotonic sequence counter; each enqueued message receives a unique
    /// cookie (its sequence number) that [`Self::consume`] uses to dequeue
    /// the exact message a prior peek identified.
    next_seq: u64,
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
            next_seq: 0,
        })
    }

    fn enqueue(&mut self, msg: ChannelMessage) -> Result<(), ChannelSendError> {
        let bytes = msg.data.len() as u64;
        let handles = msg.handles.len() as u64;
        if self.messages.len() >= MAX_CHANNEL_QUEUE_MESSAGES
            || !self.quota.fits(Resource::Memory, bytes)
            || !self.quota.fits(Resource::Handles, handles)
        {
            return Err(ChannelSendError::new(
                msg,
                ChannelSendFailure::QuotaExceeded,
            ));
        }

        // Queue storage is preallocated during channel creation. Never grow
        // it from a send path; a capacity mismatch is a normal admission
        // failure rather than a reason to allocate or panic.
        if self.messages.capacity() <= self.messages.len() {
            return Err(ChannelSendError::new(msg, ChannelSendFailure::OutOfMemory));
        }
        let _ = self.quota.try_acquire(Resource::Memory, bytes);
        let _ = self.quota.try_acquire(Resource::Handles, handles);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let mut msg = msg;
        msg.seq = seq;
        self.messages.push_back(msg);
        Ok(())
    }

    fn dequeue(&mut self) -> Option<ChannelMessage> {
        let msg = self.messages.pop_front()?;
        self.quota.release(Resource::Memory, msg.data.len() as u64);
        self.quota
            .release(Resource::Handles, msg.handles.len() as u64);
        Some(msg)
    }

    /// Inspect the front message without dequeueing. Returns
    /// `(byte_size, handle_count, cookie)`.
    fn peek_front(&self) -> Option<(usize, usize, u64)> {
        let msg = self.messages.front()?;
        Some((msg.data.len(), msg.handles.len(), msg.seq))
    }

    /// Dequeue the front message only if its cookie matches. Returns the
    /// message on match; returns `None` if the queue is empty or the
    /// cookie does not match the front (a stale cookie from a prior peek).
    fn consume(&mut self, cookie: u64) -> Option<ChannelMessage> {
        let front = self.messages.front()?;
        if front.seq != cookie {
            return None;
        }
        self.dequeue()
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
    /// Opaque sequence cookie assigned at enqueue time. Used by the
    /// peek/consume protocol to identify a specific queued message.
    pub seq: u64,
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
        let q1 = Arc::new(IrqSafeMutex::new(MessageQueue::new()?));
        let q2 = Arc::new(IrqSafeMutex::new(MessageQueue::new()?));
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
            inbox: Arc::new(IrqSafeMutex::new(MessageQueue::new()?)),
            outbox: Arc::new(IrqSafeMutex::new(MessageQueue::new()?)),
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
            // Enqueue BEFORE checking the condition so we are visible to
            // wakers; re-check while in the queue to close the lost-wakeup
            // race between check and park.
            let prepared = self.readers.prepare().ok_or(ChannelRecvError::PeerClosed)?;
            match self.recv_status()? {
                Some(msg) => {
                    prepared.cancel();
                    return Ok(msg);
                }
                None => prepared.park(),
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
            // Prepare first so we are visible to wakers before re-checking.
            let prepared = self.readers.prepare().ok_or(ChannelRecvError::PeerClosed)?;
            if let Some(msg) = self.recv_status()? {
                prepared.cancel();
                return Ok(Some(msg));
            }
            match prepared.park_timeout(timeout_ticks) {
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
            // Enqueue BEFORE checking so we are visible to wakers.
            let prepared = self.readers.prepare().ok_or(ChannelRecvError::PeerClosed)?;
            match self.recv_if_fits(byte_capacity, handle_capacity) {
                Ok(Some(msg)) => {
                    prepared.cancel();
                    return Ok(msg);
                }
                Ok(None) => prepared.park(),
                Err(e) => {
                    prepared.cancel();
                    return Err(e);
                }
            }
        }
    }

    /// Peek at the front message without dequeueing it.
    /// Returns `(byte_size, handle_count, cookie)`.
    pub fn peek(&self) -> Result<Option<(usize, usize, u64)>, ChannelRecvError> {
        let q = self.inbox.lock();
        if let Some(info) = q.peek_front() {
            return Ok(Some(info));
        }
        if !self.peer_alive.load(Ordering::Acquire) {
            return Err(ChannelRecvError::PeerClosed);
        }
        Ok(None)
    }

    /// Consume the message identified by `cookie` (from a prior [`peek`]).
    /// Returns `None` if the cookie is stale (the front message has changed
    /// since the peek) or the queue is empty.
    pub fn consume(&self, cookie: u64) -> Option<ChannelMessage> {
        self.inbox.lock().consume(cookie)
    }

    /// Reference to the reader wait queue, for syscall-level blocking peek.
    pub fn reader_queue(&self) -> &WaitQueue {
        self.readers.as_ref()
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

// ---------------------------------------------------------------------------
// Async Recv future (peek & claim protocol)
// ---------------------------------------------------------------------------

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A zero-alloc, stack-pinned future that awaits a message on a [`Channel`].
///
/// Uses the **peek & claim** protocol: [`Channel::peek`] inspects the front
/// message (size, handle count, cookie) without dequeueing; [`Channel::consume`]
/// dequeues only the identified message by cookie. This avoids reading into
/// an arbitrary user buffer as the async essence.
///
/// On each Pending return, the future registers its waker via the
/// [`WaitQueue::register_waker`] bridge. When a sender enqueues a message,
/// `wake_one` fires the waker, the executor re-polls, and the future
/// finds the message.
pub struct Recv<'a> {
    channel: &'a Channel,
}

impl<'a> Recv<'a> {
    /// Create a new Recv future for the given channel.
    pub fn new(channel: &'a Channel) -> Self {
        Self { channel }
    }
}

impl<'a> Future for Recv<'a> {
    type Output = Result<ChannelMessage, ChannelRecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.channel.peek() {
            Ok(Some((_size, _handles, cookie))) => {
                // Peek found a message. Consume by cookie (peek & claim).
                match self.channel.consume(cookie) {
                    Some(msg) => Poll::Ready(Ok(msg)),
                    // Cookie stale (queue moved between peek and consume).
                    // Re-poll immediately.
                    None => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Ok(None) => {
                // No message yet. Register waker for the next arrival.
                self.channel.reader_queue().register_waker(cx.waker());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Extension trait: async methods on [`Channel`].
pub trait ChannelAsyncExt {
    /// Await a message on this channel.
    fn recv_async(&self) -> Recv<'_>;
}

impl ChannelAsyncExt for Channel {
    fn recv_async(&self) -> Recv<'_> {
        Recv::new(self)
    }
}
