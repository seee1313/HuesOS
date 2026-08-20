//! Channel IPC objects.

use crate::irq_guard::IrqSafeMutex;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::wait::{self, WaitQueue};
use crate::{alloc_koid, Handle, KernelObject, Koid, ObjectType, Rights};
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

    #[expect(
        clippy::result_large_err,
        reason = "failed sends must return the owned message without allocating on the error path"
    )]
    fn enqueue(&mut self, msg: ChannelMessage) -> Result<(), ChannelSendError> {
        let bytes = msg.data_len() as u64;
        let handles = msg.handle_count() as u64;
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
        self.quota.release(Resource::Memory, msg.data_len() as u64);
        self.quota
            .release(Resource::Handles, msg.handle_count() as u64);
        Some(msg)
    }

    /// Inspect the front message without dequeueing. Returns
    /// `(byte_size, handle_count, cookie)`.
    fn peek_front(&self) -> Option<(usize, usize, u64)> {
        let msg = self.messages.front()?;
        Some((msg.data_len(), msg.handle_count(), msg.seq))
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

    /// Dequeue the front message only if its cookie matches and the caller's
    /// buffers can hold both byte payload and transferred handles. Size failures
    /// leave the message queued so the caller can retry with larger buffers.
    fn consume_if_fits(
        &mut self,
        cookie: u64,
        byte_capacity: usize,
        handle_capacity: usize,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        let Some(front) = self.messages.front() else {
            return Ok(None);
        };
        if front.seq != cookie {
            return Ok(None);
        }
        if front.data_len() > byte_capacity {
            return Err(ChannelRecvError::BytesTooSmall);
        }
        if front.handle_count() > handle_capacity {
            return Err(ChannelRecvError::HandlesTooSmall);
        }
        Ok(self.dequeue())
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

/// Maximum payload bytes stored inline in a queued channel message.
pub const CHANNEL_INLINE_BYTES: usize = 64;
/// Maximum transferred handles stored inline in a queued channel message.
pub const CHANNEL_INLINE_HANDLES: usize = 2;

const EMPTY_HANDLE: Handle = Handle::new(Koid::INVALID, Rights::DEFAULT);

/// Byte payload storage for a channel message.
pub enum ChannelMessageData {
    /// Inline storage for small control messages.
    Inline {
        /// Number of live bytes in `bytes`.
        len: usize,
        /// Inline bytes.
        bytes: [u8; CHANNEL_INLINE_BYTES],
    },
    /// Heap storage for larger messages.
    Heap(Vec<u8>),
}

impl ChannelMessageData {
    /// Build payload storage from an owned vector, inlining when possible.
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        if data.len() <= CHANNEL_INLINE_BYTES {
            let mut bytes = [0u8; CHANNEL_INLINE_BYTES];
            let len = data.len();
            bytes[..len].copy_from_slice(&data);
            clear_bytes(&mut data);
            Self::Inline { len, bytes }
        } else {
            Self::Heap(data)
        }
    }

    /// Build inline payload storage from a slice.
    pub fn inline(data: &[u8]) -> Option<Self> {
        if data.len() > CHANNEL_INLINE_BYTES {
            return None;
        }
        let mut bytes = [0u8; CHANNEL_INLINE_BYTES];
        bytes[..data.len()].copy_from_slice(data);
        Some(Self::Inline {
            len: data.len(),
            bytes,
        })
    }

    /// Payload length.
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len,
            Self::Heap(data) => data.len(),
        }
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Payload as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, bytes } => &bytes[..*len],
            Self::Heap(data) => data.as_slice(),
        }
    }

    fn clear(&mut self) {
        match self {
            Self::Inline { len, bytes } => clear_bytes(&mut bytes[..*len]),
            Self::Heap(data) => clear_bytes(data),
        }
    }
}

fn clear_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        *byte = 0;
        let _ = core::hint::black_box(*byte);
    }
}

/// Transferred-handle storage for a channel message.
pub enum ChannelMessageHandles {
    /// Inline storage for the common zero/one-handle bootstrap messages.
    Inline {
        /// Number of live handles in `handles`.
        len: usize,
        /// Inline handles.
        handles: [Handle; CHANNEL_INLINE_HANDLES],
    },
    /// Heap storage for larger handle batches.
    Heap(Vec<Handle>),
}

impl ChannelMessageHandles {
    /// Build handle storage from an owned vector, inlining when possible.
    pub fn from_vec(handles: Vec<Handle>) -> Self {
        if handles.len() <= CHANNEL_INLINE_HANDLES {
            let mut inline = [EMPTY_HANDLE; CHANNEL_INLINE_HANDLES];
            for (slot, handle) in inline.iter_mut().zip(handles.iter().copied()) {
                *slot = handle;
            }
            Self::Inline {
                len: handles.len(),
                handles: inline,
            }
        } else {
            Self::Heap(handles)
        }
    }

    /// Build inline handle storage from a slice.
    pub fn inline(handles: &[Handle]) -> Option<Self> {
        if handles.len() > CHANNEL_INLINE_HANDLES {
            return None;
        }
        let mut inline = [EMPTY_HANDLE; CHANNEL_INLINE_HANDLES];
        for (slot, handle) in inline.iter_mut().zip(handles.iter().copied()) {
            *slot = handle;
        }
        Some(Self::Inline {
            len: handles.len(),
            handles: inline,
        })
    }

    /// Number of transferred handles.
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len,
            Self::Heap(handles) => handles.len(),
        }
    }

    /// Whether no handles are carried.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Move handles out into `out`, clear this message's handle list, and
    /// return the number moved. `out` must be large enough for `self.len()`.
    pub fn take_into(&mut self, out: &mut [Handle]) -> usize {
        match self {
            Self::Inline { len, handles } => {
                let count = *len;
                out[..count].copy_from_slice(&handles[..count]);
                for handle in handles.iter_mut().take(count) {
                    *handle = EMPTY_HANDLE;
                }
                *len = 0;
                count
            }
            Self::Heap(handles) => {
                let count = handles.len();
                out[..count].copy_from_slice(handles.as_slice());
                handles.clear();
                count
            }
        }
    }

    fn close_all(&mut self) {
        match self {
            Self::Inline { len, handles } => {
                for handle in handles.iter().take(*len) {
                    crate::note_handle_close(handle.koid);
                }
                *len = 0;
            }
            Self::Heap(handles) => {
                for h in handles.drain(..) {
                    crate::note_handle_close(h.koid);
                }
            }
        }
    }
}

/// A message sent over a channel.
pub struct ChannelMessage {
    /// Opaque sequence cookie assigned at enqueue time. Used by the
    /// peek/consume protocol to identify a specific queued message.
    pub seq: u64,
    data: ChannelMessageData,
    handles: ChannelMessageHandles,
}

impl ChannelMessage {
    /// Build a message from owned buffers, inlining the common small case.
    pub fn new(data: Vec<u8>, handles: Vec<Handle>) -> Self {
        Self {
            seq: 0,
            data: ChannelMessageData::from_vec(data),
            handles: ChannelMessageHandles::from_vec(handles),
        }
    }

    /// Build a fully-inline message. Returns `None` if either slice exceeds
    /// the inline capacity.
    pub fn inline(data: &[u8], handles: &[Handle]) -> Option<Self> {
        Some(Self {
            seq: 0,
            data: ChannelMessageData::inline(data)?,
            handles: ChannelMessageHandles::inline(handles)?,
        })
    }

    /// Payload length.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Transferred-handle count.
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Payload bytes.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Move transferred handles into caller storage and clear the message list.
    pub fn take_handles_into(&mut self, out: &mut [Handle]) -> usize {
        self.handles.take_into(out)
    }
}

impl Drop for ChannelMessage {
    fn drop(&mut self) {
        // Channel payloads may contain KeyBroker replies. Clear all message
        // bytes before inline/heap storage is reused, then release in-flight
        // handle holds.
        self.data.clear();
        self.handles.close_all();
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
    #[expect(
        clippy::result_large_err,
        reason = "failed sends must return the owned message without allocating on the error path"
    )]
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
        if msg.data_len() > byte_capacity {
            return Err(ChannelRecvError::BytesTooSmall);
        }
        if msg.handle_count() > handle_capacity {
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

    /// Consume the identified message only if caller buffers can hold it.
    /// Size errors leave the message queued.
    pub fn consume_if_fits(
        &self,
        cookie: u64,
        byte_capacity: usize,
        handle_capacity: usize,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        self.inbox
            .lock()
            .consume_if_fits(cookie, byte_capacity, handle_capacity)
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
