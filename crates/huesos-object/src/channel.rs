//! Channel IPC objects.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::wait::{self, WaitQueue};
use crate::{alloc_koid, Handle, KernelObject, Koid, ObjectType};

/// Channel — one endpoint of a bidirectional IPC pipe.
///
/// A channel pair (created together via [`Channel::pair`]) shares two
/// message queues: writes on endpoint A enqueue onto the queue that
/// endpoint B reads from, and vice versa. Each endpoint keeps an `Arc` to
/// its peer's inbox so the pair keeps working even after one side's
/// `Channel` object handle is dropped independently.
pub struct Channel {
    koid: Koid,
    /// Queue this endpoint *reads from* (the peer writes into it).
    inbox: Arc<Mutex<Vec<ChannelMessage>>>,
    /// Queue this endpoint *writes to* (the peer reads from it).
    outbox: Arc<Mutex<Vec<ChannelMessage>>>,
    /// Waiters blocked in a read on this endpoint (shared with peer's
    /// `peer_readers` so `send` can wake them).
    readers: Arc<WaitQueue>,
    /// Peer's reader wait queue.
    peer_readers: Arc<WaitQueue>,
}

/// A message sent over a channel.
pub struct ChannelMessage {
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Handles transferred with the message.
    pub handles: Vec<Handle>,
}

/// Reason a channel message could not be received into caller-provided buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelRecvError {
    /// Byte buffer is too small for the next queued message.
    BytesTooSmall,
    /// Handle buffer is too small for the next queued message.
    HandlesTooSmall,
}

impl Channel {
    /// Create a connected pair of channel endpoints. Writing to one and
    /// reading from the other (or vice versa) delivers messages correctly.
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let q1 = Arc::new(Mutex::new(Vec::new()));
        let q2 = Arc::new(Mutex::new(Vec::new()));
        let readers_a = Arc::new(WaitQueue::new());
        let readers_b = Arc::new(WaitQueue::new());

        let a = Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::clone(&q1),
            outbox: Arc::clone(&q2),
            readers: Arc::clone(&readers_a),
            peer_readers: Arc::clone(&readers_b),
        });
        let b = Arc::new(Self {
            koid: alloc_koid(),
            inbox: q2,
            outbox: q1,
            readers: readers_b,
            peer_readers: readers_a,
        });
        (a, b)
    }

    /// Create a standalone channel endpoint with no peer (writes are
    /// dropped, reads always empty). Mainly useful for tests; real
    /// producers should use [`Channel::pair`].
    pub fn new() -> Arc<Self> {
        let readers = Arc::new(WaitQueue::new());
        Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::new(Mutex::new(Vec::new())),
            outbox: Arc::new(Mutex::new(Vec::new())),
            readers: Arc::clone(&readers),
            peer_readers: readers,
        })
    }

    /// Send a message to the peer endpoint (enqueued FIFO) and wake one reader.
    pub fn send(&self, msg: ChannelMessage) {
        self.outbox.lock().push(msg);
        self.peer_readers.wake_one();
    }

    /// Receive a message sent by the peer endpoint (non-blocking, FIFO).
    pub fn recv(&self) -> Option<ChannelMessage> {
        let mut q = self.inbox.lock();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    }

    /// Blocking receive: park until a message is available.
    pub fn recv_blocking(&self) -> ChannelMessage {
        loop {
            if let Some(msg) = self.recv() {
                return msg;
            }
            wait::park_on(self.readers.as_ref());
        }
    }

    /// Receive only if the caller-provided byte/handle capacities can hold
    /// the next queued message. The message remains queued on size errors.
    pub fn recv_if_fits(
        &self,
        byte_capacity: usize,
        handle_capacity: usize,
    ) -> Result<Option<ChannelMessage>, ChannelRecvError> {
        let mut q = self.inbox.lock();
        let Some(msg) = q.first() else {
            return Ok(None);
        };
        if msg.data.len() > byte_capacity {
            return Err(ChannelRecvError::BytesTooSmall);
        }
        if msg.handles.len() > handle_capacity {
            return Err(ChannelRecvError::HandlesTooSmall);
        }
        Ok(Some(q.remove(0)))
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
