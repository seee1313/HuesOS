//! Channel IPC objects.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

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
}

/// A message sent over a channel.
pub struct ChannelMessage {
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Handles transferred with the message.
    pub handles: Vec<Handle>,
}

impl Channel {
    /// Create a connected pair of channel endpoints. Writing to one and
    /// reading from the other (or vice versa) delivers messages correctly.
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let q1 = Arc::new(Mutex::new(Vec::new()));
        let q2 = Arc::new(Mutex::new(Vec::new()));
        let a = Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::clone(&q1),
            outbox: Arc::clone(&q2),
        });
        let b = Arc::new(Self {
            koid: alloc_koid(),
            inbox: q2,
            outbox: q1,
        });
        (a, b)
    }

    /// Create a standalone channel endpoint with no peer (writes are
    /// dropped, reads always empty). Mainly useful for tests; real
    /// producers should use [`Channel::pair`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::new(Mutex::new(Vec::new())),
            outbox: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Send a message to the peer endpoint (enqueued FIFO).
    pub fn send(&self, msg: ChannelMessage) {
        self.outbox.lock().push(msg);
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
