//! Port event queue objects.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::wait::{self, WaitQueue};
use crate::{alloc_koid, KernelObject, Koid, ObjectType};
use huesos_quota::{Limits, Quota, Resource, UNLIMITED};

/// Maximum number of packets retained in one Port.
pub const MAX_PORT_PACKETS: usize = 256;

/// Port queue packet storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortCreateError {
    /// The fixed packet ring could not be allocated.
    OutOfMemory,
}

/// Port queue admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortQueueError {
    /// The bounded packet quota is exhausted.
    QuotaExceeded,
}

/// Port — bounded wait queue for async events.
pub struct Port {
    koid: Koid,
    packets: Mutex<VecDeque<PortPacket>>,
    quota: Mutex<Quota>,
    dropped_packets: AtomicU64,
    waiters: WaitQueue,
}

/// A packet queued to a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortPacket {
    /// Key used to identify the source.
    pub key: u64,
    /// Packet type. Mirrors `huesos_abi::PORT_PACKET_*` values at the syscall
    /// boundary without making this arch-independent crate depend on the ABI
    /// crate.
    pub packet_type: u32,
    /// Status associated with this event.
    pub status: i32,
    /// Fixed-size source-specific payload.
    pub data: [u64; 4],
}

impl Port {
    /// Create a Port with preallocated bounded packet storage.
    pub fn new() -> Result<Arc<Self>, PortCreateError> {
        let mut packets = VecDeque::new();
        packets
            .try_reserve_exact(MAX_PORT_PACKETS)
            .map_err(|_| PortCreateError::OutOfMemory)?;
        let packet_bytes = core::mem::size_of::<PortPacket>() as u64;
        Ok(Arc::new(Self {
            koid: alloc_koid(),
            packets: Mutex::new(packets),
            quota: Mutex::new(Quota::new(Limits {
                max_memory: packet_bytes.saturating_mul(MAX_PORT_PACKETS as u64),
                max_handles: UNLIMITED,
                max_cpu_ticks: UNLIMITED,
            })),
            dropped_packets: AtomicU64::new(0),
            waiters: WaitQueue::new(),
        }))
    }

    /// Queue a packet and wake one blocked reader. This path is bounded and
    /// does not allocate after Port creation, making it suitable for IRQ
    /// producers.
    pub fn queue(&self, packet: PortPacket) -> Result<(), PortQueueError> {
        let packet_bytes = core::mem::size_of::<PortPacket>() as u64;
        let mut packets = self.packets.lock();
        let mut quota = self.quota.lock();
        if packets.len() >= MAX_PORT_PACKETS
            || !quota.fits(Resource::Memory, packet_bytes)
        {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
            return Err(PortQueueError::QuotaExceeded);
        }
        // Storage is preallocated in `new`; never grow it from an IRQ path.
        if packets.capacity() <= packets.len() {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
            return Err(PortQueueError::QuotaExceeded);
        }
        let _ = quota.try_acquire(Resource::Memory, packet_bytes);
        packets.push_back(packet);
        drop(quota);
        drop(packets);
        self.waiters.wake_one();
        Ok(())
    }

    /// Number of packets dropped because the bounded queue was full.
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    /// Read a packet (non-blocking, FIFO order).
    pub fn read(&self) -> Option<PortPacket> {
        let packet = self.packets.lock().pop_front()?;
        let packet_bytes = core::mem::size_of::<PortPacket>() as u64;
        self.quota
            .lock()
            .release(Resource::Memory, packet_bytes);
        Some(packet)
    }

    /// Blocking read: park until a packet is available.
    pub fn read_blocking(&self) -> PortPacket {
        self.read_blocking_timeout(0).expect("infinite wait")
    }

    /// Blocking read with timeout in scheduler ticks (`0` = forever).
    pub fn read_blocking_timeout(&self, timeout_ticks: u64) -> Option<PortPacket> {
        use wait::ParkResult;
        if timeout_ticks == 0 {
            loop {
                if let Some(p) = self.read() {
                    return Some(p);
                }
                wait::park_on(&self.waiters);
            }
        }
        loop {
            if let Some(p) = self.read() {
                return Some(p);
            }
            match wait::park_on_timeout(&self.waiters, timeout_ticks) {
                ParkResult::Woken => continue,
                ParkResult::TimedOut => return self.read(),
            }
        }
    }
}

impl KernelObject for Port {
    fn object_type(&self) -> ObjectType {
        ObjectType::Port
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
