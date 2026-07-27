//! Multi-queue NVMe support: queue selection and management.
//!
//! NVMe supports multiple I/O queue pairs for parallel I/O across CPUs.
//! This module provides [`QueueSelector`] for round-robin queue selection
//! and [`QueueManager`] for queue lifecycle tracking.
//!
//! ## Queue architecture
//!
//! ```text
//! Admin Queue (queue 0)
//!   └── Admin commands: Identify, Create I/O CQ/SQ, Set Features, ...
//!
//! I/O Queue 1 (queue 1) ─── MSI-X vector 1
//!   └── I/O commands: Read, Write, Flush for namespace 1
//!
//! I/O Queue 2 (queue 2) ─── MSI-X vector 2
//!   └── I/O commands: Read, Write, Flush for namespace 1
//!
//! ...
//! ```
//!
//! ## Queue selection
//!
//! [`QueueSelector`] distributes I/O across explicitly-created queues using
//! round-robin. It does not create queues itself.
//!
//! ## Future work
//!
//! - Submit actual Create/Delete I/O CQ/SQ admin commands.
//! - Per-CPU queue assignment (CPU affinity).
//! - Queue resizing based on workload.
//! - Priority queues for latency-sensitive I/O.
//! - Multi-namespace queue mapping.

use core::sync::atomic::{AtomicU16, Ordering};

/// Maximum queue IDs the host-testable lifecycle tracker stores.
///
/// NVMe controllers may advertise more queues; the current driver slice uses a
/// small fixed bound because it has no allocator in this policy object and the
/// integrated controller currently creates queue 1 only.
pub const MAX_TRACKED_IO_QUEUES: usize = 64;

/// Round-robin queue selector for distributing I/O across queues.
///
/// Thread-safe: uses atomic counter for lock-free selection.
pub struct QueueSelector {
    next_queue: AtomicU16,
    num_queues: u16,
}

impl QueueSelector {
    /// Create a selector for `num_queues` I/O queues (not including admin queue).
    pub fn new(num_queues: u16) -> Self {
        Self {
            next_queue: AtomicU16::new(0),
            num_queues: num_queues.max(1),
        }
    }

    /// Select the next queue (1-indexed: queue 1, 2, ..., num_queues).
    /// Returns queue ID in range [1, num_queues].
    pub fn select(&self) -> u16 {
        let queue = self.next_queue.fetch_add(1, Ordering::Relaxed);
        (queue % self.num_queues) + 1
    }

    /// Number of I/O queues (not including admin queue).
    pub fn num_queues(&self) -> u16 {
        self.num_queues
    }
}

/// Queue lifecycle management state.
///
/// This host-testable object tracks which queue IDs are active and prevents the
/// earlier bug where `delete_queue(id)` ignored `id` and simply decremented the
/// active count. The privileged controller still owns the actual admin command
/// submission; this type models the bookkeeping that code will use.
pub struct QueueManager {
    active: [bool; MAX_TRACKED_IO_QUEUES + 1],
    /// Number of currently active I/O queues.
    active_queues: u16,
    /// Maximum queue ID this manager may allocate, capped to
    /// [`MAX_TRACKED_IO_QUEUES`].
    max_queues: u16,
}

impl QueueManager {
    /// Create a queue manager with the given maximum queue count.
    pub fn new(max_queues: u16) -> Self {
        Self {
            active: [false; MAX_TRACKED_IO_QUEUES + 1],
            active_queues: 0,
            max_queues: max_queues.min(MAX_TRACKED_IO_QUEUES as u16),
        }
    }

    /// Number of currently active I/O queues.
    pub fn active_queues(&self) -> u16 {
        self.active_queues
    }

    /// Maximum queues tracked by this manager.
    pub fn max_queues(&self) -> u16 {
        self.max_queues
    }

    /// True if `queue_id` is currently active.
    pub fn is_active(&self, queue_id: u16) -> bool {
        let index = queue_id as usize;
        index < self.active.len() && self.active[index]
    }

    /// Create a new I/O queue pair. Returns the allocated queue ID (1-indexed)
    /// or `None` if at capacity.
    pub fn create_queue(&mut self) -> Option<u16> {
        if self.active_queues >= self.max_queues {
            return None;
        }
        let mut queue_id = 1u16;
        while queue_id <= self.max_queues {
            if !self.active[queue_id as usize] {
                self.active[queue_id as usize] = true;
                self.active_queues += 1;
                return Some(queue_id);
            }
            queue_id += 1;
        }
        None
    }

    /// Delete an I/O queue pair. Returns true only if that exact queue existed.
    pub fn delete_queue(&mut self, queue_id: u16) -> bool {
        let index = queue_id as usize;
        if queue_id == 0 || index >= self.active.len() || !self.active[index] {
            return false;
        }
        self.active[index] = false;
        self.active_queues = self.active_queues.saturating_sub(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_selector_round_robin() {
        let selector = QueueSelector::new(4);
        assert_eq!(selector.select(), 1);
        assert_eq!(selector.select(), 2);
        assert_eq!(selector.select(), 3);
        assert_eq!(selector.select(), 4);
        assert_eq!(selector.select(), 1); // wrap around
    }

    #[test]
    fn queue_manager_lifecycle() {
        let mut manager = QueueManager::new(4);
        assert_eq!(manager.active_queues(), 0);
        assert_eq!(manager.create_queue(), Some(1));
        assert_eq!(manager.create_queue(), Some(2));
        assert!(manager.is_active(1));
        assert!(manager.is_active(2));
        assert_eq!(manager.active_queues(), 2);
        assert!(manager.delete_queue(1));
        assert!(!manager.is_active(1));
        assert!(manager.is_active(2));
        assert_eq!(manager.active_queues(), 1);
    }

    #[test]
    fn queue_manager_capacity() {
        let mut manager = QueueManager::new(2);
        assert_eq!(manager.create_queue(), Some(1));
        assert_eq!(manager.create_queue(), Some(2));
        assert_eq!(manager.create_queue(), None); // at capacity
    }

    #[test]
    fn delete_queue_requires_exact_active_id() {
        let mut manager = QueueManager::new(4);
        assert_eq!(manager.create_queue(), Some(1));
        assert_eq!(manager.create_queue(), Some(2));
        assert!(!manager.delete_queue(4));
        assert!(!manager.delete_queue(0));
        assert_eq!(manager.active_queues(), 2);
        assert!(manager.delete_queue(2));
        assert_eq!(manager.active_queues(), 1);
        assert!(!manager.delete_queue(2));
        assert_eq!(manager.create_queue(), Some(2));
    }

    #[test]
    fn max_queue_count_is_capped_to_static_storage() {
        let manager = QueueManager::new(u16::MAX);
        assert_eq!(manager.max_queues(), MAX_TRACKED_IO_QUEUES as u16);
    }
}
