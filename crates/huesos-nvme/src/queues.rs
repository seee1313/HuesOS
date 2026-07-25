//! Multi-queue NVMe support: queue selection and management.
//!
//! NVMe supports multiple I/O queue pairs for parallel I/O across CPUs.
//! This module provides [`QueueSelector`] for round-robin queue selection
//! and [`QueueManager`] for queue lifecycle (create, delete, resize).
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
//!
//! I/O Queue N (queue N) ─── MSI-X vector N
//!   └── I/O commands: Read, Write, Flush for namespace 1
//! ```
//!
//! ## Queue selection
//!
//! [`QueueSelector`] distributes I/O across queues using round-robin. For
//! SMP systems, each CPU can have its own queue to avoid lock contention.
//!
//! ## Future work
//!
//! - Per-CPU queue assignment (CPU affinity)
//! - Queue resizing based on workload
//! - Priority queues for latency-sensitive I/O
//! - Multi-namespace queue mapping

use core::sync::atomic::{AtomicU16, Ordering};

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

/// Queue lifecycle management: create, delete, resize.
///
/// This is a placeholder for future implementation. The actual queue
/// management requires admin command submission (Create I/O CQ/SQ) and
/// MSI-X vector assignment, which is controller-specific.
pub struct QueueManager {
    /// Number of currently active I/O queues.
    active_queues: u16,
    /// Maximum queues supported by the controller (CAP.MQES).
    max_queues: u16,
}

impl QueueManager {
    /// Create a queue manager with the given maximum queue count.
    pub fn new(max_queues: u16) -> Self {
        Self {
            active_queues: 0,
            max_queues,
        }
    }

    /// Number of currently active I/O queues.
    pub fn active_queues(&self) -> u16 {
        self.active_queues
    }

    /// Maximum queues supported by the controller.
    pub fn max_queues(&self) -> u16 {
        self.max_queues
    }

    /// Create a new I/O queue pair. Returns queue ID (1-indexed) or None if
    /// at capacity.
    ///
    /// # Future work
    ///
    /// This should submit Create I/O CQ/SQ admin commands and assign MSI-X
    /// vectors. Currently a stub that tracks queue count.
    pub fn create_queue(&mut self) -> Option<u16> {
        if self.active_queues >= self.max_queues {
            return None;
        }
        self.active_queues += 1;
        Some(self.active_queues)
    }

    /// Delete an I/O queue pair. Returns true if the queue was deleted.
    ///
    /// # Future work
    ///
    /// This should submit Delete I/O CQ/SQ admin commands and release MSI-X
    /// vectors. Currently a stub that tracks queue count.
    pub fn delete_queue(&mut self, _queue_id: u16) -> bool {
        if self.active_queues == 0 {
            return false;
        }
        self.active_queues -= 1;
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
        assert_eq!(manager.active_queues(), 2);
        assert!(manager.delete_queue(1));
        assert_eq!(manager.active_queues(), 1);
    }

    #[test]
    fn queue_manager_capacity() {
        let mut manager = QueueManager::new(2);
        assert_eq!(manager.create_queue(), Some(1));
        assert_eq!(manager.create_queue(), Some(2));
        assert_eq!(manager.create_queue(), None); // at capacity
    }
}
