//! Safe ordered run queue for fair scheduling.
//!
//! The original implementation stored individually allocated WAVL nodes with
//! six raw links per node and performed rotations through broad `unsafe`
//! blocks. A malformed link could cause use-after-free, double-free, or an
//! arbitrary kernel write. The scheduler only requires four operations:
//! insert a unique `(vruntime, task_id)` key, remove that key, pop the minimum,
//! and drop the queue. `alloc::collections::BTreeSet` provides those semantics
//! safely with the same O(log n) complexity and a well-tested ownership model.
//!
//! `WavlTree` is retained as a compatibility name so this hardening change does
//! not touch scheduler policy code. It no longer exposes nodes or pointers.

use alloc::collections::BTreeSet;

/// Ordered set of runnable fair-scheduler tasks.
///
/// Keys are `(virtual runtime, task id)`. The task id tie-breaker permits many
/// tasks to have the same virtual runtime without overwriting one another.
pub struct WavlTree {
    entries: BTreeSet<(u64, u64)>,
}

impl WavlTree {
    /// Create an empty run queue.
    pub const fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
        }
    }

    /// Insert a runnable task.
    ///
    /// Insertion is idempotent for an already-present exact key. Callers that
    /// change a task's virtual runtime must remove the old key first.
    pub fn insert(&mut self, vruntime: u64, task_id: u64) {
        self.entries.insert((vruntime, task_id));
    }

    /// Remove and return the task id with the smallest fair-scheduling key.
    pub fn pop_min(&mut self) -> Option<u64> {
        self.entries.pop_first().map(|(_, task_id)| task_id)
    }

    /// Remove an exact task key. Missing keys are a harmless no-op.
    pub fn remove(&mut self, vruntime: u64, task_id: u64) {
        self.entries.remove(&(vruntime, task_id));
    }

    /// Number of runnable tasks represented in the queue.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for WavlTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_and_ordering() {
        let mut tree = WavlTree::new();
        tree.insert(100, 1);
        tree.insert(50, 2);
        tree.insert(150, 3);
        tree.insert(75, 4);

        assert_eq!(tree.pop_min(), Some(2));
        assert_eq!(tree.pop_min(), Some(4));
        assert_eq!(tree.pop_min(), Some(1));
        assert_eq!(tree.pop_min(), Some(3));
        assert_eq!(tree.pop_min(), None);
    }

    #[test]
    fn task_id_breaks_duplicate_vruntime_ties() {
        let mut tree = WavlTree::new();
        tree.insert(100, 2);
        tree.insert(100, 1);

        assert_eq!(tree.pop_min(), Some(1));
        assert_eq!(tree.pop_min(), Some(2));
    }

    #[test]
    fn exact_duplicates_are_idempotent() {
        let mut tree = WavlTree::new();
        tree.insert(10, 7);
        tree.insert(10, 7);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.pop_min(), Some(7));
        assert_eq!(tree.pop_min(), None);
    }

    #[test]
    fn removal_is_exact_and_safe_when_missing() {
        let mut tree = WavlTree::new();
        tree.insert(10, 1);
        tree.insert(10, 2);
        tree.remove(10, 1);
        tree.remove(99, 99);
        assert_eq!(tree.pop_min(), Some(2));
        assert_eq!(tree.pop_min(), None);
    }
}
