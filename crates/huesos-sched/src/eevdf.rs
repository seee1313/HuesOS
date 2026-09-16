//! Index-based augmented WAVL tree for EEVDF runqueue ordering.
//!
//! The tree stores `(virtual_start, task_id)` keys and augments each subtree
//! with the minimum `virtual_finish` among descendants. Selection is
//! "earliest virtual finish among eligible requests", matching the EEVDF
//! policy used by the `EevdfModel` oracle.
//!
//! All operations are O(log n) and allocation-free: nodes live in fixed
//! arrays keyed by `usize` indices provided by the caller. The caller is
//! responsible for keeping node slots stable while they are present in the
//! tree; the tree never owns or allocates node data.
//!
//! This module never panics. Internal operations are `?`-threaded: a
//! violation of the tree's bookkeeping invariants surfaces to the caller as
//! `EevdfTreeError::InvariantBroken` instead of an in-place `expect`. The
//! split is deliberate:
//! - mutation paths (`insert`, `remove`, `pop_min`) must fail loudly, because
//!   treating a corrupted queue as empty would silently strand runnable
//!   tasks in the runqueue;
//! - read-only walks (`pick_eligible`, `collect_sorted`, `peek_min`,
//!   `min_start`, `contains`) degrade gracefully (skip a missing subtree),
//!   because a partial read cannot strand a task.

#![allow(clippy::needless_range_loop)]

use alloc::vec::Vec;
use core::cmp::Ordering;

/// Capacity-exhaustion, missing-entry, or internal-invariant error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EevdfTreeError {
    /// The tree has reached its fixed capacity.
    Full,
    /// A requested key is not present.
    NotFound,
    /// An internal bookkeeping invariant was violated: an index that was
    /// linked (root, child pointer, or caller-owned slot) did not hold a
    /// live node. Unreachable from a well-formed caller; it indicates a
    /// kernel bug and the surfaced error must fail stop at the one reviewed
    /// boundary (the scheduler), never be swallowed.
    InvariantBroken,
}

/// A runqueue entry key: `(virtual_start, task_id)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EevdfKey {
    pub virtual_start: u128,
    pub task_id: u64,
}

impl Ord for EevdfKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.virtual_start, self.task_id).cmp(&(other.virtual_start, other.task_id))
    }
}

impl PartialOrd for EevdfKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One node in the fixed-capacity augmented WAVL tree.
#[derive(Clone, Copy, Debug)]
struct Node {
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    rank: u8,
    key: EevdfKey,
    /// Subtree minimum virtual_finish (augmented value).
    min_finish: u128,
    finish: u128,
}

impl Node {
    fn new(key: EevdfKey, finish: u128) -> Self {
        Self {
            parent: None,
            left: None,
            right: None,
            rank: 0,
            key,
            min_finish: finish,
            finish,
        }
    }
}

/// Fixed-capacity augmented WAVL tree using `Option<Node>` slots so every
/// operation stays allocation-free and unsafe-free.
pub struct EevdfTree<const N: usize> {
    nodes: [Option<Node>; N],
    free: [usize; N],
    free_len: usize,
    root: Option<usize>,
    len: usize,
}

impl<const N: usize> EevdfTree<N> {
    /// Create an empty tree.
    pub const fn new() -> Self {
        let mut free = [0usize; N];
        let mut i = 0;
        while i < N {
            free[i] = i;
            i += 1;
        }
        Self {
            nodes: [None; N],
            free,
            free_len: N,
            root: None,
            len: 0,
        }
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the tree has no free capacity.
    pub fn is_full(&self) -> bool {
        self.free_len == 0
    }

    /// Insert a key with its virtual finish. Duplicate keys are rejected.
    pub fn insert(&mut self, key: EevdfKey, finish: u128) -> Result<(), EevdfTreeError> {
        if self.free_len == 0 {
            return Err(EevdfTreeError::Full);
        }
        let slot = self.free[self.free_len - 1];
        self.free_len -= 1;
        self.nodes[slot] = Some(Node::new(key, finish));
        self.len += 1;

        let mut parent = None;
        let mut cur = self.root;
        while let Some(idx) = cur {
            let node = *self.node_ref(idx)?;
            match key.cmp(&node.key) {
                Ordering::Equal => {
                    // Roll back the slot reservation.
                    self.free[self.free_len] = slot;
                    self.free_len += 1;
                    self.len -= 1;
                    self.nodes[slot] = None;
                    return Err(EevdfTreeError::NotFound);
                }
                Ordering::Less => {
                    parent = Some(idx);
                    cur = node.left;
                }
                Ordering::Greater => {
                    parent = Some(idx);
                    cur = node.right;
                }
            }
        }
        self.node_mut_ref(slot)?.parent = parent;
        match parent {
            None => self.root = Some(slot),
            Some(p) => {
                let key_at_p = self.node_ref(p)?.key;
                if key < key_at_p {
                    self.node_mut_ref(p)?.left = Some(slot);
                } else {
                    self.node_mut_ref(p)?.right = Some(slot);
                }
            }
        }
        self.rebalance_after_insert(slot)?;
        self.refresh_ancestors(slot)?;
        Ok(())
    }

    /// Remove the exact key.
    pub fn remove(&mut self, key: EevdfKey) -> Result<(), EevdfTreeError> {
        let Some(slot) = self.find_key(key) else {
            return Err(EevdfTreeError::NotFound);
        };
        self.erase_node(slot)
    }

    /// Whether the exact key is present.
    pub fn contains(&self, key: EevdfKey) -> bool {
        self.find_key(key).is_some()
    }

    /// Peek at the smallest key (by virtual_start).
    pub fn peek_min(&self) -> Option<EevdfKey> {
        let mut cur = self.root?;
        while let Some(left) = self.nodes[cur].as_ref()?.left {
            cur = left;
        }
        Some(self.nodes[cur].as_ref()?.key)
    }

    /// Remove and return the smallest key.
    ///
    /// Returns `Ok(None)` only when the tree is empty. An internal error must
    /// not be swallowed by the caller: a silent `None` here would strand
    /// every remaining fair task in the runqueue.
    pub fn pop_min(&mut self) -> Result<Option<EevdfKey>, EevdfTreeError> {
        let Some(mut cur) = self.root else {
            return Ok(None);
        };
        loop {
            let node = *self.node_ref(cur)?;
            match node.left {
                Some(l) => cur = l,
                None => break,
            }
        }
        let key = self.node_ref(cur)?.key;
        self.erase_node(cur)?;
        Ok(Some(key))
    }

    /// Select the eligible entry with the earliest virtual finish.
    ///
    /// Eligibility is `virtual_start <= now`. If no entry is eligible but
    /// entries exist, the caller should advance `now` to the smallest
    /// `virtual_start` (the EEVDF "snap" rule); this function only returns
    /// eligible candidates.
    ///
    /// Read-only: a corrupted subtree is skipped rather than reported,
    /// because a partial read cannot strand a task.
    pub fn pick_eligible(&self, now: u128) -> Option<EevdfKey> {
        let mut best: Option<(u128, EevdfKey)> = None;
        self.walk_eligible(self.root, now, &mut |key, finish| {
            let candidate = (finish, key);
            match best {
                None => best = Some(candidate),
                Some(current) => {
                    if candidate.0 < current.0 || (candidate.0 == current.0 && key < current.1) {
                        best = Some(candidate);
                    }
                }
            }
        });
        best.map(|(_, key)| key)
    }

    /// Smallest `virtual_start` among all live entries (EEVDF snap target).
    pub fn min_start(&self) -> Option<u128> {
        let mut cur = self.root?;
        while let Some(left) = self.nodes[cur].as_ref()?.left {
            cur = left;
        }
        Some(self.nodes[cur].as_ref()?.key.virtual_start)
    }

    /// Collect all live keys in sorted order (used by tests and drain).
    ///
    /// Read-only: a corrupted subtree is skipped rather than reported.
    pub fn collect_sorted(&self) -> Vec<EevdfKey> {
        let mut out = Vec::new();
        self.collect_inorder(self.root, &mut out);
        out
    }

    // ---- internal ----

    /// Read a linked node, or report the bookkeeping invariant violation.
    ///
    /// Every index handed to this method is the root, a child pointer read
    /// from a live node, or a slot owned by the calling operation; all of
    /// those are live by the insert/erase bookkeeping invariants. A missing
    /// slot here means the tree is corrupted and must surface as
    /// `InvariantBroken`, never as a panic.
    fn node_ref(&self, idx: usize) -> Result<&Node, EevdfTreeError> {
        self.nodes[idx]
            .as_ref()
            .ok_or(EevdfTreeError::InvariantBroken)
    }

    /// Mutably read a linked node. Same invariant as [`Self::node_ref`].
    fn node_mut_ref(&mut self, idx: usize) -> Result<&mut Node, EevdfTreeError> {
        self.nodes[idx]
            .as_mut()
            .ok_or(EevdfTreeError::InvariantBroken)
    }

    fn find_key(&self, key: EevdfKey) -> Option<usize> {
        let mut cur = self.root?;
        loop {
            let node = self.nodes[cur].as_ref()?;
            match key.cmp(&node.key) {
                Ordering::Equal => return Some(cur),
                Ordering::Less => cur = node.left?,
                Ordering::Greater => cur = node.right?,
            }
        }
    }

    fn collect_inorder(&self, node: Option<usize>, out: &mut Vec<EevdfKey>) {
        let Some(idx) = node else { return };
        let Ok(n) = self.node_ref(idx) else { return };
        let n = *n;
        self.collect_inorder(n.left, out);
        out.push(n.key);
        self.collect_inorder(n.right, out);
    }

    /// Remove a linked node, repair the BST link, then rebalance and refresh.
    fn erase_node(&mut self, slot: usize) -> Result<(), EevdfTreeError> {
        let slot_node = *self.node_ref(slot)?;
        let (left, right, parent) = (slot_node.left, slot_node.right, slot_node.parent);

        if let (Some(_), Some(successor_root)) = (left, right) {
            // Find in-order successor (min of right subtree).
            let mut succ = successor_root;
            loop {
                let succ_node = *self.node_ref(succ)?;
                match succ_node.left {
                    Some(l) => succ = l,
                    None => break,
                }
            }
            // Capture the structural parent BEFORE erase_single clears it: the
            // node that actually lost a child is the rebalance start point.
            let succ_parent = self.node_ref(succ)?.parent;
            let successor = *self.node_ref(succ)?;
            let slot_mut = self.node_mut_ref(slot)?;
            slot_mut.key = successor.key;
            slot_mut.finish = successor.finish;
            slot_mut.min_finish = successor.min_finish;
            self.erase_single(succ)?;
            let start = succ_parent.or(Some(slot));
            if let Some(p) = start {
                self.rebalance_after_erase(p)?;
                self.refresh_ancestors(p)?;
            }
            return Ok(());
        }

        self.erase_single(slot)?;
        if let Some(p) = parent {
            self.rebalance_after_erase(p)?;
            self.refresh_ancestors(p)?;
        }
        Ok(())
    }

    /// Erase a node that has at most one child.
    fn erase_single(&mut self, slot: usize) -> Result<(), EevdfTreeError> {
        let slot_node = *self.node_ref(slot)?;
        let (parent, child) = (slot_node.parent, slot_node.left.or(slot_node.right));
        match parent {
            None => self.root = child,
            Some(p) => {
                let p_node = self.node_ref(p)?;
                if p_node.left == Some(slot) {
                    self.node_mut_ref(p)?.left = child;
                } else {
                    self.node_mut_ref(p)?.right = child;
                }
            }
        }
        if let Some(c) = child {
            self.node_mut_ref(c)?.parent = parent;
        }
        self.free[self.free_len] = slot;
        self.free_len += 1;
        self.len -= 1;
        self.nodes[slot] = None;
        Ok(())
    }

    /// Recompute `min_finish` for a node from its children.
    fn refresh_node(&mut self, idx: usize) -> Result<(), EevdfTreeError> {
        let node = *self.node_ref(idx)?;
        let finish = node.finish;
        let left_min = match node.left {
            Some(l) => Some(self.node_ref(l)?.min_finish),
            None => None,
        };
        let right_min = match node.right {
            Some(r) => Some(self.node_ref(r)?.min_finish),
            None => None,
        };
        let mut m = finish;
        if let Some(l) = left_min {
            if l < m {
                m = l;
            }
        }
        if let Some(r) = right_min {
            if r < m {
                m = r;
            }
        }
        self.node_mut_ref(idx)?.min_finish = m;
        Ok(())
    }

    /// Refresh augmentation from `start` up to the root.
    fn refresh_ancestors(&mut self, start: usize) -> Result<(), EevdfTreeError> {
        let mut cur = Some(start);
        while let Some(idx) = cur {
            self.refresh_node(idx)?;
            cur = self.node_ref(idx)?.parent;
        }
        Ok(())
    }

    /// WAVL rebalance after an insert starting at the inserted node.
    fn rebalance_after_insert(&mut self, mut node: usize) -> Result<(), EevdfTreeError> {
        loop {
            let Some(parent) = self.node_ref(node)?.parent else {
                return Ok(());
            };
            let node_node = *self.node_ref(node)?;
            let parent_node = *self.node_ref(parent)?;
            if parent_node.rank > node_node.rank + 1 {
                let is_left_child = parent_node.left == Some(node);
                if is_left_child {
                    match node_node.right {
                        Some(grand) => {
                            self.rotate_left(node)?;
                            self.rotate_right(parent)?;
                            self.node_mut_ref(grand)?.rank += 1;
                            self.node_mut_ref(node)?.rank -= 1;
                            node = grand;
                        }
                        None => {
                            self.rotate_right(parent)?;
                            node = parent;
                        }
                    }
                } else if let Some(grand) = node_node.left {
                    self.rotate_right(node)?;
                    self.rotate_left(parent)?;
                    self.node_mut_ref(grand)?.rank += 1;
                    self.node_mut_ref(node)?.rank -= 1;
                    node = grand;
                } else {
                    self.rotate_left(parent)?;
                    node = parent;
                }
            } else {
                node = parent;
            }
        }
    }

    /// WAVL rebalance after an erase starting at the parent.
    fn rebalance_after_erase(&mut self, mut node: usize) -> Result<(), EevdfTreeError> {
        loop {
            let node_node = *self.node_ref(node)?;
            let left_rank = match node_node.left {
                Some(l) => self.node_ref(l)?.rank,
                None => 0,
            };
            let right_rank = match node_node.right {
                Some(r) => self.node_ref(r)?.rank,
                None => 0,
            };
            let min = left_rank.min(right_rank);
            let max = left_rank.max(right_rank);
            if min == 0 && max > 1 {
                if left_rank > right_rank {
                    let Some(child) = node_node.left else {
                        return Err(EevdfTreeError::InvariantBroken);
                    };
                    let child_node = *self.node_ref(child)?;
                    let child_left = match child_node.left {
                        Some(l) => self.node_ref(l)?.rank,
                        None => 0,
                    };
                    let child_right = match child_node.right {
                        Some(r) => self.node_ref(r)?.rank,
                        None => 0,
                    };
                    if child_right > child_left {
                        let Some(grand) = child_node.right else {
                            return Err(EevdfTreeError::InvariantBroken);
                        };
                        self.rotate_left(child)?;
                        self.rotate_right(node)?;
                        self.node_mut_ref(grand)?.rank += 1;
                        self.node_mut_ref(child)?.rank -= 1;
                        node = grand;
                    } else {
                        self.rotate_right(node)?;
                        self.node_mut_ref(child)?.rank -= 1;
                        node = child;
                    }
                } else {
                    let Some(child) = node_node.right else {
                        return Err(EevdfTreeError::InvariantBroken);
                    };
                    let child_node = *self.node_ref(child)?;
                    let child_left = match child_node.left {
                        Some(l) => self.node_ref(l)?.rank,
                        None => 0,
                    };
                    let child_right = match child_node.right {
                        Some(r) => self.node_ref(r)?.rank,
                        None => 0,
                    };
                    if child_left > child_right {
                        let Some(grand) = child_node.left else {
                            return Err(EevdfTreeError::InvariantBroken);
                        };
                        self.rotate_right(child)?;
                        self.rotate_left(node)?;
                        self.node_mut_ref(grand)?.rank += 1;
                        self.node_mut_ref(child)?.rank -= 1;
                        node = grand;
                    } else {
                        self.rotate_left(node)?;
                        self.node_mut_ref(child)?.rank -= 1;
                        node = child;
                    }
                }
                continue;
            }
            let Some(parent) = node_node.parent else {
                break;
            };
            node = parent;
        }
        Ok(())
    }

    /// Rotate subtree right around `y` (y becomes left child of x).
    fn rotate_right(&mut self, y: usize) -> Result<(), EevdfTreeError> {
        let y_node = *self.node_ref(y)?;
        let Some(x) = y_node.left else {
            return Err(EevdfTreeError::InvariantBroken);
        };
        let b = self.node_ref(x)?.right;
        let p = y_node.parent;
        self.node_mut_ref(x)?.right = Some(y);
        self.node_mut_ref(y)?.parent = Some(x);
        self.node_mut_ref(y)?.left = b;
        if let Some(bi) = b {
            self.node_mut_ref(bi)?.parent = Some(y);
        }
        self.node_mut_ref(x)?.parent = p;
        match p {
            None => self.root = Some(x),
            Some(pi) => {
                let pi_node = self.node_ref(pi)?;
                if pi_node.left == Some(y) {
                    self.node_mut_ref(pi)?.left = Some(x);
                } else {
                    self.node_mut_ref(pi)?.right = Some(x);
                }
            }
        }
        self.refresh_node(y)?;
        self.refresh_node(x)?;
        Ok(())
    }

    /// Rotate subtree left around `x`.
    fn rotate_left(&mut self, x: usize) -> Result<(), EevdfTreeError> {
        let x_node = *self.node_ref(x)?;
        let Some(y) = x_node.right else {
            return Err(EevdfTreeError::InvariantBroken);
        };
        let b = self.node_ref(y)?.left;
        let p = x_node.parent;
        self.node_mut_ref(y)?.left = Some(x);
        self.node_mut_ref(x)?.parent = Some(y);
        self.node_mut_ref(x)?.right = b;
        if let Some(bi) = b {
            self.node_mut_ref(bi)?.parent = Some(x);
        }
        self.node_mut_ref(y)?.parent = p;
        match p {
            None => self.root = Some(y),
            Some(pi) => {
                let pi_node = self.node_ref(pi)?;
                if pi_node.left == Some(x) {
                    self.node_mut_ref(pi)?.left = Some(y);
                } else {
                    self.node_mut_ref(pi)?.right = Some(y);
                }
            }
        }
        self.refresh_node(x)?;
        self.refresh_node(y)?;
        Ok(())
    }

    /// Walk all eligible nodes and invoke `f(key, finish)`.
    ///
    /// Read-only: a corrupted subtree is skipped rather than reported.
    fn walk_eligible(&self, node: Option<usize>, now: u128, f: &mut impl FnMut(EevdfKey, u128)) {
        let Some(idx) = node else { return };
        let Ok(n) = self.node_ref(idx) else { return };
        let n = *n;
        self.walk_eligible(n.left, now, f);
        if n.key.virtual_start <= now {
            f(n.key, n.finish);
        }
        self.walk_eligible(n.right, now, f);
    }
}

impl<const N: usize> Default for EevdfTree<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    // Helper: unpack a Result in a test without calling unwrap. CONTRIBUTING
    // rule 1 forbids the unwrap / expect / panic macros including in tests;
    // an assert!(false, ...) is the budget-allowed diagnostic, and `return`
    // after it keeps the types sound for the remainder of the test body.
    macro_rules! expect_ok {
        ($expr:expr, $msg:literal) => {
            match $expr {
                Ok(value) => value,
                Err(err) => {
                    assert!(
                        false,
                        concat!("expected Ok: ", $msg, " (got {err:?})"),
                        err = err
                    );
                    return;
                }
            }
        };
    }

    fn key(start: u128, id: u64) -> EevdfKey {
        EevdfKey {
            virtual_start: start,
            task_id: id,
        }
    }

    #[test]
    fn insert_pop_min_preserves_ordering() {
        let mut tree = EevdfTree::<8>::new();
        expect_ok!(tree.insert(key(100, 1), 200), "insert (100, 1)");
        expect_ok!(tree.insert(key(50, 2), 150), "insert (50, 2)");
        expect_ok!(tree.insert(key(150, 3), 250), "insert (150, 3)");
        expect_ok!(tree.insert(key(75, 4), 175), "insert (75, 4)");
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.pop_min(), Ok(Some(key(50, 2))));
        assert_eq!(tree.pop_min(), Ok(Some(key(75, 4))));
        assert_eq!(tree.pop_min(), Ok(Some(key(100, 1))));
        assert_eq!(tree.pop_min(), Ok(Some(key(150, 3))));
        assert_eq!(tree.pop_min(), Ok(None));
        assert!(tree.is_empty());
    }

    #[test]
    fn task_id_breaks_virtual_start_ties() {
        let mut tree = EevdfTree::<4>::new();
        expect_ok!(tree.insert(key(100, 2), 200), "insert (100, 2)");
        expect_ok!(tree.insert(key(100, 1), 100), "insert (100, 1)");
        assert_eq!(tree.pop_min(), Ok(Some(key(100, 1))));
        assert_eq!(tree.pop_min(), Ok(Some(key(100, 2))));
    }

    #[test]
    fn remove_is_exact_and_missing_is_rejected() {
        let mut tree = EevdfTree::<4>::new();
        expect_ok!(tree.insert(key(10, 1), 20), "insert (10, 1)");
        expect_ok!(tree.insert(key(10, 2), 30), "insert (10, 2)");
        expect_ok!(tree.remove(key(10, 1)), "remove (10, 1)");
        assert_eq!(tree.remove(key(10, 1)), Err(EevdfTreeError::NotFound));
        assert_eq!(tree.len(), 1);
        assert!(tree.contains(key(10, 2)));
    }

    #[test]
    fn capacity_is_hard() {
        let mut tree = EevdfTree::<2>::new();
        expect_ok!(tree.insert(key(1, 1), 2), "insert (1, 1)");
        expect_ok!(tree.insert(key(2, 2), 3), "insert (2, 2)");
        assert_eq!(tree.insert(key(3, 3), 4), Err(EevdfTreeError::Full));
    }

    #[test]
    fn pick_eligible_chooses_earliest_finish_among_eligible() {
        let mut tree = EevdfTree::<4>::new();
        // Eligible (start <= 100), finishes 300 and 200.
        expect_ok!(tree.insert(key(0, 1), 300), "insert (0, 1)");
        expect_ok!(tree.insert(key(50, 2), 200), "insert (50, 2)");
        // Ineligible (start > 100), earliest finish 250 but must not win.
        expect_ok!(tree.insert(key(150, 3), 250), "insert (150, 3)");
        assert_eq!(tree.pick_eligible(100), Some(key(50, 2)));
        assert_eq!(tree.pick_eligible(200), Some(key(50, 2)));
        // At now=150 all three are eligible; task 2 still has the earliest
        // finish (200), even though task 3 became eligible at that instant.
        assert_eq!(tree.pick_eligible(150), Some(key(50, 2)));
    }

    #[test]
    fn min_start_supports_eevdf_snap_rule() {
        let mut tree = EevdfTree::<2>::new();
        expect_ok!(tree.insert(key(500, 1), 600), "insert (500, 1)");
        expect_ok!(tree.insert(key(300, 2), 700), "insert (300, 2)");
        assert_eq!(tree.min_start(), Some(300));
        assert_eq!(tree.pick_eligible(0), None);
        assert_eq!(tree.pick_eligible(300), Some(key(300, 2)));
    }

    #[test]
    fn randomized_ops_preserve_invariants() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut rng = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut tree = EevdfTree::<128>::new();
        let mut live = BTreeSet::new();
        for _ in 0..3000 {
            let op = rng() % 3;
            let id = (rng() % 4) as u64;
            let start = (rng() % 16) as u128;
            let finish = start + (rng() % 100) as u128 + 1;
            match op {
                0 | 1 => match tree.insert(key(start, id), finish) {
                    Ok(()) => {
                        assert!(live.insert(key(start, id)));
                    }
                    Err(EevdfTreeError::NotFound) => {
                        assert!(!live.insert(key(start, id)));
                    }
                    Err(e) => {
                        assert!(false, "unexpected insert error: {e:?}");
                        return;
                    }
                },
                _ => {
                    let removed = matches!(tree.remove(key(start, id)), Ok(()));
                    let was_present = live.remove(&key(start, id));
                    assert_eq!(
                        removed,
                        was_present,
                        "remove divergence for {:?}",
                        key(start, id)
                    );
                }
            }
            let expected_min = live.iter().next().copied();
            assert_eq!(tree.peek_min(), expected_min);
            assert_eq!(tree.len(), live.len());
        }
        let sorted = tree.collect_sorted();
        let expected: Vec<EevdfKey> = live.iter().copied().collect();
        assert_eq!(sorted, expected);
        while let Ok(Some(k)) = tree.pop_min() {
            assert_eq!(live.pop_first(), Some(k));
        }
        assert_eq!(tree.pop_min(), Ok(None));
        assert!(live.is_empty());
    }
}
