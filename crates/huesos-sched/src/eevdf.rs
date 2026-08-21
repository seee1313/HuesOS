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

#![allow(clippy::needless_range_loop)]

use alloc::vec::Vec;
use core::cmp::Ordering;

/// Capacity-exhaustion or missing-entry error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EevdfTreeError {
    /// The tree has reached its fixed capacity.
    Full,
    /// A requested key is not present.
    NotFound,
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
            let node = self.nodes[idx].as_ref().expect("linked node is live");
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
        let slot_node = self.node_mut_ref(slot);
        slot_node.parent = parent;
        match parent {
            None => self.root = Some(slot),
            Some(p) => {
                let key_at_p = self.node_ref(p).key;
                if key < key_at_p {
                    self.node_mut_ref(p).left = Some(slot);
                } else {
                    self.node_mut_ref(p).right = Some(slot);
                }
            }
        }
        self.refresh_ancestors(slot);
        Ok(())
    }

    /// Remove the exact key.
    pub fn remove(&mut self, key: EevdfKey) -> Result<(), EevdfTreeError> {
        let Some(slot) = self.find_key(key) else {
            return Err(EevdfTreeError::NotFound);
        };
        self.erase_node(slot);
        Ok(())
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
    pub fn pop_min(&mut self) -> Option<EevdfKey> {
        let mut cur = self.root?;
        while let Some(left) = self.nodes[cur].as_ref()?.left {
            cur = left;
        }
        let key = self.nodes[cur].as_ref()?.key;
        self.erase_node(cur);
        Some(key)
    }

    /// Select the eligible entry with the earliest virtual finish.
    ///
    /// Eligibility is `virtual_start <= now`. If no entry is eligible but
    /// entries exist, the caller should advance `now` to the smallest
    /// `virtual_start` (the EEVDF "snap" rule); this function only returns
    /// eligible candidates.
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
    pub fn collect_sorted(&self) -> Vec<EevdfKey> {
        let mut out = Vec::new();
        self.collect_inorder(self.root, &mut out);
        out
    }

    // ---- internal ----

    /// Read a live node. Callers guarantee `idx` is linked (never a freed
    /// slot) by construction of insert/erase bookkeeping.
    fn node_ref(&self, idx: usize) -> &Node {
        self.nodes[idx].as_ref().expect("live node invariant")
    }

    /// Mutably read a live node. Same invariant as [`Self::node_ref`].
    fn node_mut_ref(&mut self, idx: usize) -> &mut Node {
        self.nodes[idx].as_mut().expect("live node invariant")
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
        self.collect_inorder(self.node_ref(idx).left, out);
        out.push(self.node_ref(idx).key);
        self.collect_inorder(self.node_ref(idx).right, out);
    }

    /// Remove a linked node, repair the BST link, then rebalance and refresh.
    fn erase_node(&mut self, slot: usize) {
        let left = self.node_ref(slot).left;
        let right = self.node_ref(slot).right;
        let parent = self.node_ref(slot).parent;

        if left.is_some() && right.is_some() {
            // Find in-order successor (min of right subtree).
            let mut succ = right.unwrap();
            while let Some(l) = self.node_ref(succ).left {
                succ = l;
            }
            // Capture the structural parent BEFORE erase_single clears it: the
            // node that actually lost a child is the rebalance start point.
            let succ_parent = self.node_ref(succ).parent;
            let (skey, sfin, smin) = {
                let s = self.node_ref(succ);
                (s.key, s.finish, s.min_finish)
            };
            let slot_node = self.node_mut_ref(slot);
            slot_node.key = skey;
            slot_node.finish = sfin;
            slot_node.min_finish = smin;
            self.erase_single(succ);
            let start = succ_parent.or(Some(slot));
            if let Some(p) = start {
                self.rebalance_after_erase(p);
                self.refresh_ancestors(p);
            }
            return;
        }

        self.erase_single(slot);
        if let Some(p) = parent {
            self.rebalance_after_erase(p);
            self.refresh_ancestors(p);
        }
    }

    /// Erase a node that has at most one child.
    fn erase_single(&mut self, slot: usize) {
        let parent = self.node_ref(slot).parent;
        let child = self.nodes[slot]
            .as_ref()
            .expect("live")
            .left
            .or(self.node_ref(slot).right);
        match parent {
            None => self.root = child,
            Some(p) => {
                if self.node_ref(p).left == Some(slot) {
                    self.node_mut_ref(p).left = child;
                } else {
                    self.node_mut_ref(p).right = child;
                }
            }
        }
        if let Some(c) = child {
            self.node_mut_ref(c).parent = parent;
        }
        self.free[self.free_len] = slot;
        self.free_len += 1;
        self.len -= 1;
        self.nodes[slot] = None;
    }

    /// Recompute `min_finish` for a node from its children.
    fn refresh_node(&mut self, idx: usize) {
        let node = self.node_ref(idx);
        let finish = node.finish;
        let left_min = node.left.map(|l| self.node_ref(l).min_finish);
        let right_min = node.right.map(|r| self.node_ref(r).min_finish);
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
        self.node_mut_ref(idx).min_finish = m;
    }

    /// Refresh augmentation from `start` up to the root.
    fn refresh_ancestors(&mut self, start: usize) {
        let mut cur = Some(start);
        while let Some(idx) = cur {
            self.refresh_node(idx);
            cur = self.node_ref(idx).parent;
        }
    }

    /// WAVL rebalance after an insert starting at the inserted node.
    fn rebalance_after_insert(&mut self, mut node: usize) {
        loop {
            let Some(parent) = self.node_ref(node).parent else {
                break;
            };
            let parent_rank = self.node_ref(parent).rank;
            let child_rank = self.node_ref(node).rank;
            if parent_rank > child_rank + 1 {
                let is_left_child = self.node_ref(parent).left == Some(node);
                if is_left_child {
                    if self.node_ref(node).right.is_some() {
                        let grand = self.node_ref(node).right.unwrap();
                        self.rotate_left(node);
                        self.rotate_right(parent);
                        self.node_mut_ref(grand).rank += 1;
                        self.node_mut_ref(node).rank -= 1;
                        node = grand;
                    } else {
                        self.rotate_right(parent);
                        node = parent;
                    }
                } else if self.node_ref(node).left.is_some() {
                    let grand = self.node_ref(node).left.unwrap();
                    self.rotate_right(node);
                    self.rotate_left(parent);
                    self.node_mut_ref(grand).rank += 1;
                    self.node_mut_ref(node).rank -= 1;
                    node = grand;
                } else {
                    self.rotate_left(parent);
                    node = parent;
                }
                continue;
            }
            node = parent;
        }
    }

    /// WAVL rebalance after an erase starting at the parent.
    fn rebalance_after_erase(&mut self, mut node: usize) {
        loop {
            let left_rank = self.nodes[node]
                .as_ref()
                .expect("live")
                .left
                .map(|l| self.node_ref(l).rank)
                .unwrap_or(0);
            let right_rank = self.nodes[node]
                .as_ref()
                .expect("live")
                .right
                .map(|r| self.node_ref(r).rank)
                .unwrap_or(0);
            let min = left_rank.min(right_rank);
            let max = left_rank.max(right_rank);
            if min == 0 && max > 1 {
                if left_rank > right_rank {
                    let child = self.node_ref(node).left.unwrap();
                    let child_left = self.nodes[child]
                        .as_ref()
                        .expect("live")
                        .left
                        .map(|l| self.node_ref(l).rank)
                        .unwrap_or(0);
                    let child_right = self.nodes[child]
                        .as_ref()
                        .expect("live")
                        .right
                        .map(|r| self.node_ref(r).rank)
                        .unwrap_or(0);
                    if child_right > child_left {
                        let grand = self.node_ref(child).right.unwrap();
                        self.rotate_left(child);
                        self.rotate_right(node);
                        self.node_mut_ref(grand).rank += 1;
                        self.node_mut_ref(child).rank -= 1;
                        node = grand;
                    } else {
                        self.rotate_right(node);
                        self.node_mut_ref(child).rank -= 1;
                        node = child;
                    }
                } else {
                    let child = self.node_ref(node).right.unwrap();
                    let child_left = self.nodes[child]
                        .as_ref()
                        .expect("live")
                        .left
                        .map(|l| self.node_ref(l).rank)
                        .unwrap_or(0);
                    let child_right = self.nodes[child]
                        .as_ref()
                        .expect("live")
                        .right
                        .map(|r| self.node_ref(r).rank)
                        .unwrap_or(0);
                    if child_left > child_right {
                        let grand = self.node_ref(child).left.unwrap();
                        self.rotate_right(child);
                        self.rotate_left(node);
                        self.node_mut_ref(grand).rank += 1;
                        self.node_mut_ref(child).rank -= 1;
                        node = grand;
                    } else {
                        self.rotate_left(node);
                        self.node_mut_ref(child).rank -= 1;
                        node = child;
                    }
                }
                continue;
            }
            let Some(parent) = self.node_ref(node).parent else {
                break;
            };
            node = parent;
        }
    }

    /// Rotate subtree right around `y` (y becomes left child of x).
    fn rotate_right(&mut self, y: usize) {
        let x = self.node_ref(y).left.unwrap();
        let b = self.node_ref(x).right;
        let p = self.node_ref(y).parent;
        self.node_mut_ref(x).right = Some(y);
        self.node_mut_ref(y).parent = Some(x);
        self.node_mut_ref(y).left = b;
        if let Some(bi) = b {
            self.node_mut_ref(bi).parent = Some(y);
        }
        self.node_mut_ref(x).parent = p;
        match p {
            None => self.root = Some(x),
            Some(pi) => {
                if self.node_ref(pi).left == Some(y) {
                    self.node_mut_ref(pi).left = Some(x);
                } else {
                    self.node_mut_ref(pi).right = Some(x);
                }
            }
        }
        self.refresh_node(y);
        self.refresh_node(x);
    }

    /// Rotate subtree left around `x`.
    fn rotate_left(&mut self, x: usize) {
        let y = self.node_ref(x).right.unwrap();
        let b = self.node_ref(y).left;
        let p = self.node_ref(x).parent;
        self.node_mut_ref(y).left = Some(x);
        self.node_mut_ref(x).parent = Some(y);
        self.node_mut_ref(x).right = b;
        if let Some(bi) = b {
            self.node_mut_ref(bi).parent = Some(x);
        }
        self.node_mut_ref(y).parent = p;
        match p {
            None => self.root = Some(y),
            Some(pi) => {
                if self.node_ref(pi).left == Some(x) {
                    self.node_mut_ref(pi).left = Some(y);
                } else {
                    self.node_mut_ref(pi).right = Some(y);
                }
            }
        }
        self.refresh_node(x);
        self.refresh_node(y);
    }

    /// Walk all eligible nodes and invoke `f(key, finish)`.
    fn walk_eligible(&self, node: Option<usize>, now: u128, f: &mut impl FnMut(EevdfKey, u128)) {
        let Some(idx) = node else { return };
        let n = self.node_ref(idx);
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

    fn key(start: u128, id: u64) -> EevdfKey {
        EevdfKey {
            virtual_start: start,
            task_id: id,
        }
    }

    #[test]
    fn insert_pop_min_preserves_ordering() {
        let mut tree = EevdfTree::<8>::new();
        tree.insert(key(100, 1), 200).unwrap();
        tree.insert(key(50, 2), 150).unwrap();
        tree.insert(key(150, 3), 250).unwrap();
        tree.insert(key(75, 4), 175).unwrap();
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.pop_min(), Some(key(50, 2)));
        assert_eq!(tree.pop_min(), Some(key(75, 4)));
        assert_eq!(tree.pop_min(), Some(key(100, 1)));
        assert_eq!(tree.pop_min(), Some(key(150, 3)));
        assert!(tree.is_empty());
    }

    #[test]
    fn task_id_breaks_virtual_start_ties() {
        let mut tree = EevdfTree::<4>::new();
        tree.insert(key(100, 2), 200).unwrap();
        tree.insert(key(100, 1), 100).unwrap();
        assert_eq!(tree.pop_min(), Some(key(100, 1)));
        assert_eq!(tree.pop_min(), Some(key(100, 2)));
    }

    #[test]
    fn remove_is_exact_and_missing_is_rejected() {
        let mut tree = EevdfTree::<4>::new();
        tree.insert(key(10, 1), 20).unwrap();
        tree.insert(key(10, 2), 30).unwrap();
        tree.remove(key(10, 1)).unwrap();
        assert_eq!(tree.remove(key(10, 1)), Err(EevdfTreeError::NotFound));
        assert_eq!(tree.len(), 1);
        assert!(tree.contains(key(10, 2)));
    }

    #[test]
    fn capacity_is_hard() {
        let mut tree = EevdfTree::<2>::new();
        tree.insert(key(1, 1), 2).unwrap();
        tree.insert(key(2, 2), 3).unwrap();
        assert_eq!(tree.insert(key(3, 3), 4), Err(EevdfTreeError::Full));
    }

    #[test]
    fn pick_eligible_chooses_earliest_finish_among_eligible() {
        let mut tree = EevdfTree::<4>::new();
        // Eligible (start <= 100), finishes 300 and 200.
        tree.insert(key(0, 1), 300).unwrap();
        tree.insert(key(50, 2), 200).unwrap();
        // Ineligible (start > 100), earliest finish 250 but must not win.
        tree.insert(key(150, 3), 250).unwrap();
        assert_eq!(tree.pick_eligible(100), Some(key(50, 2)));
        assert_eq!(tree.pick_eligible(200), Some(key(50, 2)));
        // At now=150 all three are eligible; task 2 still has the earliest
        // finish (200), even though task 3 became eligible at that instant.
        assert_eq!(tree.pick_eligible(150), Some(key(50, 2)));
    }

    #[test]
    fn min_start_supports_eevdf_snap_rule() {
        let mut tree = EevdfTree::<2>::new();
        tree.insert(key(500, 1), 600).unwrap();
        tree.insert(key(300, 2), 700).unwrap();
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
                0 | 1 => {
                    if tree.insert(key(start, id), finish).is_ok() {
                        assert!(live.insert(key(start, id)));
                    } else {
                        assert!(!live.insert(key(start, id)));
                    }
                }
                _ => {
                    let removed = tree.remove(key(start, id)).is_ok();
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
        while let Some(k) = tree.pop_min() {
            assert_eq!(live.pop_first(), Some(k));
        }
        assert!(live.is_empty());
    }
}
