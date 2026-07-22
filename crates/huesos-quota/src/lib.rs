//! # huesos-quota — resource quotas for capability/resource limits
//!
//! Models the resource-accounting half of ROADMAP Medium-Term #8 (Job-based
//! CPU-time / memory / handle-count quotas). A `Quota` bounds a single owner's
//! usage; a `QuotaTree` enforces a Job hierarchy, where acquiring a resource on
//! a node is checked against that node's own limit *and* every ancestor's
//! subtree usage (so a parent Job constrains all of its children).
//!
//! Pure `no_std` + `alloc`; budget-neutral (no unsafe/unwrap/expect/panic).

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Unlimited sentinel for a resource limit.
pub const UNLIMITED: u64 = u64::MAX;

/// A trackable resource kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Memory in bytes.
    Memory,
    /// Handle count.
    Handles,
    /// CPU time in scheduler ticks.
    CpuTicks,
}

/// Resource limits. `UNLIMITED` disables a bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum memory in bytes.
    pub max_memory: u64,
    /// Maximum number of handles.
    pub max_handles: u64,
    /// Maximum CPU time in ticks.
    pub max_cpu_ticks: u64,
}

impl Limits {
    /// No limits on anything.
    pub const fn unlimited() -> Self {
        Limits { max_memory: UNLIMITED, max_handles: UNLIMITED, max_cpu_ticks: UNLIMITED }
    }
    /// The limit for a given resource.
    pub fn for_resource(&self, res: Resource) -> u64 {
        match res {
            Resource::Memory => self.max_memory,
            Resource::Handles => self.max_handles,
            Resource::CpuTicks => self.max_cpu_ticks,
        }
    }
}

/// Current resource usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Usage {
    /// Memory in bytes.
    pub memory: u64,
    /// Handle count.
    pub handles: u64,
    /// CPU time in ticks.
    pub cpu_ticks: u64,
}

impl Usage {
    /// The usage value for a given resource.
    pub fn for_resource(&self, res: Resource) -> u64 {
        match res {
            Resource::Memory => self.memory,
            Resource::Handles => self.handles,
            Resource::CpuTicks => self.cpu_ticks,
        }
    }
    /// Add `amount` to a resource (saturating).
    pub fn add(&mut self, res: Resource, amount: u64) {
        let slot = self.slot_mut(res);
        *slot = slot.saturating_add(amount);
    }
    /// Subtract `amount` from a resource (saturating at zero).
    pub fn sub(&mut self, res: Resource, amount: u64) {
        let slot = self.slot_mut(res);
        *slot = slot.saturating_sub(amount);
    }
    /// Sum two usages (saturating).
    pub fn add_usage(&mut self, other: Usage) {
        self.memory = self.memory.saturating_add(other.memory);
        self.handles = self.handles.saturating_add(other.handles);
        self.cpu_ticks = self.cpu_ticks.saturating_add(other.cpu_ticks);
    }
    fn slot_mut(&mut self, res: Resource) -> &mut u64 {
        match res {
            Resource::Memory => &mut self.memory,
            Resource::Handles => &mut self.handles,
            Resource::CpuTicks => &mut self.cpu_ticks,
        }
    }
}

/// A flat (single-owner) resource quota.
#[derive(Clone, Copy, Debug)]
pub struct Quota {
    limits: Limits,
    used: Usage,
}

impl Quota {
    /// A quota with the given limits and zero usage.
    pub fn new(limits: Limits) -> Self {
        Quota { limits, used: Usage::default() }
    }
    /// Current limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Current usage.
    pub fn used(&self) -> Usage {
        self.used
    }
    /// Remaining capacity for a resource (saturating; `UNLIMITED` if unbounded).
    pub fn remaining(&self, res: Resource) -> u64 {
        let limit = self.limits.for_resource(res);
        if limit == UNLIMITED {
            UNLIMITED
        } else {
            limit.saturating_sub(self.used.for_resource(res))
        }
    }
    /// True if `amount` of `res` fits within the limit.
    pub fn fits(&self, res: Resource, amount: u64) -> bool {
        let limit = self.limits.for_resource(res);
        limit == UNLIMITED || self.used.for_resource(res).saturating_add(amount) <= limit
    }
    /// Try to acquire `amount` of `res`. On success, records the usage and
    /// returns true; otherwise leaves usage unchanged and returns false.
    pub fn try_acquire(&mut self, res: Resource, amount: u64) -> bool {
        if self.fits(res, amount) {
            self.used.add(res, amount);
            true
        } else {
            false
        }
    }
    /// Release `amount` of `res` (saturating at zero).
    pub fn release(&mut self, res: Resource, amount: u64) {
        self.used.sub(res, amount);
    }
    /// True if usage is within all limits.
    pub fn within_limits(&self) -> bool {
        self.fits(Resource::Memory, 0)
            && self.fits(Resource::Handles, 0)
            && self.fits(Resource::CpuTicks, 0)
    }
}

/// A node identifier in a [`QuotaTree`].
///
/// The tree tag prevents accidentally using a node from one quota tree with a
/// different tree. Invalid/cross-tree IDs are rejected by every public tree
/// operation instead of indexing and panicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId {
    index: usize,
    tree_id: u64,
}

impl NodeId {
    /// An invalid sentinel useful to callers that need a non-panicking fallback.
    pub const INVALID: NodeId = NodeId {
        index: usize::MAX,
        tree_id: 0,
    };
}

/// Error returned when a node does not belong to the target tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaTreeError {
    /// The node is out of range or was created by another tree.
    InvalidNode,
}

struct Node {
    parent: Option<usize>,
    children: Vec<usize>,
    limits: Limits,
    used: Usage,
}

/// A hierarchical resource-quota tree (the Job-tree model).
///
/// Each node has its own limits and usage. Acquiring a resource on a node is
/// checked against that node's limit and every ancestor's *subtree* usage, so a
/// parent Job's limit constrains the aggregate of all its descendants.
pub struct QuotaTree {
    nodes: Vec<Node>,
    tree_id: u64,
}

impl Default for QuotaTree {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaTree {
    /// An empty tree.
    pub fn new() -> Self {
        static NEXT_TREE_ID: AtomicU64 = AtomicU64::new(1);
        let tree_id = NEXT_TREE_ID.fetch_add(1, Ordering::Relaxed).max(1);
        QuotaTree {
            nodes: Vec::new(),
            tree_id,
        }
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when the tree has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Add a root node (no parent).
    pub fn add_root(&mut self, limits: Limits) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node { parent: None, children: Vec::new(), limits, used: Usage::default() });
        NodeId {
            index: id,
            tree_id: self.tree_id,
        }
    }

    fn index_of(&self, node: NodeId) -> Result<usize, QuotaTreeError> {
        if node.tree_id != self.tree_id || node.index >= self.nodes.len() {
            Err(QuotaTreeError::InvalidNode)
        } else {
            Ok(node.index)
        }
    }

    /// Add a child node under `parent`.
    pub fn add_child(&mut self, parent: NodeId, limits: Limits) -> Result<NodeId, QuotaTreeError> {
        let parent_index = self.index_of(parent)?;
        let id = self.nodes.len();
        self.nodes.push(Node { parent: Some(parent_index), children: Vec::new(), limits, used: Usage::default() });
        self.nodes[parent_index].children.push(id);
        Ok(NodeId {
            index: id,
            tree_id: self.tree_id,
        })
    }

    fn subtree_usage_index(&self, index: usize) -> Usage {
        let mut total = self.nodes[index].used;
        for &child in &self.nodes[index].children {
            total.add_usage(self.subtree_usage_index(child));
        }
        total
    }

    /// Subtree usage of `node`, or [`QuotaTreeError::InvalidNode`].
    pub fn subtree_usage(&self, node: NodeId) -> Result<Usage, QuotaTreeError> {
        let index = self.index_of(node)?;
        Ok(self.subtree_usage_index(index))
    }

    /// Try to acquire `amount` of `res` on `node`. Checked against the node and
    /// every ancestor's subtree usage; on success charges the node, else leaves
    /// the tree unchanged.
    pub fn try_acquire(&mut self, node: NodeId, res: Resource, amount: u64) -> bool {
        let Ok(index) = self.index_of(node) else {
            return false;
        };
        let mut cur = Some(index);
        while let Some(idx) = cur {
            let limit = self.nodes[idx].limits.for_resource(res);
            let subtree = self.subtree_usage_index(idx).for_resource(res);
            if limit != UNLIMITED && subtree.saturating_add(amount) > limit {
                return false;
            }
            cur = self.nodes[idx].parent;
        }
        self.nodes[index].used.add(res, amount);
        true
    }

    /// Release `amount` of `res` from `node` (saturating at zero). Returns
    /// false when `node` is invalid.
    pub fn release(&mut self, node: NodeId, res: Resource, amount: u64) -> bool {
        let Ok(index) = self.index_of(node) else {
            return false;
        };
        self.nodes[index].used.sub(res, amount);
        true
    }

    /// A node's own usage.
    pub fn used(&self, node: NodeId) -> Result<Usage, QuotaTreeError> {
        Ok(self.nodes[self.index_of(node)?].used)
    }

    /// A node's limits.
    pub fn limits(&self, node: NodeId) -> Result<Limits, QuotaTreeError> {
        Ok(self.nodes[self.index_of(node)?].limits)
    }

    /// Replace a node's limits. Returns false when `node` is invalid.
    pub fn set_limits(&mut self, node: NodeId, limits: Limits) -> bool {
        let Ok(index) = self.index_of(node) else {
            return false;
        };
        self.nodes[index].limits = limits;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_limits(max: u64) -> Limits {
        Limits { max_memory: max, max_handles: UNLIMITED, max_cpu_ticks: UNLIMITED }
    }

    fn child(t: &mut QuotaTree, parent: NodeId, limits: Limits) -> NodeId {
        match t.add_child(parent, limits) {
            Ok(node) => node,
            Err(_) => NodeId::INVALID,
        }
    }

    fn subtree_memory(t: &QuotaTree, node: NodeId) -> u64 {
        match t.subtree_usage(node) {
            Ok(usage) => usage.memory,
            Err(_) => 0,
        }
    }

    // --- flat Quota ---

    #[test]
    fn quota_acquire_within_limit() {
        let mut q = Quota::new(mem_limits(1000));
        assert!(q.try_acquire(Resource::Memory, 600));
        assert_eq!(q.used().memory, 600);
        assert_eq!(q.remaining(Resource::Memory), 400);
        // 600 + 500 > 1000 -> rejected, usage unchanged.
        assert!(!q.try_acquire(Resource::Memory, 500));
        assert_eq!(q.used().memory, 600);
        // 600 + 400 == 1000 -> ok (<=).
        assert!(q.try_acquire(Resource::Memory, 400));
        assert_eq!(q.used().memory, 1000);
        assert_eq!(q.remaining(Resource::Memory), 0);
    }

    #[test]
    fn quota_release_frees_capacity() {
        let mut q = Quota::new(mem_limits(100));
        assert!(q.try_acquire(Resource::Memory, 100));
        assert!(!q.try_acquire(Resource::Memory, 1));
        q.release(Resource::Memory, 50);
        assert_eq!(q.used().memory, 50);
        assert!(q.try_acquire(Resource::Memory, 50));
    }

    #[test]
    fn quota_release_saturates_at_zero() {
        let mut q = Quota::new(mem_limits(100));
        q.release(Resource::Memory, 999); // nothing acquired
        assert_eq!(q.used().memory, 0);
    }

    #[test]
    fn unlimited_never_rejects() {
        let mut q = Quota::new(Limits::unlimited());
        assert!(q.try_acquire(Resource::Memory, u64::MAX / 2));
        assert!(q.try_acquire(Resource::Memory, u64::MAX / 2));
        assert_eq!(q.remaining(Resource::Memory), UNLIMITED);
    }

    #[test]
    fn quota_tracks_each_resource_independently() {
        let mut q = Quota::new(Limits { max_memory: 100, max_handles: 2, max_cpu_ticks: UNLIMITED });
        assert!(q.try_acquire(Resource::Handles, 2));
        assert!(!q.try_acquire(Resource::Handles, 1)); // handles exhausted
        assert!(q.try_acquire(Resource::Memory, 100)); // memory independent
        assert!(q.within_limits());
    }

    // --- hierarchical QuotaTree ---

    #[test]
    fn tree_single_node_behaves_like_flat_quota() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        assert!(t.try_acquire(root, Resource::Memory, 60));
        assert!(!t.try_acquire(root, Resource::Memory, 50));
        assert_eq!(subtree_memory(&t, root), 60);
    }

    #[test]
    fn parent_limit_constrains_child() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100)); // parent caps total at 100
        let child = child(&mut t, root, mem_limits(UNLIMITED)); // child itself unbounded
        // Child can use up to the parent's 100.
        assert!(t.try_acquire(child, Resource::Memory, 60));
        assert!(t.try_acquire(child, Resource::Memory, 40));
        // Now the parent's subtree is at 100; further acquisition is denied by
        // the ancestor even though the child's own limit is unlimited.
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        assert_eq!(subtree_memory(&t, root), 100);
    }

    #[test]
    fn siblings_share_parent_budget() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        let a = child(&mut t, root, mem_limits(UNLIMITED));
        let b = child(&mut t, root, mem_limits(UNLIMITED));
        assert!(t.try_acquire(a, Resource::Memory, 70));
        // b can only get 30 more before the parent's 100 is exhausted.
        assert!(t.try_acquire(b, Resource::Memory, 30));
        assert!(!t.try_acquire(b, Resource::Memory, 1));
        assert!(!t.try_acquire(a, Resource::Memory, 1));
        assert_eq!(subtree_memory(&t, root), 100);
    }

    #[test]
    fn child_own_limit_also_enforced() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(1000)); // generous parent
        let child = child(&mut t, root, mem_limits(50)); // tight child
        assert!(t.try_acquire(child, Resource::Memory, 50));
        // Child's own 50 limit denies this, even though the parent has room.
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        assert_eq!(t.used(child).map(|usage| usage.memory), Some(50));
    }

    #[test]
    fn release_on_child_frees_parent_budget() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        let child = child(&mut t, root, mem_limits(UNLIMITED));
        assert!(t.try_acquire(child, Resource::Memory, 100));
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        t.release(child, Resource::Memory, 40);
        assert_eq!(subtree_memory(&t, root), 60);
        assert!(t.try_acquire(child, Resource::Memory, 40));
    }

    #[test]
    fn three_level_hierarchy() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(200));
        let mid = child(&mut t, root, mem_limits(120));
        let leaf = child(&mut t, mid, mem_limits(UNLIMITED));
        // leaf is bounded by mid (120) and root (200).
        assert!(t.try_acquire(leaf, Resource::Memory, 120));
        assert!(!t.try_acquire(leaf, Resource::Memory, 1)); // mid's 120 caps it
        assert_eq!(subtree_memory(&t, root), 120);
        assert_eq!(subtree_memory(&t, mid), 120);
    }

    #[test]
    fn set_limits_tightens() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        assert!(t.try_acquire(root, Resource::Memory, 80));
        t.set_limits(root, mem_limits(50)); // tighten below current usage
        assert!(!t.try_acquire(root, Resource::Memory, 1));
        assert_eq!(t.limits(root).map(|limits| limits.max_memory), Some(50));
    }
    #[test]
    fn cross_tree_and_invalid_nodes_are_rejected_without_panicking() {
        let mut first = QuotaTree::new();
        let root = first.add_root(mem_limits(10));
        let mut second = QuotaTree::new();
        assert_eq!(second.add_child(root, mem_limits(10)), Err(QuotaTreeError::InvalidNode));
        assert_eq!(second.subtree_usage(root), Err(QuotaTreeError::InvalidNode));
        assert!(!second.try_acquire(root, Resource::Memory, 1));
        assert!(!second.release(root, Resource::Memory, 1));
        assert_eq!(second.used(root), Err(QuotaTreeError::InvalidNode));
        assert_eq!(second.limits(root), Err(QuotaTreeError::InvalidNode));
        assert!(!second.set_limits(root, mem_limits(1)));
        assert!(!second.try_acquire(NodeId::INVALID, Resource::Memory, 1));
    }

}
