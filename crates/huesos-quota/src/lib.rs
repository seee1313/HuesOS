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

extern crate alloc;
use alloc::vec::Vec;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(usize);

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
#[derive(Default)]
pub struct QuotaTree {
    nodes: Vec<Node>,
}

impl QuotaTree {
    /// An empty tree.
    pub fn new() -> Self {
        QuotaTree { nodes: Vec::new() }
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
        NodeId(id)
    }

    /// Add a child node under `parent`.
    pub fn add_child(&mut self, parent: NodeId, limits: Limits) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node { parent: Some(parent.0), children: Vec::new(), limits, used: Usage::default() });
        self.nodes[parent.0].children.push(id);
        NodeId(id)
    }

    /// Subtree usage of `node`: its own usage plus all descendants'.
    pub fn subtree_usage(&self, node: NodeId) -> Usage {
        let mut total = self.nodes[node.0].used;
        for &child in &self.nodes[node.0].children {
            total.add_usage(self.subtree_usage(NodeId(child)));
        }
        total
    }

    /// Try to acquire `amount` of `res` on `node`. Checked against the node and
    /// every ancestor's subtree usage; on success charges the node, else leaves
    /// the tree unchanged.
    pub fn try_acquire(&mut self, node: NodeId, res: Resource, amount: u64) -> bool {
        let mut cur = Some(node.0);
        while let Some(idx) = cur {
            let limit = self.nodes[idx].limits.for_resource(res);
            let subtree = self.subtree_usage(NodeId(idx)).for_resource(res);
            if limit != UNLIMITED && subtree.saturating_add(amount) > limit {
                return false;
            }
            cur = self.nodes[idx].parent;
        }
        self.nodes[node.0].used.add(res, amount);
        true
    }

    /// Release `amount` of `res` from `node` (saturating at zero).
    pub fn release(&mut self, node: NodeId, res: Resource, amount: u64) {
        self.nodes[node.0].used.sub(res, amount);
    }

    /// A node's own usage.
    pub fn used(&self, node: NodeId) -> Usage {
        self.nodes[node.0].used
    }

    /// A node's limits.
    pub fn limits(&self, node: NodeId) -> Limits {
        self.nodes[node.0].limits
    }

    /// Replace a node's limits.
    pub fn set_limits(&mut self, node: NodeId, limits: Limits) {
        self.nodes[node.0].limits = limits;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_limits(max: u64) -> Limits {
        Limits { max_memory: max, max_handles: UNLIMITED, max_cpu_ticks: UNLIMITED }
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
        assert_eq!(t.subtree_usage(root).memory, 60);
    }

    #[test]
    fn parent_limit_constrains_child() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100)); // parent caps total at 100
        let child = t.add_child(root, mem_limits(UNLIMITED)); // child itself unbounded
        // Child can use up to the parent's 100.
        assert!(t.try_acquire(child, Resource::Memory, 60));
        assert!(t.try_acquire(child, Resource::Memory, 40));
        // Now the parent's subtree is at 100; further acquisition is denied by
        // the ancestor even though the child's own limit is unlimited.
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        assert_eq!(t.subtree_usage(root).memory, 100);
    }

    #[test]
    fn siblings_share_parent_budget() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        let a = t.add_child(root, mem_limits(UNLIMITED));
        let b = t.add_child(root, mem_limits(UNLIMITED));
        assert!(t.try_acquire(a, Resource::Memory, 70));
        // b can only get 30 more before the parent's 100 is exhausted.
        assert!(t.try_acquire(b, Resource::Memory, 30));
        assert!(!t.try_acquire(b, Resource::Memory, 1));
        assert!(!t.try_acquire(a, Resource::Memory, 1));
        assert_eq!(t.subtree_usage(root).memory, 100);
    }

    #[test]
    fn child_own_limit_also_enforced() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(1000)); // generous parent
        let child = t.add_child(root, mem_limits(50)); // tight child
        assert!(t.try_acquire(child, Resource::Memory, 50));
        // Child's own 50 limit denies this, even though the parent has room.
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        assert_eq!(t.used(child).memory, 50);
    }

    #[test]
    fn release_on_child_frees_parent_budget() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        let child = t.add_child(root, mem_limits(UNLIMITED));
        assert!(t.try_acquire(child, Resource::Memory, 100));
        assert!(!t.try_acquire(child, Resource::Memory, 1));
        t.release(child, Resource::Memory, 40);
        assert_eq!(t.subtree_usage(root).memory, 60);
        assert!(t.try_acquire(child, Resource::Memory, 40));
    }

    #[test]
    fn three_level_hierarchy() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(200));
        let mid = t.add_child(root, mem_limits(120));
        let leaf = t.add_child(mid, mem_limits(UNLIMITED));
        // leaf is bounded by mid (120) and root (200).
        assert!(t.try_acquire(leaf, Resource::Memory, 120));
        assert!(!t.try_acquire(leaf, Resource::Memory, 1)); // mid's 120 caps it
        assert_eq!(t.subtree_usage(root).memory, 120);
        assert_eq!(t.subtree_usage(mid).memory, 120);
    }

    #[test]
    fn set_limits_tightens() {
        let mut t = QuotaTree::new();
        let root = t.add_root(mem_limits(100));
        assert!(t.try_acquire(root, Resource::Memory, 80));
        t.set_limits(root, mem_limits(50)); // tighten below current usage
        assert!(!t.try_acquire(root, Resource::Memory, 1));
        assert_eq!(t.limits(root).max_memory, 50);
    }
}
