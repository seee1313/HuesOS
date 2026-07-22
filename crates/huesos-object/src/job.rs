//! Job container objects and hierarchical resource accounting.

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};
use huesos_quota::{Limits, QuotaTree, QuotaTreeError, Resource, Usage};

/// Failure while creating a child Job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobError {
    /// The parent node was invalid or belonged to another quota tree.
    InvalidParent,
}

/// Job — container of processes and a node in the resource-quota hierarchy.
pub struct Job {
    koid: Koid,
    name: Mutex<String>,
    parent: Option<Arc<Job>>,
    quota_tree: Arc<Mutex<QuotaTree>>,
    quota_node: huesos_quota::NodeId,
}

impl Job {
    /// Create the unlimited root job.
    pub fn root() -> Arc<Self> {
        Self::root_with_limits(Limits::unlimited())
    }

    /// Create the root job with explicit resource limits.
    pub fn root_with_limits(limits: Limits) -> Arc<Self> {
        let mut tree = QuotaTree::new();
        let node = tree.add_root(limits);
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from("root")),
            parent: None,
            quota_tree: Arc::new(Mutex::new(tree)),
            quota_node: node,
        })
    }

    /// Create a child Job under `parent`.
    pub fn child(parent: &Arc<Self>, name: &str, limits: Limits) -> Result<Arc<Self>, JobError> {
        let node = parent
            .quota_tree
            .lock()
            .add_child(parent.quota_node, limits)
            .map_err(|_| JobError::InvalidParent)?;
        Ok(Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from(name)),
            parent: Some(Arc::clone(parent)),
            quota_tree: Arc::clone(&parent.quota_tree),
            quota_node: node,
        }))
    }

    /// Job koid.
    pub const fn koid(&self) -> Koid {
        self.koid
    }

    /// Job name.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    /// Parent Job, if this is not the root.
    pub fn parent(&self) -> Option<Arc<Job>> {
        self.parent.clone()
    }

    /// Try to charge a resource to this Job and all ancestor limits.
    pub fn charge(&self, resource: Resource, amount: u64) -> bool {
        self.quota_tree
            .lock()
            .try_acquire(self.quota_node, resource, amount)
    }

    /// Release a previously charged resource.
    pub fn release(&self, resource: Resource, amount: u64) -> bool {
        self.quota_tree
            .lock()
            .release(self.quota_node, resource, amount)
    }

    /// Usage charged directly to this Job node.
    pub fn usage(&self) -> Result<Usage, QuotaTreeError> {
        self.quota_tree.lock().used(self.quota_node)
    }

    /// Aggregate usage of this Job and all descendants.
    pub fn subtree_usage(&self) -> Result<Usage, QuotaTreeError> {
        self.quota_tree.lock().subtree_usage(self.quota_node)
    }
}

impl KernelObject for Job {
    fn object_type(&self) -> ObjectType {
        ObjectType::Job
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_limits(bytes: u64) -> Limits {
        Limits {
            max_memory: bytes,
            max_handles: huesos_quota::UNLIMITED,
            max_cpu_ticks: huesos_quota::UNLIMITED,
        }
    }

    #[test]
    fn child_jobs_share_parent_memory_budget() {
        let root = Job::root_with_limits(memory_limits(100));
        let left = match Job::child(&root, "left", Limits::unlimited()) {
            Ok(job) => job,
            Err(_) => return,
        };
        let right = match Job::child(&root, "right", Limits::unlimited()) {
            Ok(job) => job,
            Err(_) => return,
        };
        assert!(left.charge(Resource::Memory, 70));
        assert!(right.charge(Resource::Memory, 30));
        assert!(!right.charge(Resource::Memory, 1));
        assert_eq!(root.subtree_usage().map(|usage| usage.memory), Ok(100));
    }

    #[test]
    fn release_returns_capacity_to_parent() {
        let root = Job::root_with_limits(memory_limits(100));
        let child = match Job::child(&root, "child", Limits::unlimited()) {
            Ok(job) => job,
            Err(_) => return,
        };
        assert!(child.charge(Resource::Memory, 100));
        assert!(!child.charge(Resource::Memory, 1));
        assert!(child.release(Resource::Memory, 40));
        assert!(child.charge(Resource::Memory, 40));
    }
}
