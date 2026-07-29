//! Job container objects and hierarchical resource accounting.

use crate::irq_guard::IrqSafeMutex;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::{alloc_koid, KernelObject, Koid, ObjectType, Port, PortPacket};
use huesos_quota::{Limits, QuotaTree, QuotaTreeError, Resource, Usage};

const PORT_PACKET_QUOTA_EXHAUSTED: u32 = 3;
const MAX_QUOTA_PORTS: usize = 8;

struct QuotaPortBinding {
    port: Arc<Port>,
    key: u64,
}

/// Failure while creating a child Job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobError {
    /// The parent node was invalid or belonged to another quota tree.
    InvalidParent,
}

/// Job — container of processes and a node in the resource-quota hierarchy.
pub struct Job {
    koid: Koid,
    name: IrqSafeMutex<String>,
    parent: Option<Arc<Job>>,
    quota_tree: Arc<IrqSafeMutex<QuotaTree>>,
    quota_node: huesos_quota::NodeId,
    quota_ports: IrqSafeMutex<alloc::vec::Vec<QuotaPortBinding>>,
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
            name: IrqSafeMutex::new(String::from("root")),
            parent: None,
            quota_tree: Arc::new(IrqSafeMutex::new(tree)),
            quota_node: node,
            quota_ports: IrqSafeMutex::new(alloc::vec::Vec::new()),
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
            name: IrqSafeMutex::new(String::from(name)),
            parent: Some(Arc::clone(parent)),
            quota_tree: Arc::clone(&parent.quota_tree),
            quota_node: node,
            quota_ports: IrqSafeMutex::new(alloc::vec::Vec::new()),
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
        let charged = self
            .quota_tree
            .lock()
            .try_acquire(self.quota_node, resource, amount);
        if !charged {
            self.notify_quota_exhausted(resource, amount);
        }
        charged
    }

    /// Release a previously charged resource.
    pub fn release(&self, resource: Resource, amount: u64) -> bool {
        self.quota_tree
            .lock()
            .release(self.quota_node, resource, amount)
    }

    /// Current limits for this Job node.
    pub fn limits(&self) -> Result<Limits, QuotaTreeError> {
        self.quota_tree.lock().limits(self.quota_node)
    }

    /// Replace limits for this Job node.
    pub fn set_limits(&self, limits: Limits) -> bool {
        self.quota_tree.lock().set_limits(self.quota_node, limits)
    }

    /// Bind a Port to receive quota-exhaustion packets for this Job.
    pub fn bind_quota_port(&self, port: Arc<Port>, key: u64) -> bool {
        let mut ports = self.quota_ports.lock();
        if ports.len() >= MAX_QUOTA_PORTS || ports.try_reserve_exact(1).is_err() {
            return false;
        }
        ports.push(QuotaPortBinding { port, key });
        true
    }

    /// Notify observers that a charge failed.
    pub fn notify_quota_exhausted(&self, resource: Resource, amount: u64) {
        let resource_id = match resource {
            Resource::Memory => 0,
            Resource::Handles => 1,
            Resource::CpuTicks => 2,
        };
        let ports = self.quota_ports.lock();
        for binding in ports.iter() {
            let _ = binding.port.queue(PortPacket {
                key: binding.key,
                packet_type: PORT_PACKET_QUOTA_EXHAUSTED,
                status: 0,
                data: [self.koid.0, resource_id, amount, 0],
            });
        }
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
    fn cpu_tick_budget_is_accounted() {
        let root = Job::root_with_limits(Limits {
            max_memory: huesos_quota::UNLIMITED,
            max_handles: huesos_quota::UNLIMITED,
            max_cpu_ticks: 1,
        });
        assert!(root.charge(Resource::CpuTicks, 1));
        assert!(!root.charge(Resource::CpuTicks, 1));
        assert_eq!(root.usage().map(|usage| usage.cpu_ticks), Ok(1));
    }

    #[test]
    fn quota_exhaustion_queues_bound_port_packet() {
        let job = Job::root_with_limits(Limits {
            max_memory: 1,
            max_handles: huesos_quota::UNLIMITED,
            max_cpu_ticks: huesos_quota::UNLIMITED,
        });
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => return,
        };
        assert!(job.bind_quota_port(port.clone(), 7));
        assert!(job.charge(Resource::Memory, 1));
        assert!(!job.charge(Resource::Memory, 1));
        let packet = port.read();
        assert!(packet.is_some(), "exhaustion should queue a packet");
        if let Some(packet) = packet {
            assert_eq!(packet.key, 7);
            assert_eq!(packet.packet_type, PORT_PACKET_QUOTA_EXHAUSTED);
            assert_eq!(packet.data[0], job.koid().0);
            assert_eq!(packet.data[1], 0);
            assert_eq!(packet.data[2], 1);
        }
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
