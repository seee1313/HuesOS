//! Job container objects and hierarchical resource accounting.

use crate::irq_guard::IrqSafeMutex;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::{alloc_koid, KernelObject, KernelObjectExt, Koid, ObjectType, Port, PortPacket};
use huesos_quota::{Limits, QuotaTree, QuotaTreeError, Resource, Usage};

const PORT_PACKET_QUOTA_EXHAUSTED: u32 = 3;
const MAX_QUOTA_PORTS: usize = 8;
const MAX_PENDING_QUOTA_EVENTS: usize = 256;
const EMPTY_QUOTA_EVENT: QuotaEvent = QuotaEvent {
    job: Koid::INVALID,
    resource_id: 0,
    amount: 0,
};

#[derive(Clone, Copy)]
struct QuotaEvent {
    job: Koid,
    resource_id: u64,
    amount: u64,
}

struct PendingQuotaEvents {
    events: [QuotaEvent; MAX_PENDING_QUOTA_EVENTS],
    head: usize,
    len: usize,
    dropped: u64,
}

impl PendingQuotaEvents {
    const fn new() -> Self {
        Self {
            events: [EMPTY_QUOTA_EVENT; MAX_PENDING_QUOTA_EVENTS],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, event: QuotaEvent) {
        if self.len == MAX_PENDING_QUOTA_EVENTS {
            self.dropped = self.dropped.saturating_add(1);
            self.events[self.head] = event;
            self.head = (self.head + 1) % MAX_PENDING_QUOTA_EVENTS;
            return;
        }
        let slot = (self.head + self.len) % MAX_PENDING_QUOTA_EVENTS;
        self.events[slot] = event;
        self.len += 1;
    }

    fn drain_into(&mut self, out: &mut [QuotaEvent; MAX_PENDING_QUOTA_EVENTS]) -> usize {
        let count = self.len;
        for (index, slot) in out.iter_mut().enumerate().take(count) {
            *slot = self.events[(self.head + index) % MAX_PENDING_QUOTA_EVENTS];
        }
        self.head = 0;
        self.len = 0;
        count
    }
}

static PENDING_QUOTA_EVENTS: IrqSafeMutex<PendingQuotaEvents> =
    IrqSafeMutex::new(PendingQuotaEvents::new());

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
    quota_ports: IrqSafeMutex<Vec<QuotaPortBinding>>,
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

    /// Roll back this Job's quota-tree node before the Job is published.
    pub fn rollback_unpublished_quota_node(&self) -> bool {
        self.quota_tree.lock().remove_leaf(self.quota_node).is_ok()
    }

    /// Try to charge a resource to this Job and all ancestor limits.
    pub fn charge(&self, resource: Resource, amount: u64) -> bool {
        let charged = self
            .quota_tree
            .lock()
            .try_acquire(self.quota_node, resource, amount);
        if !charged {
            enqueue_quota_exhaustion(self.koid, resource, amount);
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

    fn quota_port_snapshot(&self, out: &mut Vec<(Arc<Port>, u64)>) {
        let ports = self.quota_ports.lock();
        for binding in ports.iter() {
            out.push((Arc::clone(&binding.port), binding.key));
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

fn resource_id(resource: Resource) -> u64 {
    match resource {
        Resource::Memory => 0,
        Resource::Handles => 1,
        Resource::CpuTicks => 2,
    }
}

fn enqueue_quota_exhaustion(job: Koid, resource: Resource, amount: u64) {
    PENDING_QUOTA_EVENTS.lock().push(QuotaEvent {
        job,
        resource_id: resource_id(resource),
        amount,
    });
}

/// Deliver pending quota-exhaustion packets outside the charge path.
///
/// This must be called from ordinary process/deferred context, not while a
/// scheduler or object critical section is held. `Job::charge` may run from the
/// scheduler tick path, so it only records a bounded event and never queues a
/// Port packet directly.
pub fn flush_pending_quota_notifications() {
    let mut drained = [EMPTY_QUOTA_EVENT; MAX_PENDING_QUOTA_EVENTS];
    let count = PENDING_QUOTA_EVENTS.lock().drain_into(&mut drained);
    for event in drained.iter().copied().take(count) {
        let Some(object) = crate::lookup_object(event.job) else {
            continue;
        };
        let Some(job) = object.downcast_ref::<Job>() else {
            continue;
        };
        let mut ports: Vec<(Arc<Port>, u64)> = Vec::new();
        job.quota_port_snapshot(&mut ports);
        for (port, key) in ports {
            let _ = port.queue(PortPacket {
                key,
                packet_type: PORT_PACKET_QUOTA_EXHAUSTED,
                status: 0,
                data: [event.job.0, event.resource_id, event.amount, 0],
            });
        }
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
        crate::register_object(job.clone());
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => {
                crate::unregister_object(job.koid());
                return;
            }
        };
        assert!(job.bind_quota_port(port.clone(), 7));
        assert!(job.charge(Resource::Memory, 1));
        assert!(!job.charge(Resource::Memory, 1));
        assert_eq!(port.read(), None);
        flush_pending_quota_notifications();
        let packet = port.read();
        assert!(packet.is_some(), "exhaustion should queue a packet");
        if let Some(packet) = packet {
            assert_eq!(packet.key, 7);
            assert_eq!(packet.packet_type, PORT_PACKET_QUOTA_EXHAUSTED);
            assert_eq!(packet.data[0], job.koid().0);
            assert_eq!(packet.data[1], 0);
            assert_eq!(packet.data[2], 1);
        }
        crate::unregister_object(job.koid());
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
