//! Queue and DMA layout planning for the userspace NVMe DriverHost.

/// Production baseline queue depth for admin and I/O queues.
pub const HUESOS_NVME_QUEUE_DEPTH: u16 = 256;
/// Size of one NVMe submission queue entry.
pub const SQE_BYTES: u64 = 64;
/// Size of one NVMe completion queue entry.
pub const CQE_BYTES: u64 = 16;
/// PRP-list pages reserved per CPU queue in the first no-heap design.
///
/// Request slots are 256 deep, but not every in-flight request needs a PRP
/// list page: single/two-page transfers use PRP1/PRP2 directly, and larger
/// transfers borrow pages from this bounded per-CPU pool.
pub const PRP_LIST_PAGES_PER_CPU: u64 = 16;
/// Size of one PRP-list page.
pub const PRP_LIST_PAGE_BYTES: u64 = 4096;

/// Interrupt strategy selected for this controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptMode {
    /// MSI-X vectors are available; prefer one vector per I/O queue.
    Msix,
    /// MSI only; queues share a smaller interrupt set.
    Msi,
    /// No usable interrupt mode; bounded polling fallback.
    Polling,
}

/// Inputs discovered before queue creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuePlanInput {
    /// Number of online dense CPUs.
    pub cpu_count: usize,
    /// Controller CAP.MQES value (zero-based max queue entries).
    pub cap_mqes: u16,
    /// Whether MSI-X setup succeeded.
    pub msix_available: bool,
    /// Whether MSI setup succeeded.
    pub msi_available: bool,
}

/// Planned queue topology and DMA footprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuePlan {
    /// Admin queue depth.
    pub admin_depth: u16,
    /// Per-CPU I/O queue depth.
    pub io_depth: u16,
    /// Number of I/O queue pairs.
    pub io_queue_count: usize,
    /// Selected interrupt mode.
    pub interrupt_mode: InterruptMode,
    /// Bytes needed for admin SQ/CQ.
    pub admin_queue_bytes: u64,
    /// Bytes needed for all I/O SQ/CQ pairs.
    pub io_queue_bytes: u64,
    /// Bytes reserved for the bounded PRP-list page pool.
    pub prp_list_bytes: u64,
}

impl QueuePlan {
    /// Total DMA bytes required by the planned queues and PRP-list pool.
    pub fn total_dma_bytes(&self) -> u64 {
        self.admin_queue_bytes
            .saturating_add(self.io_queue_bytes)
            .saturating_add(self.prp_list_bytes)
    }
}

/// Build the first production queue plan.
pub fn plan_queues(input: QueuePlanInput) -> Option<QueuePlan> {
    let max_entries = u32::from(input.cap_mqes)
        .saturating_add(1)
        .min(u32::from(u16::MAX));
    if max_entries == 0 || input.cpu_count == 0 {
        return None;
    }
    let depth = HUESOS_NVME_QUEUE_DEPTH.min(max_entries as u16).max(2);
    let io_queue_count = input.cpu_count.clamp(1, 64);
    let interrupt_mode = if input.msix_available {
        InterruptMode::Msix
    } else if input.msi_available {
        InterruptMode::Msi
    } else {
        InterruptMode::Polling
    };
    let admin_queue_bytes = queue_pair_bytes(depth)?;
    let one_io = queue_pair_bytes(depth)?;
    let io_queue_bytes = one_io.checked_mul(io_queue_count as u64)?;
    let prp_list_bytes = PRP_LIST_PAGE_BYTES
        .checked_mul(PRP_LIST_PAGES_PER_CPU)?
        .checked_mul(io_queue_count as u64)?;
    Some(QueuePlan {
        admin_depth: depth,
        io_depth: depth,
        io_queue_count,
        interrupt_mode,
        admin_queue_bytes,
        io_queue_bytes,
        prp_list_bytes,
    })
}

fn queue_pair_bytes(depth: u16) -> Option<u64> {
    let depth = u64::from(depth);
    depth
        .checked_mul(SQE_BYTES)?
        .checked_add(depth.checked_mul(CQE_BYTES)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_per_cpu_queues_depth_256() {
        let Some(plan) = plan_queues(QueuePlanInput {
            cpu_count: 4,
            cap_mqes: 1023,
            msix_available: true,
            msi_available: true,
        }) else {
            assert!(false, "plan should exist");
            return;
        };
        assert_eq!(plan.admin_depth, 256);
        assert_eq!(plan.io_depth, 256);
        assert_eq!(plan.io_queue_count, 4);
        assert_eq!(plan.interrupt_mode, InterruptMode::Msix);
    }

    #[test]
    fn clamps_depth_to_controller_capacity() {
        let Some(plan) = plan_queues(QueuePlanInput {
            cpu_count: 2,
            cap_mqes: 63,
            msix_available: false,
            msi_available: true,
        }) else {
            assert!(false, "plan should exist");
            return;
        };
        assert_eq!(plan.admin_depth, 64);
        assert_eq!(plan.io_depth, 64);
        assert_eq!(plan.interrupt_mode, InterruptMode::Msi);
    }

    #[test]
    fn falls_back_to_polling() {
        let Some(plan) = plan_queues(QueuePlanInput {
            cpu_count: 1,
            cap_mqes: 255,
            msix_available: false,
            msi_available: false,
        }) else {
            assert!(false, "plan should exist");
            return;
        };
        assert_eq!(plan.interrupt_mode, InterruptMode::Polling);
    }

    #[test]
    fn rejects_zero_cpus() {
        assert_eq!(
            plan_queues(QueuePlanInput {
                cpu_count: 0,
                cap_mqes: 255,
                msix_available: true,
                msi_available: true,
            }),
            None
        );
    }

    #[test]
    fn handles_minimal_queue_capacity() {
        assert_eq!(
            plan_queues(QueuePlanInput {
                cpu_count: 1,
                cap_mqes: 0,
                msix_available: true,
                msi_available: true,
            })
            .map(|plan| plan.admin_depth),
            Some(2)
        );
    }

    #[test]
    fn fits_inside_sixty_four_mib_pool_for_64_cpus() {
        let Some(plan) = plan_queues(QueuePlanInput {
            cpu_count: 64,
            cap_mqes: 1023,
            msix_available: true,
            msi_available: true,
        }) else {
            assert!(false, "plan should exist");
            return;
        };
        assert!(plan.total_dma_bytes() < 64 * 1024 * 1024);
    }
}
