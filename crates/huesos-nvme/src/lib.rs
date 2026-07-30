//! # huesos-nvme — NVMe protocol and driver
//!
//! NVMe support for a ring-3 DriverHost (ROADMAP Short-Term #7). This first
//! slice is the **host-testable protocol foundation**:
//!
//! - [`regs`]: controller register map (BAR0) and bitfield helpers (CAP/CC/
//!   CSTS/AQA, doorbell offsets).
//! - [`cmd`]: submission/completion queue entry structures, admin + NVM I/O
//!   opcodes, status decoding, Identify/Set-Features constants, and SQE
//!   builders.
//! - [`prp`]: PRP (Physical Region Page) layout computation for Read/Write.
//!
//! Everything here is pure `no_std` + `core` and unit-tested on the host. The
//! async controller (built on `hues-async`), the block service, and the kernel
//! MMIO/DMA plumbing are layered on top; see `docs/NVME.md` for the design and
//! the on-target follow-ups.
#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

pub mod async_controller;
pub mod block;
pub mod block_async;
pub mod block_client;
pub mod buffer_pool;
pub mod cmd;
pub mod controller;
pub mod device;
pub mod identify;
pub mod pci_transport;
pub mod prp;
pub mod queue_plan;
pub mod queues;
pub mod regs;
pub mod reliability;
pub mod transport;

pub use async_controller::{AsyncController, InterruptController, PollingInterrupts};
pub use block::{BlockDevice, BlockInfo, BlockOp};
pub use block_async::{
    completion_data, decode_completion_data, AsyncBlockOp, AsyncBlockRequest, AsyncBlockStatus,
};
pub use block_client::{
    ClientRequest, ClientRequestTracker, ClientTrackerError, MatchedCompletion,
};
pub use buffer_pool::DmaBufferPool;
pub use cmd::{Cqe, Sqe};
pub use controller::{Controller, ControllerConfig, ControllerInitInfo, NvmeError};
pub use device::{BarRegion, DeviceResources, DmaRegion};
pub use identify::{parse_controller, parse_namespace, ControllerInfo, NamespaceInfo};
pub use pci_transport::PciMmioTransport;
pub use queue_plan::{plan_queues, InterruptMode, QueuePlan, QueuePlanInput};
pub use queues::{QueueManager, QueueSelector};
pub use reliability::{
    validate_maintenance, MaintenanceOp, NvmeTelemetry, QueueSlot, QueueSlotTracker,
    ReliabilityError, ResetController, ResetState,
};
pub use transport::{MockNvme, NvmeTransport};
