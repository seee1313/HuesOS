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

pub mod block;
pub mod cmd;
pub mod controller;
pub mod device;
pub mod prp;
pub mod regs;
pub mod transport;

pub use block::{BlockDevice, BlockInfo, BlockOp};
pub use cmd::{Cqe, Sqe};
pub use controller::{Controller, NvmeError};
pub use device::{BarRegion, DeviceResources, DmaRegion};
pub use transport::{MockNvme, NvmeTransport};
