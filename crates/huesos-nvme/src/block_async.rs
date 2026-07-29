//! Async BlockDevice wire protocol for NVMe DriverHost.
//!
//! The canonical ABI lives in `huesos_abi::block`; this module re-exports it
//! for existing `huesos-nvme` users.

pub use huesos_abi::block::*;
