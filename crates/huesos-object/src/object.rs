//! Type-erased kernel object trait and object type tags.

use alloc::sync::Arc;
use core::any::Any;

use crate::Koid;

/// Trait for all kernel objects. `Any` enables safe downcasting from the
/// type-erased registry back to the concrete object type (e.g. `Vmo`,
/// `Channel`) that syscalls need.
pub trait KernelObject: Send + Sync + Any {
    /// Return the object type.
    fn object_type(&self) -> ObjectType;
    /// Return the kernel object id.
    fn koid(&self) -> Koid;
    /// Upcast to `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
}

/// Convenience extension providing typed downcasts on `Arc<dyn KernelObject>`.
pub trait KernelObjectExt {
    /// Attempt to downcast to a concrete kernel object type `T`.
    fn downcast_ref<T: KernelObject + 'static>(&self) -> Option<&T>;
}

impl KernelObjectExt for Arc<dyn KernelObject> {
    fn downcast_ref<T: KernelObject + 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }
}

/// Object types in HuesOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ObjectType {
    /// Virtual Memory Object.
    Vmo = 1,
    /// Process.
    Process = 2,
    /// Thread.
    Thread = 3,
    /// Channel (IPC pipe).
    Channel = 4,
    /// Port (wait queue / async signal).
    Port = 5,
    /// Job (container for processes).
    Job = 6,
    /// Interrupt object.
    Interrupt = 7,
    /// Virtual memory address region.
    Vmar = 8,
    /// Generic / unknown.
    Unknown = 0xFF,
}
