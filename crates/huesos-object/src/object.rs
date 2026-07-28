//! Type-erased kernel object trait and object type tags.

use alloc::sync::Arc;
use core::any::Any;

use crate::Koid;

/// Blanket-implemented helper that lets any concrete kernel object type be
/// converted from an owned `Arc<Self>` into `Arc<dyn Any + Send + Sync>`,
/// which `alloc::sync::Arc` can safely `downcast::<T>()` back from (this is
/// exactly `std`/`alloc`'s own `Arc<dyn Any>::downcast`, just reached
/// through our custom `KernelObject` trait object instead of a bare `dyn
/// Any`). No per-type boilerplate is required: the blanket impl covers
/// every `KernelObject` automatically.
pub trait AsAnyArc {
    /// Erase to `Arc<dyn Any + Send + Sync>` for a safe owned downcast.
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<T: Any + Send + Sync> AsAnyArc for T {
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// Trait for all kernel objects. `Any` enables safe downcasting from the
/// type-erased registry back to the concrete object type (e.g. `Vmo`,
/// `Channel`) that syscalls need.
pub trait KernelObject: Send + Sync + Any + AsAnyArc {
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
    /// Attempt to downcast an owned `Arc<dyn KernelObject>` to `Arc<T>`,
    /// returning the original `Arc` unchanged on mismatch. Implemented with
    /// zero `unsafe`: clones the `Arc`, erases the clone to `Arc<dyn Any +
    /// Send + Sync>` via [`AsAnyArc`], and uses `alloc`'s own safe
    /// `Arc::downcast`.
    fn downcast_arc<T: KernelObject + 'static>(self) -> Result<Arc<T>, Arc<dyn KernelObject>>;
}

impl KernelObjectExt for Arc<dyn KernelObject> {
    fn downcast_ref<T: KernelObject + 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    fn downcast_arc<T: KernelObject + 'static>(self) -> Result<Arc<T>, Arc<dyn KernelObject>> {
        let any_arc: Arc<dyn Any + Send + Sync> = Arc::clone(&self).as_any_arc();
        match any_arc.downcast::<T>() {
            Ok(t) => Ok(t),
            Err(_) => Err(self),
        }
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
    /// Restricted privileged-operation broker for Ring-3 ACPI.
    AcpiBroker = 9,
    /// Immutable capability grant over a `[base, base+len)` range of a
    /// physical-address-space kind (I/O port, MMIO, IRQ). See the
    /// `Resource` docs and `docs/ARCHITECTURE_ROADMAP.md` §2.
    Resource = 10,
    /// Level-triggered waitable signal object.
    Signal = 11,
    /// Generic / unknown.
    Unknown = 0xFF,
}
