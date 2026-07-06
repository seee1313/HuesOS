//! # HuesOS Kernel Object Subsystem
//!
//! Object-centric design in the spirit of Zircon: everything is a Kernel
//! Object. Userspace references them via Handles (capabilities with rights).

#![no_std]
#![warn(missing_docs)]
#![allow(dead_code)] // `name` fields are reserved for future GET_PROPERTY/SET_PROPERTY syscalls

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use bitflags::bitflags;
use spin::Mutex;

static NEXT_KOID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh Kernel Object ID.
pub fn alloc_koid() -> Koid {
    Koid(NEXT_KOID.fetch_add(1, Ordering::SeqCst))
}

/// Kernel object unique ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Koid(pub u64);

impl Koid {
    /// Invalid koid.
    pub const INVALID: Koid = Koid(0);
    /// Check validity.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

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
    /// Generic / unknown.
    Unknown = 0xFF,
}

bitflags! {
    /// Capability rights on a Handle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Rights: u32 {
        /// May duplicate this handle.
        const DUPLICATE = 1 << 0;
        /// May transfer this handle to another process via a channel.
        const TRANSFER = 1 << 1;
        /// May read from the underlying object.
        const READ = 1 << 2;
        /// May write to the underlying object.
        const WRITE = 1 << 3;
        /// May execute (map executable) the underlying object.
        const EXECUTE = 1 << 4;
        /// May map the underlying object into an address space.
        const MAP = 1 << 5;
        /// May query properties of the underlying object.
        const GET_PROPERTY = 1 << 6;
        /// May modify properties of the underlying object.
        const SET_PROPERTY = 1 << 7;
        /// May enumerate children (e.g. jobs).
        const ENUMERATE = 1 << 8;
        /// May destroy the underlying object.
        const DESTROY = 1 << 9;
        /// Placeholder meaning "duplicate with the same rights".
        const SAME_RIGHTS = 1 << 31;
        /// Default rights for most objects.
        const DEFAULT = Self::READ.bits() | Self::WRITE.bits() | Self::DUPLICATE.bits() | Self::TRANSFER.bits();
        /// Default rights for VMOs.
        const DEFAULT_VMO = Self::READ.bits() | Self::WRITE.bits() | Self::MAP.bits() | Self::DUPLICATE.bits();
    }
}

/// A Handle is a `(Koid, Rights)` pair in a process handle table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    /// Object koid.
    pub koid: Koid,
    /// Rights.
    pub rights: Rights,
}

impl Handle {
    /// Create a new handle.
    pub const fn new(koid: Koid, rights: Rights) -> Self {
        Self { koid, rights }
    }
    /// Check if rights contain `required`.
    pub fn has_rights(self, required: Rights) -> bool {
        self.rights.contains(required)
    }
}

/// Userspace handle value (index into handle table).
pub type HandleValue = u32;
/// Invalid handle value.
pub const INVALID_HANDLE: HandleValue = 0;

/// Per-process handle table.
pub struct HandleTable {
    table: Mutex<Vec<Option<Handle>>>,
}

impl HandleTable {
    /// Create empty handle table.
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Vec::new()),
        }
    }
    /// Add a handle, return its value. Value 0 is reserved as
    /// [`INVALID_HANDLE`], so real handles start at 1.
    pub fn add(&self, handle: Handle) -> HandleValue {
        let mut t = self.table.lock();
        if t.is_empty() {
            t.push(None); // reserve slot 0
        }
        for (i, slot) in t.iter_mut().enumerate().skip(1) {
            if slot.is_none() {
                *slot = Some(handle);
                return i as u32;
            }
        }
        let idx = t.len() as u32;
        t.push(Some(handle));
        idx
    }
    /// Get handle by value.
    pub fn get(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table.lock().get(value as usize).copied().flatten()
    }
    /// Remove handle.
    pub fn remove(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table
            .lock()
            .get_mut(value as usize)
            .and_then(|h| h.take())
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Global object registry (koid -> Arc<dyn KernelObject>).
static OBJECT_REGISTRY: Mutex<BTreeMap<Koid, Arc<dyn KernelObject>>> = Mutex::new(BTreeMap::new());

/// Register a kernel object globally.
pub fn register_object(obj: Arc<dyn KernelObject>) {
    OBJECT_REGISTRY.lock().insert(obj.koid(), obj);
}

/// Lookup a kernel object by koid.
pub fn lookup_object(koid: Koid) -> Option<Arc<dyn KernelObject>> {
    OBJECT_REGISTRY.lock().get(&koid).cloned()
}

/// Remove an object from the global registry (called on final handle close
/// in a full refcounted implementation; for the MVP this is invoked
/// explicitly by `ProcessExit`/object-specific teardown).
pub fn unregister_object(koid: Koid) {
    OBJECT_REGISTRY.lock().remove(&koid);
}

/// Current process (set by the scheduler on every context switch).
static CURRENT_PROCESS: Mutex<Option<Arc<Process>>> = Mutex::new(None);

/// Set the current process.
pub fn set_current_process(p: Arc<Process>) {
    *CURRENT_PROCESS.lock() = Some(p);
}

/// Get the current process.
pub fn current_process() -> Option<Arc<Process>> {
    CURRENT_PROCESS.lock().clone()
}

/// Root job (set during object init).
static ROOT_JOB: Mutex<Option<Arc<Job>>> = Mutex::new(None);

/// Get the root job.
pub fn root_job() -> Option<Arc<Job>> {
    ROOT_JOB.lock().clone()
}

/// Callback used to translate a physical address into a kernel-accessible
/// virtual address (the HHDM). Injected by the kernel at init time so that
/// `huesos-object` doesn't need to depend on `huesos-arch` directly.
static PHYS_TO_VIRT: Mutex<Option<fn(u64) -> u64>> = Mutex::new(None);

/// Register the physical-to-virtual translator. Must be called once during
/// kernel init, after paging is set up.
pub fn set_phys_to_virt(f: fn(u64) -> u64) {
    *PHYS_TO_VIRT.lock() = Some(f);
}

fn phys_to_virt(phys: u64) -> u64 {
    (PHYS_TO_VIRT.lock().expect("phys_to_virt not registered"))(phys)
}

// ============================================================================
// Concrete Kernel Objects
// ============================================================================

/// Virtual Memory Object — a resizable collection of physical page frames.
///
/// Backed by real physical memory (via `huesos-pmm`), not a `Vec<u8>` — so
/// it can actually be mapped into a process's page tables.
pub struct Vmo {
    koid: Koid,
    name: Mutex<String>,
    size: Mutex<usize>,
    /// Physical frame addresses, one per 4 KiB page.
    frames: Mutex<Vec<u64>>,
}

const PAGE_SIZE: usize = 4096;

impl Vmo {
    /// Create a VMO covering at least `size` bytes, backed by freshly
    /// allocated, zeroed physical frames.
    pub fn new(size: usize) -> Arc<Self> {
        let koid = alloc_koid();
        let page_count = size.div_ceil(PAGE_SIZE).max(1);
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            let frame = huesos_pmm::alloc_frame().expect("VMO: out of physical memory");
            let virt = phys_to_virt(frame) as *mut u8;
            unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
            frames.push(frame);
        }
        Arc::new(Self {
            koid,
            name: Mutex::new(String::new()),
            size: Mutex::new(size),
            frames: Mutex::new(frames),
        })
    }

    /// Number of 4 KiB pages backing this VMO.
    pub fn page_count(&self) -> usize {
        self.frames.lock().len()
    }

    /// Physical address of the `index`-th page, if present.
    pub fn frame_at(&self, index: usize) -> Option<u64> {
        self.frames.lock().get(index).copied()
    }

    /// Logical size in bytes.
    pub fn size(&self) -> usize {
        *self.size.lock()
    }

    /// Read bytes at `offset`, copying into `buf`. Returns bytes copied.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let size = self.size();
        if offset >= size {
            return 0;
        }
        let len = buf.len().min(size - offset);
        let frames = self.frames.lock();
        let mut copied = 0;
        while copied < len {
            let abs = offset + copied;
            let page_idx = abs / PAGE_SIZE;
            let page_off = abs % PAGE_SIZE;
            let Some(&frame) = frames.get(page_idx) else {
                break;
            };
            let chunk = (PAGE_SIZE - page_off).min(len - copied);
            let src = (phys_to_virt(frame) as *const u8).wrapping_add(page_off);
            unsafe {
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(copied), chunk);
            }
            copied += chunk;
        }
        copied
    }

    /// Write bytes at `offset` from `buf`. Returns bytes copied.
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let size = self.size();
        if offset >= size {
            return 0;
        }
        let len = buf.len().min(size - offset);
        let frames = self.frames.lock();
        let mut copied = 0;
        while copied < len {
            let abs = offset + copied;
            let page_idx = abs / PAGE_SIZE;
            let page_off = abs % PAGE_SIZE;
            let Some(&frame) = frames.get(page_idx) else {
                break;
            };
            let chunk = (PAGE_SIZE - page_off).min(len - copied);
            let dst = (phys_to_virt(frame) as *mut u8).wrapping_add(page_off);
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr().add(copied), dst, chunk);
            }
            copied += chunk;
        }
        copied
    }

    /// Grow the VMO to `new_size` bytes, allocating new physical frames as
    /// needed. Shrinking is not supported in the MVP.
    pub fn set_size(&self, new_size: usize) {
        let mut size = self.size.lock();
        if new_size <= *size {
            return;
        }
        let mut frames = self.frames.lock();
        let needed_pages = new_size.div_ceil(PAGE_SIZE);
        while frames.len() < needed_pages {
            let frame = huesos_pmm::alloc_frame().expect("VMO: out of physical memory");
            let virt = phys_to_virt(frame) as *mut u8;
            unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
            frames.push(frame);
        }
        *size = new_size;
    }
}

impl KernelObject for Vmo {
    fn object_type(&self) -> ObjectType {
        ObjectType::Vmo
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Channel — one endpoint of a bidirectional IPC pipe.
///
/// A channel pair (created together via [`Channel::pair`]) shares two
/// message queues: writes on endpoint A enqueue onto the queue that
/// endpoint B reads from, and vice versa. Each endpoint keeps an `Arc` to
/// its peer's inbox so the pair keeps working even after one side's
/// `Channel` object handle is dropped independently.
pub struct Channel {
    koid: Koid,
    /// Queue this endpoint *reads from* (the peer writes into it).
    inbox: Arc<Mutex<Vec<ChannelMessage>>>,
    /// Queue this endpoint *writes to* (the peer reads from it).
    outbox: Arc<Mutex<Vec<ChannelMessage>>>,
}

/// A message sent over a channel.
pub struct ChannelMessage {
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Handles transferred with the message.
    pub handles: Vec<Handle>,
}

impl Channel {
    /// Create a connected pair of channel endpoints. Writing to one and
    /// reading from the other (or vice versa) delivers messages correctly.
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let q1 = Arc::new(Mutex::new(Vec::new()));
        let q2 = Arc::new(Mutex::new(Vec::new()));
        let a = Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::clone(&q1),
            outbox: Arc::clone(&q2),
        });
        let b = Arc::new(Self {
            koid: alloc_koid(),
            inbox: q2,
            outbox: q1,
        });
        (a, b)
    }

    /// Create a standalone channel endpoint with no peer (writes are
    /// dropped, reads always empty). Mainly useful for tests; real
    /// producers should use [`Channel::pair`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            inbox: Arc::new(Mutex::new(Vec::new())),
            outbox: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Send a message to the peer endpoint (enqueued FIFO).
    pub fn send(&self, msg: ChannelMessage) {
        self.outbox.lock().push(msg);
    }
    /// Receive a message sent by the peer endpoint (non-blocking, FIFO).
    pub fn recv(&self) -> Option<ChannelMessage> {
        let mut q = self.inbox.lock();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    }
}

impl KernelObject for Channel {
    fn object_type(&self) -> ObjectType {
        ObjectType::Channel
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Port — wait queue for async events.
pub struct Port {
    koid: Koid,
    packets: Mutex<Vec<PortPacket>>,
}

/// A packet queued to a port.
pub struct PortPacket {
    /// Key used to identify the source.
    pub key: u64,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Port {
    /// Create a new port.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            packets: Mutex::new(Vec::new()),
        })
    }
    /// Queue a packet.
    pub fn queue(&self, packet: PortPacket) {
        self.packets.lock().push(packet);
    }
    /// Read a packet (non-blocking, FIFO order).
    pub fn read(&self) -> Option<PortPacket> {
        let mut q = self.packets.lock();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    }
}

impl KernelObject for Port {
    fn object_type(&self) -> ObjectType {
        ObjectType::Port
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Job — container of processes (hierarchy root for resource limits).
pub struct Job {
    koid: Koid,
    name: Mutex<String>,
}

impl Job {
    /// Create the root job.
    pub fn root() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from("root")),
        })
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

/// Thread — execution context (userspace-visible object wrapping a kernel
/// scheduler task).
pub struct Thread {
    koid: Koid,
    name: Mutex<String>,
    /// Scheduler task id this Thread object corresponds to.
    pub task_id: Mutex<Option<u64>>,
}

impl Thread {
    /// Create a thread object (not yet bound to a scheduler task).
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from(name)),
            task_id: Mutex::new(None),
        })
    }
}

impl KernelObject for Thread {
    fn object_type(&self) -> ObjectType {
        ObjectType::Thread
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Process — address space + handle table + exit state.
pub struct Process {
    koid: Koid,
    name: Mutex<String>,
    /// Handle table for this process.
    pub handles: HandleTable,
    /// Exit code, set by `ProcessExit`. `None` while still running.
    pub exit_code: Mutex<Option<i64>>,
    /// Opaque pointer to the arch-specific address space (owned elsewhere;
    /// stored here so syscalls/scheduler can find it without a separate
    /// process table). Boxed `dyn Any` to avoid a dependency on huesos-arch.
    pub address_space: Mutex<Option<Box<dyn Any + Send + Sync>>>,
}

impl Process {
    /// Create a process.
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from(name)),
            handles: HandleTable::new(),
            exit_code: Mutex::new(None),
            address_space: Mutex::new(None),
        })
    }

    /// Human-readable process name.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }
}

impl KernelObject for Process {
    fn object_type(&self) -> ObjectType {
        ObjectType::Process
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Initialize root job and kernel objects. Does not set up the
/// phys-to-virt translator; call [`set_phys_to_virt`] separately once
/// paging is initialized.
pub fn init() {
    let root = Job::root();
    *ROOT_JOB.lock() = Some(root.clone());
    register_object(root);
}
