//! Process creation: builds a fresh address space, loads an ELF binary into
//! it via `huesos-elf`, and spawns a scheduler task that jumps to ring3.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_abi::{vmar_flags, ErrorCode, ResourceMapArgs, VmarMapArgs, VmarOpArgs};
use huesos_arch::gdt;
use huesos_arch::paging::{flags, AddressSpace, UserPageError};
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};
use huesos_elf::{Loader, SegmentFlags};
use huesos_object::{KernelObject, KernelObjectExt};
use huesos_object::{Process, Resource, ResourceKind, Vmar, VmarError, VmarMapping};
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Top of the initial user stack (grows down from here).
const USER_STACK_TOP: u64 = huesos_abi::USER_STACK_TOP;
/// Size of the initial user stack.
const USER_STACK_SIZE: u64 = huesos_abi::USER_STACK_SIZE;
/// Base of the userspace heap region (Stage A.6: the kernel
/// reserves the region so a process with a global allocator can
/// allocate from boot; the hxfs-service heap lives here).
const USER_HEAP_BASE: u64 = huesos_abi::USER_HEAP_BASE;
/// Size of the userspace heap region.
const USER_HEAP_SIZE: u64 = huesos_abi::USER_HEAP_SIZE;

/// Kernel-owned runtime state for a process.
///
/// Stored behind `huesos_object::Process::address_space` as `Box<dyn Any>`
/// so the object crate stays architecture-independent while the kernel can
/// still keep the real x86_64 page-table owner alive for as long as the
/// process object lives.
pub struct ProcessRuntime {
    /// Real process address space. Wrapped in `Option` so `destroy` and `Drop`
    /// can move it out exactly once and return all page-table / owned frames.
    pub address_space: Option<AddressSpace>,
    /// Root VMAR object for this address space.
    pub root_vmar: Arc<Vmar>,
}

impl ProcessRuntime {
    /// Create an empty runtime and register its root VMAR object.
    pub fn new(process_koid: huesos_object::Koid) -> Result<Self, UserPageError> {
        let address_space = AddressSpace::new()?;
        let root_vmar = Vmar::new_root(
            process_koid,
            huesos_abi::USER_ASPACE_BASE,
            huesos_abi::USER_ASPACE_SIZE,
        );
        huesos_object::register_object(root_vmar.clone());
        Ok(Self {
            address_space: Some(address_space),
            root_vmar,
        })
    }

    /// CR3 value for scheduling this process.
    pub fn cr3(&self) -> u64 {
        self.address_space
            .as_ref()
            .map(|address_space| address_space.phys_addr().as_u64())
            .unwrap_or(0)
    }

    fn address_space_mut(&mut self) -> Option<&mut AddressSpace> {
        self.address_space.as_mut()
    }
}

impl Drop for ProcessRuntime {
    fn drop(&mut self) {
        if let Some(address_space) = self.address_space.take() {
            // SAFETY: dropping ProcessRuntime is only permitted after the
            // owning process has left every scheduler current slot, or during
            // construction/launch rollback before the CR3 was ever published.
            unsafe { address_space.destroy() };
        }
        huesos_object::unregister_object(self.root_vmar.koid());
    }
}

/// Adapter that lets `huesos-elf::load` map pages into a real
/// `huesos_arch::paging::AddressSpace`.
struct KernelLoader<'a> {
    aspace: &'a mut AddressSpace,
}

impl<'a> Loader for KernelLoader<'a> {
    type Error = UserPageError;

    fn map_zeroed_page(
        &mut self,
        vaddr: u64,
        flags_req: SegmentFlags,
    ) -> Result<*mut u8, Self::Error> {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(vaddr));
        let mut pt_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if flags_req.write {
            pt_flags |= PageTableFlags::WRITABLE;
        }
        if !flags_req.execute {
            pt_flags |= PageTableFlags::NO_EXECUTE;
        }
        let frame = self.aspace.map_new_user_page(page, pt_flags)?;
        Ok(huesos_arch::paging::phys_to_virt(frame.start_address().as_u64()).as_mut_ptr())
    }
}

/// Failure while constructing a process from an ELF image.
#[derive(Debug)]
pub enum SpawnError {
    /// The process address space or stack could not be allocated/mapped.
    Paging(UserPageError),
    /// ELF validation or segment mapping failed.
    Elf(huesos_elf::ElfLoadError<UserPageError>),
}

impl From<UserPageError> for SpawnError {
    fn from(error: UserPageError) -> Self {
        Self::Paging(error)
    }
}

/// A fully constructed userspace process, ready to be scheduled.
pub struct SpawnedProcess {
    /// The kernel object representing this process (handle table, etc).
    pub process: Arc<Process>,
    /// Entry point to resume at (set by the ELF loader).
    pub entry_point: u64,
    /// Initial user stack pointer.
    pub user_rsp: u64,
    /// Physical address of the process's PML4 (for CR3).
    pub cr3: u64,
}

/// Create a suspended process with an empty address space and a root VMAR.
///
/// This is the kernel-side implementation behind the `ProcessCreate` syscall.
/// It intentionally does not create threads, map ELF segments, or start
/// execution; those are separate VMAR/thread syscalls in the approved launch
/// model.
pub fn create_suspended_process(
    name: &str,
) -> Result<(Arc<Process>, Arc<Vmar>), huesos_abi::ErrorCode> {
    let process = Process::new(if name.is_empty() { "process" } else { name });
    finish_process_creation(process)
}

/// Create a suspended process in an explicit Job.
pub fn create_suspended_process_in_job(
    name: &str,
    job: Arc<huesos_object::Job>,
) -> Result<(Arc<Process>, Arc<Vmar>), huesos_abi::ErrorCode> {
    let process = Process::new_in_job(if name.is_empty() { "process" } else { name }, job);
    finish_process_creation(process)
}

fn finish_process_creation(
    process: Arc<Process>,
) -> Result<(Arc<Process>, Arc<Vmar>), huesos_abi::ErrorCode> {
    huesos_object::register_process(process.clone());

    let mut runtime = ProcessRuntime::new(process.koid()).map_err(|_| ErrorCode::NoMemory)?;
    // Map the userspace heap region (fixed RW, non-executable) for
    // every process at creation. Stage A.6 wired the hxfs-service's
    // global allocator against `huesos_abi::USER_HEAP_BASE` but the
    // mapping itself was never delivered: the service's first heap
    // allocation faulted at USER_HEAP_BASE (page fault, error=0x6)
    // as soon as a code path actually allocated (Stage B.5's
    // compression policy table). The region is inert for processes
    // that never touch it. Note: launcher-created processes map
    // their ELF segments and stacks through the root VMAR; the heap
    // stays outside the VMAR bookkeeping, mirroring the legacy
    // `spawn_from_elf` stack mapping.
    {
        let Some(address_space) = runtime.address_space_mut() else {
            runtime.destroy();
            huesos_object::unregister_object(process.koid());
            return Err(ErrorCode::NoMemory);
        };
        // Commit only the bootstrap prefix; the rest of the window is
        // reserved address space the process grows through
        // `VmarHeapExtend` as its allocator needs it. Committing all
        // 18 MiB here burned 4608 frames per process even for the
        // processes that never allocate a byte.
        let heap_end = USER_HEAP_BASE + USER_HEAP_EAGER_PAGES * PAGE_SIZE;
        let mut addr = USER_HEAP_BASE;
        while addr < heap_end {
            let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(addr));
            if address_space
                .map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE)
                .is_err()
            {
                runtime.destroy();
                huesos_object::unregister_object(process.koid());
                return Err(ErrorCode::NoMemory);
            }
            addr += 4096;
        }
    }
    let root_vmar = Arc::clone(&runtime.root_vmar);
    *process.address_space.lock() =
        Some(Box::new(runtime) as Box<dyn core::any::Any + Send + Sync>);

    Ok((process, root_vmar))
}

const PAGE_SIZE: u64 = 4096;
const ALL_VMAR_FLAGS: u32 = vmar_flags::READ
    | vmar_flags::WRITE
    | vmar_flags::EXECUTE
    | vmar_flags::USER
    | vmar_flags::SPECIFIC;

/// Map a VMO into a process root VMAR at a fixed userspace address.
///
/// First-cut VMAR policy is deliberately strict: page-aligned VMO offsets,
/// page-aligned fixed addresses, root VMAR only, user mappings only, and no
/// W+X pages. Later commits can add child VMAR allocation and first-fit
/// address selection without changing the ABI shape.
pub fn map_vmo_into_vmar(
    vmar: &Vmar,
    vmo: &huesos_object::Vmo,
    args: VmarMapArgs,
) -> Result<u64, ErrorCode> {
    validate_vmar_map_args(vmar, vmo, args)?;

    let process_obj = huesos_object::lookup_object(vmar.process()).ok_or(ErrorCode::BadHandle)?;
    let process = process_obj
        .downcast_ref::<Process>()
        .ok_or(ErrorCode::WrongType)?;

    let mut runtime_guard = process.address_space.lock();
    let runtime = runtime_guard
        .as_mut()
        .and_then(|runtime| runtime.downcast_mut::<ProcessRuntime>())
        .ok_or(ErrorCode::BadHandle)?;

    if runtime.root_vmar.process() != vmar.process() {
        return Err(ErrorCode::AccessDenied);
    }

    let page_flags = page_flags_from_vmar_flags(args.flags)?;
    let first_vmo_page = (args.vmo_offset / PAGE_SIZE) as usize;
    let page_count = (args.len / PAGE_SIZE) as usize;

    // Validate every backing frame before reserving metadata or touching page
    // tables. Ordinary argument errors therefore have no rollback work.
    for index in 0..page_count {
        if vmo.frame_at(first_vmo_page + index).is_none() {
            return Err(ErrorCode::InvalidArgs);
        }
    }

    let mapping = VmarMapping {
        base: args.addr,
        size: args.len,
        vmo: vmo.koid(),
        vmo_offset: args.vmo_offset,
        flags: args.flags,
    };
    // Acquire the VMAR-owned lifetime reference atomically with registry
    // lookup. A concurrent last-handle close must not collect the VMO between
    // metadata reservation and reference accounting.
    let _vmo_kernel_ref =
        huesos_object::acquire_kernel_ref(vmo.koid()).ok_or(ErrorCode::BadHandle)?;
    if let Err(error) = vmar.record_mapping(mapping) {
        huesos_object::note_kernel_ref_close(vmo.koid());
        return Err(match error {
            VmarError::InvalidRange => ErrorCode::InvalidArgs,
            VmarError::Overlap => ErrorCode::Busy,
        });
    }

    let address_space = runtime.address_space_mut().ok_or(ErrorCode::BadHandle)?;
    let mut mapped_pages = 0usize;
    let map_result = (|| -> Result<(), ErrorCode> {
        for index in 0..page_count {
            let frame_phys = vmo
                .frame_at(first_vmo_page + index)
                .ok_or(ErrorCode::InvalidArgs)?;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                args.addr + index as u64 * PAGE_SIZE,
            ));
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(frame_phys));
            address_space
                .try_map_user_page(page, frame, page_flags)
                .map_err(|error| match error {
                    huesos_arch::paging::UserPageError::OutOfMemory => ErrorCode::NoMemory,
                    huesos_arch::paging::UserPageError::NotInitialized => ErrorCode::Internal,
                    huesos_arch::paging::UserPageError::AlreadyMapped => ErrorCode::Busy,
                    huesos_arch::paging::UserPageError::ParentHugePage
                    | huesos_arch::paging::UserPageError::NotMapped
                    | huesos_arch::paging::UserPageError::InvalidFrameAddress => {
                        ErrorCode::InvalidArgs
                    }
                })?;
            mapped_pages += 1;
        }
        Ok(())
    })();

    if let Err(error) = map_result {
        // Roll back only pages installed by this transaction, in reverse order.
        for index in (0..mapped_pages).rev() {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                args.addr + index as u64 * PAGE_SIZE,
            ));
            let _ = address_space.unmap_user_page(page);
        }
        let removed = vmar.remove_mapping(mapping);
        debug_assert!(removed, "VMAR rollback lost its reservation");
        huesos_object::note_kernel_ref_close(vmo.koid());
        return Err(error);
    }

    Ok(args.addr)
}

/// Map a page-aligned `Mmio` or `DmaPool` Resource into the caller's root VMAR.
///
/// This is the hardware-driver escape hatch for Stage B: authority comes from a
/// Resource handle, the mapping is fixed-address and user-accessible, and only
/// the resource's own half-open physical range may be exposed. No arbitrary
/// physical memory mapping is available.
pub fn map_resource_into_current(
    resource: &Resource,
    args: ResourceMapArgs,
) -> Result<u64, ErrorCode> {
    validate_resource_map_args(resource, args)?;
    let process = huesos_object::current_process().ok_or(ErrorCode::AccessDenied)?;
    let _memory_guard = process.user_memory_lock.lock();
    // Do not take VMAR_MUTATION_LOCK here: resource mapping mutates an inactive
    // userspace page table and `try_map_user_page` reads architecture state at
    // LockRank::ARCHITECTURE. Holding the PROCESS-ranked VMAR mutation lock
    // across that path trips the runtime rank checker. The per-process
    // address-space lock plus the VMAR mapping lock serialize this operation.

    let mut runtime_guard = process.address_space.lock();
    let runtime = runtime_guard
        .as_mut()
        .and_then(|runtime| runtime.downcast_mut::<ProcessRuntime>())
        .ok_or(ErrorCode::BadHandle)?;
    let root_vmar = Arc::clone(&runtime.root_vmar);
    if root_vmar.process() != process.koid() {
        return Err(ErrorCode::AccessDenied);
    }
    if root_vmar.overlaps_existing(args.addr, args.len) {
        return Err(ErrorCode::Busy);
    }

    let phys_base = resource
        .base()
        .checked_add(args.resource_offset)
        .ok_or(ErrorCode::InvalidArgs)?;
    let page_flags = resource_page_flags(resource.kind(), args.flags)?;
    let mapping = VmarMapping {
        base: args.addr,
        size: args.len,
        vmo: resource.koid(),
        vmo_offset: args.resource_offset,
        flags: args.flags,
    };
    let _resource_ref =
        huesos_object::acquire_kernel_ref(resource.koid()).ok_or(ErrorCode::BadHandle)?;
    if let Err(error) = root_vmar.record_mapping(mapping) {
        huesos_object::note_kernel_ref_close(resource.koid());
        return Err(match error {
            VmarError::InvalidRange => ErrorCode::InvalidArgs,
            VmarError::Overlap => ErrorCode::Busy,
        });
    }

    let address_space = runtime.address_space_mut().ok_or(ErrorCode::BadHandle)?;
    let page_count = (args.len / PAGE_SIZE) as usize;
    let mut mapped_pages = 0usize;
    let map_result = (|| -> Result<(), ErrorCode> {
        for index in 0..page_count {
            let virt = args.addr + index as u64 * PAGE_SIZE;
            let phys = phys_base + index as u64 * PAGE_SIZE;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys));
            address_space
                .try_map_user_page(page, frame, page_flags)
                .map_err(|error| match error {
                    huesos_arch::paging::UserPageError::OutOfMemory => ErrorCode::NoMemory,
                    huesos_arch::paging::UserPageError::NotInitialized => ErrorCode::Internal,
                    huesos_arch::paging::UserPageError::AlreadyMapped => ErrorCode::Busy,
                    huesos_arch::paging::UserPageError::ParentHugePage
                    | huesos_arch::paging::UserPageError::NotMapped
                    | huesos_arch::paging::UserPageError::InvalidFrameAddress => {
                        ErrorCode::InvalidArgs
                    }
                })?;
            mapped_pages += 1;
        }
        Ok(())
    })();

    if let Err(error) = map_result {
        for index in (0..mapped_pages).rev() {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                args.addr + index as u64 * PAGE_SIZE,
            ));
            let _ = address_space.unmap_user_page(page);
        }
        let removed = root_vmar.remove_mapping(mapping);
        debug_assert!(removed, "resource VMAR rollback lost its reservation");
        huesos_object::note_kernel_ref_close(resource.koid());
        return Err(error);
    }

    huesos_arch::paging::shootdown_range(
        args.addr,
        args.addr + args.len,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(args.addr)
}

fn validate_resource_map_args(resource: &Resource, args: ResourceMapArgs) -> Result<(), ErrorCode> {
    if args.len == 0
        || !args.addr.is_multiple_of(PAGE_SIZE)
        || !args.len.is_multiple_of(PAGE_SIZE)
        || !args.resource_offset.is_multiple_of(PAGE_SIZE)
    {
        return Err(ErrorCode::InvalidArgs);
    }
    if args.flags & !ALL_VMAR_FLAGS != 0
        || args.flags & vmar_flags::USER == 0
        || args.flags & vmar_flags::SPECIFIC == 0
        || args.flags & (vmar_flags::READ | vmar_flags::WRITE) == 0
        || args.flags & vmar_flags::EXECUTE != 0
    {
        return Err(ErrorCode::InvalidArgs);
    }
    if !matches!(resource.kind(), ResourceKind::Mmio | ResourceKind::DmaPool) {
        return Err(ErrorCode::WrongType);
    }
    let phys = resource
        .base()
        .checked_add(args.resource_offset)
        .ok_or(ErrorCode::InvalidArgs)?;
    if !resource.contains(resource.kind(), phys, args.len) {
        return Err(ErrorCode::AccessDenied);
    }
    Ok(())
}

fn resource_page_flags(kind: ResourceKind, flags: u32) -> Result<PageTableFlags, ErrorCode> {
    let mut pt_flags = page_flags_from_vmar_flags(flags)?;
    if matches!(kind, ResourceKind::Mmio) {
        pt_flags |= PageTableFlags::NO_CACHE;
    }
    Ok(pt_flags)
}

fn validate_vmar_map_args(
    vmar: &Vmar,
    vmo: &huesos_object::Vmo,
    args: VmarMapArgs,
) -> Result<(), ErrorCode> {
    if args.len == 0
        || !args.addr.is_multiple_of(PAGE_SIZE)
        || !args.len.is_multiple_of(PAGE_SIZE)
        || !args.vmo_offset.is_multiple_of(PAGE_SIZE)
    {
        return Err(ErrorCode::InvalidArgs);
    }

    if args.flags & !ALL_VMAR_FLAGS != 0
        || args.flags & vmar_flags::USER == 0
        || args.flags & vmar_flags::SPECIFIC == 0
        || args.flags & (vmar_flags::READ | vmar_flags::WRITE | vmar_flags::EXECUTE) == 0
    {
        return Err(ErrorCode::InvalidArgs);
    }

    if args.flags & vmar_flags::WRITE != 0 && args.flags & vmar_flags::EXECUTE != 0 {
        return Err(ErrorCode::InvalidArgs);
    }

    let end_offset = args
        .vmo_offset
        .checked_add(args.len)
        .ok_or(ErrorCode::InvalidArgs)?;
    if end_offset > vmo.size() as u64 {
        return Err(ErrorCode::InvalidArgs);
    }

    if !vmar.contains_range(args.addr, args.len) {
        return Err(ErrorCode::InvalidArgs);
    }
    if vmar.overlaps_existing(args.addr, args.len) {
        return Err(ErrorCode::Busy);
    }

    Ok(())
}

fn page_flags_from_vmar_flags(flags: u32) -> Result<PageTableFlags, ErrorCode> {
    let mut pt_flags = PageTableFlags::PRESENT;
    if flags & vmar_flags::USER != 0 {
        pt_flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    if flags & vmar_flags::WRITE != 0 {
        pt_flags |= PageTableFlags::WRITABLE;
    }
    if flags & vmar_flags::EXECUTE == 0 {
        pt_flags |= PageTableFlags::NO_EXECUTE;
    }
    Ok(pt_flags)
}

fn process_runtime_for_vmar(vmar: &Vmar) -> Result<Arc<Process>, ErrorCode> {
    let object = huesos_object::lookup_object(vmar.process()).ok_or(ErrorCode::BadHandle)?;
    let process = object
        .downcast_ref::<Process>()
        .ok_or(ErrorCode::WrongType)?;
    huesos_object::lookup_process(process.koid()).ok_or(ErrorCode::BadHandle)
}

fn validate_vmar_op_args(
    vmar: &Vmar,
    args: VmarOpArgs,
    protect: bool,
) -> Result<VmarMapping, ErrorCode> {
    if args.len == 0 || !args.addr.is_multiple_of(PAGE_SIZE) || !args.len.is_multiple_of(PAGE_SIZE)
    {
        return Err(ErrorCode::InvalidArgs);
    }
    if protect {
        if args.flags & !ALL_VMAR_FLAGS != 0
            || args.flags & vmar_flags::USER == 0
            || args.flags & vmar_flags::SPECIFIC == 0
            || args.flags & (vmar_flags::READ | vmar_flags::WRITE | vmar_flags::EXECUTE) == 0
            || args.flags & (vmar_flags::WRITE | vmar_flags::EXECUTE)
                == (vmar_flags::WRITE | vmar_flags::EXECUTE)
        {
            return Err(ErrorCode::InvalidArgs);
        }
    } else if args.flags != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if !vmar.contains_range(args.addr, args.len) {
        return Err(ErrorCode::InvalidArgs);
    }
    vmar.mapping_covering(args.addr, args.len)
        .ok_or(ErrorCode::NotFound)
}

fn split_mapping_for_unmap(mapping: VmarMapping, addr: u64, len: u64) -> [Option<VmarMapping>; 2] {
    let unmap_end = addr + len;
    let mapping_end = mapping.base + mapping.size;
    let mut out = [None, None];
    if addr > mapping.base {
        out[0] = Some(VmarMapping {
            base: mapping.base,
            size: addr - mapping.base,
            vmo: mapping.vmo,
            vmo_offset: mapping.vmo_offset,
            flags: mapping.flags,
        });
    }
    if unmap_end < mapping_end {
        out[1] = Some(VmarMapping {
            base: unmap_end,
            size: mapping_end - unmap_end,
            vmo: mapping.vmo,
            vmo_offset: mapping.vmo_offset + (unmap_end - mapping.base),
            flags: mapping.flags,
        });
    }
    out
}

fn split_mapping_for_protect(
    mapping: VmarMapping,
    addr: u64,
    len: u64,
    flags: u32,
) -> [Option<VmarMapping>; 3] {
    let protect_end = addr + len;
    let mapping_end = mapping.base + mapping.size;
    let mut out = [None, None, None];
    if addr > mapping.base {
        out[0] = Some(VmarMapping {
            base: mapping.base,
            size: addr - mapping.base,
            vmo: mapping.vmo,
            vmo_offset: mapping.vmo_offset,
            flags: mapping.flags,
        });
    }
    out[1] = Some(VmarMapping {
        base: addr,
        size: len,
        vmo: mapping.vmo,
        vmo_offset: mapping.vmo_offset + (addr - mapping.base),
        flags,
    });
    if protect_end < mapping_end {
        out[2] = Some(VmarMapping {
            base: protect_end,
            size: mapping_end - protect_end,
            vmo: mapping.vmo,
            vmo_offset: mapping.vmo_offset + (protect_end - mapping.base),
            flags: mapping.flags,
        });
    }
    out
}

fn compact_replacements<const N: usize>(
    items: [Option<VmarMapping>; N],
) -> ([VmarMapping; 3], usize) {
    let empty = VmarMapping {
        base: 0,
        size: 0,
        vmo: huesos_object::Koid::INVALID,
        vmo_offset: 0,
        flags: 0,
    };
    let mut out = [empty; 3];
    let mut count = 0usize;
    for item in items.into_iter().flatten() {
        out[count] = item;
        count += 1;
    }
    (out, count)
}

fn adjust_mapping_refcount(
    vmo: huesos_object::Koid,
    replacement_count: usize,
) -> Result<usize, ErrorCode> {
    let extra = replacement_count.saturating_sub(1);
    for acquired in 0..extra {
        if huesos_object::acquire_kernel_ref(vmo).is_none() {
            for _ in 0..acquired {
                huesos_object::note_kernel_ref_close(vmo);
            }
            return Err(ErrorCode::BadHandle);
        }
    }
    Ok(extra)
}

fn release_extra_mapping_refs(vmo: huesos_object::Koid, extra: usize) {
    for _ in 0..extra {
        huesos_object::note_kernel_ref_close(vmo);
    }
}

fn remap_mapping_pages(
    runtime: &mut ProcessRuntime,
    vmo: &huesos_object::Vmo,
    mapping: VmarMapping,
    count: usize,
) -> bool {
    let Ok(flags) = page_flags_from_vmar_flags(mapping.flags) else {
        return false;
    };
    let Some(address_space) = runtime.address_space_mut() else {
        return false;
    };
    for index in 0..count {
        let first_page = (mapping.vmo_offset / PAGE_SIZE) as usize;
        let Some(frame_phys) = vmo.frame_at(first_page + index) else {
            return false;
        };
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            mapping.base + index as u64 * PAGE_SIZE,
        ));
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(frame_phys));
        if address_space.try_map_user_page(page, frame, flags).is_err() {
            return false;
        }
    }
    true
}

/// Remove one exact VMAR mapping under the address-space/copy lock and perform
/// a cross-CPU TLB shootdown before returning to userspace.
pub fn unmap_vmar_mapping(vmar: &Vmar, args: VmarOpArgs) -> Result<u64, ErrorCode> {
    let process = process_runtime_for_vmar(vmar)?;
    let _memory_guard = process.user_memory_lock.lock();
    let _mutation_guard = VMAR_MUTATION_LOCK.lock();
    let mapping = validate_vmar_op_args(vmar, args, false)?;
    let object = huesos_object::lookup_object(mapping.vmo).ok_or(ErrorCode::BadHandle)?;
    let vmo = object
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let runtime_any = process.address_space.lock();
    let mut runtime = runtime_any;
    let runtime = runtime
        .as_mut()
        .and_then(|value| value.downcast_mut::<ProcessRuntime>())
        .ok_or(ErrorCode::BadHandle)?;
    let page_count = (args.len / PAGE_SIZE) as usize;
    let sub_mapping = VmarMapping {
        base: args.addr,
        size: args.len,
        vmo: mapping.vmo,
        vmo_offset: mapping.vmo_offset + (args.addr - mapping.base),
        flags: mapping.flags,
    };
    let replacements_raw = split_mapping_for_unmap(mapping, args.addr, args.len);
    let (replacements, replacement_count) = compact_replacements(replacements_raw);
    let extra_refs = adjust_mapping_refcount(mapping.vmo, replacement_count)?;

    let mut unmapped = 0usize;
    for index in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            args.addr + index as u64 * PAGE_SIZE,
        ));
        let unmap_result = runtime
            .address_space_mut()
            .ok_or(ErrorCode::BadHandle)?
            .unmap_user_page(page);
        if unmap_result.is_err() {
            let _ = remap_mapping_pages(runtime, vmo, sub_mapping, unmapped);
            release_extra_mapping_refs(mapping.vmo, extra_refs);
            return Err(ErrorCode::Internal);
        }
        unmapped += 1;
    }
    if vmar
        .replace_mapping(mapping, &replacements[..replacement_count])
        .is_err()
    {
        let _ = remap_mapping_pages(runtime, vmo, sub_mapping, unmapped);
        release_extra_mapping_refs(mapping.vmo, extra_refs);
        return Err(ErrorCode::Internal);
    }
    if replacement_count == 0 {
        huesos_object::note_kernel_ref_close(mapping.vmo);
    }
    huesos_arch::paging::shootdown_range(
        args.addr,
        args.addr + args.len,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(args.addr)
}

/// Change permissions on one exact VMAR mapping under the address-space/copy
/// lock and perform a cross-CPU TLB shootdown.
pub fn protect_vmar_mapping(vmar: &Vmar, args: VmarOpArgs) -> Result<u64, ErrorCode> {
    let process = process_runtime_for_vmar(vmar)?;
    let _memory_guard = process.user_memory_lock.lock();
    let _mutation_guard = VMAR_MUTATION_LOCK.lock();
    let mapping = validate_vmar_op_args(vmar, args, true)?;
    let old_flags = page_flags_from_vmar_flags(mapping.flags)?;
    let new_flags = page_flags_from_vmar_flags(args.flags)?;
    let runtime_any = process.address_space.lock();
    let mut runtime = runtime_any;
    let runtime = runtime
        .as_mut()
        .and_then(|value| value.downcast_mut::<ProcessRuntime>())
        .ok_or(ErrorCode::BadHandle)?;
    let page_count = (args.len / PAGE_SIZE) as usize;
    let replacements_raw = split_mapping_for_protect(mapping, args.addr, args.len, args.flags);
    let (replacements, replacement_count) = compact_replacements(replacements_raw);
    let extra_refs = adjust_mapping_refcount(mapping.vmo, replacement_count)?;

    let mut changed = 0usize;
    for index in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            args.addr + index as u64 * PAGE_SIZE,
        ));
        let protect_result = runtime
            .address_space_mut()
            .ok_or(ErrorCode::BadHandle)?
            .protect_user_page(page, new_flags);
        if protect_result.is_err() {
            for rollback in 0..changed {
                let rollback_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                    args.addr + rollback as u64 * PAGE_SIZE,
                ));
                if let Some(address_space) = runtime.address_space_mut() {
                    let _ = address_space.protect_user_page(rollback_page, old_flags);
                }
            }
            release_extra_mapping_refs(mapping.vmo, extra_refs);
            return Err(ErrorCode::Internal);
        }
        changed += 1;
    }
    if vmar
        .replace_mapping(mapping, &replacements[..replacement_count])
        .is_err()
    {
        for rollback in 0..changed {
            let rollback_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                args.addr + rollback as u64 * PAGE_SIZE,
            ));
            if let Some(address_space) = runtime.address_space_mut() {
                let _ = address_space.protect_user_page(rollback_page, old_flags);
            }
        }
        release_extra_mapping_refs(mapping.vmo, extra_refs);
        return Err(ErrorCode::Internal);
    }
    huesos_arch::paging::shootdown_range(
        args.addr,
        args.addr + args.len,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(args.addr)
}

/// Number of heap pages committed eagerly at process creation.
///
/// Before the `VmarHeapExtend` syscall existed the launcher had to
/// commit the *entire* 18 MiB window (4608 frames) to every process,
/// including the many that never allocate, because a process had no
/// way to ask for more later. With on-demand commit the launcher only
/// needs enough for an allocator to bootstrap its first region; the
/// rest is reserved address space that costs nothing until used.
const USER_HEAP_EAGER_PAGES: u64 = 16;

/// Commit or decommit pages inside the calling process's own heap window.
///
/// This is the `mmap`/`munmap` substitute for a ring-3 process that
/// holds no handle to its own VMAR. Authority is implicit and
/// deliberately minimal: the range is expressed as an offset into
/// `[USER_HEAP_BASE, USER_HEAP_BASE + USER_HEAP_SIZE)` and clamped to
/// that window, so this syscall can never name, map, or free memory
/// outside the caller's own pre-reserved heap. No handle, resource, or
/// right can be escalated through it.
///
/// Committing is idempotent per page: an already-committed page is
/// left alone rather than failing the whole request, so an allocator
/// can re-commit a region without tracking kernel state exactly.
/// Decommitting frees the backing frames, so the heap can shrink.
pub fn heap_extend_current(args: huesos_abi::HeapExtendArgs) -> Result<u64, ErrorCode> {
    use huesos_abi::heap_op;

    if args.reserved != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if args.len == 0
        || !args.offset.is_multiple_of(PAGE_SIZE)
        || !args.len.is_multiple_of(PAGE_SIZE)
        || args.op > heap_op::DECOMMIT
    {
        return Err(ErrorCode::InvalidArgs);
    }
    // Checked arithmetic: a wrapping end would otherwise let a huge
    // offset+len pair pass a naive `end <= HEAP_SIZE` test.
    let end = args
        .offset
        .checked_add(args.len)
        .ok_or(ErrorCode::InvalidArgs)?;
    if end > USER_HEAP_SIZE {
        return Err(ErrorCode::InvalidArgs);
    }

    let process = huesos_object::current_process().ok_or(ErrorCode::AccessDenied)?;
    // Serialize against the validated user-copy layer: a page must not
    // be unmapped while a syscall is copying through it.
    let _memory_guard = process.user_memory_lock.lock();

    let base = USER_HEAP_BASE + args.offset;
    let page_count = (args.len / PAGE_SIZE) as usize;

    let mut runtime_guard = process.address_space.lock();
    let runtime = runtime_guard
        .as_mut()
        .and_then(|runtime| runtime.downcast_mut::<ProcessRuntime>())
        .ok_or(ErrorCode::BadHandle)?;
    let address_space = runtime.address_space_mut().ok_or(ErrorCode::BadHandle)?;

    if args.op == heap_op::COMMIT {
        let mut committed = 0usize;
        let result = (|| -> Result<(), ErrorCode> {
            for index in 0..page_count {
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                    base + index as u64 * PAGE_SIZE,
                ));
                if address_space.is_user_page_mapped(page) {
                    continue;
                }
                address_space
                    .map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE)
                    .map_err(|error| match error {
                        UserPageError::OutOfMemory => ErrorCode::NoMemory,
                        UserPageError::NotInitialized => ErrorCode::Internal,
                        UserPageError::AlreadyMapped => ErrorCode::Busy,
                        UserPageError::ParentHugePage
                        | UserPageError::NotMapped
                        | UserPageError::InvalidFrameAddress => ErrorCode::InvalidArgs,
                    })?;
                committed += 1;
            }
            Ok(())
        })();

        if let Err(error) = result {
            // Roll the transaction back: a partially grown heap would
            // hand the allocator a region with a hole in it.
            for index in (0..page_count).rev() {
                if committed == 0 {
                    break;
                }
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                    base + index as u64 * PAGE_SIZE,
                ));
                if address_space.unmap_and_release_user_page(page).is_ok() {
                    committed -= 1;
                }
            }
            return Err(error);
        }
        // Newly mapped pages were absent before, so no CPU can hold a
        // stale positive TLB entry for them; nothing to shoot down.
        return Ok(base);
    }

    // DECOMMIT
    for index in 0..page_count {
        let page =
            Page::<Size4KiB>::containing_address(VirtAddr::new(base + index as u64 * PAGE_SIZE));
        // Tolerate holes: decommitting an uncommitted page is a no-op,
        // not an error, so an allocator may release a range it only
        // partially committed.
        let _ = address_space.unmap_and_release_user_page(page);
    }
    drop(runtime_guard);
    // Removing mappings *does* require invalidating other CPUs, or a
    // stale TLB entry would keep a freed frame reachable from ring 3.
    huesos_arch::paging::shootdown_range(
        base,
        base + args.len,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(base)
}

/// Start a suspended userspace thread.
///
/// The syscall layer owns bootstrap-channel creation and installs the child
/// endpoint before calling this function; this function only validates the
/// target process runtime, creates the scheduler task, and records the task
/// id on the thread object.
pub fn start_thread(
    thread: &huesos_object::Thread,
    entry: u64,
    stack: u64,
) -> Result<u64, ErrorCode> {
    let userspace = huesos_abi::USER_ASPACE_BASE..huesos_abi::USER_ASPACE_END;
    if !userspace.contains(&entry) || !userspace.contains(&stack) {
        return Err(ErrorCode::InvalidArgs);
    }

    let process = huesos_object::lookup_process(thread.process()).ok_or(ErrorCode::BadHandle)?;
    if process.exit_code().is_some() {
        return Err(ErrorCode::Busy);
    }
    let cr3 = {
        let mut runtime_guard = process.address_space.lock();
        let runtime = runtime_guard
            .as_mut()
            .and_then(|runtime| runtime.downcast_mut::<ProcessRuntime>())
            .ok_or(ErrorCode::BadHandle)?;
        runtime
            .address_space
            .as_ref()
            .ok_or(ErrorCode::BadHandle)?
            .phys_addr()
            .as_u64()
    };

    let mut task_name = [0u8; 32];
    let label = b"user-thread";
    task_name[..label.len()].copy_from_slice(label);

    let target_cpu = process.home_cpu();
    crate::scheduler::spawn_user_thread_on_cpu(&task_name, process, entry, stack, cr3, target_cpu)
        .ok_or(ErrorCode::Busy)
}

/// Load `elf_bytes` into a brand new address space and prepare a process
/// object ready to hand to the scheduler.
pub fn spawn_from_elf(name: &str, elf_bytes: &[u8]) -> Result<SpawnedProcess, SpawnError> {
    let process = Process::new(name);
    huesos_object::register_process(process.clone());
    let mut runtime = match ProcessRuntime::new(process.koid()) {
        Ok(runtime) => runtime,
        Err(error) => {
            huesos_object::unregister_object(process.koid());
            return Err(SpawnError::Paging(error));
        }
    };

    let loaded = {
        let Some(address_space) = runtime.address_space_mut() else {
            runtime.destroy();
            huesos_object::unregister_object(process.koid());
            return Err(SpawnError::Paging(UserPageError::NotInitialized));
        };
        let mut loader = KernelLoader {
            aspace: address_space,
        };
        match huesos_elf::load(elf_bytes, &mut loader) {
            Ok(loaded) => loaded,
            Err(error) => {
                runtime.destroy();
                huesos_object::unregister_object(process.koid());
                return Err(SpawnError::Elf(error));
            }
        }
    };

    // Map the initial user stack (grows down from USER_STACK_TOP).
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let mut addr = stack_bottom;
    while addr < USER_STACK_TOP {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(addr));
        let map_result = runtime
            .address_space_mut()
            .ok_or(UserPageError::NotInitialized)
            .and_then(|address_space| {
                address_space.map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE)
            });
        if let Err(error) = map_result {
            runtime.destroy();
            huesos_object::unregister_object(process.koid());
            return Err(SpawnError::Paging(error));
        }
        addr += 4096;
    }

    let cr3 = runtime.cr3();
    *process.address_space.lock() =
        Some(Box::new(runtime) as Box<dyn core::any::Any + Send + Sync>);

    Ok(SpawnedProcess {
        process,
        entry_point: loaded.entry_point,
        // SysV x86_64 function entry expects `(RSP + 8) % 16 == 0`, i.e.
        // `RSP % 16 == 8`, as if a `call` had just pushed a return address.
        // `iretq` does not push one into user memory, so we synthesize the
        // same shape by pointing the initial RSP one qword below a
        // 16-byte-aligned top. Compute this explicitly instead of the
        // previous magic `USER_STACK_TOP - 40`, which happened to satisfy
        // the ABI only because `USER_STACK_TOP` was itself 16-byte aligned;
        // any future ASLR / randomized-top work would have silently broken
        // SSE/AVX in user code.
        user_rsp: initial_user_rsp(USER_STACK_TOP),
        cr3,
    })
}

/// Return an initial user RSP that satisfies the SysV x86_64 ABI on first
/// entry: `(RSP + 8) % 16 == 0`. The chosen value is one qword below the
/// 16-byte-aligned top of the caller-supplied stack region, so a userspace
/// prologue can `sub rsp, N` (for any 16-byte-aligned N) and remain aligned
/// through every subsequent `call`.
///
/// Extracted as a `const fn` so the property can be exercised by host tests
/// without pulling in the entire process-launch machinery.
pub const fn initial_user_rsp(stack_top: u64) -> u64 {
    let aligned_top = stack_top & !0xf;
    aligned_top - 8
}

/// Entry trampoline installed as a task's initial resume address (via
/// `Context::new`). Runs once, in ring0, immediately after the scheduler
/// first switches to this task; its job is to jump into ring3 at the
/// process's real entry point and never return (the `iretq` inside
/// `enter_userspace` does that).
///
/// Reads the target RIP/RSP out of per-task pending-entry records set by
/// `spawn_user_thread` just before the task is inserted into the scheduler.
/// `Context::new` only supports a plain `fn() -> !` with no arguments, so
/// the trampoline resolves its own task id and consumes the corresponding
/// pending record on first run.
struct PendingUserEntry {
    task_id: u64,
    entry: u64,
    rsp: u64,
}

static PENDING_USER_ENTRIES: RankedIrqSafeTicketLock<Vec<PendingUserEntry>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::PROCESS);

static VMAR_MUTATION_LOCK: RankedIrqSafeTicketLock<()> =
    RankedIrqSafeTicketLock::new((), LockRank::PROCESS);

/// Queue the first userspace RIP/RSP pair for a just-created scheduler task.
pub fn queue_user_entry(task_id: u64, entry: u64, rsp: u64) {
    PENDING_USER_ENTRIES.lock().push(PendingUserEntry {
        task_id,
        entry,
        rsp,
    });
}

fn take_user_entry(task_id: u64) -> Option<(u64, u64)> {
    let mut entries = PENDING_USER_ENTRIES.lock();
    let pos = entries
        .iter()
        .position(|pending| pending.task_id == task_id)?;
    let pending = entries.swap_remove(pos);
    Some((pending.entry, pending.rsp))
}

/// Remove a startup record for a task killed before its first schedule.
/// The generation-bearing ID ensures this cannot remove a replacement task's
/// record after slot reuse.
pub(crate) fn cancel_user_entry(task_id: u64) {
    PENDING_USER_ENTRIES
        .lock()
        .retain(|pending| pending.task_id != task_id);
}

/// Trampoline used as the initial RIP for user tasks.
pub extern "C" fn user_entry_trampoline() -> ! {
    let Some(task_id) = crate::scheduler::current_task_id() else {
        crate::scheduler::terminate_current_process(huesos_abi::fault_exit::STARTUP_FAILED);
    };
    let Some((entry, rsp)) = take_user_entry(task_id) else {
        crate::scheduler::terminate_current_process(huesos_abi::fault_exit::STARTUP_FAILED);
    };
    crate::scheduler::mark_user_entry_consumed(task_id);

    let sel = gdt::selectors();
    let user_cs = (sel.user_code.0 as u64) | 3; // RPL=3
    let user_ss = (sel.user_data.0 as u64) | 3;

    {
        use core::fmt::Write;
        let mut w = huesos_arch::serial::SerialWriter;
        let _ = writeln!(
            &mut w,
            "[kernel] entering userspace: rip={:#x} rsp={:#x} cs={:#x} ss={:#x}",
            entry, rsp, user_cs, user_ss
        );
    }

    unsafe {
        huesos_arch::context_switch::enter_userspace(entry, rsp, user_cs, user_ss, 0x202);
    }
}

impl ProcessRuntime {
    /// Destroy the address space and drop the root VMAR registration.
    pub fn destroy(mut self) {
        if let Some(address_space) = self.address_space.take() {
            // SAFETY: caller must ensure no CPU still has this CR3 loaded.
            unsafe { address_space.destroy() };
        }
        // Drop runs next and unregisters the root VMAR exactly once.
    }
}

/// Tear down process resources after exit: free page tables / owned frames,
/// clear the handle table, leave the Process object itself for ProcessWait
/// until its last handle is closed.
///
/// # Safety
/// No task may still run with this process's CR3.
pub fn teardown_process(process: &Process) {
    if let Some(any) = process.address_space.lock().take() {
        if let Ok(runtime) = any.downcast::<ProcessRuntime>() {
            drop(runtime);
        }
    }
    process.handles.clear();
}

#[cfg(test)]
mod tests {
    use super::initial_user_rsp;

    // SysV x86_64: (RSP + 8) % 16 == 0 on function entry, equivalently
    // RSP % 16 == 8. If this ever regresses, userspace SSE/AVX prologues
    // will fault at runtime for reasons that look completely unrelated
    // (misaligned MOVAPS / VMOVAPS).
    #[test]
    fn initial_user_rsp_matches_sysv_call_frame() {
        // Aligned top: canonical case that mirrors USER_STACK_TOP today.
        let aligned = 0x0000_7fff_ff00_0000u64;
        let rsp = initial_user_rsp(aligned);
        assert_eq!(rsp % 16, 8, "RSP={rsp:#x} violates SysV entry alignment");
        assert!(rsp < aligned);
        assert!(aligned - rsp <= 16, "wasted more than one qword of stack");
    }

    #[test]
    fn initial_user_rsp_absorbs_unaligned_top() {
        // Any future ASLR / randomized top must still satisfy the ABI.
        for offset in 0u64..64 {
            let top = 0x0000_7fff_ff00_0000u64 + offset;
            let rsp = initial_user_rsp(top);
            assert_eq!(
                rsp % 16,
                8,
                "RSP={rsp:#x} for top={top:#x} violates SysV entry alignment"
            );
            // The returned RSP must stay inside the caller-supplied region.
            assert!(rsp < top, "RSP={rsp:#x} escapes top={top:#x}");
        }
    }
}
