//! Process creation: builds a fresh address space, loads an ELF binary into
//! it via `huesos-elf`, and spawns a scheduler task that jumps to ring3.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_abi::{ErrorCode, VmarMapArgs, VmarOpArgs, vmar_flags};
use huesos_arch::gdt;
use huesos_arch::paging::{AddressSpace, UserPageError, flags};
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};
use huesos_elf::{Loader, SegmentFlags};
use huesos_object::{KernelObject, KernelObjectExt};
use huesos_object::{Process, Vmar, VmarError, VmarMapping};
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Top of the initial user stack (grows down from here).
const USER_STACK_TOP: u64 = huesos_abi::USER_STACK_TOP;
/// Size of the initial user stack.
const USER_STACK_SIZE: u64 = huesos_abi::USER_STACK_SIZE;

/// Kernel-owned runtime state for a process.
///
/// Stored behind `huesos_object::Process::address_space` as `Box<dyn Any>`
/// so the object crate stays architecture-independent while the kernel can
/// still keep the real x86_64 page-table owner alive for as long as the
/// process object lives.
pub struct ProcessRuntime {
    /// Real process address space.
    pub address_space: AddressSpace,
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
            address_space,
            root_vmar,
        })
    }

    /// CR3 value for scheduling this process.
    pub fn cr3(&self) -> u64 {
        self.address_space.phys_addr().as_u64()
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
    huesos_object::register_process(process.clone());

    let runtime = ProcessRuntime::new(process.koid()).map_err(|_| ErrorCode::NoMemory)?;
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

    // Root-VMAR-only MVP: child VMAR allocation exists in the object shape,
    // but the syscall API to create child VMARs is intentionally deferred.
    if runtime.root_vmar.koid() != vmar.koid() {
        return Err(ErrorCode::NotSupported);
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
            runtime
                .address_space
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
            let _ = runtime.address_space.unmap_user_page(page);
        }
        let removed = vmar.remove_mapping(mapping);
        debug_assert!(removed, "VMAR rollback lost its reservation");
        huesos_object::note_kernel_ref_close(vmo.koid());
        return Err(error);
    }

    Ok(args.addr)
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

fn process_runtime_for_vmar(
    vmar: &Vmar,
) -> Result<Arc<Process>, ErrorCode> {
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
    if args.len == 0
        || !args.addr.is_multiple_of(PAGE_SIZE)
        || !args.len.is_multiple_of(PAGE_SIZE)
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
    vmar.mapping(args.addr, args.len).ok_or(ErrorCode::NotFound)
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
    for index in 0..count {
        let first_page = (mapping.vmo_offset / PAGE_SIZE) as usize;
        let Some(frame_phys) = vmo.frame_at(first_page + index) else {
            return false;
        };
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            mapping.base + index as u64 * PAGE_SIZE,
        ));
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(frame_phys));
        if runtime
            .address_space
            .try_map_user_page(page, frame, flags)
            .is_err()
        {
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
    let page_count = (mapping.size / PAGE_SIZE) as usize;
    let mut unmapped = 0usize;
    for index in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            mapping.base + index as u64 * PAGE_SIZE,
        ));
        if runtime.address_space.unmap_user_page(page).is_err() {
            let _ = remap_mapping_pages(runtime, vmo, mapping, unmapped);
            return Err(ErrorCode::Internal);
        }
        unmapped += 1;
    }
    if !vmar.remove_mapping(mapping) {
        let _ = remap_mapping_pages(runtime, vmo, mapping, unmapped);
        return Err(ErrorCode::Internal);
    }
    huesos_object::note_kernel_ref_close(mapping.vmo);
    huesos_arch::paging::shootdown_range(
        mapping.base,
        mapping.base + mapping.size,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(mapping.base)
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
    let page_count = (mapping.size / PAGE_SIZE) as usize;
    let mut changed = 0usize;
    for index in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            mapping.base + index as u64 * PAGE_SIZE,
        ));
        if runtime.address_space.protect_user_page(page, new_flags).is_err() {
            for rollback in 0..changed {
                let rollback_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                    mapping.base + rollback as u64 * PAGE_SIZE,
                ));
                let _ = runtime.address_space.protect_user_page(rollback_page, old_flags);
            }
            return Err(ErrorCode::Internal);
        }
        changed += 1;
    }
    if !vmar.update_mapping_flags(mapping, args.flags) {
        for rollback in 0..changed {
            let rollback_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                mapping.base + rollback as u64 * PAGE_SIZE,
            ));
            let _ = runtime.address_space.protect_user_page(rollback_page, old_flags);
        }
        return Err(ErrorCode::Internal);
    }
    huesos_arch::paging::shootdown_range(
        mapping.base,
        mapping.base + mapping.size,
        crate::scheduler::online_remote_cpu_count(),
    );
    Ok(mapping.base)
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

    if thread.task_id.lock().is_some() {
        return Err(ErrorCode::Busy);
    }

    let process = huesos_object::lookup_process(thread.process()).ok_or(ErrorCode::BadHandle)?;
    let cr3 = {
        let mut runtime_guard = process.address_space.lock();
        let runtime = runtime_guard
            .as_mut()
            .and_then(|runtime| runtime.downcast_mut::<ProcessRuntime>())
            .ok_or(ErrorCode::BadHandle)?;
        runtime.cr3()
    };

    let mut task_name = [0u8; 32];
    let label = b"user-thread";
    task_name[..label.len()].copy_from_slice(label);

    let task_id = crate::scheduler::spawn_user_thread(&task_name, process, entry, stack, cr3);
    *thread.task_id.lock() = Some(task_id);
    Ok(task_id)
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
        let mut loader = KernelLoader {
            aspace: &mut runtime.address_space,
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
        if let Err(error) = runtime
            .address_space
            .map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE)
        {
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
        // SysV x86_64 function entry expects RSP % 16 == 8 (as if a call
        // pushed a return address). iretq does not push one into user memory.
        user_rsp: USER_STACK_TOP - 40,
        cr3,
    })
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
    pub fn destroy(self) {
        let root_koid = self.root_vmar.koid();
        // Safety: caller must ensure no CPU still has this CR3 loaded.
        unsafe {
            self.address_space.destroy();
        }
        huesos_object::unregister_object(root_koid);
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
            runtime.destroy();
        }
    }
    process.handles.clear();
}
