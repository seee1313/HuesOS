//! Process creation: builds a fresh address space, loads an ELF binary into
//! it via `huesos-elf`, and spawns a scheduler task that jumps to ring3.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_arch::gdt;
use huesos_arch::paging::{flags, AddressSpace};
use huesos_abi::{vmar_flags, ErrorCode, VmarMapArgs};
use huesos_elf::{Loader, SegmentFlags};
use huesos_object::{KernelObject, KernelObjectExt};
use huesos_object::{Process, Vmar, VmarMapping};
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Top of the initial user stack (grows down from here).
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
/// Size of the initial user stack.
const USER_STACK_SIZE: u64 = 4096 * 16;


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
    pub fn new(process_koid: huesos_object::Koid) -> Self {
        let address_space = AddressSpace::new();
        let root_vmar = Vmar::new_root(
            process_koid,
            huesos_abi::USER_ASPACE_BASE,
            huesos_abi::USER_ASPACE_SIZE,
        );
        huesos_object::register_object(root_vmar.clone());
        Self {
            address_space,
            root_vmar,
        }
    }

    /// CR3 value for scheduling this process.
    pub fn cr3(&self) -> u64 {
        self.address_space.phys_addr().as_u64()
    }
}

/// Adapter that lets `huesos-elf::load` map pages into a real
/// `huesos_arch::paging::AddressSpace`.
struct KernelLoader<'a> {
    aspace: &'a AddressSpace,
}

impl<'a> Loader for KernelLoader<'a> {
    fn map_zeroed_page(&mut self, vaddr: u64, flags_req: SegmentFlags) -> *mut u8 {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(vaddr));
        let mut pt_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if flags_req.write {
            pt_flags |= PageTableFlags::WRITABLE;
        }
        if !flags_req.execute {
            pt_flags |= PageTableFlags::NO_EXECUTE;
        }
        let frame = self.aspace.map_new_user_page(page, pt_flags);
        huesos_arch::paging::phys_to_virt(frame.start_address().as_u64()).as_mut_ptr()
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
    huesos_object::register_object(process.clone());

    let runtime = ProcessRuntime::new(process.koid());
    let root_vmar = Arc::clone(&runtime.root_vmar);
    *process.address_space.lock() = Some(Box::new(runtime) as Box<dyn core::any::Any + Send + Sync>);

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

    // Validate all backing frames before mutating page tables, so ordinary
    // userspace argument errors do not leave partial mappings behind.
    for i in 0..page_count {
        if vmo.frame_at(first_vmo_page + i).is_none() {
            return Err(ErrorCode::InvalidArgs);
        }
    }

    for i in 0..page_count {
        let frame_phys = vmo.frame_at(first_vmo_page + i).ok_or(ErrorCode::InvalidArgs)?;
        let page: Page<Size4KiB> =
            Page::containing_address(VirtAddr::new(args.addr + i as u64 * PAGE_SIZE));
        let frame: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(frame_phys));
        runtime.address_space.map_user_page(page, frame, page_flags);
    }

    vmar.record_mapping(VmarMapping {
        base: args.addr,
        size: args.len,
        vmo: vmo.koid(),
        flags: args.flags,
    })
    .map_err(|_| ErrorCode::Busy)?;

    Ok(args.addr)
}

fn validate_vmar_map_args(
    vmar: &Vmar,
    vmo: &huesos_object::Vmo,
    args: VmarMapArgs,
) -> Result<(), ErrorCode> {
    if args.len == 0
        || args.addr % PAGE_SIZE != 0
        || args.len % PAGE_SIZE != 0
        || args.vmo_offset % PAGE_SIZE != 0
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

/// Load `elf_bytes` into a brand new address space and prepare a process
/// object ready to hand to the scheduler.
pub fn spawn_from_elf(name: &str, elf_bytes: &[u8]) -> SpawnedProcess {
    let process = Process::new(name);
    let runtime = ProcessRuntime::new(process.koid());

    let loaded = {
        let mut loader = KernelLoader {
            aspace: &runtime.address_space,
        };
        huesos_elf::load(elf_bytes, &mut loader).expect("failed to load userspace ELF")
    };

    // Map the initial user stack (grows down from USER_STACK_TOP).
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let mut addr = stack_bottom;
    while addr < USER_STACK_TOP {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(addr));
        runtime
            .address_space
            .map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE);
        addr += 4096;
    }

    let cr3 = runtime.cr3();
    *process.address_space.lock() = Some(Box::new(runtime) as Box<dyn core::any::Any + Send + Sync>);

    SpawnedProcess {
        process,
        entry_point: loaded.entry_point,
        user_rsp: USER_STACK_TOP - 32, // leave a little red-zone-ish slack
        cr3,
    }
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

static PENDING_USER_ENTRIES: spin::Mutex<Vec<PendingUserEntry>> = spin::Mutex::new(Vec::new());

/// Queue the first userspace RIP/RSP pair for a just-created scheduler task.
pub fn queue_user_entry(task_id: u64, entry: u64, rsp: u64) {
    PENDING_USER_ENTRIES.lock().push(PendingUserEntry { task_id, entry, rsp });
}

fn take_user_entry(task_id: u64) -> Option<(u64, u64)> {
    let mut entries = PENDING_USER_ENTRIES.lock();
    let pos = entries.iter().position(|pending| pending.task_id == task_id)?;
    let pending = entries.swap_remove(pos);
    Some((pending.entry, pending.rsp))
}

/// Trampoline used as the initial RIP for user tasks.
pub extern "C" fn user_entry_trampoline() -> ! {
    let task_id = crate::scheduler::current_task_id()
        .expect("user_entry_trampoline invoked without a current task id");
    let (entry, rsp) = take_user_entry(task_id)
        .expect("user_entry_trampoline invoked without a pending entry");

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
