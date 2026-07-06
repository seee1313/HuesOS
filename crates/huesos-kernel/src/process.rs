//! Process creation: builds a fresh address space, loads an ELF binary into
//! it via `huesos-elf`, and spawns a scheduler task that jumps to ring3.

use alloc::sync::Arc;
use alloc::boxed::Box;
use huesos_arch::paging::{flags, AddressSpace};
use huesos_arch::gdt;
use huesos_elf::{Loader, SegmentFlags};
use huesos_object::Process;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

/// Top of the initial user stack (grows down from here).
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
/// Size of the initial user stack.
const USER_STACK_SIZE: u64 = 4096 * 16;

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

/// Load `elf_bytes` into a brand new address space and prepare a process
/// object ready to hand to the scheduler.
pub fn spawn_from_elf(name: &str, elf_bytes: &[u8]) -> SpawnedProcess {
    let aspace = AddressSpace::new();

    let loaded = {
        let mut loader = KernelLoader { aspace: &aspace };
        huesos_elf::load(elf_bytes, &mut loader).expect("failed to load userspace ELF")
    };

    // Map the initial user stack (grows down from USER_STACK_TOP).
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let mut addr = stack_bottom;
    while addr < USER_STACK_TOP {
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(addr));
        aspace.map_new_user_page(page, flags::USER_RW | PageTableFlags::NO_EXECUTE);
        addr += 4096;
    }

    let process = Process::new(name);
    *process.address_space.lock() = Some(Box::new(()) as Box<dyn core::any::Any + Send + Sync>);

    SpawnedProcess {
        process,
        entry_point: loaded.entry_point,
        user_rsp: USER_STACK_TOP - 32, // leave a little red-zone-ish slack
        cr3: aspace_leak_phys(aspace),
    }
}

/// Leak the `AddressSpace` (its PML4 frame must outlive the process; the MVP
/// doesn't yet reclaim process address spaces on exit) and return the
/// physical address of its PML4 for CR3.
fn aspace_leak_phys(aspace: AddressSpace) -> u64 {
    let phys = aspace.phys_addr().as_u64();
    core::mem::forget(aspace);
    phys
}

/// Entry trampoline installed as a task's `context.rip`. Runs once, in
/// ring0, immediately after the scheduler first switches to this task; its
/// job is to jump into ring3 at the process's real entry point and never
/// return (the `iretq` inside `enter_userspace` does that).
///
/// Reads the target RIP/RSP out of thread-local-ish statics set by
/// `spawn_user_thread` just before scheduling, since `Context::new` only
/// supports a plain `fn() -> !` with no arguments.
pub static PENDING_ENTRY: spin::Mutex<Option<(u64, u64)>> = spin::Mutex::new(None);

/// Trampoline used as the initial RIP for user tasks.
pub extern "C" fn user_entry_trampoline() -> ! {
    let (entry, rsp) = PENDING_ENTRY
        .lock()
        .take()
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
