//! Paging: kernel address space + per-process page table management.
//!
//! Frame allocation is backed by `huesos-pmm`'s bitmap allocator (a real
//! physical memory manager fed from the Limine memory map), not a hardcoded
//! bump range.

use crate::{LockRank, RankedIrqSafeTicketLock};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

const TLB_SHOOTDOWN_VECTOR: u8 = 0xF3;
static TLB_ACTIVE: AtomicBool = AtomicBool::new(false);
static TLB_START: AtomicU64 = AtomicU64::new(0);
static TLB_END: AtomicU64 = AtomicU64::new(0);
static TLB_ACKS: AtomicUsize = AtomicUsize::new(0);

/// Invalidate the requested range on the local CPU as part of an active
/// cross-CPU TLB shootdown request.
pub fn handle_tlb_shootdown() {
    if !TLB_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let mut page = TLB_START.load(Ordering::Acquire);
    let end = TLB_END.load(Ordering::Acquire);
    while page < end {
        crate::x86_64::cpu::invlpg(page);
        page = page.saturating_add(4096);
    }
    TLB_ACKS.fetch_add(1, Ordering::Release);
}

/// Invalidate a virtual-address range on every online CPU.
///
/// The caller supplies the number of remote online CPUs expected to acknowledge
/// the IPI. The request is serialized by the kernel VMAR mutation lock; this
/// architecture primitive only owns the fixed atomic mailbox and IPI handshake.
pub fn shootdown_range(start: u64, end: u64, expected_remote: usize) {
    let start = start & !0xfff;
    let end = end.saturating_add(0xfff) & !0xfff;
    if start >= end {
        return;
    }

    let interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    TLB_START.store(start, Ordering::Relaxed);
    TLB_END.store(end, Ordering::Relaxed);
    TLB_ACKS.store(0, Ordering::Relaxed);
    TLB_ACTIVE.store(true, Ordering::Release);

    crate::x86_64::lapic::broadcast_excluding_self(TLB_SHOOTDOWN_VECTOR);
    let mut page = start;
    while page < end {
        crate::x86_64::cpu::invlpg(page);
        page = page.saturating_add(4096);
    }
    while TLB_ACKS.load(Ordering::Acquire) < expected_remote {
        core::hint::spin_loop();
    }
    TLB_ACTIVE.store(false, Ordering::Release);
    if interrupts_were_enabled {
        x86_64::instructions::interrupts::enable();
    }
}

/// Higher-half direct map offset, fixed once at boot.
static HHDM_OFFSET: RankedIrqSafeTicketLock<u64> =
    RankedIrqSafeTicketLock::new(0, LockRank::ARCHITECTURE);

/// Kernel's own mapper over the bootloader-provided top-level table.
static KERNEL_PAGE_TABLE: RankedIrqSafeTicketLock<Option<OffsetPageTable<'static>>> =
    RankedIrqSafeTicketLock::new(None, LockRank::ARCHITECTURE);

/// Frame allocator adapter over `huesos-pmm`.
pub struct PmmFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for PmmFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        huesos_pmm::alloc_frame()
            .ok()
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

impl FrameDeallocator<Size4KiB> for PmmFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        huesos_pmm::free_frame(frame.start_address().as_u64());
    }
}

/// Initialize paging with `phys_offset` from Limine HHDM.
///
/// # Safety
/// `phys_offset` must be a valid higher-half direct map covering all
/// physical memory, and the PMM must already be initialized.
pub unsafe fn init(phys_offset: VirtAddr) {
    *HHDM_OFFSET.lock() = phys_offset.as_u64();
    let level_4_table = unsafe { active_level_4_table(phys_offset) };
    *KERNEL_PAGE_TABLE.lock() = Some(OffsetPageTable::new(level_4_table, phys_offset));
}

unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_frame, _) = Cr3::read();
    let phys = level_4_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    unsafe { &mut *virt.as_mut_ptr() }
}

/// Translate a physical address to a kernel-accessible virtual address via
/// the HHDM.
pub fn phys_to_virt(phys: u64) -> VirtAddr {
    VirtAddr::new(*HHDM_OFFSET.lock() + phys)
}

/// Failure while mutating the shared kernel page table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelPageError {
    /// Paging initialization has not installed the kernel mapper.
    NotInitialized,
    /// The PMM could not allocate a data or intermediate table frame.
    OutOfMemory,
    /// The virtual page already has a mapping.
    AlreadyMapped,
    /// A huge parent mapping prevents insertion of a 4 KiB page.
    ParentHugePage,
    /// The requested physical range overflows the address space.
    Overflow,
}

/// Map `page` to `frame` with `flags` in the *kernel* address space.
pub fn map_page(
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), KernelPageError> {
    use x86_64::structures::paging::mapper::MapToError;

    let mut guard = KERNEL_PAGE_TABLE.lock();
    let mapper = guard.as_mut().ok_or(KernelPageError::NotInitialized)?;
    let flush =
        unsafe { mapper.map_to(page, frame, flags, &mut PmmFrameAllocator) }.map_err(|error| {
            match error {
                MapToError::FrameAllocationFailed => KernelPageError::OutOfMemory,
                MapToError::PageAlreadyMapped(_) => KernelPageError::AlreadyMapped,
                MapToError::ParentEntryHugePage => KernelPageError::ParentHugePage,
            }
        })?;
    flush.flush();
    Ok(())
}

/// Ensure that `[phys_base, phys_base + length)` is reachable via the HHDM.
///
/// Limine base revision 3 only maps a subset of the memory map into the HHDM
/// (usable / bootloader-reclaimable / executable+modules / framebuffer).
/// ACPI tables, ACPI NVS and other reserved regions are *not* mapped, so
/// reading the RSDP/XSDT/MADT through `hhdm + phys` page-faults. This helper
/// installs 4 KiB HHDM identity mappings (`virt = hhdm + phys -> phys`) for
/// the requested range; already-present pages are left untouched.
///
/// # Safety / requirements
/// - [`init`] must have been called (kernel mapper live).
/// - The PMM must be initialized so intermediate page-table frames can be
///   allocated if a new PT/PD is needed.
pub fn map_hhdm_range(phys_base: u64, length: u64) -> Result<(), KernelPageError> {
    // W^X for HHDM data windows: ACPI/RSDP/MMIO ranges never need to be
    // executed from, and marking them NX blocks a write-what-where in the
    // higher half from being reused as a code-execution gadget. Callers
    // that genuinely need executable HHDM pages must use
    // `map_hhdm_range_flags` with an explicit flag set (there are none in
    // the current kernel).
    map_hhdm_range_flags(
        phys_base,
        length,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    )
}

/// Like [`map_hhdm_range`], but with explicit page flags (e.g. `NO_CACHE` for MMIO).
pub fn map_hhdm_range_flags(
    phys_base: u64,
    length: u64,
    flags: PageTableFlags,
) -> Result<(), KernelPageError> {
    map_phys_range(phys_base, length, flags, phys_to_virt)
}

/// Identity-map `[phys_base, phys_base + length)` so `virt == phys`.
///
/// Required for the AP trampoline: after it enables paging with the kernel
/// CR3 it still loads RSP/entry from absolute addresses `0x7008` / `0x7010`.
/// Base revision 3 dropped the unconditional low 4 GiB identity map, so we
/// must reinstall the few pages the trampoline needs.
///
/// Deliberately **not** `NO_EXECUTE`: the trampoline itself executes from
/// this range (it jumps to `AP_TRAMPOLINE_PHYS` in long mode before hopping
/// into the higher-half kernel), so setting NX here would #GP the AP on
/// its first instruction. Callers that only need a data identity mapping
/// should compose `map_phys_range` with their own flag set.
pub fn map_identity_range(phys_base: u64, length: u64) -> Result<(), KernelPageError> {
    map_phys_range(
        phys_base,
        length,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        VirtAddr::new,
    )
}

/// Stamp `NO_EXECUTE` on every 4 KiB page in the higher-half virtual
/// range `[start, end)`. Pages that are unmapped or already NX are
/// silently skipped; huge-page parent entries are skipped as well
/// because HuesOS's linker script page-aligns each load segment, so
/// no huge page ever covers one of the ranges we stamp here.
///
/// This is intended for kernel-image data ranges (`.rodata`, `.data`,
/// `.bss`, `.limine_requests`) — never for `.text`, which must remain
/// executable. See [`apply_kernel_wx`].
///
/// # Errors
/// Returns [`KernelPageError::NotInitialized`] if paging has not been
/// initialized yet. Individual per-page failures do not surface as
/// errors: this hardening pass is opportunistic and never worth
/// halting the boot for.
///
/// # Safety
/// Must run after [`init`] and after EFER.NXE is set on the current
/// CPU (established by [`crate::cpu::enable_memory_protection`]).
pub fn stamp_nx_range(start: u64, end: u64) -> Result<(), KernelPageError> {
    use x86_64::structures::paging::mapper::{FlagUpdateError, Translate, TranslateResult};

    if start >= end {
        return Ok(());
    }
    let mut guard = KERNEL_PAGE_TABLE.lock();
    let mapper = guard.as_mut().ok_or(KernelPageError::NotInitialized)?;

    let mut virt = start & !0xfff;
    let last = (end - 1) & !0xfff;
    loop {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        // Peek the current flags so we can OR in NO_EXECUTE without
        // clobbering PRESENT / WRITABLE / other bits Limine set at load
        // time. TranslateResult::Mapped exposes the leaf-entry flags.
        if let TranslateResult::Mapped { flags: current, .. } =
            mapper.translate(page.start_address())
        {
            let target = current | PageTableFlags::NO_EXECUTE;
            if target != current {
                // SAFETY: mapper is the kernel PML4; the page is
                // mapped (per the Translate check above); we only OR
                // NX in and preserve every other bit. `update_flags`
                // still enforces its own preconditions internally and
                // returns Err for a huge-page parent entry, which we
                // treat as a benign skip rather than an error.
                match unsafe { mapper.update_flags(page, target) } {
                    Ok(flush) => flush.flush(),
                    Err(FlagUpdateError::PageNotMapped)
                    | Err(FlagUpdateError::ParentEntryHugePage) => {}
                }
            }
        }
        if virt == last {
            break;
        }
        // Saturating on overflow guards against a caller passing
        // `end == u64::MAX`; higher-half kernel ranges never
        // approach that value.
        let next = virt.saturating_add(4096);
        if next <= virt {
            break;
        }
        virt = next;
    }
    Ok(())
}

/// Post-init W^X sweep for the kernel image.
///
/// Walks the non-`.text` load segments (`.limine_requests`, `.rodata`,
/// `.data`, `.bss`) exported by `scripts/linker.ld` and stamps
/// `NO_EXECUTE` on every 4 KiB page they cover. `.text` is the only
/// higher-half range that must remain executable and is intentionally
/// not touched.
///
/// This turns a hypothetical write-what-where in kernel data into a
/// `#PF` NX-violation instead of a code-execution primitive. It is a
/// hardening layer on top of [`flags::KERNEL_RW`] (which already sets
/// `NO_EXECUTE` on every mapping installed *by us* through
/// [`init::heap_init`] etc.); this sweep additionally covers the
/// pages *Limine* installed at load time before we owned the mapper.
///
/// The kernel boots successfully whether or not this succeeds; a
/// failure only removes the extra hardening layer.
///
/// # Safety
/// Same contract as [`stamp_nx_range`].
pub fn apply_kernel_wx() -> Result<(), KernelPageError> {
    extern "C" {
        static __huesos_limine_requests_start: u8;
        static __huesos_limine_requests_end: u8;
        static __huesos_rodata_start: u8;
        static __huesos_rodata_end: u8;
        static __huesos_data_start: u8;
        static __huesos_data_end: u8;
    }
    // Taking the address of an extern static via `addr_of!` is safe
    // (no dereference); we cast to u64 for the byte-range API.
    let (rq_start, rq_end, ro_start, ro_end, da_start, da_end) = (
        core::ptr::addr_of!(__huesos_limine_requests_start) as u64,
        core::ptr::addr_of!(__huesos_limine_requests_end) as u64,
        core::ptr::addr_of!(__huesos_rodata_start) as u64,
        core::ptr::addr_of!(__huesos_rodata_end) as u64,
        core::ptr::addr_of!(__huesos_data_start) as u64,
        core::ptr::addr_of!(__huesos_data_end) as u64,
    );
    stamp_nx_range(rq_start, rq_end)?;
    stamp_nx_range(ro_start, ro_end)?;
    stamp_nx_range(da_start, da_end)?;
    Ok(())
}

fn map_phys_range(
    phys_base: u64,
    length: u64,
    flags: PageTableFlags,
    virt_of: impl Fn(u64) -> VirtAddr,
) -> Result<(), KernelPageError> {
    if length == 0 {
        return Ok(());
    }
    let start = phys_base & !0xfff;
    let raw_end = phys_base
        .checked_add(length)
        .ok_or(KernelPageError::Overflow)?;
    let end = raw_end
        .checked_add(0xfff)
        .ok_or(KernelPageError::Overflow)?
        & !0xfff;

    let mut guard = KERNEL_PAGE_TABLE.lock();
    let mapper = guard.as_mut().ok_or(KernelPageError::NotInitialized)?;

    let mut phys = start;
    while phys < end {
        let page = Page::<Size4KiB>::containing_address(virt_of(phys));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        unsafe {
            match mapper.map_to(page, frame, flags, &mut PmmFrameAllocator) {
                Ok(flush) => flush.flush(),
                Err(x86_64::structures::paging::mapper::MapToError::PageAlreadyMapped(_)) => {
                    // Page present (e.g. Limine left it WB). Force the flags
                    // we want — critical for LAPIC/IOAPIC NO_CACHE + NX.
                    mapper.update_flags(page, flags).map(|f| f.flush()).map_err(|error| {
                        match error {
                            x86_64::structures::paging::mapper::FlagUpdateError::PageNotMapped => {
                                KernelPageError::AlreadyMapped
                            }
                            x86_64::structures::paging::mapper::FlagUpdateError::ParentEntryHugePage => {
                                KernelPageError::ParentHugePage
                            }
                        }
                    })?;
                }
                Err(x86_64::structures::paging::mapper::MapToError::ParentEntryHugePage) => {
                    return Err(KernelPageError::ParentHugePage);
                }
                Err(x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed) => {
                    return Err(KernelPageError::OutOfMemory);
                }
            }
        }
        phys = phys.saturating_add(4096);
        if phys == 0 {
            break;
        }
    }
    Ok(())
}

/// Check whether a 4 KiB page in the currently active address space is
/// accessible from ring 3 with the requested access.
///
/// The walk checks the effective permissions at every page-table level, not
/// only the leaf PTE: x86 requires `PRESENT` and `USER_ACCESSIBLE` throughout
/// the walk, and a write is permitted only when every traversed entry is
/// `WRITABLE`. 1 GiB and 2 MiB huge-page leaves are supported even though
/// HuesOS currently maps ordinary userspace with 4 KiB pages.
///
/// This function deliberately validates only page-table permissions. ABI
/// policy such as the null guard and the upper userspace bound belongs to the
/// syscall user-copy layer.
pub fn active_user_page_accessible(addr: VirtAddr, write: bool) -> bool {
    fn permits(flags: PageTableFlags, write: bool) -> bool {
        flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE)
            && (!write || flags.contains(PageTableFlags::WRITABLE))
    }

    fn table_at(phys: PhysAddr) -> &'static PageTable {
        // Page-table frames are ordinary RAM and are therefore reachable
        // through the HHDM established during early paging initialization.
        unsafe { &*phys_to_virt(phys.as_u64()).as_ptr::<PageTable>() }
    }

    let (p4_frame, _) = Cr3::read();
    let p4 = table_at(p4_frame.start_address());
    let p4e = &p4[addr.p4_index()];
    if !permits(p4e.flags(), write) || p4e.flags().contains(PageTableFlags::HUGE_PAGE) {
        return false;
    }

    let p3 = table_at(p4e.addr());
    let p3e = &p3[addr.p3_index()];
    if !permits(p3e.flags(), write) {
        return false;
    }
    if p3e.flags().contains(PageTableFlags::HUGE_PAGE) {
        return true;
    }

    let p2 = table_at(p3e.addr());
    let p2e = &p2[addr.p2_index()];
    if !permits(p2e.flags(), write) {
        return false;
    }
    if p2e.flags().contains(PageTableFlags::HUGE_PAGE) {
        return true;
    }

    let p1 = table_at(p2e.addr());
    permits(p1[addr.p1_index()].flags(), write)
}

/// Allocate a fresh physical frame and map it at `page` in the kernel
/// address space. Returns the physical frame allocated.
pub fn map_new_page(
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, KernelPageError> {
    let frame = PmmFrameAllocator
        .allocate_frame()
        .ok_or(KernelPageError::OutOfMemory)?;
    if let Err(error) = map_page(page, frame, flags) {
        // SAFETY: map_page failed, so the fresh frame has no published owner.
        unsafe { PmmFrameAllocator.deallocate_frame(frame) };
        return Err(error);
    }
    Ok(frame)
}

/// Failure while mutating a userspace page table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPageError {
    /// The PMM could not allocate a data or intermediate page-table frame.
    OutOfMemory,
    /// Paging initialization has not installed the required mapper.
    NotInitialized,
    /// The virtual page already has a mapping.
    AlreadyMapped,
    /// A huge parent entry prevents a 4 KiB mapping/unmapping operation.
    ParentHugePage,
    /// The requested page was not mapped during rollback.
    NotMapped,
    /// A page-table entry contained an invalid physical frame address.
    InvalidFrameAddress,
}

/// A process's private top-level page table (PML4), sharing the kernel's
/// higher-half mappings but with an independent lower half for userspace.
pub struct AddressSpace {
    pml4_frame: PhysFrame<Size4KiB>,
    /// User pages allocated via [`Self::map_new_user_page`] (e.g. stacks).
    /// Freed on [`Self::destroy`]. Frames mapped from VMOs are *not* listed
    /// here — the VMO owns those and frees them on Drop.
    owned_frames: alloc::vec::Vec<u64>,
}

impl AddressSpace {
    /// Create a new address space that inherits kernel mappings (so that
    /// syscalls/interrupts keep working after a `CR3` switch) but starts
    /// with an empty user half.
    pub fn new() -> Result<Self, UserPageError> {
        let pml4_frame = PmmFrameAllocator
            .allocate_frame()
            .ok_or(UserPageError::OutOfMemory)?;
        let virt = phys_to_virt(pml4_frame.start_address().as_u64());
        let new_table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };
        new_table.zero();

        // Copy the upper half (kernel space, indices 256..512) from the
        // currently active table so kernel code/data/heap stay mapped.
        let (current_frame, _) = Cr3::read();
        let current_virt = phys_to_virt(current_frame.start_address().as_u64());
        let current_table: &PageTable = unsafe { &*current_virt.as_ptr() };
        for i in 256..512 {
            new_table[i] = current_table[i].clone();
        }

        Ok(Self {
            pml4_frame,
            owned_frames: alloc::vec::Vec::new(),
        })
    }

    /// Fallibly map a non-owned frame into this inactive address space.
    pub fn try_map_user_page(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), UserPageError> {
        use x86_64::structures::paging::mapper::MapToError;

        let virt = phys_to_virt(self.pml4_frame.start_address().as_u64());
        // SAFETY: pml4_frame is owned by this AddressSpace and HHDM maps every
        // page-table frame for its full lifetime.
        let table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };
        let phys_offset = VirtAddr::new(*HHDM_OFFSET.lock());
        // SAFETY: table is the unique mutable PML4 owned behind &mut self.
        let mut mapper = unsafe { OffsetPageTable::new(table, phys_offset) };
        let flush = unsafe { mapper.map_to(page, frame, flags, &mut PmmFrameAllocator) }.map_err(
            |error| match error {
                MapToError::FrameAllocationFailed => UserPageError::OutOfMemory,
                MapToError::PageAlreadyMapped(_) => UserPageError::AlreadyMapped,
                MapToError::ParentEntryHugePage => UserPageError::ParentHugePage,
            },
        )?;
        // The child CR3 is inactive, so it cannot contain a stale TLB entry.
        flush.ignore();
        Ok(())
    }

    /// Remove one 4 KiB mapping from this inactive address space.
    ///
    /// Data-frame ownership is unchanged; rollback callers only remove VMO
    /// mappings. Empty intermediate page tables remain allocated until normal
    /// address-space destruction.
    pub fn unmap_user_page(&mut self, page: Page<Size4KiB>) -> Result<(), UserPageError> {
        use x86_64::structures::paging::mapper::UnmapError;

        let virt = phys_to_virt(self.pml4_frame.start_address().as_u64());
        // SAFETY: identical unique-PML4 invariant to try_map_user_page.
        let table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };
        let phys_offset = VirtAddr::new(*HHDM_OFFSET.lock());
        // SAFETY: table and physical offset describe this owned address space.
        let mut mapper = unsafe { OffsetPageTable::new(table, phys_offset) };
        let (_, flush) = mapper.unmap(page).map_err(|error| match error {
            UnmapError::PageNotMapped => UserPageError::NotMapped,
            UnmapError::ParentEntryHugePage => UserPageError::ParentHugePage,
            UnmapError::InvalidFrameAddress(_) => UserPageError::InvalidFrameAddress,
        })?;
        flush.ignore();
        Ok(())
    }

    /// Update permissions on one mapped 4 KiB user page in this address space.
    pub fn protect_user_page(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), UserPageError> {
        let virt = phys_to_virt(self.pml4_frame.start_address().as_u64());
        // SAFETY: pml4_frame is owned by this AddressSpace and HHDM maps every
        // page-table frame for its full lifetime.
        let table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };
        let phys_offset = VirtAddr::new(*HHDM_OFFSET.lock());
        // SAFETY: table is the unique mutable PML4 owned behind &mut self;
        // update_flags changes only the validated page in that table.
        let flush = unsafe {
            let mut mapper = OffsetPageTable::new(table, phys_offset);
            mapper.update_flags(page, flags)
        }
        .map_err(|_| UserPageError::NotMapped)?;
        // The caller performs one range TLB shootdown after the transaction.
        flush.ignore();
        Ok(())
    }

    /// Allocate a fresh frame and map it into this address space.
    /// The frame is owned by this address space and freed in [`Self::destroy`].
    /// If page-table insertion fails, the newly allocated frame is returned
    /// immediately and is never published in `owned_frames`.
    pub fn map_new_user_page(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<PhysFrame<Size4KiB>, UserPageError> {
        let frame = PmmFrameAllocator
            .allocate_frame()
            .ok_or(UserPageError::OutOfMemory)?;
        if let Err(error) = self.try_map_user_page(page, frame, flags) {
            // SAFETY: this frame was allocated immediately above and no
            // mapping or owner retained it after try_map_user_page failed.
            unsafe { PmmFrameAllocator.deallocate_frame(frame) };
            return Err(error);
        }
        self.owned_frames.push(frame.start_address().as_u64());
        Ok(frame)
    }

    /// Physical address of this address space's PML4, suitable for CR3.
    pub fn phys_addr(&self) -> PhysAddr {
        self.pml4_frame.start_address()
    }

    /// Switch the CPU to this address space.
    ///
    /// # Safety
    /// The address space must contain valid kernel mappings (so interrupts
    /// keep working) and must outlive the switch.
    pub unsafe fn activate(&self) {
        unsafe {
            Cr3::write(self.pml4_frame, Cr3Flags::empty());
        }
    }

    /// Tear down the user half of this address space and free owned frames
    /// plus intermediate page-table frames. Kernel upper-half entries are
    /// shared clones and are not freed.
    ///
    /// # Safety
    /// No CPU may still have this PML4 loaded in CR3 (switch away first).
    pub unsafe fn destroy(mut self) {
        let pml4_phys = self.pml4_frame.start_address().as_u64();
        let pml4: &mut PageTable =
            unsafe { &mut *phys_to_virt(pml4_phys).as_mut_ptr::<PageTable>() };

        // Only the lower half is private to this process.
        for i in 0..256 {
            let entry = &pml4[i];
            if entry.is_unused() {
                continue;
            }
            let flags = entry.flags();
            if flags.contains(PageTableFlags::HUGE_PAGE) {
                // Unexpected in our mapper path; free if we own it.
                let addr = entry.addr().as_u64();
                if let Some(pos) = self.owned_frames.iter().position(|&f| f == addr) {
                    self.owned_frames.swap_remove(pos);
                    huesos_pmm::free_frame(addr);
                }
            } else {
                unsafe {
                    free_page_table_recursive(entry.addr().as_u64(), 3, &mut self.owned_frames);
                }
            }
            pml4[i].set_unused();
        }

        for f in self.owned_frames.drain(..) {
            huesos_pmm::free_frame(f);
        }
        huesos_pmm::free_frame(pml4_phys);
        // Forget self fields so Drop doesn't double-free (we consumed frames).
        core::mem::forget(self);
    }
}

/// Recursively free a PDPT (level=3), PD (2), or PT (1).
/// User data frames are only freed if present in `owned`.
/// Intermediate page-table frames are always freed (they were allocated by
/// `map_to` via the PMM and are private to this address space).
unsafe fn free_page_table_recursive(table_phys: u64, level: u8, owned: &mut alloc::vec::Vec<u64>) {
    let table: &mut PageTable = unsafe { &mut *phys_to_virt(table_phys).as_mut_ptr::<PageTable>() };
    for i in 0..512 {
        if table[i].is_unused() {
            continue;
        }
        let flags = table[i].flags();
        let addr = table[i].addr().as_u64();
        if level == 1 || flags.contains(PageTableFlags::HUGE_PAGE) {
            // Leaf data frame: free only if we own it (stack pages, etc.).
            if let Some(pos) = owned.iter().position(|&f| f == addr) {
                owned.swap_remove(pos);
                huesos_pmm::free_frame(addr);
            }
        } else {
            // Intermediate table: recurse (frees `addr` itself at the end).
            unsafe {
                free_page_table_recursive(addr, level - 1, owned);
            }
        }
        table[i].set_unused();
    }
    huesos_pmm::free_frame(table_phys);
}

/// Common page flag combinations.
///
/// Kernel-side data mappings default to W^X: every `KERNEL_RW`-flagged page
/// is `NO_EXECUTE`. The kernel's own `.text` is mapped by Limine with its
/// own flags and is unaffected. New kernel data mappings created through
/// this module (heap pages via `init::heap_init`, ACPI/RSDP windows via
/// `map_hhdm_range`, and future kernel stacks) therefore cannot be reached
/// as a code-execution gadget even if a write-what-where primitive lands in
/// heap memory. EFER.NXE is enabled by `cpu::enable_memory_protection` on
/// every CPU before any of these mappings are installed.
pub mod flags {
    use x86_64::structures::paging::PageTableFlags as F;

    /// Kernel read/write, not user accessible, not executable (W^X).
    pub const KERNEL_RW: F =
        F::from_bits_truncate(F::PRESENT.bits() | F::WRITABLE.bits() | F::NO_EXECUTE.bits());
    /// User read/write.
    pub const USER_RW: F =
        F::from_bits_truncate(F::PRESENT.bits() | F::WRITABLE.bits() | F::USER_ACCESSIBLE.bits());
    /// User read/execute (no write) — for code pages.
    pub const USER_RX: F = F::from_bits_truncate(F::PRESENT.bits() | F::USER_ACCESSIBLE.bits());
}
