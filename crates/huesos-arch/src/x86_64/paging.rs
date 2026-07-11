//! Paging: kernel address space + per-process page table management.
//!
//! Frame allocation is backed by `huesos-pmm`'s bitmap allocator (a real
//! physical memory manager fed from the Limine memory map), not a hardcoded
//! bump range.

use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// Higher-half direct map offset, fixed once at boot.
static HHDM_OFFSET: Mutex<u64> = Mutex::new(0);

/// Kernel's own mapper over the bootloader-provided top-level table.
static KERNEL_PAGE_TABLE: Mutex<Option<OffsetPageTable<'static>>> = Mutex::new(None);

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

/// Map `page` to `frame` with `flags` in the *kernel* address space.
pub fn map_page(page: Page<Size4KiB>, frame: PhysFrame<Size4KiB>, flags: PageTableFlags) {
    let mut guard = KERNEL_PAGE_TABLE.lock();
    let mapper = guard.as_mut().expect("page table not initialized");
    unsafe {
        mapper
            .map_to(page, frame, flags, &mut PmmFrameAllocator)
            .expect("kernel map_to failed")
            .flush();
    }
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
pub fn map_hhdm_range(phys_base: u64, length: u64) {
    map_hhdm_range_flags(
        phys_base,
        length,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    );
}

/// Like [`map_hhdm_range`], but with explicit page flags (e.g. `NO_CACHE` for MMIO).
pub fn map_hhdm_range_flags(phys_base: u64, length: u64, flags: PageTableFlags) {
    map_phys_range(phys_base, length, flags, |phys| phys_to_virt(phys));
}

/// Identity-map `[phys_base, phys_base + length)` so `virt == phys`.
///
/// Required for the AP trampoline: after it enables paging with the kernel
/// CR3 it still loads RSP/entry from absolute addresses `0x7008` / `0x7010`.
/// Base revision 3 dropped the unconditional low 4 GiB identity map, so we
/// must reinstall the few pages the trampoline needs.
pub fn map_identity_range(phys_base: u64, length: u64) {
    map_phys_range(
        phys_base,
        length,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        |phys| VirtAddr::new(phys),
    );
}

fn map_phys_range(
    phys_base: u64,
    length: u64,
    flags: PageTableFlags,
    virt_of: impl Fn(u64) -> VirtAddr,
) {
    if length == 0 {
        return;
    }
    let start = phys_base & !0xfff;
    let end = phys_base
        .checked_add(length)
        .unwrap_or(u64::MAX)
        .saturating_add(0xfff)
        & !0xfff;

    let mut guard = KERNEL_PAGE_TABLE.lock();
    let mapper = guard.as_mut().expect("page table not initialized");

    let mut phys = start;
    while phys < end {
        let page = Page::<Size4KiB>::containing_address(virt_of(phys));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        unsafe {
            match mapper.map_to(page, frame, flags, &mut PmmFrameAllocator) {
                Ok(flush) => flush.flush(),
                Err(x86_64::structures::paging::mapper::MapToError::PageAlreadyMapped(_)) => {
                    // Page present (e.g. Limine left it WB). Force the flags
                    // we want — critical for LAPIC NO_CACHE.
                    let _ = mapper.update_flags(page, flags).map(|f| f.flush());
                }
                Err(x86_64::structures::paging::mapper::MapToError::ParentEntryHugePage) => {}
                Err(_) => {
                    // Best-effort: leave unmapped; caller will observe the #PF.
                }
            }
        }
        phys = phys.saturating_add(4096);
        if phys == 0 {
            break;
        }
    }
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
pub fn map_new_page(page: Page<Size4KiB>, flags: PageTableFlags) -> PhysFrame<Size4KiB> {
    let frame = PmmFrameAllocator
        .allocate_frame()
        .expect("out of physical memory");
    map_page(page, frame, flags);
    frame
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
    pub fn new() -> Self {
        let pml4_frame = PmmFrameAllocator
            .allocate_frame()
            .expect("out of memory allocating PML4");
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

        Self {
            pml4_frame,
            owned_frames: alloc::vec::Vec::new(),
        }
    }

    /// Map a page into this address space (user-accessible).
    ///
    /// Does **not** take ownership of `frame` (VMO-backed mappings).
    pub fn map_user_page(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) {
        let virt = phys_to_virt(self.pml4_frame.start_address().as_u64());
        let table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };
        let phys_offset = VirtAddr::new(*HHDM_OFFSET.lock());
        let mut mapper = unsafe { OffsetPageTable::new(table, phys_offset) };
        unsafe {
            mapper
                .map_to(page, frame, flags, &mut PmmFrameAllocator)
                .expect("user map_to failed")
                .flush();
        }
    }

    /// Allocate a fresh frame and map it into this address space.
    /// The frame is owned by this address space and freed in [`Self::destroy`].
    pub fn map_new_user_page(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> PhysFrame<Size4KiB> {
        let frame = PmmFrameAllocator.allocate_frame().expect("out of memory");
        self.owned_frames.push(frame.start_address().as_u64());
        self.map_user_page(page, frame, flags);
        frame
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

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Common page flag combinations.
pub mod flags {
    use x86_64::structures::paging::PageTableFlags as F;

    /// Kernel read/write, not user accessible.
    pub const KERNEL_RW: F = F::from_bits_truncate(F::PRESENT.bits() | F::WRITABLE.bits());
    /// User read/write.
    pub const USER_RW: F =
        F::from_bits_truncate(F::PRESENT.bits() | F::WRITABLE.bits() | F::USER_ACCESSIBLE.bits());
    /// User read/execute (no write) — for code pages.
    pub const USER_RX: F = F::from_bits_truncate(F::PRESENT.bits() | F::USER_ACCESSIBLE.bits());
}
