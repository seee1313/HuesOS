//! Global Descriptor Table with kernel + user segments and a TSS.
//!
//! Layout (selector index order matters for the `syscall`/`sysret`
//! fast path, which expects a specific arrangement of segments in
//! the `STAR` MSR):
//!
//! 0: null
//! 1: kernel code (ring0)
//! 2: kernel data (ring0)
//! 3: user data (ring3)     -- placed before user code for SYSRET's layout
//! 4: user code (ring3)
//! 5-6: TSS (takes two GDT slots on x86_64)

use core::cell::UnsafeCell;
use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Size of the interrupt stack used on double-fault / NMI.
pub const IST_STACK_SIZE: usize = 4096 * 5;
/// Size of the privilege-level 0 stack loaded on ring3 -> ring0 transitions.
pub const PRIVILEGE_STACK_SIZE: usize = 4096 * 16;

/// Index of the double-fault IST stack inside the TSS.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Fixed early-boot stack storage with explicit interior mutability.
///
/// The BSP owns these stacks exclusively. APs allocate separate stacks after
/// the heap is available, so no two CPUs can write the same stack memory.
struct StaticStack<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: each instance is assigned to one CPU and is never exposed as a Rust
// reference. Hardware uses only the raw address recorded in that CPU's TSS.
unsafe impl<const N: usize> Sync for StaticStack<N> {}

impl<const N: usize> StaticStack<N> {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    fn top(&'static self) -> VirtAddr {
        VirtAddr::from_ptr(self.0.get()) + N as u64
    }
}

static BSP_IST_STACK: StaticStack<IST_STACK_SIZE> = StaticStack::new();
static BSP_PRIVILEGE_STACK: StaticStack<PRIVILEGE_STACK_SIZE> = StaticStack::new();

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = BSP_IST_STACK.top();
    // RSP0: kernel stack loaded automatically on ring3->ring0 interrupts/syscalls.
    tss.privilege_stack_table[0] = BSP_PRIVILEGE_STACK.top();
    tss
});

/// Selectors resolved once the GDT is built.
pub struct Selectors {
    /// Kernel code segment selector (ring0).
    pub kernel_code: SegmentSelector,
    /// Kernel data segment selector (ring0).
    pub kernel_data: SegmentSelector,
    /// User data segment selector (ring3).
    pub user_data: SegmentSelector,
    /// User code segment selector (ring3).
    pub user_code: SegmentSelector,
    /// TSS selector.
    pub tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (
        gdt,
        Selectors {
            kernel_code,
            kernel_data,
            user_data,
            user_code,
            tss,
        },
    )
});

/// Return the resolved GDT selectors (kernel/user code+data, TSS).
pub fn selectors() -> &'static Selectors {
    &GDT.1
}

/// Update RSP0 in the TSS. Called by the scheduler when switching tasks so
/// that the next ring3->ring0 transition lands on the correct kernel stack.
pub fn set_kernel_stack(stack_top: VirtAddr) {
    unsafe {
        let cpu_local_ptr = crate::cpu_local::cpu_local_ptr();
        if !cpu_local_ptr.is_null() && !(*cpu_local_ptr).gdt.is_null() {
            let per_cpu_gdt = &mut *((*cpu_local_ptr).gdt as *mut PerCpuGdt);
            per_cpu_gdt.set_kernel_stack(stack_top);
        } else {
            let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
            (*tss_ptr).privilege_stack_table[0] = stack_top;
        }
    }
}

/// Per-CPU GDT + TSS bundle. Each CPU must have its own instance so that
/// `set_kernel_stack` is race-free under SMP.
pub struct PerCpuGdt {
    /// Leaked, permanently pinned descriptor table loaded by this CPU.
    pub table: &'static GlobalDescriptorTable,
    /// Segment selectors belonging to `table`.
    pub selectors: Selectors,
    /// Pinned TSS updated only by the owning CPU's scheduler.
    tss_ptr: *mut TaskStateSegment,
}

impl Default for PerCpuGdt {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuGdt {
    /// Create a fresh GDT + TSS for the current CPU.
    /// The GDT and TSS are leaked to `'static` so that `Descriptor::tss_segment`
    /// is satisfied and the selectors remain valid forever.
    pub fn new() -> Self {
        let tss = alloc::boxed::Box::leak(alloc::boxed::Box::new(TaskStateSegment::new()));
        let ist_stack = alloc::boxed::Box::leak(alloc::boxed::Box::new([0u8; IST_STACK_SIZE]));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            VirtAddr::from_ptr(ist_stack.as_ptr()) + IST_STACK_SIZE as u64;
        let tss_ptr: *mut TaskStateSegment = tss;
        let mut gdt = alloc::boxed::Box::new(GlobalDescriptorTable::new());
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss_sel = gdt.append(Descriptor::tss_segment(tss));
        let table = alloc::boxed::Box::leak(gdt);
        Self {
            table,
            selectors: Selectors {
                kernel_code,
                kernel_data,
                user_data,
                user_code,
                tss: tss_sel,
            },
            tss_ptr,
        }
    }

    /// Load this GDT into the current CPU and update segment registers.
    pub fn load(&self) {
        self.table.load();
        unsafe {
            CS::set_reg(self.selectors.kernel_code);
            DS::set_reg(self.selectors.kernel_data);
            ES::set_reg(self.selectors.kernel_data);
            SS::set_reg(self.selectors.kernel_data);
            load_tss(self.selectors.tss);
        }
    }

    /// Update RSP0 in this CPU's TSS.
    pub fn set_kernel_stack(&self, stack_top: VirtAddr) {
        unsafe {
            (*self.tss_ptr).privilege_stack_table[0] = stack_top;
        }
    }
}

/// Load GDT and update segment registers.
pub fn init() {
    GDT.0.load();
    let sel = selectors();
    unsafe {
        CS::set_reg(sel.kernel_code);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        SS::set_reg(sel.kernel_data);
        load_tss(sel.tss);
    }
}
