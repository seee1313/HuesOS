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

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        static mut STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
        stack_start + IST_STACK_SIZE as u64
    };
    // RSP0: kernel stack loaded automatically on ring3->ring0 interrupts/syscalls.
    tss.privilege_stack_table[0] = {
        static mut STACK: [u8; PRIVILEGE_STACK_SIZE] = [0; PRIVILEGE_STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
        stack_start + PRIVILEGE_STACK_SIZE as u64
    };
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
    // Safety: TSS is a `Lazy` — we get away with interior mutability via a
    // raw pointer since only one CPU touches it in this single-core MVP.
    let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
    unsafe {
        (*tss_ptr).privilege_stack_table[0] = stack_top;
    }
}

/// Per-CPU GDT + TSS bundle. Each CPU must have its own instance so that
/// `set_kernel_stack` is race-free under SMP.
pub struct PerCpuGdt {
    pub table: &'static GlobalDescriptorTable,
    pub selectors: Selectors,
    tss_ptr: *mut TaskStateSegment,
}

impl PerCpuGdt {
    /// Create a fresh GDT + TSS for the current CPU.
    /// The GDT and TSS are leaked to `'static` so that `Descriptor::tss_segment`
    /// is satisfied and the selectors remain valid forever.
    pub fn new() -> Self {
        let tss = alloc::boxed::Box::leak(alloc::boxed::Box::new(TaskStateSegment::new()));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            static mut STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(core::ptr::addr_of!(STACK));
            stack_start + IST_STACK_SIZE as u64
        };
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
        unsafe { (*self.tss_ptr).privilege_stack_table[0] = stack_top; }
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
