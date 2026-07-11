//! Local APIC (xAPIC) driver for x86_64 SMP.
//! Uses memory-mapped registers via the HHDM.

#![allow(missing_docs)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Shared LAPIC timer initial-count for ~100 Hz (Div16), calibrated once on
/// the BSP against the PIT and reused by every AP so they do not race the
/// PIT or invent wildly different tick rates.
static TIMER_INITIAL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Program the LAPIC base address (called once after MADT parsing).
///
/// Also ensures the 4 KiB MMIO page is present in the HHDM. Limine base
/// revision 3 does not map reserved/MMIO ranges, so without this the first
/// `write_reg` in [`init`] page-faults on `0xfee000f0` (SVR).
///
/// # Safety
/// `phys` must be the LAPIC MMIO base reported by validated MADT/MSR state,
/// and `hhdm_offset` must name the active direct map. Call exactly once before
/// any LAPIC register access.
pub unsafe fn set_base(phys: u32, hhdm_offset: u64) {
    // LAPIC is MMIO: must be uncacheable. WB mapping can hang IPI delivery
    // status polls forever (writes never reach the device).
    use x86_64::structures::paging::PageTableFlags;
    crate::x86_64::paging::map_hhdm_range_flags(
        phys as u64,
        0x1000,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
    );
    LAPIC_BASE.store(hhdm_offset + phys as u64, Ordering::Relaxed);
}

fn base() -> u64 {
    LAPIC_BASE.load(Ordering::Relaxed)
}

fn read_reg(offset: u32) -> u32 {
    let ptr = (base() + offset as u64) as *const u32;
    unsafe { read_volatile(ptr) }
}

fn write_reg(offset: u32, value: u32) {
    let ptr = (base() + offset as u64) as *mut u32;
    unsafe { write_volatile(ptr, value) }
}

/// Local APIC ID register offset.
pub const REG_APIC_ID: u32 = 0x020;
/// Error Status Register offset.
pub const REG_EOI: u32 = 0x0B0;
/// Spurious Interrupt Vector Register offset.
pub const REG_SPURIOUS: u32 = 0x0F0;
/// In-Service Register (bits 0-31) offset.
pub const REG_ICR_LOW: u32 = 0x300;
/// In-Service Register (bits 32-63) offset.
pub const REG_ICR_HIGH: u32 = 0x310;
/// LVT Timer Register offset.
pub const REG_LVT_TIMER: u32 = 0x320;
/// Timer Initial Count Register offset.
pub const REG_TIMER_INIT_COUNT: u32 = 0x380;
/// Timer Current Count Register offset.
pub const REG_TIMER_CUR_COUNT: u32 = 0x390;
/// Timer Divide Configuration Register offset.
pub const REG_TIMER_DIVIDE: u32 = 0x3E0;

/// Read the local APIC ID of this CPU.
pub fn id() -> u32 {
    read_reg(REG_APIC_ID) >> 24
}

/// Send End-Of-Interrupt to the local APIC.
///
/// No-op if [`set_base`] has not been called yet (avoids writing through a
/// null HHDM pointer during very early boot).
pub fn eoi() {
    if base() == 0 {
        return;
    }
    write_reg(REG_EOI, 0);
}

/// Store the BSP-calibrated LAPIC timer initial count for all CPUs.
pub fn set_timer_initial_count(count: u32) {
    TIMER_INITIAL_COUNT.store(count.max(1), Ordering::Relaxed);
}

/// Read the shared LAPIC timer initial count (0 if not calibrated yet).
pub fn timer_initial_count() -> u32 {
    TIMER_INITIAL_COUNT.load(Ordering::Relaxed)
}

/// Initialize the local APIC: enable it and set the spurious vector.
pub fn init() {
    // Enable LAPIC and set spurious vector to 0xFF (255).
    write_reg(REG_SPURIOUS, 0x1FF);
}

/// IPI delivery modes.
#[derive(Clone, Copy)]
pub enum IpiDelivery {
    Fixed = 0x0000_0000,
    Init = 0x0000_0500,
    Startup = 0x0000_0600,
}

/// Rough microsecond busy-wait. Not cycle-accurate; good enough for
/// INIT-SIPI settle times under QEMU TCG / KVM.
pub fn delay_us(us: u32) {
    // Pure CPU spin — no MMIO. Keep the multiplier modest so TCG does not
    // spend tens of seconds here.
    let iters = (us as u64).saturating_mul(50).max(50);
    for _ in 0..iters {
        core::hint::spin_loop();
    }
}

fn wait_icr_idle() {
    // Delivery Status (bit 12). Cap hard: every iteration is an MMIO load,
    // and under QEMU TCG those are *extremely* expensive. A few hundred
    // polls is plenty on real HW and on KVM; on TCG we must not spin 200k.
    for _ in 0..256 {
        if read_reg(REG_ICR_LOW) & 0x1000 == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Send an IPI to `dest_apic_id`.
///
/// # Safety
/// Must not be called before `set_base`.
pub unsafe fn send_ipi(dest_apic_id: u8, vector: u8, delivery: IpiDelivery) {
    wait_icr_idle();
    write_reg(REG_ICR_HIGH, (dest_apic_id as u32) << 24);

    let mut cmd = (vector as u32) | (delivery as u32);
    // INIT requires Level=Assert (bit 14) and Trigger=Level (bit 15).
    // SIPI is edge-triggered; level bits must be clear.
    if matches!(delivery, IpiDelivery::Init) {
        cmd |= (1 << 14) | (1 << 15);
    }
    write_reg(REG_ICR_LOW, cmd);
}

/// INIT IPI with Level=Assert | Trigger=Level (Intel SDM INIT-SIPI-SIPI).
///
/// # Safety
/// LAPIC MMIO must be initialized and `dest_apic_id` must identify a CPU that
/// may legally receive the AP bootstrap sequence.
pub unsafe fn send_init_assert(dest_apic_id: u8) {
    send_ipi(dest_apic_id, 0, IpiDelivery::Init);
}

/// SIPI with startup vector = physical page of the trampoline.
///
/// # Safety
/// LAPIC MMIO must be initialized; `vector` must address a prepared low-memory
/// trampoline page and the destination CPU must already have received INIT.
pub unsafe fn send_startup(dest_apic_id: u8, vector: u8) {
    send_ipi(dest_apic_id, vector, IpiDelivery::Startup);
}

/// APIC timer divide values.
pub enum TimerDivide {
    Div1 = 0b1011,
    Div2 = 0b0000,
    Div4 = 0b0001,
    Div8 = 0b0010,
    Div16 = 0b0011,
    Div32 = 0b1000,
    Div64 = 0b1001,
    Div128 = 0b1010,
}

/// APIC timer modes.
#[derive(Clone, Copy)]
pub enum TimerMode {
    OneShot = 0b00 << 17,
    Periodic = 0b01 << 17,
    TscDeadline = 0b10 << 17,
}

/// Configure the APIC timer in periodic mode.
///
/// # Safety
/// Must not be called before `set_base` and `init`.
pub unsafe fn timer_init(divide: TimerDivide, mode: TimerMode, initial_count: u32, vector: u8) {
    write_reg(REG_TIMER_DIVIDE, divide as u32);
    let lvt = (vector as u32) | (mode as u32) | 0x0002_0000; // mask timer initially
    write_reg(REG_LVT_TIMER, lvt);
    write_reg(REG_TIMER_INIT_COUNT, initial_count);
    // Unmask timer.
    write_reg(REG_LVT_TIMER, (vector as u32) | (mode as u32));
}

/// Stop the APIC timer.
pub fn timer_stop() {
    if base() == 0 {
        return;
    }
    write_reg(REG_LVT_TIMER, 0x0001_0000); // masked
    write_reg(REG_TIMER_INIT_COUNT, 0);
}

/// Calibrate the LAPIC timer against the PIT.
/// Returns the initial count value for ~100 Hz periodic timer.
pub fn calibrate_timer() -> u32 {
    use x86_64::instructions::port::Port;

    let saved = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();

    // PIT channel 0: one-shot (mode 0), lobyte/hibyte, ~50 ms.
    let mut cmd: Port<u8> = Port::new(0x43);
    let mut data0: Port<u8> = Port::new(0x40);
    const DIVIDER: u16 = 59_659; // 50 ms @ 1.193182 MHz

    unsafe {
        cmd.write(0x30); // channel 0, lobyte/hibyte, mode 0
        data0.write((DIVIDER & 0xFF) as u8);
        data0.write((DIVIDER >> 8) as u8);
    }

    // LAPIC: start counting down from max.
    write_reg(REG_TIMER_DIVIDE, TimerDivide::Div16 as u32);
    write_reg(REG_LVT_TIMER, 0x0001_0000); // masked
    write_reg(REG_TIMER_INIT_COUNT, 0xFFFFFFFF);

    // Poll PIT until count reaches 0.
    loop {
        unsafe {
            cmd.write(0x00);
        } // latch
        let lo = unsafe { data0.read() } as u16;
        let hi = unsafe { data0.read() } as u16;
        if ((hi << 8) | lo) == 0 {
            break;
        }
    }

    let lapic_cur = read_reg(REG_TIMER_CUR_COUNT);
    let ticks_50ms = 0xFFFFFFFFu32 - lapic_cur;

    if saved {
        x86_64::instructions::interrupts::enable();
    }

    // 100 Hz = 10 ms period = 50 ms / 5.
    ticks_50ms / 5
}

/// Send a fixed-vector IPI to every CPU except the caller.
///
/// Used by the fatal panic path. This is best-effort: before LAPIC setup there
/// are no running APs to stop, so an unavailable LAPIC is a harmless no-op.
pub fn broadcast_excluding_self(vector: u8) {
    if base() == 0 {
        return;
    }
    wait_icr_idle();
    // Destination shorthand 0b11 = all excluding self, fixed delivery.
    write_reg(REG_ICR_LOW, vector as u32 | (0b11 << 18));
    wait_icr_idle();
}

/// Send a reschedule IPI to `dest_apic_id`.
/// Uses the timer vector (0x20) to trigger a scheduler tick on the target CPU.
pub fn ipi_reschedule(dest_apic_id: u8) {
    unsafe {
        send_ipi(dest_apic_id, 0x20, IpiDelivery::Fixed);
    }
}
