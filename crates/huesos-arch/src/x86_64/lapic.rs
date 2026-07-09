//! Local APIC (xAPIC) driver for x86_64 SMP.
//! Uses memory-mapped registers via the HHDM.

#![allow(missing_docs)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Program the LAPIC base address (called once after MADT parsing).
pub unsafe fn set_base(phys: u32, hhdm_offset: u64) {
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
pub fn eoi() {
    write_reg(REG_EOI, 0);
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

/// Send an IPI to `dest_apic_id`.
///
/// # Safety
/// Must not be called before `set_base`.
pub unsafe fn send_ipi(dest_apic_id: u8, vector: u8, delivery: IpiDelivery) {
    // Wait for Delivery Status bit (bit 12) to clear.
    while read_reg(REG_ICR_LOW) & 0x1000 != 0 {
        core::hint::spin_loop();
    }

    // Write destination to ICR_HIGH.
    write_reg(REG_ICR_HIGH, (dest_apic_id as u32) << 24);

    // Write command to ICR_LOW.
    let mut cmd = (vector as u32) | (delivery as u32);
    // Level=assert (bit 14) for INIT and STARTUP.
    if matches!(delivery, IpiDelivery::Init | IpiDelivery::Startup) {
        cmd |= 0x4000;
    }
    write_reg(REG_ICR_LOW, cmd);
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
        unsafe { cmd.write(0x00); } // latch
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

/// Send a reschedule IPI to `dest_apic_id`.
/// Uses the timer vector (0x20) to trigger a scheduler tick on the target CPU.
pub fn ipi_reschedule(dest_apic_id: u8) {
    unsafe {
        send_ipi(dest_apic_id, 0x20, IpiDelivery::Fixed);
    }
}
