//! Local APIC (`xAPIC` MMIO + `x2APIC` MSR) driver for x86_64 SMP.

#![allow(missing_docs)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);
static X2APIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Shared LAPIC timer initial-count for ~100 Hz (10 ms @ Div16), calibrated
/// once on the BSP against the PIT and reused by every AP for both one-shot
/// nanosecond conversion and periodic fallback.
static TIMER_INITIAL_COUNT: AtomicU32 = AtomicU32::new(0);

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_EN: u64 = 1 << 11;
const APIC_BASE_EXTD: u64 = 1 << 10;
const X2APIC_MSR_BASE: u32 = 0x800;
const X2APIC_ICR_MSR: u32 = 0x830;

/// Whether CPUID advertises `x2APIC` support (`CPUID.1:ECX[21]`).
pub fn x2apic_supported() -> bool {
    (core::arch::x86_64::__cpuid(1).ecx & (1 << 21)) != 0
}

/// Whether the active LAPIC backend is `x2APIC` MSR mode.
pub fn x2apic_enabled() -> bool {
    X2APIC_ACTIVE.load(Ordering::Acquire)
}

/// True when the active or supported APIC mode can address `apic_id` via unicast IPI.
pub fn can_address_apic_id(apic_id: u32) -> bool {
    x2apic_enabled() || x2apic_supported() || apic_id < 0xff
}

/// Program the LAPIC MMIO base address (called once after MADT parsing).
///
/// # Safety
/// `phys` must be the LAPIC MMIO base reported by validated MADT/MSR state,
/// and `hhdm_offset` must name the active direct map. Call before xAPIC MMIO
/// register access.
pub unsafe fn set_base(phys: u64, hhdm_offset: u64) {
    use x86_64::structures::paging::PageTableFlags;
    let _ = crate::x86_64::paging::map_hhdm_range_flags(
        phys,
        4096,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::NO_EXECUTE,
    );
    LAPIC_BASE.store(hhdm_offset + phys, Ordering::Release);
}

#[inline]
fn base() -> u64 {
    LAPIC_BASE.load(Ordering::Relaxed)
}

#[inline]
fn is_ready() -> bool {
    X2APIC_ACTIVE.load(Ordering::Acquire) || base() != 0
}

fn read_reg(offset: u32) -> u32 {
    unsafe {
        if X2APIC_ACTIVE.load(Ordering::Acquire) {
            let msr = X2APIC_MSR_BASE + (offset >> 4);
            let lo: u32;
            let _hi: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") lo,
                out("edx") _hi,
                options(nomem, nostack, preserves_flags),
            );
            lo
        } else {
            let ptr = (base() + offset as u64) as *const u32;
            read_volatile(ptr)
        }
    }
}

fn write_reg(offset: u32, value: u32) {
    unsafe {
        if X2APIC_ACTIVE.load(Ordering::Acquire) {
            let msr = X2APIC_MSR_BASE + (offset >> 4);
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") value,
                in("edx") 0u32,
                options(nomem, nostack, preserves_flags),
            );
        } else {
            let ptr = (base() + offset as u64) as *mut u32;
            write_volatile(ptr, value);
        }
    }
}

/// Local APIC ID register offset.
pub const REG_APIC_ID: u32 = 0x020;
/// End-Of-Interrupt register offset.
pub const REG_EOI: u32 = 0x0B0;
/// Spurious Interrupt Vector Register offset.
pub const REG_SPURIOUS: u32 = 0x0F0;
/// Interrupt Command Register (bits 0-31) offset.
pub const REG_ICR_LOW: u32 = 0x300;
/// Interrupt Command Register (bits 32-63) offset.
pub const REG_ICR_HIGH: u32 = 0x310;
/// LVT Timer Register offset.
pub const REG_LVT_TIMER: u32 = 0x320;
/// Timer Initial Count Register offset.
pub const REG_TIMER_INIT_COUNT: u32 = 0x380;
/// Timer Current Count Register offset.
pub const REG_TIMER_CUR_COUNT: u32 = 0x390;
/// Timer Divide Configuration Register offset.
pub const REG_TIMER_DIVIDE: u32 = 0x3E0;

/// Read the 32-bit Local APIC / x2APIC ID of this CPU.
pub fn id() -> u32 {
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        read_reg(REG_APIC_ID)
    } else {
        read_reg(REG_APIC_ID) >> 24
    }
}

/// Send End-Of-Interrupt to the local APIC.
pub fn eoi() {
    if !is_ready() {
        return;
    }
    write_reg(REG_EOI, 0);
}

/// Store the BSP-calibrated LAPIC timer initial count (10 ms @ Div16) for all CPUs.
pub fn set_timer_initial_count(count: u32) {
    TIMER_INITIAL_COUNT.store(count.max(1), Ordering::Release);
}

/// Read the shared LAPIC timer initial count (0 if not calibrated yet).
pub fn timer_initial_count() -> u32 {
    TIMER_INITIAL_COUNT.load(Ordering::Acquire)
}

/// Initialize the local APIC on the calling CPU: enable `x2APIC` when supported
/// by CPUID (or already active in `IA32_APIC_BASE`), otherwise enable `xAPIC`
/// MMIO, and unmask the spurious interrupt vector (`0xFF`).
pub fn init() {
    let want_x2apic = x2apic_supported();
    unsafe {
        use x86_64::registers::model_specific::Msr;
        let mut apic_msr = Msr::new(IA32_APIC_BASE_MSR);
        let mut apic_base = apic_msr.read();
        if apic_base & APIC_BASE_EN == 0 {
            apic_base |= APIC_BASE_EN;
            apic_msr.write(apic_base);
        }
        if (apic_base & APIC_BASE_EXTD) != 0 || want_x2apic {
            if apic_base & APIC_BASE_EXTD == 0 {
                apic_base |= APIC_BASE_EXTD;
                apic_msr.write(apic_base);
            }
            X2APIC_ACTIVE.store(true, Ordering::Release);
        }
    }
    write_reg(REG_SPURIOUS, 0x1FF);
}

/// Delivery modes for ICR.
#[derive(Clone, Copy)]
pub enum IpiDelivery {
    Fixed = 0x0000_0000,
    Init = 0x0000_0500,
    Startup = 0x0000_0600,
}

/// Rough microsecond busy-wait for INIT-SIPI settle windows.
pub fn delay_us(us: u32) {
    let iters = (us as u64).saturating_mul(50).max(50);
    for _ in 0..iters {
        core::hint::spin_loop();
    }
}

fn wait_icr_idle() {
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    for _ in 0..256 {
        if read_reg(REG_ICR_LOW) & 0x1000 == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Send an IPI to 32-bit `dest_apic_id`.
///
/// # Safety
/// Must not be called before `init` (and `set_base` when running in `xAPIC` mode).
pub unsafe fn send_ipi(dest_apic_id: u32, vector: u8, delivery: IpiDelivery) {
    if !is_ready() {
        return;
    }
    let mut cmd = (vector as u32) | (delivery as u32) | (1 << 14);
    if matches!(delivery, IpiDelivery::Init) {
        cmd |= 1 << 15;
    }
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        core::arch::asm!(
            "wrmsr",
            in("ecx") X2APIC_ICR_MSR,
            in("eax") cmd,
            in("edx") dest_apic_id,
            options(nomem, nostack, preserves_flags),
        );
    } else {
        if dest_apic_id >= 0xff {
            return;
        }
        wait_icr_idle();
        write_reg(REG_ICR_HIGH, dest_apic_id << 24);
        write_reg(REG_ICR_LOW, cmd);
    }
}

/// INIT IPI with Level=Assert | Trigger=Level (Intel SDM INIT-SIPI-SIPI).
///
/// # Safety
/// LAPIC must be initialized and `dest_apic_id` must identify a CPU that may
/// legally receive the AP bootstrap sequence.
pub unsafe fn send_init_assert(dest_apic_id: u32) {
    send_ipi(dest_apic_id, 0, IpiDelivery::Init);
}

/// SIPI with startup vector = physical page of the trampoline.
///
/// # Safety
/// LAPIC must be initialized; `vector` must address a prepared low-memory
/// trampoline page and the destination CPU must already have received INIT.
pub unsafe fn send_startup(dest_apic_id: u32, vector: u8) {
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

/// Configure the APIC timer.
///
/// # Safety
/// Must not be called before `init`.
pub unsafe fn timer_init(divide: TimerDivide, mode: TimerMode, initial_count: u32, vector: u8) {
    if !is_ready() {
        return;
    }
    write_reg(REG_TIMER_DIVIDE, divide as u32);
    let lvt = (vector as u32) | (mode as u32) | 0x0001_0000;
    write_reg(REG_LVT_TIMER, lvt);
    write_reg(REG_TIMER_INIT_COUNT, initial_count);
    write_reg(REG_LVT_TIMER, (vector as u32) | (mode as u32));
}

/// Arm the local APIC timer in calibrated `OneShot` mode for `delay_ns`
/// nanoseconds using the BSP-calibrated `10 ms` (`Div16`) count.
pub fn timer_arm_oneshot_ns(delay_ns: u64, vector: u8) -> bool {
    if !is_ready() {
        return false;
    }
    let count_10ms = timer_initial_count();
    if count_10ms == 0 {
        return false;
    }
    let clamped_ns = delay_ns.clamp(50_000, 100_000_000);
    let scaled = ((clamped_ns as u128) * (count_10ms as u128)) / 10_000_000u128;
    let count = scaled.clamp(1, u32::MAX as u128) as u32;
    write_reg(REG_TIMER_DIVIDE, TimerDivide::Div16 as u32);
    write_reg(REG_LVT_TIMER, (vector as u32) | (TimerMode::OneShot as u32));
    write_reg(REG_TIMER_INIT_COUNT, count);
    true
}

/// Stop the APIC timer (including disarming `IA32_TSC_DEADLINE` when supported).
pub fn timer_stop() {
    if !is_ready() {
        return;
    }
    write_reg(REG_LVT_TIMER, 0x0001_0000);
    write_reg(REG_TIMER_INIT_COUNT, 0);
    if tsc_deadline_supported() {
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0x6E0u32,
                in("edx") 0u32,
                in("eax") 0u32,
                options(nomem, nostack),
            );
        }
    }
}

/// Arm the LAPIC timer in TSC-deadline mode.
///
/// # Safety
/// Must not be called before `init`, and only when `tsc_deadline_supported()` is true.
pub unsafe fn timer_arm_tsc_deadline(deadline_tsc: u64, vector: u8) {
    if !is_ready() || !tsc_deadline_supported() {
        return;
    }
    let lvt = (vector as u32) | (TimerMode::TscDeadline as u32);
    write_reg(REG_LVT_TIMER, lvt);
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x6E0u32,
            in("edx") (deadline_tsc >> 32) as u32,
            in("eax") deadline_tsc as u32,
            options(nomem, nostack),
        );
    }
}

/// Whether the CPU exposes the TSC-deadline timer mode (`CPUID.1:ECX[24]`).
pub fn tsc_deadline_supported() -> bool {
    let leaf1 = core::arch::x86_64::__cpuid(1);
    leaf1.ecx & (1 << 24) != 0
}

/// Whether the TSC is architectural Invariant TSC (`CPUID.80000007H:EDX[8]`).
pub fn tsc_invariant() -> bool {
    let max_ext = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if max_ext < 0x8000_0007 {
        return false;
    }
    let leaf8000 = core::arch::x86_64::__cpuid(0x8000_0007);
    leaf8000.edx & (1 << 8) != 0
}

fn cpuid_tsc_hz() -> Option<u64> {
    let max_basic = core::arch::x86_64::__cpuid(0).eax;
    if max_basic >= 0x15 {
        let l15 = core::arch::x86_64::__cpuid(0x15);
        if l15.eax != 0 && l15.ebx != 0 {
            if l15.ecx != 0 {
                let hz = (l15.ecx as u64).saturating_mul(l15.ebx as u64) / (l15.eax as u64);
                if hz >= 10_000_000 {
                    return Some(hz);
                }
            } else if max_basic >= 0x16 {
                let l16 = core::arch::x86_64::__cpuid(0x16);
                let base_mhz = (l16.eax & 0xffff) as u64;
                if base_mhz >= 100 {
                    return Some(base_mhz.saturating_mul(1_000_000));
                }
            }
        }
    }
    None
}

/// Calibrate the TSC frequency in Hz using CPUID leaves `0x15`/`0x16` when
/// available, otherwise measuring a full latched 50 ms PIT countdown.
pub fn calibrate_tsc_hz() -> u64 {
    if let Some(cpuid_hz) = cpuid_tsc_hz() {
        return cpuid_hz;
    }

    use x86_64::instructions::port::Port;
    let saved = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();

    let mut cmd: Port<u8> = Port::new(0x43);
    let mut data0: Port<u8> = Port::new(0x40);
    const DIVIDER: u16 = 59_659; // 50 ms @ 1.193182 MHz

    let start: u64;
    let end: u64;
    unsafe {
        cmd.write(0x30);
        data0.write((DIVIDER & 0xFF) as u8);
        data0.write((DIVIDER >> 8) as u8);
        start = crate::rdtsc();

        let mut armed = false;
        for _ in 0..50_000_000u32 {
            cmd.write(0x00);
            let lo = data0.read() as u16;
            let hi = data0.read() as u16;
            let cur = (hi << 8) | lo;
            if cur <= DIVIDER && cur > 0 {
                armed = true;
            }
            if cur == 0 || (armed && cur > DIVIDER) {
                break;
            }
        }
        end = crate::rdtsc();
    }

    if saved {
        x86_64::instructions::interrupts::enable();
    }
    end.wrapping_sub(start).saturating_mul(20).max(1_000_000)
}

/// Calibrate the LAPIC timer against the PIT (returns initial count for ~100 Hz @ Div16).
pub fn calibrate_timer() -> u32 {
    use x86_64::instructions::port::Port;

    let saved = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();

    let mut cmd: Port<u8> = Port::new(0x43);
    let mut data0: Port<u8> = Port::new(0x40);
    const DIVIDER: u16 = 59_659; // 50 ms @ 1.193182 MHz

    write_reg(REG_TIMER_DIVIDE, TimerDivide::Div16 as u32);
    write_reg(REG_LVT_TIMER, 0x0001_0000);
    write_reg(REG_TIMER_INIT_COUNT, 0xFFFF_FFFF);

    unsafe {
        cmd.write(0x30);
        data0.write((DIVIDER & 0xFF) as u8);
        data0.write((DIVIDER >> 8) as u8);

        let mut armed = false;
        for _ in 0..50_000_000u32 {
            cmd.write(0x00);
            let lo = data0.read() as u16;
            let hi = data0.read() as u16;
            let cur = (hi << 8) | lo;
            if cur <= DIVIDER && cur > 0 {
                armed = true;
            }
            if cur == 0 || (armed && cur > DIVIDER) {
                break;
            }
        }
    }

    let lapic_cur = read_reg(REG_TIMER_CUR_COUNT);
    let ticks_50ms = 0xFFFF_FFFFu32.wrapping_sub(lapic_cur);

    if saved {
        x86_64::instructions::interrupts::enable();
    }

    (ticks_50ms / 5).max(1)
}

/// Send a fixed-vector IPI to every CPU except the caller.
pub fn broadcast_excluding_self(vector: u8) {
    if !is_ready() {
        return;
    }
    let cmd = (vector as u32) | (1 << 14) | (0b11 << 18);
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") X2APIC_ICR_MSR,
                in("eax") cmd,
                in("edx") 0u32,
                options(nomem, nostack, preserves_flags),
            );
        }
    } else {
        wait_icr_idle();
        write_reg(REG_ICR_LOW, cmd);
        wait_icr_idle();
    }
}

/// Send a fixed-vector unicast IPI to `dest_apic_id`.
pub fn ipi_vector(dest_apic_id: u32, vector: u8) {
    unsafe {
        send_ipi(dest_apic_id, vector, IpiDelivery::Fixed);
    }
}

/// Send a reschedule IPI to `dest_apic_id`.
pub fn ipi_reschedule(dest_apic_id: u32) {
    ipi_vector(dest_apic_id, super::idt::RESCHEDULE_VECTOR);
}
