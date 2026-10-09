//! Boot-time raw-GSI level-interrupt self-test, requested by `irq_test=1` on
//! the HBI command line.
//!
//! The probe drives QEMU's `edu` PCI test device. That device raises a real
//! INTx line (level-triggered, active-low on the wire) when software writes to
//! its interrupt-raise register and deasserts it when software writes to its
//! interrupt-acknowledge register. This is the same hardware shape a userspace
//! driver sees for a non-keyboard PCI function, so the probe exercises the whole
//! raw-GSI path end to end:
//!
//! 1. `Interrupt::new_gsi` + `bind_port` acquires the IOAPIC route (masked-first
//!    programming, read-back verification, dynamic IDT vector);
//! 2. the device asserts the line; the IDT stub masks the level route before
//!    LAPIC EOI and forwards the event to the bound `Port`;
//! 3. the line stays masked until the owner has deasserted the device and
//!    called `Interrupt::acknowledge`;
//! 4. after acknowledgement the route is unmasked and a second assertion is
//!    delivered again.
//!
//! The probe is test-only, runs once on the BSP after interrupts are enabled,
//! and never runs on a normal boot. It reports `[irq-test] ...` markers that
//! `scripts/ci-qemu-irq-level-smoke.sh` checks.

use core::fmt::Write;

use huesos_object::{register_interrupt, Interrupt, KernelObject, Port};
use huesos_pci::{command, off, PciAddress};

use super::storage::{
    map_mmio_window, read_config_space, read_config_u16, read_config_u32, size_bar0,
    write_config_u16,
};

const EDU_VENDOR_ID: u16 = 0x1234;
const EDU_DEVICE_ID: u16 = 0x11e8;
/// Identification register value of the `edu` device (`0x010000ed`).
const EDU_ID_VALUE: u32 = 0x0100_00ed;
const EDU_ID_OFFSET: usize = 0x00;
const EDU_INTR_RAISE_OFFSET: usize = 0x60;
const EDU_INTR_ACK_OFFSET: usize = 0x64;
/// Bit 0 of the raise/ack registers: the single INTx source the device owns.
const EDU_INTR_BIT: u32 = 1;

const PCI_INTERRUPT_LINE: usize = 0x3c;
/// PCI INTx lines wired through the Q35 I/O APIC occupy GSIs below 24.
const MAX_TEST_GSI: u32 = 24;

const PROBE_KEY: u64 = 0x6772_7371;
/// Timer ticks to wait for a delivery (100 Hz, so 3 seconds).
const DELIVERY_TIMEOUT_TICKS: u64 = 300;
/// Ticks used to prove a masked line stays silent (500 ms).
const QUIET_WINDOW_TICKS: u64 = 50;

/// Run the probe and print the outcome on the early serial console.
pub fn run() {
    let mut writer = huesos_arch::serial::SerialWriter;
    match probe() {
        Ok(()) => {
            let _ = writeln!(writer, "[irq-test] raw GSI level route self-test OK");
        }
        Err(reason) => {
            let _ = writeln!(writer, "[irq-test] FAILED: {reason}");
        }
    }
}

fn probe() -> Result<(), &'static str> {
    let (location, bar0_base, bar0_len) = find_edu().ok_or("edu device not found on bus 0")?;
    let interrupt_word = read_config_u32(location, PCI_INTERRUPT_LINE);
    let pin = ((interrupt_word >> 8) & 0xff) as u8;
    let line = (interrupt_word & 0xff) as u8;
    if pin == 0 {
        return Err("edu device has no INTx pin");
    }
    if u32::from(line) >= MAX_TEST_GSI || line == 0xff {
        return Err("firmware interrupt line is not a routable GSI");
    }
    let gsi = u32::from(line);
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "[irq-test] edu INTx pin {pin} -> GSI {gsi}");

    map_mmio_window(bar0_base, bar0_len).map_err(|_| "BAR0 mapping failed")?;
    let base = huesos_arch::paging::phys_to_virt(bar0_base).as_u64();
    enable_intx(location);

    if mmio_read32(base + EDU_ID_OFFSET as u64) != EDU_ID_VALUE {
        return Err("edu identification register mismatch");
    }

    let port = Port::new().map_err(|_| "port create failed")?;
    let interrupt = Interrupt::new_gsi(gsi);
    register_interrupt(interrupt.clone());
    interrupt
        .bind_port(port.clone(), PROBE_KEY)
        .map_err(|_| "raw GSI route unavailable")?;
    log_line("[irq-test] raw GSI route acquired and bound to Port");

    // 1. First assertion is delivered through the IOAPIC route into the Port.
    mmio_write32(base + EDU_INTR_RAISE_OFFSET as u64, EDU_INTR_BIT);
    let first = wait_for_packet(&port, DELIVERY_TIMEOUT_TICKS)?;
    check_packet(&first, gsi)?;
    log_line("[irq-test] level IRQ delivered to Port");

    // 2. The device is still asserted and unacknowledged: the route must stay
    //    masked, so no second packet may arrive.
    if wait_for_packet(&port, QUIET_WINDOW_TICKS).is_ok() {
        return Err("level route delivered again before acknowledge");
    }
    log_line("[irq-test] level route stayed masked until acknowledge");

    // 3. Deassert the device, then acknowledge the route to unmask it.
    mmio_write32(base + EDU_INTR_ACK_OFFSET as u64, EDU_INTR_BIT);
    interrupt
        .acknowledge()
        .map_err(|_| "level acknowledge rejected")?;

    // 4. A fresh assertion must now be delivered again.
    mmio_write32(base + EDU_INTR_RAISE_OFFSET as u64, EDU_INTR_BIT);
    let second = wait_for_packet(&port, DELIVERY_TIMEOUT_TICKS)?;
    check_packet(&second, gsi)?;
    log_line("[irq-test] level re-enable after acknowledge OK");

    // Clean up: deassert and acknowledge so the route is released quiescent.
    mmio_write32(base + EDU_INTR_ACK_OFFSET as u64, EDU_INTR_BIT);
    interrupt
        .acknowledge()
        .map_err(|_| "final level acknowledge rejected")?;
    huesos_object::unregister_object(interrupt.koid());
    drop(interrupt);
    Ok(())
}

/// Locate the first `edu` function on PCI bus 0. Returns its address and
/// decoded BAR0 window.
fn find_edu() -> Option<(PciAddress, u64, u64)> {
    let mut device = 0u8;
    while device < 32 {
        let location = PciAddress::try_new(0, 0, device, 0).ok()?;
        let vendor = read_config_u16(location, off::VENDOR_ID);
        let device_id = read_config_u16(location, off::DEVICE_ID);
        if vendor == EDU_VENDOR_ID && device_id == EDU_DEVICE_ID {
            let config = read_config_space(location);
            let bar0 = size_bar0(location, &config)?;
            return Some((location, bar0.base, bar0.len));
        }
        device += 1;
    }
    None
}

/// Enable memory decoding and bus mastering, and clear `INTX_DISABLE` so the
/// device's INTx line can reach the interrupt controller.
fn enable_intx(location: PciAddress) {
    let current = read_config_u16(location, off::COMMAND);
    let enabled = (current | command::MEMORY_SPACE | command::BUS_MASTER) & !command::INTX_DISABLE;
    write_config_u16(location, off::COMMAND, enabled);
}

fn wait_for_packet(
    port: &Port,
    timeout_ticks: u64,
) -> Result<huesos_object::PortPacket, &'static str> {
    let start = crate::scheduler::global_ticks();
    loop {
        if let Some(packet) = port.read() {
            return Ok(packet);
        }
        if crate::scheduler::global_ticks().saturating_sub(start) >= timeout_ticks {
            return Err("timed out waiting for IRQ packet");
        }
        core::hint::spin_loop();
    }
}

fn check_packet(packet: &huesos_object::PortPacket, gsi: u32) -> Result<(), &'static str> {
    if packet.key != PROBE_KEY {
        return Err("IRQ packet carried the wrong port key");
    }
    if packet.packet_type != huesos_abi::PORT_PACKET_INTERRUPT {
        return Err("IRQ packet has the wrong type");
    }
    if packet.data[0] != u64::from(gsi) {
        return Err("IRQ packet names the wrong GSI");
    }
    Ok(())
}

fn log_line(message: &str) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{message}");
}

/// Read a 32-bit device register through the kernel HHDM mapping of BAR0.
fn mmio_read32(address: u64) -> u32 {
    // SAFETY: `address` lies inside the BAR0 window that `map_mmio_window`
    // mapped uncached for this probe; the window is device MMIO of a 32-bit
    // register at a 4-byte-aligned offset.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// Write a 32-bit device register through the kernel HHDM mapping of BAR0.
fn mmio_write32(address: u64, value: u32) {
    // SAFETY: same BAR0 window and alignment contract as `mmio_read32`.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}
