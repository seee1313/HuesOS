//! PS/2 controller helpers that must remain kernel-side.
//!
//! The PS/2 keyboard **driver itself** (scancode decoding, ring buffer,
//! wait-queue plumbing) lives in userspace as `driver-host:input`. The
//! kernel intentionally has no knowledge of scancode set 1, shift state,
//! ASCII mappings, or wait-queue wakers.
//!
//! What remains here are the last unavoidable kernel-side PS/2 touches:
//!
//! * [`prepare_shutdown`] disables both 8042 ports on the orderly-halt
//!   path. The controller is a platform device the kernel must quiesce
//!   before an unrecoverable `hlt` so no more IRQs are generated while
//!   the shutdown screen stays on. A follow-up change will move even
//!   this step behind a userspace shutdown broker via an `IoPort`
//!   capability, at which point this module can be deleted entirely.

/// Quiesce both PS/2 interfaces before the kernel halts the machine.
///
/// 8042 command `0xAD` disables the first port and `0xA7` disables the second.
/// These commands do not cut system power; they prevent new keyboard/mouse
/// traffic while the orderly software-shutdown screen remains displayed.
pub fn prepare_shutdown() {
    use x86_64::instructions::port::Port;

    let mut status: Port<u8> = Port::new(0x64);
    let mut command: Port<u8> = Port::new(0x64);
    for value in [0xADu8, 0xA7u8] {
        // Input-buffer-full (status bit 1) must clear before a controller
        // command is accepted. Bound the poll so broken/non-PS2 hardware
        // cannot hang shutdown.
        for _ in 0..100_000 {
            let ready = unsafe { status.read() } & 0x02 == 0;
            if ready {
                unsafe { command.write(value) };
                break;
            }
            core::hint::spin_loop();
        }
    }
}
