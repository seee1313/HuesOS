//! # HuesOS userspace init
//!
//! The first userspace process, launched by the kernel after boot. This is
//! a real ring3 program: no_std, no alloc, talks to the kernel exclusively
//! through the `syscall` instruction. It proves out the full pipeline
//! (ELF load -> ring3 entry -> real syscall -> IPC) by:
//!
//!   1. Writing a banner via the `DebugWrite` syscall (kernel prints it to
//!      the serial console, proving syscalls work from ring3).
//!   2. Creating a VMO, writing to it, reading it back, and verifying the
//!      round trip (proving VMOs + memory syscalls work).
//!   3. Creating a channel pair and sending itself a message (proving IPC
//!      syscalls work).
//!   4. Exiting cleanly via `ProcessExit`.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_VMO_CREATE: u64 = 1;
const SYS_HANDLE_CLOSE: u64 = 2;
const SYS_VMO_READ: u64 = 5;
const SYS_VMO_WRITE: u64 = 6;
const SYS_CHANNEL_CREATE: u64 = 7;
const SYS_CHANNEL_WRITE: u64 = 8;
const SYS_CHANNEL_READ: u64 = 9;
const SYS_PROCESS_EXIT: u64 = 10;
const SYS_DEBUG_WRITE: u64 = 11;

#[inline(always)]
unsafe fn syscall5(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inout("rax") num => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            out("rcx") _,
            out("r11") _,
            clobber_abi("sysv64"),
        );
    }
    ret
}

fn debug_write(msg: &[u8]) {
    unsafe {
        syscall5(SYS_DEBUG_WRITE, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0);
    }
}

fn vmo_create(size: u64) -> u32 {
    let mut handle: u32 = 0;
    unsafe {
        syscall5(SYS_VMO_CREATE, size, &mut handle as *mut u32 as u64, 0, 0, 0);
    }
    handle
}

fn vmo_write(handle: u32, offset: u64, data: &[u8]) -> i64 {
    unsafe {
        syscall5(
            SYS_VMO_WRITE,
            handle as u64,
            offset,
            data.as_ptr() as u64,
            data.len() as u64,
            0,
        )
    }
}

fn vmo_read(handle: u32, offset: u64, buf: &mut [u8]) -> i64 {
    unsafe {
        syscall5(
            SYS_VMO_READ,
            handle as u64,
            offset,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
        )
    }
}

fn handle_close(handle: u32) {
    unsafe {
        syscall5(SYS_HANDLE_CLOSE, handle as u64, 0, 0, 0, 0);
    }
}

fn channel_create() -> (u32, u32) {
    let mut h0: u32 = 0;
    let mut h1: u32 = 0;
    unsafe {
        syscall5(
            SYS_CHANNEL_CREATE,
            &mut h0 as *mut u32 as u64,
            &mut h1 as *mut u32 as u64,
            0,
            0,
            0,
        );
    }
    (h0, h1)
}

fn channel_write(handle: u32, data: &[u8]) -> i64 {
    unsafe {
        syscall5(
            SYS_CHANNEL_WRITE,
            handle as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            0,
            0,
        )
    }
}

fn channel_read(handle: u32, buf: &mut [u8]) -> (i64, u32) {
    let mut actual: u32 = 0;
    let ret = unsafe {
        syscall5(
            SYS_CHANNEL_READ,
            handle as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            &mut actual as *mut u32 as u64,
            0,
        )
    };
    (ret, actual)
}

fn process_exit(code: i64) -> ! {
    unsafe {
        syscall5(SYS_PROCESS_EXIT, code as u64, 0, 0, 0, 0);
    }
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    debug_write(b"[init] hello from ring3 userspace!\n");

    // VMO round trip.
    let vmo = vmo_create(4096);
    let payload = b"HuesOS VMO round-trip OK\n";
    vmo_write(vmo, 0, payload);
    let mut readback = [0u8; 32];
    let n = vmo_read(vmo, 0, &mut readback);
    if n > 0 && &readback[..payload.len()] == payload {
        debug_write(b"[init] VMO read/write round-trip OK\n");
    } else {
        debug_write(b"[init] VMO read/write round-trip FAILED\n");
    }
    handle_close(vmo);

    // Channel round trip (self-send/self-receive).
    let (tx, rx) = channel_create();
    let msg = b"ping over huesos channel\n";
    channel_write(tx, msg);
    let mut buf = [0u8; 64];
    let (ret, actual) = channel_read(rx, &mut buf);
    if ret >= 0 && actual as usize == msg.len() && &buf[..actual as usize] == msg {
        debug_write(b"[init] channel IPC round-trip OK\n");
    } else {
        debug_write(b"[init] channel IPC round-trip FAILED\n");
    }
    handle_close(tx);
    handle_close(rx);

    debug_write(b"[init] all checks complete, exiting cleanly\n");
    process_exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_write(b"[init] PANIC in userspace init\n");
    process_exit(-1);
}
