//! HuesOS DoomGeneric userspace port (GPL-2.0-only).

#![no_std]
#![no_main]
// DoomGeneric invokes all platform callbacks synchronously on its one game
// thread. These globals are initialized once in DG_Init and never accessed
// concurrently; wrapping them in a locking runtime would add no safety here.
#![allow(static_mut_refs)]

use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode};

static FREEDOOM_WAD: &[u8] = include_bytes!("../../../../third_party/freedoom/freedoom1.wad");
static mut CANVAS: Option<Canvas> = None;
static mut KEYBOARD: Option<Channel> = None;
static mut PRESENT_X: u32 = 0;
static mut PRESENT_Y: u32 = 0;
// The keyboard service currently reports make events only. Keep a Doom key
// logically held for several scheduler ticks so gameplay samples it as down;
// releasing it on the very next DG_GetKey poll works in menus but is too fast
// for G_BuildTiccmd and produces no player movement.
static mut HELD_KEY: Option<u8> = None;
static mut RELEASE_AT: u64 = 0;
static mut QUEUED_PRESS: Option<u8> = None;
const KEY_HOLD_TICKS: u64 = 8;

unsafe extern "C" {
    fn doomgeneric_Create(argc: i32, argv: *mut *mut u8);
    fn doomgeneric_Tick();
    static mut DG_ScreenBuffer: *mut u32;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    libcanvas::println!("[doom] HuesOS DoomGeneric starting (Freedoom Phase 1)");
    let arg0 = b"doom\0".as_ptr() as *mut u8;
    let arg1 = b"-iwad\0".as_ptr() as *mut u8;
    let arg2 = b"freedoom1.wad\0".as_ptr() as *mut u8;
    let arg3 = b"-nosound\0".as_ptr() as *mut u8;
    let mut argv = [arg0, arg1, arg2, arg3];
    unsafe { doomgeneric_Create(argv.len() as i32, argv.as_mut_ptr()) };
    loop {
        unsafe { doomgeneric_Tick() };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_Init() {
    if let Ok(info) = libcanvas::framebuffer::info() {
        unsafe {
            PRESENT_X = info.width.saturating_sub(640) / 2;
            PRESENT_Y = info.height.saturating_sub(400) / 2;
            CANVAS = Canvas::new(640, 400).ok();
        }
    }
    let bootstrap = libcanvas::channel::bootstrap();
    let mut message = [0u8; 32];
    loop {
        match bootstrap.read_channel_handle(&mut message) {
            Ok((n, channel)) if &message[..n] == b"keyboard" => {
                unsafe { KEYBOARD = Some(channel) };
                break;
            }
            Ok(_) | Err(ErrorCode::ShouldWait | ErrorCode::TimedOut | ErrorCode::InvalidArgs) => {
                libcanvas::process::yield_now();
            }
            Err(_) => break,
        }
    }
    core::mem::forget(bootstrap);
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_DrawFrame() {
    unsafe {
        let Some(canvas) = CANVAS.as_ref() else { return };
        if DG_ScreenBuffer.is_null() { return; }
        let pixels = core::slice::from_raw_parts(DG_ScreenBuffer as *const u8, 640 * 400 * 4);
        let _ = canvas.write_bytes(0, pixels);
        let _ = canvas.present_at(PRESENT_X, PRESENT_Y);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_SleepMs(ms: u32) {
    let ticks = ((ms as u64 + 9) / 10).max(1);
    let deadline = DG_GetTicksMs().saturating_add((ticks * 10) as u32);
    while (DG_GetTicksMs().wrapping_sub(deadline) as i32) < 0 {
        libcanvas::process::yield_now();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_GetTicksMs() -> u32 {
    libcanvas::system::monotonic_ticks().unwrap_or(0).wrapping_mul(10) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_GetKey(pressed: *mut i32, key: *mut u8) -> i32 {
    let now = libcanvas::system::monotonic_ticks().unwrap_or(0);

    unsafe {
        if let Some(value) = QUEUED_PRESS.take() {
            HELD_KEY = Some(value);
            RELEASE_AT = now.saturating_add(KEY_HOLD_TICKS);
            *pressed = 1;
            *key = value;
            return 1;
        }
    }

    let mut message = [0u8; 16];
    let incoming = unsafe { KEYBOARD.as_ref() }.and_then(|channel| match channel.read_into(&mut message) {
        Ok(n) => decode_key(&message[..n]),
        Err(ErrorCode::ShouldWait | ErrorCode::TimedOut) => None,
        Err(_) => None,
    });

    unsafe {
        if let Some(value) = incoming {
            match HELD_KEY {
                Some(held) if held == value => {
                    // Hardware repeat extends the hold without generating a
                    // second key-down event.
                    RELEASE_AT = now.saturating_add(KEY_HOLD_TICKS);
                    return 0;
                }
                Some(held) => {
                    // Release the previous key first; deliver the new press on
                    // the next poll to preserve event ordering.
                    HELD_KEY = None;
                    QUEUED_PRESS = Some(value);
                    *pressed = 0;
                    *key = held;
                    return 1;
                }
                None => {
                    HELD_KEY = Some(value);
                    RELEASE_AT = now.saturating_add(KEY_HOLD_TICKS);
                    *pressed = 1;
                    *key = value;
                    return 1;
                }
            }
        }

        if let Some(held) = HELD_KEY {
            if now >= RELEASE_AT {
                HELD_KEY = None;
                *pressed = 0;
                *key = held;
                return 1;
            }
        }
    }
    0
}

fn decode_key(message: &[u8]) -> Option<u8> {
    match message {
        [b'c', b'w' | b'W'] => Some(0xad),
        [b'c', b's' | b'S'] => Some(0xaf),
        [b'c', b'a' | b'A'] => Some(0xac),
        [b'c', b'd' | b'D'] => Some(0xae),
        [b'c', b'f' | b'F'] => Some(0xa3),
        [b'c', b'e' | b'E'] => Some(0xa2),
        [b'c', value] => Some(*value),
        b"enter" => Some(13),
        b"backspace" => Some(0x7f),
        _ => None,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_SetWindowTitle(_title: *const u8) {}

#[unsafe(no_mangle)]
pub extern "C" fn hues_wad_len() -> usize { FREEDOOM_WAD.len() }

#[unsafe(no_mangle)]
pub extern "C" fn hues_wad_read(offset: usize, output: *mut u8, length: usize) -> usize {
    if output.is_null() || offset >= FREEDOOM_WAD.len() { return 0; }
    let count = length.min(FREEDOOM_WAD.len() - offset);
    unsafe { core::ptr::copy_nonoverlapping(FREEDOOM_WAD.as_ptr().add(offset), output, count) };
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_debug(text: *const u8, length: usize) {
    if text.is_null() || length == 0 { return; }
    let bytes = unsafe { core::slice::from_raw_parts(text, length) };
    if let Ok(text) = core::str::from_utf8(bytes) { libcanvas::debug::write_str(text); }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_exit(code: i32) -> ! { libcanvas::process::exit(code as i64) }

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[doom] Rust panic\n");
    libcanvas::process::exit(-1)
}
