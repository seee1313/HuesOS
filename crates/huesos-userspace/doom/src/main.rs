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
static mut OUTPUT_WIDTH: u32 = 640;
static mut OUTPUT_HEIGHT: u32 = 400;
static mut OUTPUT_BPP: u32 = 4;

const DOOM_WIDTH: usize = 640;
const DOOM_HEIGHT: usize = 400;
const SCALE_CHUNK_SIZE: usize = 1024 * 1024;
// One reusable 1 MiB staging area keeps fullscreen scaling to a handful of
// bounded VMO writes per frame instead of one syscall per destination row.
static mut SCALE_CHUNK: [u8; SCALE_CHUNK_SIZE] = [0; SCALE_CHUNK_SIZE];

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
            OUTPUT_WIDTH = info.width;
            OUTPUT_HEIGHT = info.height;
            OUTPUT_BPP = (info.bpp as u32).div_ceil(8);
            // Doom's packed adapter currently targets the normal 32-bpp UEFI
            // framebuffer. Keep a 640x400 fallback for unusual pixel formats.
            CANVAS = if OUTPUT_BPP == 4 {
                Canvas::new_fullscreen().ok()
            } else {
                OUTPUT_WIDTH = 640;
                OUTPUT_HEIGHT = 400;
                OUTPUT_BPP = 4;
                Canvas::new(640, 400).ok()
            };
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
        if DG_ScreenBuffer.is_null() || OUTPUT_BPP != 4 {
            return;
        }

        let width = OUTPUT_WIDTH as usize;
        let height = OUTPUT_HEIGHT as usize;
        let row_bytes = width.saturating_mul(4);
        if width == 0 || height == 0 || row_bytes > SCALE_CHUNK_SIZE {
            return;
        }
        let rows_per_chunk = (SCALE_CHUNK_SIZE / row_bytes).max(1);
        let source = core::slice::from_raw_parts(DG_ScreenBuffer, DOOM_WIDTH * DOOM_HEIGHT);

        let mut first_y = 0usize;
        while first_y < height {
            let rows = rows_per_chunk.min(height - first_y);
            let output = &mut SCALE_CHUNK[..rows * row_bytes];
            for local_y in 0..rows {
                let dst_y = first_y + local_y;
                let src_y = dst_y * DOOM_HEIGHT / height;
                let dst_row = &mut output[local_y * row_bytes..(local_y + 1) * row_bytes];
                for dst_x in 0..width {
                    let src_x = dst_x * DOOM_WIDTH / width;
                    let pixel = source[src_y * DOOM_WIDTH + src_x].to_le_bytes();
                    let offset = dst_x * 4;
                    dst_row[offset..offset + 4].copy_from_slice(&pixel);
                }
            }
            let _ = canvas.write_bytes((first_y * row_bytes) as u64, output);
            first_y += rows;
        }
        let _ = canvas.present();
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
    let mut message = [0u8; 16];
    let event = unsafe { KEYBOARD.as_ref() }.and_then(|channel| match channel.read_into(&mut message) {
        Ok(n) => decode_key(&message[..n]),
        Err(ErrorCode::ShouldWait | ErrorCode::TimedOut) => None,
        Err(_) => None,
    });
    let Some((is_pressed, value)) = event else { return 0 };

    // Q is a HuesOS emergency return-to-terminal shortcut. Doom's normal
    // Escape/menu quit path still works, but this guarantees supervisors can
    // recover even if the engine gets stuck while leaving a menu.
    if is_pressed && matches!(value, b'q' | b'Q') {
        libcanvas::debug::write_str("[doom] Q pressed; returning to terminal\n");
        libcanvas::process::exit(0);
    }

    unsafe {
        *pressed = is_pressed as i32;
        *key = value;
    }
    1
}

fn decode_key(message: &[u8]) -> Option<(bool, u8)> {
    let [b'k', state, raw] = message else { return None };
    let key = match *raw {
        b'w' | b'W' => 0xad,
        b's' | b'S' => 0xaf,
        b'a' | b'A' => 0xac,
        b'd' | b'D' => 0xae,
        b'f' | b'F' => 0xa3,
        b'e' | b'E' => 0xa2,
        b'\n' => 13,
        8 => 0x7f,
        value => value,
    };
    Some((*state != 0, key))
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
