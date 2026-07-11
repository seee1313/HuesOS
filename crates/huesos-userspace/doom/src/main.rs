//! HuesOS DoomGeneric userspace port (GPL-2.0-only).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode};

static FREEDOOM_WAD: &[u8] = include_bytes!("../../../../third_party/freedoom/freedoom1.wad");

const DOOM_WIDTH: usize = 640;
const DOOM_HEIGHT: usize = 400;
const SCALE_CHUNK_SIZE: usize = 1024 * 1024;

struct DoomState {
    canvas: Option<Canvas>,
    keyboard: Option<Channel>,
    output_width: u32,
    output_height: u32,
    output_bpp: u32,
    scale_chunk: [u8; SCALE_CHUNK_SIZE],
}

impl DoomState {
    const fn new() -> Self {
        Self {
            canvas: None,
            keyboard: None,
            output_width: 640,
            output_height: 400,
            output_bpp: 4,
            scale_chunk: [0; SCALE_CHUNK_SIZE],
        }
    }
}

/// Interior-mutable state for DoomGeneric's synchronous platform callbacks.
///
/// DoomGeneric invokes every `DG_*` callback on its sole game thread and does
/// not re-enter a callback before it returns. Keeping the unsafe cell private
/// lets the rest of the adapter use ordinary references without `static mut`.
struct SingleThreadState(UnsafeCell<DoomState>);

// SAFETY: the process has one thread and DoomGeneric's callback contract is
// synchronous/non-reentrant. No reference produced by `with` escapes it.
unsafe impl Sync for SingleThreadState {}

impl SingleThreadState {
    const fn new() -> Self {
        Self(UnsafeCell::new(DoomState::new()))
    }

    fn with<R>(&self, operation: impl FnOnce(&mut DoomState) -> R) -> R {
        // SAFETY: justified by the type-level single-thread/non-reentrant
        // invariant above. The mutable borrow is scoped to this call.
        unsafe { operation(&mut *self.0.get()) }
    }
}

static STATE: SingleThreadState = SingleThreadState::new();

unsafe extern "C" {
    fn doomgeneric_Create(argc: i32, argv: *mut *mut u8);
    fn doomgeneric_Tick();
    static mut DG_ScreenBuffer: *mut u32;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    libcanvas::println!("[doom] HuesOS DoomGeneric starting (Freedoom Phase 1)");
    let arg0 = c"doom".as_ptr() as *mut u8;
    let arg1 = c"-iwad".as_ptr() as *mut u8;
    let arg2 = c"freedoom1.wad".as_ptr() as *mut u8;
    let arg3 = c"-nosound".as_ptr() as *mut u8;
    let mut argv = [arg0, arg1, arg2, arg3];
    // SAFETY: argv points to four NUL-terminated static strings and remains
    // valid for DoomGeneric's process lifetime.
    unsafe { doomgeneric_Create(argv.len() as i32, argv.as_mut_ptr()) };
    loop {
        // SAFETY: Create completed engine initialization; Tick is called from
        // this one thread exactly as required by DoomGeneric.
        unsafe { doomgeneric_Tick() };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_Init() {
    if let Ok(info) = libcanvas::framebuffer::info() {
        STATE.with(|state| {
            state.output_width = info.width;
            state.output_height = info.height;
            state.output_bpp = (info.bpp as u32).div_ceil(8);
            state.canvas = if state.output_bpp == 4 {
                Canvas::new_fullscreen().ok()
            } else {
                state.output_width = 640;
                state.output_height = 400;
                state.output_bpp = 4;
                Canvas::new(640, 400).ok()
            };
        });
    }
    let bootstrap = libcanvas::channel::bootstrap();
    let mut message = [0u8; 32];
    loop {
        match bootstrap.read_channel_handle(&mut message) {
            Ok((n, channel)) if &message[..n] == b"keyboard" => {
                STATE.with(|state| state.keyboard = Some(channel));
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
    // SAFETY: DoomGeneric owns a valid 640x400 screen buffer after Create and
    // calls DrawFrame synchronously while it remains allocated.
    let source_ptr = unsafe { DG_ScreenBuffer };
    if source_ptr.is_null() {
        return;
    }
    let source = unsafe { core::slice::from_raw_parts(source_ptr, DOOM_WIDTH * DOOM_HEIGHT) };

    STATE.with(|state| {
        let Some(canvas) = state.canvas.as_ref() else {
            return;
        };
        if state.output_bpp != 4 {
            return;
        }
        let width = state.output_width as usize;
        let height = state.output_height as usize;
        let row_bytes = width.saturating_mul(4);
        if width == 0 || height == 0 || row_bytes > SCALE_CHUNK_SIZE {
            return;
        }
        let rows_per_chunk = (SCALE_CHUNK_SIZE / row_bytes).max(1);
        let mut first_y = 0usize;
        while first_y < height {
            let rows = rows_per_chunk.min(height - first_y);
            let output = &mut state.scale_chunk[..rows * row_bytes];
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
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_SleepMs(ms: u32) {
    let ticks = (ms as u64).div_ceil(10).max(1);
    let deadline = DG_GetTicksMs().saturating_add((ticks * 10) as u32);
    while (DG_GetTicksMs().wrapping_sub(deadline) as i32) < 0 {
        libcanvas::process::yield_now();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn DG_GetTicksMs() -> u32 {
    libcanvas::system::monotonic_ticks()
        .unwrap_or(0)
        .wrapping_mul(10) as u32
}

/// Poll one DoomGeneric keyboard event.
///
/// # Safety
/// DoomGeneric must pass two live writable output pointers for the complete
/// duration of this callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DG_GetKey(pressed: *mut i32, key: *mut u8) -> i32 {
    if pressed.is_null() || key.is_null() {
        return 0;
    }
    let mut message = [0u8; 16];
    let event = STATE.with(|state| {
        state
            .keyboard
            .as_ref()
            .and_then(|channel| match channel.read_into(&mut message) {
                Ok(n) => decode_key(&message[..n]),
                Err(ErrorCode::ShouldWait | ErrorCode::TimedOut) => None,
                Err(_) => None,
            })
    });
    let Some((is_pressed, value)) = event else {
        return 0;
    };

    // Q is a HuesOS emergency return-to-terminal shortcut. Doom's normal
    // Escape/menu quit path still works, but this guarantees supervisors can
    // recover even if the engine gets stuck while leaving a menu.
    if is_pressed && matches!(value, b'q' | b'Q') {
        libcanvas::debug::write_str("[doom] Q pressed; returning to terminal\n");
        libcanvas::process::exit(0);
    }

    // SAFETY: both output pointers were checked non-null above and are supplied
    // by DoomGeneric as writable stack locals for the duration of this call.
    unsafe {
        *pressed = is_pressed as i32;
        *key = value;
    }
    1
}

fn decode_key(message: &[u8]) -> Option<(bool, u8)> {
    let [b'k', state, raw] = message else {
        return None;
    };
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
pub extern "C" fn hues_wad_len() -> usize {
    FREEDOOM_WAD.len()
}

/// Copy bytes from the embedded IWAD into a C caller buffer.
///
/// # Safety
/// `output` must be writable for `length` bytes or null. The function bounds
/// the actual copy to the embedded WAD length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hues_wad_read(offset: usize, output: *mut u8, length: usize) -> usize {
    if output.is_null() || offset >= FREEDOOM_WAD.len() {
        return 0;
    }
    let count = length.min(FREEDOOM_WAD.len() - offset);
    unsafe { core::ptr::copy_nonoverlapping(FREEDOOM_WAD.as_ptr().add(offset), output, count) };
    count
}

/// Forward a C debug byte range to the HuesOS debug channel.
///
/// # Safety
/// `text` must be readable for `length` bytes or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hues_debug(text: *const u8, length: usize) {
    if text.is_null() || length == 0 {
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts(text, length) };
    if let Ok(text) = core::str::from_utf8(bytes) {
        libcanvas::debug::write_str(text);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_exit(code: i32) -> ! {
    libcanvas::process::exit(code as i64)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[doom] Rust panic\n");
    libcanvas::process::exit(-1)
}
