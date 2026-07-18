//! HuesOS DoomGeneric userspace port (GPL-2.0-only).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode, Vmo};

const DOOM_WIDTH: usize = 640;
const DOOM_HEIGHT: usize = 400;
const SCALE_CHUNK_SIZE: usize = 1024 * 1024;

struct DoomState {
    canvas: Option<Canvas>,
    keyboard: Option<Channel>,
    wad: Option<Vmo>,
    wad_offset: u64,
    wad_len: u64,
    output_width: u32,
    output_height: u32,
    output_x: u32,
    output_y: u32,
    output_bpp: u32,
    scale_chunk: [u8; SCALE_CHUNK_SIZE],
}

impl DoomState {
    const fn new() -> Self {
        Self {
            canvas: None,
            keyboard: None,
            wad: None,
            wad_offset: 0,
            wad_len: 0,
            output_width: 640,
            output_height: 400,
            output_x: 0,
            output_y: 0,
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
        let output_bpp = (info.bpp as u32).div_ceil(8);
        let (width, height) = adaptive_output_size(info.width, info.height);
        if output_bpp == 4 {
            // Clear pixels outside the bounded game viewport once. Subsequent
            // frames present only the smaller Doom canvas.
            if let Ok(background) = Canvas::new_fullscreen() {
                let _ = background.fill_rect(0, 0, info.width, info.height, 3, 6, 12);
                let _ = background.present();
            }
        }
        libcanvas::println!(
            "[doom] adaptive viewport {}x{} at {},{} on {}x{}",
            width,
            height,
            info.width.saturating_sub(width) / 2,
            info.height.saturating_sub(height) / 2,
            info.width,
            info.height
        );
        STATE.with(|state| {
            state.output_width = width;
            state.output_height = height;
            state.output_x = info.width.saturating_sub(width) / 2;
            state.output_y = info.height.saturating_sub(height) / 2;
            state.output_bpp = output_bpp;
            state.canvas = if output_bpp == 4 {
                Canvas::new(width, height).ok()
            } else {
                state.output_width = DOOM_WIDTH as u32;
                state.output_height = DOOM_HEIGHT as u32;
                state.output_x = 0;
                state.output_y = 0;
                state.output_bpp = 4;
                Canvas::new(DOOM_WIDTH as u32, DOOM_HEIGHT as u32).ok()
            };
        });
    }

    let bootstrap = libcanvas::channel::bootstrap();
    let mut message = [0u8; 32];
    loop {
        match bootstrap.read_optional_handle(&mut message) {
            Ok((n, Some(handle))) if &message[..n] == b"keyboard" => {
                STATE.with(|state| state.keyboard = Some(Channel::from_handle(handle)));
            }
            Ok((20, Some(handle))) if &message[..4] == b"wad\0" => {
                let offset = read_u64(&message[4..12]);
                let len = read_u64(&message[12..20]);
                STATE.with(|state| {
                    state.wad = Some(Vmo::from_handle(handle));
                    state.wad_offset = offset;
                    state.wad_len = len;
                });
            }
            Ok(_) | Err(ErrorCode::ShouldWait | ErrorCode::TimedOut | ErrorCode::InvalidArgs) => {
                libcanvas::process::yield_now();
            }
            Err(_) => break,
        }
        let ready = STATE.with(|state| state.keyboard.is_some() && state.wad.is_some());
        if ready {
            break;
        }
    }
    core::mem::forget(bootstrap);
}

fn adaptive_output_size(framebuffer_width: u32, framebuffer_height: u32) -> (u32, u32) {
    // 960x600 keeps the 16:10 engine aspect ratio while bounding physical
    // pixels to at most 1-2 display pixels on common 1280p/1080p/1440p modes.
    const COMFORT_WIDTH: u32 = 960;
    const COMFORT_HEIGHT: u32 = 600;
    if framebuffer_width >= COMFORT_WIDTH && framebuffer_height >= COMFORT_HEIGHT {
        return (COMFORT_WIDTH, COMFORT_HEIGHT);
    }

    let width_scale = framebuffer_width as u64 * DOOM_HEIGHT as u64;
    let height_scale = framebuffer_height as u64 * DOOM_WIDTH as u64;
    if width_scale <= height_scale {
        let width = framebuffer_width.clamp(1, COMFORT_WIDTH);
        (
            width,
            (width * DOOM_HEIGHT as u32 / DOOM_WIDTH as u32).max(1),
        )
    } else {
        let height = framebuffer_height.clamp(1, COMFORT_HEIGHT);
        (height * DOOM_WIDTH as u32 / DOOM_HEIGHT as u32, height)
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
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
        let _ = canvas.present_at(state.output_x, state.output_y);
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
    STATE.with(|state| state.wad_len.min(usize::MAX as u64) as usize)
}

/// Read bytes from the read-only BOOTFS IWAD capability into a C buffer.
///
/// # Safety
/// `output` must be writable for `length` bytes or null. Reads are bounded by
/// the validated BOOTFS entry supplied by init.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hues_wad_read(offset: usize, output: *mut u8, length: usize) -> usize {
    if output.is_null() || length == 0 {
        return 0;
    }
    STATE.with(|state| {
        let Some(wad) = state.wad.as_ref() else {
            return 0;
        };
        let offset = offset as u64;
        if offset >= state.wad_len {
            return 0;
        }
        let count = length.min((state.wad_len - offset).min(usize::MAX as u64) as usize);
        // SAFETY: caller guarantees the output range; count is no larger than
        // that range and the VMO wrapper writes only into this temporary slice.
        let destination = unsafe { core::slice::from_raw_parts_mut(output, count) };
        let Some(vmo_offset) = state.wad_offset.checked_add(offset) else {
            return 0;
        };
        wad.read(vmo_offset, destination).unwrap_or_default()
    })
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
