//! # HuesOS Syscall Interface
//!
//! Table-driven syscall dispatch, called from the arch-level `syscall`
//! trampoline with the raw register frame.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use huesos_object::{Handle, HandleValue, KernelObject, KernelObjectExt, Rights, INVALID_HANDLE};
use spin::Mutex;

/// Syscall error codes (subset of zx_status_t).
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallError {
    /// Invalid argument.
    InvalidArgs = -10,
    /// Bad handle.
    BadHandle = -11,
    /// Wrong type for handle.
    WrongType = -12,
    /// Access denied (rights violation).
    AccessDenied = -13,
    /// Out of memory.
    NoMemory = -14,
    /// Resource busy.
    Busy = -15,
    /// Should wait (non-blocking call would block).
    ShouldWait = -16,
    /// Not found.
    NotFound = -17,
}

/// Result type for syscalls: `Ok(value)` or a negative error code.
pub type SyscallResult = Result<i64, SyscallError>;

/// Syscall number enumeration (kept in sync with userspace's `libhues`).
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallNumber {
    /// nop / debug.
    Nop = 0,
    /// Create a VMO.
    VmoCreate = 1,
    /// Close a handle.
    HandleClose = 2,
    /// Duplicate a handle.
    HandleDuplicate = 3,
    /// Yield the current thread (cooperative).
    Yield = 4,
    /// Read from VMO.
    VmoRead = 5,
    /// Write to VMO.
    VmoWrite = 6,
    /// Create a channel pair.
    ChannelCreate = 7,
    /// Write to a channel.
    ChannelWrite = 8,
    /// Read from a channel.
    ChannelRead = 9,
    /// Exit current process.
    ProcessExit = 10,
    /// Write a debug string to the kernel log (serial). MVP substitute for
    /// a real console/VFS.
    DebugWrite = 11,
}

/// Global yield callback (set by kernel scheduler to avoid circular deps).
static YIELD_FN: Mutex<Option<fn()>> = Mutex::new(None);
/// Global process-exit callback (set by kernel scheduler).
static EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Global debug-write callback (set by kernel to point at the serial writer).
static DEBUG_WRITE_FN: Mutex<Option<fn(&[u8])>> = Mutex::new(None);

/// Set the yield function. Called once by kernel init.
pub fn set_yield_fn(f: fn()) {
    *YIELD_FN.lock() = Some(f);
}

/// Set the process-exit function. Called once by kernel init.
pub fn set_exit_fn(f: fn(i64) -> !) {
    *EXIT_FN.lock() = Some(f);
}

/// Set the debug-write function. Called once by kernel init.
pub fn set_debug_write_fn(f: fn(&[u8])) {
    *DEBUG_WRITE_FN.lock() = Some(f);
}

/// Dispatch a syscall by number. This is architecture-independent; the
/// arch layer is responsible for extracting `num`/`a1..a5` from registers.
pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SyscallResult {
    match num {
        0 => sys_nop(),
        1 => sys_vmo_create(a1 as usize, a2 as *mut HandleValue),
        2 => sys_handle_close(a1 as HandleValue),
        3 => sys_handle_duplicate(a1 as HandleValue, a2 as u32, a3 as *mut HandleValue),
        4 => sys_yield(),
        5 => sys_vmo_read(a1 as HandleValue, a2, a3 as *mut u8, a4 as usize),
        6 => sys_vmo_write(a1 as HandleValue, a2, a3 as *const u8, a4 as usize),
        7 => sys_channel_create(a1 as *mut HandleValue, a2 as *mut HandleValue),
        8 => sys_channel_write(
            a1 as HandleValue,
            a2 as *const u8,
            a3 as u32,
            a4 as *const HandleValue,
            a5 as u32,
        ),
        9 => sys_channel_read(a1 as HandleValue, a2 as *mut u8, a3 as u32, a4 as *mut u32),
        10 => sys_process_exit(a1 as i64),
        11 => sys_debug_write(a1 as *const u8, a2 as usize),
        _ => Err(SyscallError::InvalidArgs),
    }
}

fn sys_nop() -> SyscallResult {
    Ok(0)
}

fn current_proc() -> Result<alloc::sync::Arc<huesos_object::Process>, SyscallError> {
    huesos_object::current_process().ok_or(SyscallError::BadHandle)
}

/// Upper bound on a single VMO's size (4 GiB). This is *not* a real memory
/// accounting/quota system (see the Job resource-limits roadmap item) — it
/// exists purely to reject obviously-bogus sizes (e.g. a userspace bug
/// passing `usize::MAX`) before they reach `Vec::with_capacity`, which
/// would otherwise abort the whole kernel with a "capacity overflow" panic
/// while trying to allocate a frame-address array sized for an
/// astronomical page count, rather than cleanly failing the syscall.
const MAX_VMO_SIZE: usize = 4 * 1024 * 1024 * 1024;

fn sys_vmo_create(size: usize, out_handle: *mut HandleValue) -> SyscallResult {
    if out_handle.is_null() || size == 0 {
        return Err(SyscallError::InvalidArgs);
    }
    if size > MAX_VMO_SIZE {
        return Err(SyscallError::NoMemory);
    }
    let vmo = huesos_object::Vmo::new(size).map_err(|_| SyscallError::NoMemory)?;
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let proc = current_proc()?;
    let hv = proc.handles.add(Handle::new(koid, Rights::DEFAULT_VMO));
    unsafe {
        *out_handle = hv;
    }
    Ok(0)
}

fn sys_vmo_read(handle: HandleValue, offset: u64, buf: *mut u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(SyscallError::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(SyscallError::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(SyscallError::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(SyscallError::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(SyscallError::WrongType)?;
    let mut tmp = vec![0u8; len];
    let n = vmo.read(offset as usize, &mut tmp);
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n);
    }
    Ok(n as i64)
}

fn sys_vmo_write(handle: HandleValue, offset: u64, buf: *const u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(SyscallError::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(SyscallError::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(SyscallError::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(SyscallError::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(SyscallError::WrongType)?;
    let tmp = unsafe { core::slice::from_raw_parts(buf, len) };
    let n = vmo.write(offset as usize, tmp);
    Ok(n as i64)
}

fn sys_handle_close(handle: HandleValue) -> SyscallResult {
    if handle == INVALID_HANDLE {
        return Err(SyscallError::BadHandle);
    }
    let proc = current_proc()?;
    proc.handles.remove(handle).ok_or(SyscallError::BadHandle)?;
    Ok(0)
}

fn sys_handle_duplicate(handle: HandleValue, rights: u32, out: *mut HandleValue) -> SyscallResult {
    if handle == INVALID_HANDLE || out.is_null() {
        return Err(SyscallError::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(SyscallError::BadHandle)?;
    let new_rights = if rights == Rights::SAME_RIGHTS.bits() {
        h.rights
    } else {
        Rights::from_bits_truncate(rights)
    };
    let new_h = Handle::new(h.koid, new_rights);
    let new_hv = proc.handles.add(new_h);
    unsafe {
        *out = new_hv;
    }
    Ok(0)
}

fn sys_yield() -> SyscallResult {
    if let Some(f) = *YIELD_FN.lock() {
        f();
    }
    Ok(0)
}

fn sys_channel_create(out0: *mut HandleValue, out1: *mut HandleValue) -> SyscallResult {
    if out0.is_null() || out1.is_null() {
        return Err(SyscallError::InvalidArgs);
    }
    let (ch0, ch1) = huesos_object::Channel::pair();
    let koid0 = ch0.koid();
    let koid1 = ch1.koid();
    huesos_object::register_object(ch0);
    huesos_object::register_object(ch1);
    let proc = current_proc()?;
    let hv0 = proc.handles.add(Handle::new(koid0, Rights::DEFAULT));
    let hv1 = proc.handles.add(Handle::new(koid1, Rights::DEFAULT));
    unsafe {
        *out0 = hv0;
        *out1 = hv1;
    }
    Ok(0)
}

fn sys_channel_write(
    handle: HandleValue,
    bytes: *const u8,
    num_bytes: u32,
    handles: *const HandleValue,
    num_handles: u32,
) -> SyscallResult {
    if bytes.is_null() && num_bytes > 0 {
        return Err(SyscallError::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(SyscallError::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(SyscallError::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(SyscallError::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(SyscallError::WrongType)?;
    let data: Vec<u8> = if num_bytes > 0 {
        unsafe { core::slice::from_raw_parts(bytes, num_bytes as usize).to_vec() }
    } else {
        Vec::new()
    };
    let mut transferred = Vec::new();
    for i in 0..num_handles {
        let hv = unsafe { *handles.add(i as usize) };
        let inner_h = proc.handles.get(hv).ok_or(SyscallError::BadHandle)?;
        transferred.push(inner_h);
    }
    ch.send(huesos_object::ChannelMessage {
        data,
        handles: transferred,
    });
    Ok(0)
}

fn sys_channel_read(
    handle: HandleValue,
    buf: *mut u8,
    len: u32,
    out_actual: *mut u32,
) -> SyscallResult {
    if buf.is_null() || out_actual.is_null() {
        return Err(SyscallError::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(SyscallError::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(SyscallError::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(SyscallError::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(SyscallError::WrongType)?;
    let msg = ch.recv().ok_or(SyscallError::ShouldWait)?;
    let to_copy = msg.data.len().min(len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.data.as_ptr(), buf, to_copy);
        *out_actual = to_copy as u32;
    }
    Ok(0)
}

fn sys_process_exit(code: i64) -> SyscallResult {
    if let Some(f) = *EXIT_FN.lock() {
        f(code);
    }
    // No exit handler registered: park forever rather than UB.
    loop {
        huesos_arch::hlt();
    }
}

fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 || len > 4096 {
        return Err(SyscallError::InvalidArgs);
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len) };
    if let Some(f) = *DEBUG_WRITE_FN.lock() {
        f(slice);
    }
    Ok(len as i64)
}
