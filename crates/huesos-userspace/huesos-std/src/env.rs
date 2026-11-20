//! The process environment: arguments and the capability mask.
//!
//! HuesOS has no environment variables. What a program gets instead is its
//! `argv` (set by whoever launched it) and a mask of the capability classes the
//! kernel granted it. Both live in the bootstrap record `libcanvas` parses, so
//! these are thin, allocation-light wrappers over it.

use alloc::string::String;
use alloc::vec::Vec;

use libcanvas::stdio;

/// The longest argument `arg` will return; longer ones are truncated the way
/// the bootstrap buffer truncates them.
pub const MAX_ARG_BYTES: usize = 512;

/// Number of arguments, including `argv[0]`.
pub fn args_count() -> usize {
    stdio::args_count()
}

/// Argument `index` (`0` is the program name), if it exists.
pub fn arg(index: usize) -> Option<String> {
    let mut buf = [0u8; MAX_ARG_BYTES];
    stdio::arg_str(index, &mut buf).map(String::from)
}

/// All arguments, including `argv[0]`.
pub fn argv() -> Vec<String> {
    (0..args_count()).filter_map(arg).collect()
}

/// The arguments a program normally wants: everything after the program name.
pub fn args() -> Vec<String> {
    (1..args_count()).filter_map(arg).collect()
}

/// The capability mask the kernel granted this process.
pub fn caps() -> u64 {
    stdio::caps_mask()
}

/// True when every bit of `mask` is granted.
pub fn has_caps(mask: u64) -> bool {
    caps() & mask == mask
}
