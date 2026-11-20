//! Process control: exit and yield.
//!
//! There is deliberately no `fork` and no `exec`: a program is launched by a
//! parent that hands it a bootstrap channel, and it leaves by exiting with a
//! status. Spawning belongs to whoever owns the ELF image (the shell, `init`),
//! not to the standard library.

use libcanvas::process;

/// Exit the process with `code`.
pub fn exit(code: i32) -> ! {
    process::exit(i64::from(code))
}

/// Give up the rest of the time slice.
pub fn yield_now() {
    process::yield_now();
}
