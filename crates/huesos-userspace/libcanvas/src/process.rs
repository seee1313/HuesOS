//! Process/thread-level primitives and userspace static ELF launching.

mod elf;
mod launcher;
mod lifecycle;
mod objects;

pub use launcher::spawn_elf;
pub use launcher::spawn_elf_from_vmo;
pub use lifecycle::{exit, yield_now};
pub use objects::{Process, Thread, Vmar, CHILD_BOOTSTRAP_HANDLE};
