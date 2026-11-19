//! Process/thread-level primitives and userspace static ELF launching.

mod elf;
mod launcher;
mod lifecycle;
mod objects;

pub use launcher::{spawn_elf, spawn_elf_on_cpu, spawn_elf_with_stack};
pub use launcher::{
    spawn_elf_from_vmo, spawn_elf_from_vmo_with_lib, spawn_elf_from_vmo_with_lib_and_hxfs,
    spawn_elf_from_vmo_with_stack, spawn_elf_from_vmo_with_vmar,
    spawn_elf_from_vmo_with_vmar_and_stack,
};
pub use launcher::{spawn_elf_on_cpu_with_lib, spawn_elf_with_lib, spawn_elf_with_lib_and_hxfs};
pub use lifecycle::{exit, exit_thread, set_fs_base, yield_now};
pub use objects::{Process, Thread, Vmar, CHILD_BOOTSTRAP_HANDLE};
