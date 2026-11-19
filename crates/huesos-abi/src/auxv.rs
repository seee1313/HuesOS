//! SysV AMD64 Auxiliary Vector (`auxv`) ABI for dynamic ELF loading.
//!
//! Used by userspace process launchers (`libcanvas::process::launcher`) when
//! starting a `PT_INTERP` executable via `/lib/ld-huesos.so`.

/// End of the auxiliary vector.
pub const AT_NULL: u64 = 0;
/// Address of the main executable's program headers in memory.
pub const AT_PHDR: u64 = 3;
/// Size of one program header entry (`e_phentsize`).
pub const AT_PHENT: u64 = 4;
/// Number of program headers in the main executable (`e_phnum`).
pub const AT_PHNUM: u64 = 5;
/// System page size in bytes (`4096`).
pub const AT_PAGESZ: u64 = 6;
/// Base load address of the dynamic linker (`ld-huesos.so`).
pub const AT_BASE: u64 = 7;
/// Flags (currently `0`).
pub const AT_FLAGS: u64 = 8;
/// Entry point virtual address of the main executable (`e_entry + load_bias`).
pub const AT_ENTRY: u64 = 9;
/// Address of 16 random bytes (populated from `SystemGetEntropy`).
pub const AT_RANDOM: u64 = 25;
/// HuesOS extension: non-zero when the parent launcher queued `self_vmar`
/// and `lib_vmo` ahead of normal messages on bootstrap handle `1`.
pub const AT_HUESOS_LD_BOOTSTRAP: u64 = 0x1001;

/// Bootstrap channel label carrying the child's own root VMAR handle to
/// `ld-huesos.so` (closed by the dynamic linker before entering the app).
pub const LD_BOOTSTRAP_SELF_VMAR_LABEL: &[u8] = b"huesos:ld:self-vmar";
/// Bootstrap channel label carrying the read-only `BOOTFS` VMO handle to
/// `ld-huesos.so` for resolving `/lib/*.so` (closed before entering the app).
pub const LD_BOOTSTRAP_LIB_VMO_LABEL: &[u8] = b"huesos:ld:lib-vmo";

/// Default interpreter path expected in `PT_INTERP`.
pub const DEFAULT_INTERP_PATH: &str = "/lib/ld-huesos.so";

/// One entry in the SysV AMD64 auxiliary vector on the initial user stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuxEntry {
    /// Auxiliary tag (`AT_*`).
    pub a_type: u64,
    /// Auxiliary value or pointer.
    pub a_val: u64,
}
