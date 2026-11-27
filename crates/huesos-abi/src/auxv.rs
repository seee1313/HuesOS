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
/// HuesOS extension: non-zero when the parent launcher transferred a read-only
/// `BOOTFS` library VMO handle (`LD_BOOTSTRAP_LIB_VMO_LABEL`) on bootstrap.
pub const AT_HUESOS_LIB_VMO: u64 = 0x1002;
/// HuesOS extension: non-zero when the parent launcher transferred a
/// capability `HxFS` library directory/service handle
/// (`LD_BOOTSTRAP_HXFS_DIR_LABEL`) on bootstrap ahead of normal messages.
pub const AT_HUESOS_HXFS_DIR: u64 = 0x1003;
/// HuesOS extension: non-zero when a standard input `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_STDIN_LABEL`).
pub const AT_HUESOS_STDIN: u64 = 0x1004;
/// HuesOS extension: non-zero when a standard output `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_STDOUT_LABEL`).
pub const AT_HUESOS_STDOUT: u64 = 0x1005;
/// HuesOS extension: non-zero when a standard error `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_STDERR_LABEL`).
pub const AT_HUESOS_STDERR: u64 = 0x1006;
/// HuesOS extension: capability attenuation bitmask (`caps_mask::*`) granted
/// by the spawning shell/supervisor.
pub const AT_HUESOS_CAPS_MASK: u64 = 0x1007;
/// HuesOS extension: non-zero when an `HxFS` service `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_HXFS_SERVICE_LABEL`).
pub const AT_HUESOS_HXFS_SERVICE: u64 = 0x1008;
/// HuesOS extension: non-zero when a block/volume `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_BLOCK_DEV_LABEL`).
pub const AT_HUESOS_BLOCK_DEV: u64 = 0x1009;
/// HuesOS extension: non-zero when a `FrameDraw` handle was queued on
/// bootstrap (`LD_BOOTSTRAP_FRAME_DRAW_LABEL`).
pub const AT_HUESOS_FRAME_DRAW: u64 = 0x100a;
/// HuesOS extension: non-zero when a read-only `DriverManager` query/registry
/// `Channel` handle was queued on bootstrap (`LD_BOOTSTRAP_REGISTRY_LABEL`).
pub const AT_HUESOS_REGISTRY: u64 = 0x100b;
/// HuesOS extension: non-zero when a target PE32+ `.exe` VMO handle was queued
/// on bootstrap (`LD_BOOTSTRAP_PE_VMO_LABEL`) for `/lib/ld-pe.so`.
pub const AT_HUESOS_PE_VMO: u64 = 0x100c;
/// HuesOS extension: byte offset of the target PE32+ `.exe` inside `pe_vmo`.
pub const AT_HUESOS_PE_OFFSET: u64 = 0x100d;
/// HuesOS extension: byte length of the target PE32+ `.exe` inside `pe_vmo`.
pub const AT_HUESOS_PE_LEN: u64 = 0x100e;
/// HuesOS extension: non-zero when a `net-service` (`Plan 9 /net`) `Channel`
/// handle was queued on bootstrap (`LD_BOOTSTRAP_NET_SERVICE_LABEL`).
pub const AT_HUESOS_NET_SERVICE: u64 = 0x100f;
/// HuesOS extension: non-zero when a `wlan-service` `Channel` handle was
/// queued on bootstrap (`LD_BOOTSTRAP_WLAN_SERVICE_LABEL`).
pub const AT_HUESOS_WLAN_SERVICE: u64 = 0x1010;
/// HuesOS extension: non-zero when a `btl-service` (`Plan 9 /net/btl`) `Channel`
/// handle was queued on bootstrap (`LD_BOOTSTRAP_BTL_SERVICE_LABEL`).
pub const AT_HUESOS_BTL_SERVICE: u64 = 0x1011;
/// HuesOS extension: non-zero when an `audio-service` (`/dev/audio`) `Channel`
/// handle was queued on bootstrap (`LD_BOOTSTRAP_AUDIO_SERVICE_LABEL`).
pub const AT_HUESOS_AUDIO_SERVICE: u64 = 0x1012;

/// Bootstrap channel label carrying the child's own root VMAR handle to
/// `ld-huesos.so` (closed by the dynamic linker before entering the app).
pub const LD_BOOTSTRAP_SELF_VMAR_LABEL: &[u8] = b"huesos:ld:self-vmar";
/// Bootstrap channel label carrying the read-only `BOOTFS` VMO handle to
/// `ld-huesos.so` for resolving `/lib/*.so` (closed before entering the app
/// when `caps_mask::BOOTFS_RO` is clear).
pub const LD_BOOTSTRAP_LIB_VMO_LABEL: &[u8] = b"huesos:ld:lib-vmo";
/// Bootstrap channel label carrying an `HxFS` library directory/service
/// channel handle to `ld-huesos.so` for capability-first SONAME lookup.
pub const LD_BOOTSTRAP_HXFS_DIR_LABEL: &[u8] = b"huesos:ld:hxfs-dir";
/// Bootstrap channel label carrying the child's `stdin` IPC `Channel`.
pub const LD_BOOTSTRAP_STDIN_LABEL: &[u8] = b"huesos:ld:stdin";
/// Bootstrap channel label carrying the child's `stdout` IPC `Channel`.
pub const LD_BOOTSTRAP_STDOUT_LABEL: &[u8] = b"huesos:ld:stdout";
/// Bootstrap channel label carrying the child's `stderr` IPC `Channel`.
pub const LD_BOOTSTRAP_STDERR_LABEL: &[u8] = b"huesos:ld:stderr";
/// Bootstrap channel label carrying the child's `HxFS` service `Channel`.
pub const LD_BOOTSTRAP_HXFS_SERVICE_LABEL: &[u8] = b"huesos:ld:hxfs-service";
/// Bootstrap channel label carrying the child's block/volume `Channel`.
pub const LD_BOOTSTRAP_BLOCK_DEV_LABEL: &[u8] = b"huesos:ld:block-dev";
/// Bootstrap channel label carrying the child's `FrameDraw` handle.
pub const LD_BOOTSTRAP_FRAME_DRAW_LABEL: &[u8] = b"huesos:ld:frame-draw";
/// Bootstrap channel label carrying the child's `DriverManager` query `Channel`.
pub const LD_BOOTSTRAP_REGISTRY_LABEL: &[u8] = b"huesos:ld:registry";
/// Bootstrap channel label carrying the target PE32+ `.exe` VMO to `/lib/ld-pe.so`.
pub const LD_BOOTSTRAP_PE_VMO_LABEL: &[u8] = b"huesos:ld:pe-vmo";
/// Bootstrap channel label carrying the child's `net-service` `Channel`.
pub const LD_BOOTSTRAP_NET_SERVICE_LABEL: &[u8] = b"huesos:ld:net-service";
/// Bootstrap channel label carrying the child's `wlan-service` `Channel`.
pub const LD_BOOTSTRAP_WLAN_SERVICE_LABEL: &[u8] = b"huesos:ld:wlan-service";
/// Bootstrap channel label carrying the child's `btl-service` (`Plan 9 /net/btl`) `Channel`.
pub const LD_BOOTSTRAP_BTL_SERVICE_LABEL: &[u8] = b"huesos:ld:btl-service";
/// Bootstrap channel label carrying the child's `audio-service` `Channel`.
pub const LD_BOOTSTRAP_AUDIO_SERVICE_LABEL: &[u8] = b"huesos:ld:audio-service";

/// Capability bitmask carried in `AT_HUESOS_CAPS_MASK`.
pub mod caps_mask {
    /// Application may retain and read from the `BOOTFS` VMO.
    pub const BOOTFS_RO: u64 = 1 << 0;
    /// Application may read from the granted `HxFS` capability.
    pub const HXFS_RO: u64 = 1 << 1;
    /// Application may mutate the granted `HxFS` capability.
    pub const HXFS_RW: u64 = 1 << 2;
    /// Application may blit to the framebuffer via `FrameDraw`.
    pub const FB_RO: u64 = 1 << 3;
    /// Application may read from the granted block device / volume.
    pub const BLOCK_RO: u64 = 1 << 4;
    /// Application may write to the granted block device / volume.
    pub const BLOCK_RW: u64 = 1 << 5;
    /// `HxFS` access is restricted to a scoped subpath directory handle.
    pub const HXFS_DIR_SCOPED: u64 = 1 << 6;
    /// Application may query `DriverManager` read-only (`query:pci`, `query:acpi`, `query:ps`).
    pub const QUERY_RO: u64 = 1 << 7;
    /// Application may read network telemetry and perform read-only DNS queries.
    pub const NET_RO: u64 = 1 << 8;
    /// Application may open TCP/UDP/ICMP sockets and configure `/net`.
    pub const NET_RW: u64 = 1 << 9;
    /// Application may read Wi-Fi status and non-secret saved profile summaries.
    pub const WLAN_RO: u64 = 1 << 10;
    /// Application may scan, connect, run SoftAP, and update Wi-Fi regulatory/MAC policy.
    pub const WLAN_ADMIN: u64 = 1 << 11;
    /// Application may read `/net/btl` status, peers, non-secret key tags, SDP, and snoop.
    pub const BTL_RO: u64 = 1 << 12;
    /// Application may open L2CAP channels and issue SDP queries over `/net/btl`.
    pub const BTL_RW: u64 = 1 << 13;
    /// Application may scan, pair, connect, disconnect, and manage `/net/btl` radio state.
    pub const BTL_ADMIN: u64 = 1 << 14;
    /// Application may read `/dev/audio` status and sink telemetry.
    pub const AUDIO_RO: u64 = 1 << 15;
    /// Application may open SPSC PCM playback streams on `/dev/audio`.
    pub const AUDIO_RW: u64 = 1 << 16;
    /// Application may change master volume, mute, sink routing (`auto`/`mirror`), and A2DP link.
    pub const AUDIO_ADMIN: u64 = 1 << 17;
    /// Full default interactive shell capability set.
    pub const ALL_DEFAULT: u64 = BOOTFS_RO
        | HXFS_RO
        | HXFS_RW
        | FB_RO
        | BLOCK_RO
        | BLOCK_RW
        | QUERY_RO
        | NET_RO
        | NET_RW
        | WLAN_RO
        | WLAN_ADMIN
        | BTL_RO
        | BTL_RW
        | BTL_ADMIN
        | AUDIO_RO
        | AUDIO_RW
        | AUDIO_ADMIN;
}

/// Default interpreter path expected in `PT_INTERP`.
pub const DEFAULT_INTERP_PATH: &str = "/lib/ld-huesos.so";
/// Native PE32+ (`.exe` / `.dll`) userspace runtime loader path.
pub const DEFAULT_PE_INTERP_PATH: &str = "/lib/ld-pe.so";

/// One entry in the SysV AMD64 auxiliary vector on the initial user stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuxEntry {
    /// Auxiliary tag (`AT_*`).
    pub a_type: u64,
    /// Auxiliary value or pointer.
    pub a_val: u64,
}
