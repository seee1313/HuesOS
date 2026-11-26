# Executable Loaders: Static ELF, Dynamic ELF, and Win64 PE32+

- **Status:** implemented and verified in host tests and QEMU (`huesos-elf`,
  `/lib/ld-huesos.so`, `huesos-pe`, `/lib/ld-pe.so`, `win64-runtime`)
- **Related:** [ARCHITECTURE.md](ARCHITECTURE.md), [USERSPACE.md](USERSPACE.md),
  [SHELL_AND_STD.md](SHELL_AND_STD.md), [USER_MEMORY.md](USER_MEMORY.md)

HuesOS executes three classes of Ring-3 binaries without embedding dynamic linker
or PE32+ policy in the microkernel:

1. **Static `ET_EXEC` ELF64** — bootstrap supervisors and low-level services
   (`init`, `driver-manager`, `acpi-manager`, `pci-manager`, `hxfs-service`,
   `key-broker`, `shutdown-broker`, `driver-host-*`).
2. **Dynamically linked PIE/ET_DYN ELF64** — programs carrying `PT_INTERP`
   resolved in Ring 3 by `/lib/ld-huesos.so` against `/lib/libcanvas.so` and
   optional runtime plugins.
3. **Native Windows x64 (`PE32+`, `Machine = 0x8664`)** — `.exe` and `.dll`
   binaries loaded in Ring 3 by `/lib/ld-pe.so` with native PE32+ system DLLs
   (`ntdll.dll`, `kernel32.dll`, `ucrtbase.dll`, `msvcrt.dll`, `ws2_32.dll`,
   `bcrypt.dll`, `bcryptprimitives.dll`, `advapi32.dll`).

---

## 1. Static ELF64 launch (`huesos-elf` & `libcanvas::process::launcher`)

- `huesos-elf` (`#![no_std]`) validates headers, program-header bounds, alignment,
  overflows, and W^X segment permissions (`PF_W | PF_X` is rejected).
- `libcanvas::process::launcher` creates the child `Process` and root `Vmar`,
  allocates dedicated VMOs per `PT_LOAD` segment in bounded chunks, maps an
  unmapped-guard-protected user stack, transfers only explicitly granted
  capability handles on the bootstrap channel / `auxv`, and starts the initial
  thread with SysV ABI stack alignment.
- Binaries can be spawned from both the immutable `BOOTFS` VMO and mutable
  `HxFS v7` files (`hsh` resolves `/bin/*` and relative/absolute VFS paths).

---

## 2. Dynamic ELF64 linker (`/lib/ld-huesos.so`)

When `libcanvas::process::launcher` detects an ELF `PT_INTERP` header, it maps
`/lib/ld-huesos.so` into the child `Vmar` and passes program metadata plus
capability handles through `huesos_abi::auxv` (`AT_PHDR`, `AT_ENTRY`,
`AT_HUESOS_*`).

Key properties of `crates/huesos-userspace/ld-huesos`:

- **Strict W^X + Full RELRO:** eager `BIND_NOW` relocation resolution followed by
  `VmarProtect(READ)` on `PT_GNU_RELRO` segments before jumping to user entry.
- **Symbol versioning & init/fini:** GNU `DT_VERSYM` / `DT_VERDEF` / `DT_VERNEED`
  checks, topological `DT_INIT` / `DT_INIT_ARRAY`, and reverse-topological
  `__cxa_atexit` + `DT_FINI_ARRAY` / `DT_FINI`.
- **Multi-threaded TLS:** Variant-II static TLS block layout and General-Dynamic
  `__tls_get_addr` / DTV support.
- **Capability-first `dlopen` family:** `canvas_dlopen_vmo`,
  `canvas_dlopen_soname`, `canvas_dlopen_blob`, `canvas_dlsym`,
  `canvas_dlclose`, `canvas_dlerror`, `canvas_dladdr`, and
  `canvas_dl_iterate_phdr` up to `MAX_OBJECTS = 64` with module-graph reference
  counting and `SONAME` verification.
- **Library search without ambient VFS:** loads shared objects from a confined
  `HxFS` `/lib` `DirectoryHandle` (`AT_HUESOS_HXFS_DIR`) with fallback to the
  read-only `BOOTFS` library archive (`AT_HUESOS_LIB_VMO`).

---

## 3. Native Win64 PE32+ subsystem (`huesos-pe`, `ld-pe`, `win64-runtime`)

### 3.1 Minimal kernel support

The kernel stays free of PE parsing and Win32 semantics; it provides only three
architectural mechanisms needed by Microsoft x64 (`extern "win64"`) code:

- **Per-thread Ring-3 `GS_BASE`:** saved and restored across context switches,
  with `SwapGsGuard` on Ring-3 interrupt/exception entries so `gs:[0x30]` (`TEB`)
  and `gs:[0x60]` (`PEB`) work natively alongside kernel per-CPU `GS_BASE`.
- **Syscalls `91..=93`:** `ThreadSetGsBase`, `ThreadGetGsBase`, and
  `ProcessSetAbi` (`ProcessAbi::Elf64` vs `ProcessAbi::Pe64`).
- **Exception/SEH cooperation:** `huesos-pe::unwind` implements safe bounds-checked
  `.pdata` / `.xdata` (`RUNTIME_FUNCTION` / `UNWIND_INFO`) virtual unwinding for
  Win64 Structured Exception Handling.

### 3.2 Pure-policy parser (`crates/huesos-pe`)

`huesos-pe` is `#![no_std]` and `#![forbid(unsafe_code)]`:

- Validates `MZ` / `PE\0\0` / `IMAGE_NT_OPTIONAL_HDR64_MAGIC` (`0x020B`), section
  bounds, and W^X permissions.
- Applies `IMAGE_REL_BASED_DIR64` base relocations, resolves IAT/export tables
  (by name, ordinal, and forwarder string), maps `api-ms-win-*` / `ext-ms-win-*`
  ApiSet contracts to host DLLs, and defines `PEB`, `TEB`, `PEB_LDR_DATA`, and
  read-only `KUSER_SHARED_DATA` structures.

### 3.3 Loader (`/lib/ld-pe.so`) and native system DLLs (`win64-runtime`)

When spawning a `.exe`, `libcanvas::process::launcher` starts `/lib/ld-pe.so`,
which maps the executable and its transitive DLL imports, wires the `PeHostApi`
syscall/capability bridge into `ntdll.dll`, runs PE TLS callbacks and
`DllMain(DLL_PROCESS_ATTACH)`, sets `GS_BASE` to the primary thread's `TEB`, and
invokes the Win64 entry point.

Shipped native `x86_64-huesos-pe64` DLLs under `/lib/`:

- **`ntdll.dll` & `kernel32.dll`:** process heaps (`RtlAllocateHeap`), W^X
  virtual memory (`VirtualAlloc` / `VirtualProtect` / `VirtualFree`), Win32
  threads, futex-backed synchronization (`CRITICAL_SECTION`, `SRWLOCK`,
  `CONDITION_VARIABLE`, `WaitOnAddress`), FLS/TLS, SEH dispatch, command-line /
  environment blocks, console stdio, and `HxFS`-backed Win32 file/directory I/O.
- **`ucrtbase.dll` & `msvcrt.dll`:** C runtime startup (`_initterm`), stdio,
  allocator/string/math/formatting routines, and exit handling for MSVC/MinGW
  binaries.
- **`ws2_32.dll`:** Winsock2 TCP/UDP/DNS client API bridged to `net-service`.
- **`bcrypt.dll`, `bcryptprimitives.dll`, `advapi32.dll`:** `BCryptGenRandom` /
  `RtlGenRandom` CSPRNG and basic Win32 crypto/registry stub surfaces expected by
  standard Rust/C Windows toolchains.

Production ISOs package only `/lib/ld-pe.so` and the system DLLs; Win64 smoke
executables (`win-apps`) are built only for test/selftest verification.
