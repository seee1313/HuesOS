# Shell (`hsh`), `huesos-std`, and Userspace Utilities

- **Status:** implemented and verified in host suites (`huesos-hsh`) and QEMU
  (`hsh`, `/bin/std-smoke.elf`, 45 `coreutils` binaries, `fdisk`/`btop` TUIs)
- **Related:** [USERSPACE.md](USERSPACE.md), [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md),
  [NETWORKING.md](NETWORKING.md), [TERMINAL_RENDERING.md](TERMINAL_RENDERING.md)

HuesOS splits interactive userspace into three clean layers:

1. **`terminal` (`/bin/terminal.elf`)** — owns the framebuffer shadow surface,
   ANSI/truecolor VT parser, keyboard `Channel`, and PTY-equivalent stdio
   channels for foreground/TUI children.
2. **`hsh` (`crates/huesos-hsh` + `/bin/hsh.elf`)** — capability-attenuating
   interactive and scripting shell with zero `unsafe` in its language/pipeline
   engine (`#![forbid(unsafe_code)]`).
3. **`huesos-std` + `/bin/*.elf` (`coreutils`, `fdisk`)** — standalone Ring-3
   programs written against HuesOS's capability-explicit standard library.

---

## 1. `huesos-std` (`crates/huesos-userspace/huesos-std`)

`huesos-std` sits on top of `libcanvas` and `huesos-scudo` (`ScudoHeap`) to give
`/bin` utilities ergonomic Rust APIs without POSIX ambient authority:

- **`entry!(fn_main)`:** initializes `ScudoHeap`, parses `auxv` capability
  handles (`stdin`/`stdout`/`stderr`, `HxFS` service + confined working
  directory, `BOOTFS`, `net-service`, `wlan-service`, framebuffer, `argv`, `cwd`,
  and `@caps` mask), runs `fn_main() -> i32`, flushes stdio, and exits cleanly.
- **`io` & `buffered`:** `Read`/`Write`, `BufReader`/`BufWriter`, `Stdin`/`Stdout`/`Stderr`,
  and `print!` / `println!` / `eprintln!` over streaming IPC Channels.
- **`fs` & `path`:** `File`, `OpenOptions`, random-offset reads/writes,
  `truncate`, `readdir`, `mkdir`, `remove`, cross-directory `rename`, `symlink`,
  `read_link`, `chmod`/`set_mode`, `stat` / `lstat` (`O_NOFOLLOW`), and `stat_fs`
  over `hxfs-service` (with transparent `/boot` `BOOTFS` fallback).
- **`net`:** TCP/UDP/DNS/ICMP helpers over `net-service`.
- **`thread` & `sync`:** user threads + `FutexWait`/`FutexWake`-backed `Mutex`,
  `Condvar`, and `Once`.
- **`process`, `env`, `time`, `tui`:** child spawning, `argv`/`cwd`/capability
  inspection, monotonic nanosecond/tick clocks, and truecolor ANSI/raw-mode TUI
  rendering helpers.

Live verification runs in QEMU via `/bin/std-smoke.elf` (`scripts/ci-qemu-smoke.sh`).

---

## 2. `hsh` shell (`crates/huesos-hsh` & `crates/huesos-userspace/hsh-bin`)

### 2.1 Language and interactive UX

- **Predictable quoting:** Plan 9 `rc`-style argument evaluation (variables do
  not silently word-split on whitespace) plus unquoted globbing (`*`, `?`).
- **Scripting & control flow:** `fn name(...) { ... }`, `local`, `return`,
  `if` / `elif` / `else`, `while`, `for x in ...`, `break` / `continue`,
  `$((...))` integer arithmetic, `$?` / `$#` / `$@` / `$0..$9`, `!` negation,
  `export`, `read`, `test` / `[`, and `source` / `.` script execution.
- **Interactive terminal UX:** Fish-style live syntax highlighting
  (`huesos_hsh::highlight_line`), history-backed autosuggestions, path/command
  tab completion, working-directory prompt, background jobs (`&`, `jobs`, `fg`),
  and `Ctrl-C` termination of stuck foreground pipelines via `ProcessTerminate`.

### 2.2 Streaming pipelines and structured filters

- **N-stage streaming IPC pipelines:** `cmd1 | cmd2 | cmd3` connects sibling
  processes directly with kernel `Channel` pairs so multi-megabyte streams flow
  concurrently without buffering whole outputs in the shell.
- **Structured `Table` builtins:** `where`, `select`, `sort`, `head`, `tail`,
  `count`, and `grep` can filter structured command records as well as byte
  streams (for example `pci | count`).

### 2.3 `@caps(...)` capability attenuation

Every external command launched by `hsh` can have its capability set narrowed at
spawn time:

```text
@caps(fs=ro, net=none, wlan=none, fb=none) /bin/curl.elf https://example.com
@caps(dir=/tmp:rw) /bin/tar.elf -xf archive.tar
```

Supported clauses cover `hxfs` (`rw`/`ro`/`none`), confined `dir` (`DirectoryHandle`
subtree grants that reject `..` or symlink escapes), `bootfs`, `net`, `wlan`,
and `fb`. Denied handles are never transferred into the child's handle table.

---

## 3. Standalone utilities (`coreutils` & `fdisk`)

All utilities live under `/bin/*.elf` in `BOOTFS` (45 binaries in
`crates/huesos-userspace/coreutils/src/bin/` plus `/bin/fdisk.elf`):

- **Filesystem & archives:** `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `ln`,
  `readlink`, `chmod`, `touch`, `write`, `stat`, `find`, `du`, `df`, `dd`,
  `tar`, `sha256sum`, `hexdump`, `nano` (interactive text editor).
- **Text & pipelines:** `grep`, `head`, `tail`, `wc`, `sort`, `uniq`, `seq`,
  `tee`, `basename`, `dirname`, `sleep`.
- **Storage & partitioning:**
  - `fdisk` (`/bin/fdisk.elf`, backed by `huesos-gpt`) — CLI (`list`, `inspect`,
    `verify`, `gpt-init`) plus full-screen truecolor `cfdisk` TUI studio;
    recognizes bare `HxFS v7` superfloppy volumes and refuses destructive GPT
    initialization without `--force`;
  - `lsblk`, `mkfs`, `fsck`, `hxfs` (snapshots, scrub, volume inspection).
- **System, scheduler & hardware observability:**
  - `btop` — full-screen truecolor system studio showing live per-CPU EEVDF/CBS
    utilization, memory/quota counters, and per-task KOID/CPU rates via
    `SystemSchedStats` and `SystemTaskQuery`;
  - `ps`, `schedctl` (Fair weight / CBS deadline policy & 256-CPU affinity),
    `pci` (default TSV + `-v` / `--bars` / `--iommu` over read-only `HPIN` v1 VMO),
    `acpi`.
- **Networking & wireless:** `netctl`, `wlanctl`, `ping`, `curl` (HTTP/1.1 +
  TLS 1.3 HTTPS).
