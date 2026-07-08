# BOOTFS

BOOTFS is the first HuesOS filesystem backend. It is a RAM-resident archive
built at kernel build time and handed to userspace `init`, which then passes it
as a VMO capability to DriverManager.

This is intentionally not FAT32 yet. BOOTFS gives the userspace driver stack a
filesystem-shaped source of manifests, drivers, programs, and shell-visible
files before we have real block drivers. FAT32 should become another backend
behind the same FileSystemService protocol later.

## Goals

- Keep the kernel out of filesystem parsing.
- Let DriverManager own a `filesystem` service.
- Move driver manifests toward files with a dedicated extension.
- Provide shell-visible `ls`, `cat`, and `stat` commands.
- Provide a clean stepping stone toward loading DriverHosts from files instead
  of `include_bytes!`.

## Manifest extension

Driver manifests use the `.hdriver` extension.

Example path:

```text
/manifests/input-host.hdriver
```

The MVP manifest is plain ASCII key/value text so it can be parsed in no_std
userspace without pulling in a complex parser:

```text
name=input-host
kind=driver-host
provides=keyboard
irq=1
ioport=0x60:1
ioport=0x64:1
elf=/drivers/input-host.elf
heartbeat=true
```

## Archive format version 1

All integers are little-endian.

```text
BootFsHeader
  magic[8]    = "HBOOTFS1"
  file_count  = u32
  reserved    = u32

BootFsEntry[file_count] (216 bytes)
  path[192]   = UTF-8 path, NUL-padded
  offset      = u64, absolute byte offset from start of image
  len         = u64
  flags       = u32
  reserved    = u32

data bytes
```

Paths are absolute, slash-separated, and ASCII/UTF-8. Directories are implicit:
`/drivers/input-host.elf` implies `/drivers`.

## Initial BOOTFS layout

```text
/welcome.txt
/manifests/input-host.hdriver
/drivers/input-host.elf
/bin/terminal.elf
```

## Current service protocol

DriverManager exposes a `filesystem` service over a Channel. The initial MVP
uses line-oriented ASCII requests:

```text
LIST <path>
CAT <path>
STAT <path>
```

Responses are text intended for early shell/debug use. This will eventually be
replaced by a typed binary VFS protocol once the service model is stable.
