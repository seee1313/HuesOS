#!/usr/bin/env python3
"""Rewrite too-new GLIBC_2.xx version requirements down to the local glibc.

The vendored QEMU build was produced on Ubuntu 24.04 (glibc 2.38) while the
sandbox runs Debian 12 (glibc 2.36).  ld.so validates each `verneed` entry of
an object against the *named* dependency (`libc.so.6`), so an LD_PRELOAD shim
cannot satisfy the check: the requirement itself has to be lowered.

For every `.gnu.version_r` entry that names GLIBC_2.xx with xx > TARGET we
rename it to GLIBC_2.<target> and recompute the SysV hash stored in
`vna_hash`.  The actual newer symbols (`__isoc23_*`, `strlcpy`, `strlcat`) are
provided at run time by the unversioned shim library, which ld.so accepts for
versioned references.
"""

import struct
import sys

TARGET_MINOR = 36

SHT_GNU_VERNEED = 0x6FFFFFFE


def elf_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g
    return h


def patch(path: str) -> int:
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        if data[:4] != b"\x7fELF" or data[4] != 2:
            return 0
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            (sh_type, sh_offset, sh_size, sh_link) = (
                struct.unpack_from("<I", data, off + 4)[0],
                struct.unpack_from("<Q", data, off + 0x18)[0],
                struct.unpack_from("<Q", data, off + 0x20)[0],
                struct.unpack_from("<I", data, off + 0x28)[0],
            )
            sections.append((sh_type, sh_offset, sh_size, sh_link))

        patched = 0
        for sh_type, sh_offset, sh_size, sh_link in sections:
            if sh_type != SHT_GNU_VERNEED:
                continue
            dynstr_off = sections[sh_link][1]
            pos = sh_offset
            end = sh_offset + sh_size
            while pos < end:
                _vn_version, vn_cnt, _vn_file, vn_aux, vn_next = \
                    struct.unpack_from("<HHIII", data, pos)
                aux = pos + vn_aux
                for _ in range(vn_cnt):
                    _vna_hash, _vna_flags, _vna_other, vna_name, vna_next = \
                        struct.unpack_from("<IHHII", data, aux)
                    str_off = dynstr_off + vna_name
                    name_end = data.index(b"\0", str_off)
                    name = bytes(data[str_off:name_end])
                    if name.startswith(b"GLIBC_2."):
                        try:
                            minor = int(name.split(b".")[1])
                        except (IndexError, ValueError):
                            minor = 0
                        if minor > TARGET_MINOR:
                            new = b"GLIBC_2.%d" % TARGET_MINOR
                            if len(new) != len(name):
                                raise SystemExit(
                                    f"{path}: refusing to resize version string {name!r}")
                            data[str_off:name_end] = new
                            struct.pack_into("<I", data, aux, elf_hash(new))
                            patched += 1
                    if vna_next == 0:
                        break
                    aux += vna_next
                if vn_next == 0:
                    break
                pos += vn_next

        if patched:
            f.seek(0)
            f.write(data)
        return patched


def main(argv):
    total = 0
    for path in argv[1:]:
        n = patch(path)
        if n:
            print(f"[patch] {path}: lowered {n} version requirement(s) to 2.{TARGET_MINOR}")
            total += n
    if total == 0:
        print("[patch] nothing to lower")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
