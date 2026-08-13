# ADR: no Zstd backend in Hxfs; LZ4 is the only compression engine

Status: **accepted** (owner-approved). Closes the production-gate item
"no-heap Zstd backend audit or final rejection" by taking the
rejection.

## Context

`compression.rs` defines a `COMPRESSION_ZSTD` algorithm id and names
an audit candidate (`AUDITED_ZSTD_CRATE = "zstd"`), but no Zstd engine
is linked. Both the compress and decompress paths return
`EngineUnavailable` for that id. The gate asks for either a completed
audit of a no-heap Zstd backend, or a final rejection.

This rejects it.

## Decision

LZ4 (`lz4_flex`, via the `compression-engines` feature) is the only
compression engine Hxfs links. `COMPRESSION_ZSTD` remains a reserved
on-disk id that no writer emits and every reader rejects with
`EngineUnavailable`.

### Why not Zstd

**The allocation model is the blocker, not the ratio.** Hxfs's write
path runs under a no-heap policy: `driver-host-nvme` and the
filesystem core allocate nothing per request, and the compression
scratch buffer is a fixed `BLOCK_SIZE + 512` stack array. Zstd's
compressor is built around a working context — window, match tables,
entropy workspaces — typically hundreds of KiB to megabytes, sized at
init from the compression level. Getting that into a no-heap kernel
path means either:

- a statically reserved worst-case context, permanently resident, for
  a codec that only helps on a subset of files; or
- a custom allocator shim under a large C library, which is exactly
  the arrangement that made vendoring LLVM's Scudo impossible earlier
  in this project (`sanitizer_common` assumed libc/pthread/TLS).

**The audit surface is disproportionate.** Zstd's decoder is a large
attack surface reached with attacker-influenced bytes: a compressed
extent read back from disk. On an encrypted volume the AEAD tag is
checked first, but a plain volume feeds unverified on-disk bytes
straight into the decoder. LZ4's block format is small enough to
reason about; auditing Zstd's frame/FSE/Huffman layers to the standard
this project applies to `unsafe` is not a proportionate use of the
review budget.

**The benefit is modest here.** Hxfs compresses per 4 KiB block, not
per stream. Zstd's advantage over LZ4 comes largely from a large
window across a long input; at one block per frame, with no dictionary
carried between blocks, the ratio gap narrows sharply while the CPU
cost does not. Paying a large allocation and audit cost for a small
per-block gain is the wrong trade for a filesystem whose stated
priority is durability.

## Consequences

- `COMPRESSION_ZSTD` stays a reserved id. Writers never emit it;
  readers reject it with `EngineUnavailable` rather than silently
  storing or returning wrong bytes. This is already the behaviour and
  is now pinned by tests.
- `AUDITED_ZSTD_CRATE` remains as documentation of the candidate that
  was considered, not as a commitment to link it.
- Volumes needing a better ratio use LZ4 with a larger logical block,
  or compress at the application layer where a heap exists.

## What would reopen this

1. A no-heap Zstd decoder with a bounded, statically sized context
   that fits the filesystem's fixed-capacity budget — most plausibly a
   decode-only implementation, since decode contexts are far smaller
   than compress contexts.
2. Hxfs moving to multi-block compression units, where Zstd's window
   would actually pay off.
3. A measured workload showing LZ4's ratio is the binding constraint
   on a real deployment.

A "decode-only Zstd" variant is the most likely path back: it would
let volumes written elsewhere be read, without putting a compressor in
the no-heap write path. That is a different, smaller question than the
one this ADR rejects.
