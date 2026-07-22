# Contributing to HuesOS

Thank you for your interest in HuesOS. This is a **microkernel** for x86_64
written in Rust, inspired by Google Zircon (Fuchsia). It boots via UEFI
(Limine) and runs real ring3 userspace over capability-based IPC.

These rules are **strict and non-negotiable**. They exist because a kernel's
value is its correctness and safety story, and that story only holds if every
change is reviewable, testable, and keeps the audited surface from growing.
A change that violates these rules will be rejected regardless of intent.

---

## 0. Ground rules (read first)

1. **Do not claim verification you did not perform.** Never write "verified in
   QEMU", "tested on hardware", or "works" unless you actually ran it and can
   point to the command and the observed output. "Should work" and "untested"
   are acceptable and must be stated explicitly.
2. **The kernel is `no_std`.** No `std` in kernel crates. `alloc` is available
   after heap init. Host-testable logic must be written so it runs without
   hardware.
3. **Userspace never touches the kernel directly.** Userspace programs go
   through `libcanvas` only — never a raw `syscall`. See `docs/USERSPACE.md`.
4. **One focused change per PR.** If the commit message needs the word "and"
   to describe unrelated things, split it.
5. **CI must be green before review:** `make audit-check`, `make clippy`,
   `make test`, and a QEMU boot smoke (see `docs/TESTING.md`).

---

## 1. Safety budget (hard gate)

The repository tracks a **safety regression budget** in `safety-budget.json`,
enforced by `tools/check-safety-budget.py` (`make audit-check`). The following
counts may **never grow** relative to the baseline:

- `unsafe_blocks`, `unsafe_functions`, `unsafe_impls`
- `static_mut`
- `unwrap_calls`, `expect_calls`, `panic_macros`

Important: the auditor (`tools/audit-safety.py`) scans the **raw text of every
`crates/**/*.rs` file, including `#[cfg(test)]` code**. Therefore:

- New code must be **budget-neutral by default**: zero new `unsafe`, and zero
  `.unwrap()` / `.expect()` / `panic!(...)` — *including in tests*.
- In tests, use `assert!`, `assert_eq!`, `assert_ne!`, `matches!`, and explicit
  `match` / `if let` instead of `.unwrap()` / `.expect()`.
- Prefer `core::array::from_fn`, fallible allocation, and `Option`/`Result`
  propagation over panicking.
- Host-testable policy logic must be expressible with **no `unsafe` at all**
  (see `crates/huesos-abi/src/broker_policy.rs` and
  `crates/huesos-lifecycle` as references).

If a change genuinely requires growing the surface, it must ship as a
**dedicated safety-budget review**: a separate PR that (a) justifies each new
unit of surface, (b) documents it in `docs/UNSAFE_AUDIT.md`, and (c) updates
`safety-budget.json` in the same commit. Do **not** silently raise the budget.

```bash
python3 tools/audit-safety.py          # report current surface
python3 tools/check-safety-budget.py   # hard gate (CI runs this)
python3 tools/check-policy-crates.py   # policy crate/documentation gate
```

---

## 2. Lock policy (hard gate for privileged crates)

`tools/check-lock-policy.py` rejects **unranked blocking locks** in the
privileged crates:

- `crates/huesos-arch/src`
- `crates/huesos-kernel/src`
- `crates/huesos-uacpi/src`

In these crates, `spin::Mutex` / `use spin::Mutex` is **forbidden**. Use the
ranked lock API exclusively, and assign every privileged lock a rank per
`docs/LOCK_ORDER.md`. Object/userspace crates are exempt only because they are
also built by host tests; new privileged locks there should still be ranked by
convention.

```bash
python3 tools/check-lock-policy.py     # hard gate (CI runs this)
```

---

## 3. Memory-safety boundaries (security)

- **User pointers are never dereferenced directly.** Every pointer-bearing
  syscall goes through the validated user-copy layer in
  `crates/huesos-syscalls/src/user_memory.rs` (ABI-bound check + full active
  page-table walk: `PRESENT`, `USER_ACCESSIBLE`, `WRITABLE` for outputs).
  See `docs/USER_MEMORY.md` for the full contract and review checklist.
- **Capabilities are the only namespace.** Resources are reached via handles
  with rights (`huesos-object::Rights`). Handle duplication may preserve or
  reduce rights, never add rights absent from the source.
- **W^X is enforced** on user pages; `NO_EXECUTE` requires `EFER.NXE` on every
  CPU. Do not introduce mappings that break this.
- Any change that could let a copy race a userspace `unmap`/`protect` requires
  the recoverable-copy / address-space-locking work tracked in
  `docs/ROADMAP.md` **before** it is exposed. Do not widen the attack surface
  speculatively.

---

## 4. Commit messages and history

HuesOS uses **Conventional Commits** with a scope:

```
<type>(<scope>): <imperative summary>

<body: what and why, not how>

<footer: verified-by notes, co-authors, refs>
```

- `type` ∈ {`feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `build`, `ci`,
  `chore`}.
- `scope` is the crate or subsystem, e.g. `feat(acpi-broker):`,
  `fix(scheduler):`, `docs(safety):`.
- The **body must explain the motivation and any root cause** (for fixes).
  Short one-liners are only acceptable for trivial doc/build changes.
- Include a **verification note**: what you ran and what you observed, e.g.
  `Verified: cargo test -p huesos-lifecycle (N pass), check-safety-budget.py,
  check-lock-policy.py`. If something is untested, say so.

Do not rewrite published history. Work on feature branches.

---

## 5. Branching and pull requests

- Branch from `main`. Name branches `huesos-dev/<topic>` (e.g.
  `huesos-dev/ioapic-routing`).
- Keep PRs small and reviewable; a reviewer must be able to hold the whole
  change in their head.
- A PR must include:
  - the code change,
  - tests (host tests for hardware-independent logic; QEMU expectations for
    on-target behavior),
  - doc updates (see §7),
  - a passing `make audit-check` and a verification note.
- Squash-merge is preferred; the squashed message must still satisfy §4.

---

## 6. Testing

Hardware-independent logic **must** be host-tested and wired into `make test`.
When you add a host-testable crate, add it to the `test` target in the
`Makefile`.

```bash
make test        # host tests on the pinned toolchain (uses -Z build-std=)
make run         # full QEMU boot smoke, default -smp 2
```

On-target changes must update the expected serial / framebuffer assertions in
`docs/TESTING.md`. See that file for the QEMU smoke matrix, the adversarial
user-pointer matrix, and the panic/shutdown/Snake/Doom tests.

**Honesty rule:** if you cannot run QEMU/hardware in your environment, say so
in the PR and mark the on-target portion as "requires on-target verification".
Never present unverified privileged code as done.

---

## 7. Documentation

Every non-trivial subsystem has a document in `docs/`. A PR that changes
behavior must update the relevant doc **in the same PR**. New subsystems need a
new doc covering: purpose, design, invariants, security notes, testing, and
**known limitations / not-yet-verified** items.

Always keep `docs/ROADMAP.md` current: move finished items to "Done (recent)"
with a short rationale, and keep "Needed" honest about what remains.

---

## 8. Adding a crate

- Pure, hardware-independent logic belongs in its own `no_std` crate so it is
  host-testable in isolation (pattern: `huesos-pmm`, `huesos-elf`,
  `huesos-abi::broker_policy`, `huesos-lifecycle`).
- Add the crate to the workspace `members` in the root `Cargo.toml`, and to the
  `make test` target if it has host tests.
- Keep external dependencies minimal and already present in
  `[workspace.dependencies]` where possible. New dependencies need justification
  in the PR.
- Kernel crates must build for the `x86_64-huesos.json` target with
  `-Z build-std` and must not pull in `std`-requiring crates (e.g. `clap`).

---

## 9. Licensing

- The kernel and native Rust crates are **MIT**.
- GPL code (e.g. DoomGeneric, GPL-2.0-only) is isolated in a **separate
  userspace process** and must never be linked into the MIT kernel.
- Do not import code with an incompatible license. Vendored third-party code
  lives under `third_party/` with its license retained.
- By contributing, you agree your contribution is licensed under the same
  terms as the component it modifies.

---

## 10. Definition of Done (checklist)

- [ ] Compiles warning-free on the pinned toolchain (`scripts/clippy.sh`).
- [ ] `make audit-check` passes (safety budget + lock policy + policy-crate check).
- [ ] Host tests added/updated and wired into `make test`; all pass.
- [ ] On-target behavior verified in QEMU (or explicitly marked unverified).
- [ ] Relevant `docs/` updated; `ROADMAP.md` current.
- [ ] Commit message follows §4 with a verification note.
- [ ] No new `unsafe`/`unwrap`/`expect`/`panic!` outside a dedicated
      safety-budget review.
- [ ] Licensing respected (no GPL in the kernel).

If you cannot tick a box, explain why in the PR rather than leaving it silent.
