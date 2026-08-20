# Required GitHub repository settings

These settings cannot be enforced by a source-code PR. The owner must apply
them in **Settings → Rules → Rulesets** after this branch is pushed.

## `main` ruleset

- Enforcement: Active
- Target: default branch `main`
- Restrict deletions and force pushes
- Require a pull request before merging
- Required approvals: 1
- Dismiss stale approvals when new commits are pushed
- Require review from Code Owners
- Require conversation resolution
- Require signed commits
- Require linear history
- Required status checks:
  - `static-safety`
  - all `qemu-boot` matrix entries (debug/release, 1/2/4/8 CPUs)
  - `qemu-acpi-restart`
  - all NVMe/fault-injection/power-fail/storage-off jobs
  - `address-sanitizer`
- Do not allow bypass except emergency repository owner recovery

## Repository hygiene

- Enable private vulnerability reporting.
- Delete head branches after merge.
- Set description to: `Capability-based x86_64 Rust microkernel with SMP,
  userspace drivers and HxFS`.
- Add topics: `rust`, `operating-system`, `microkernel`, `x86-64`, `uefi`,
  `capability-security`.
- Keep Actions token permissions read-only by default.
- Enable Dependabot security updates.

The workflow actions in this repository are pinned by commit SHA. Review and
update those pins deliberately rather than switching back to floating tags.
