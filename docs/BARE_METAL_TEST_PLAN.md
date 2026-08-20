# Bare-metal release-candidate test plan

Status: **protocol prepared; execution requires owner-provided hardware**.

QEMU results must never be recorded as bare-metal evidence. Run every first boot
with `STORAGE_OFF=1`, photograph/retain serial output, and record the exact HuesOS
commit.

## Minimum matrix

| Platform | Required coverage |
|---|---|
| Intel UEFI laptop/desktop | cold/warm boot, SMP 1/all CPUs, framebuffer, PS/2 or USB-fallback observation, shutdown |
| AMD UEFI laptop/desktop | same, plus APIC/MADT topology validation |
| NVMe controller A | storage-off image hash unchanged; then disposable-disk identify/read/write/reboot |
| NVMe controller B | same, different vendor/controller family |
| No-TPM machine | plain HxFS mount and all non-encryption services |
| TPM 2.0 CRB machine | sealed-key success and PCR-mismatch rejection |

## Procedure

1. Build and record `git rev-parse HEAD`, toolchain and ISO SHA-256.
2. Boot `STORAGE_OFF=1`; require the kernel/init disable markers and verify every
   installed disk is byte-for-byte unchanged at sampled sectors.
3. Capture CPU count, AP online messages, ACPI archive validation and terminal
   readiness over serial.
4. Reboot ten cold and ten warm cycles; no panic, triple fault or missing AP.
5. On a disposable NVMe only, enable storage and seed HxFS v6.
6. Run write/read, scrub, fsck, snapshot/reclaim and graceful shutdown.
7. Cut power during repeated writes, then require unattended replay, clean fsck
   and complete scrub.
8. For TPM testing, seal to the recorded PCR policy, verify mount, alter one
   measured component and require key denial.

## Evidence record

Append results to `docs/HARDWARE.md` with firmware version, CPU/chipset, APIC
mode, RAM, GPU/framebuffer, NVMe model/firmware, TPM interface, boot medium,
commit, ISO hash, pass/fail per step and attached serial-log path.
