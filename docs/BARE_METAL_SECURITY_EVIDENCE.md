# Bare-metal security evidence checklist

QEMU and `swtpm` are deterministic CI dependencies only. They are not accepted as physical Intel/AMD/NVMe/TPM evidence. Before merge, the operator runs the signed release candidate on available hardware and attaches the collector bundles to the PR.

## Required systems

Collect one bundle per available system. The release target is:

- at least one Intel x86-64 system and one AMD x86-64 system;
- UEFI Secure Boot enabled with the owner `db` certificate enrolled;
- TPM 2.0 using the platform's real CRB interface;
- an NVMe namespace dedicated to the destructive HxFS test.

If a class is unavailable, record it as missing evidence; do not substitute QEMU.

## Two-stage image flow

1. Build a production-key **probe** ISO without `HUESOS_SEALED_KEY_MODULE` using `scripts/prepare-bare-metal-security-image.sh probe`. Boot it with Secure Boot enabled and capture serial output containing the verified HBI marker and PCR 7/PCR 12 values.
2. Verify the PCR values are stable over a cold boot. Provision the real TPM against exactly PCRs 7 and 12, using the owner-approved persistent handle and the commands in `docs/VERIFIED_BOOT_TPM.md`.
3. Package `seal.pub`/`seal.priv`, export `HUESOS_SEALED_KEY_MODULE`, and run `scripts/prepare-bare-metal-security-image.sh final`. Prepare the dedicated encrypted test NVMe namespace with the matching volume key.
4. Boot the final image. Capture successful unseal, KeyBroker generation 1, HxFS self-check, BOOTFS-manifest verification, and BSP/AP SMEP/SMAP markers.
5. Build a separately signed image with only the command line changed. Boot against the same TPM object and capture PCR-policy rejection and encrypted-volume refusal.
6. Run the KeyBroker crash image and capture: broker exit after grant 1, continued HxFS self-check/write markers, and generation 2 denial until reboot.
7. Attempt an unsigned Limine image with Secure Boot still enabled. Capture firmware rejection and verify that `[HuesOS] Bootloader handed over control` is absent.
8. Run the HxFS v5→v6 migration power-fail plan, cutting power after each harness-selected write/flush point. Every recovered image must be complete read-only v5 or mountable v6; mixed state is a failure.

Do not use a production data namespace. TPM ownership and Secure Boot enrollment can make a machine unbootable if performed incorrectly; retain the platform's owner-approved recovery media and key backups.

## Serial markers required in a successful final boot

```text
[HuesOS] Bootloader handed over control
[HBI] Ed25519 signature verified (v2.2)
[measure] signed kernel/HBI/cmdline digest ready for PCR 12
[tpm] PCR7=<64 lowercase hex>
[tpm] PCR12=<64 lowercase hex>
[tpm] volume key unsealed (PCR policy satisfied)
[key-broker] ambient/wrong-type key take denied
[key-broker] kernel key moved; state=available
[driver-manager] BOOTFS hash manifest verified and mounted
[hxfs] self-check ok
```

Each online CPU must report either `SMEP=on SMAP=on` or an explicit `degraded` marker. A degraded marker is evidence of unsupported CPU capability, not a successful SMEP/SMAP enablement; identify the exact CPU in the bundle.

## Bundle collection

On the collector Linux host, save the complete, unedited serial log and run:

```sh
sudo bash scripts/collect-bare-metal-security-evidence.sh \
  evidence/intel-system-a serial-final.log
```

Run it separately for final success, PCR mismatch, KeyBroker crash, unsigned rejection, and migration cases. The script copies the serial log, records host/CPU/PCI/NVMe/TPM metadata where tools are available, evaluates markers without editing the source log, and emits SHA-256 hashes. Attach the whole output directory to the PR.

A bundle is evidence, not an automatic attestation. Reviewers must compare image hashes with the release candidate, identify the physical system and test operator, and inspect failures/degraded markers before merge.
