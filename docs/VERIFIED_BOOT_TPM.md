# Verified boot, TPM sealing, and release keys

## Enforced chain

The release path is one chain; none of these checks replaces another:

1. UEFI Secure Boot authenticates the Limine `BOOT*.EFI` image against the owner-managed `db` certificate.
2. `limine enroll-config` embeds the BLAKE2B digest of the generated `limine.conf` into that EFI image. For optical boot, the signed image is also replaced inside `limine-uefi-cd.bin`; signing only the duplicate ISO file is insufficient.
3. `limine.conf` uses `hash_mismatch_panic: yes` and BLAKE2B-locked paths for the HuesOS kernel and HBI.
4. HBI v2.2 carries an Ed25519 signature over its header, directory, and all modules. The kernel verifies it before parsing any module.
5. BOOTFS contains `/manifests/bootfs.sha256`. DriverManager verifies every userspace ELF, `.hdriver`, and boot-driver manifest before using it.
6. After HBI verification, HuesOS extends PCR 12 with the domain-separated digest of executable kernel `PT_LOAD` segments, BOOTFS, command line, and platform module. The sealed-key module is excluded to avoid a circular measurement.
7. The volume key is unsealed only under the SHA-256 PCR selection `{7,12}`. PCR 7 is firmware Secure Boot policy; PCR 12 is the signed HuesOS measurement.

An HBI signature failure halts before userspace. TPM absence, TPM failure, or PCR mismatch never falls back to a compiled key: encrypted HxFS fails closed, while a plain volume may still boot.

## Key ownership

Production private keys are never committed:

- `HUESOS_HBI_SIGNING_KEY_FILE`: PKCS#8 PEM Ed25519 private key.
- `HUESOS_HBI_VERIFY_KEY_HEX`: matching 32-byte public key, lowercase hex.
- `HUESOS_HBI_REQUIRE_PRODUCTION_KEY=1`: forbids the generated development key.
- `HUESOS_UEFI_DB_KEY`: owner UEFI `db` private key for `sbsign`.
- `HUESOS_UEFI_DB_CERT`: matching X.509 certificate.

The default development HBI key is generated under ignored `build/` and is not a release identity. A release build should use an offline signer or tightly controlled CI secret mount and should retain only the public certificate/key plus artifact hashes.

```sh
HUESOS_HBI_REQUIRE_PRODUCTION_KEY=1 \
HUESOS_HBI_SIGNING_KEY_FILE=/secure/hbi-ed25519.pem \
HUESOS_HBI_VERIFY_KEY_HEX="$(cat /secure/hbi-ed25519.pub.hex)" \
HUESOS_SECURE_BOOT=1 \
HUESOS_UEFI_DB_KEY=/secure/uefi-db.key \
HUESOS_UEFI_DB_CERT=/secure/uefi-db.crt \
make iso-release
```

## Sealed-key module

`tools/make-sealed-key-module.py` packages an owner-selected persistent parent handle and canonical `TPM2B_PUBLIC`/`TPM2B_PRIVATE` files from `tpm2_create`. The complete module is included inside the signed HBI. It contains no plaintext volume key.

Provisioning policy:

```sh
tpm2_createpolicy --policy-pcr -l sha256:7,12 -f pcr.bin -L policy.dat
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
tpm2_flushcontext -t
tpm2_create -C 0x81000001 -u seal.pub -r seal.priv \
  -i volume-key.bin -L policy.dat \
  -a 'fixedtpm|fixedparent|adminwithpolicy|noda'
python3 tools/make-sealed-key-module.py --parent 0x81000001 \
  --public seal.pub --private seal.priv --output sealed-key.bin
```

Before using `0x81000001`, the owner must inspect `tpm2_getcap handles-persistent` and choose a non-conflicting handle. Never evict an existing object implicitly. `volume-key.bin`, primary contexts, and temporary policy inputs are sensitive installation artifacts and must be erased according to the owner's media policy.

The expected PCR file contains the 32-byte PCR 7 value followed by the 32-byte PCR 12 value. Provision only after booting the exact signed probe image under the intended firmware Secure Boot configuration. Firmware updates, Secure Boot database changes, kernel/HBI/cmdline/platform changes, and some hardware policy changes can require an authorized reseal/recovery procedure.

## KeyBroker lifecycle

The kernel moves the unsealed master key exactly once into KeyBroker. DriverManager owns the only generation-grant channel. Generations are non-zero and strictly increasing; replay and backwards requests are denied.

After KeyBroker exits, it is not restarted before reboot. An already-mounted encrypted HxFS continues with keys it has already derived. A new encrypted HxFS generation cannot obtain the master key and is denied. The QEMU crash gate explicitly proves generation 1 continues its self-check/write workload and generation 2 sees a closed broker authority.

## Deterministic gates

```sh
bash scripts/ci-qemu-hbi-signature-smoke.sh debug 120
bash scripts/ci-qemu-secure-boot-smoke.sh debug 45
bash scripts/ci-qemu-tpm-sealed-key-smoke.sh debug 120
bash scripts/ci-qemu-key-broker-fail-smoke.sh debug 180
bash scripts/ci-qemu-smep-smap-smoke.sh release 120
```

These are QEMU/swtpm CI gates, not bare-metal evidence. Physical evidence required before merge is described in `docs/BARE_METAL_SECURITY_EVIDENCE.md`.
