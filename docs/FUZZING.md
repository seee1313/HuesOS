# Coverage-guided fuzzing

HuesOS keeps deterministic randomized decoder tests, but they are not a
replacement for coverage-guided fuzzing. The `fuzz/` cargo-fuzz project adds two
libFuzzer/AddressSanitizer targets:

- `abi_decoders`: ACPI archive, storage boot, PCI and KeyBroker wire decoders;
- `elf_loader`: hostile ELF bytes through the kernel-independent loader.

Run locally:

```bash
bash scripts/restore-dev-env.sh
cd fuzz
cargo fuzz run abi_decoders -- -max_total_time=60
cargo fuzz run elf_loader -- -max_total_time=60
```

The sanitizer workflow runs both on every PR. Corpus/artifact directories are
ignored; every discovered crash must become a small deterministic regression
test before the fix is accepted.

The first `elf_loader` run found a panic in `xmas-elf::program_iter` reached by
an ELF32/truncated program-header geometry. HuesOS now pre-validates ELF64
class, endianness, header sizes and the complete program-header table before
constructing the dependency iterator; the reproducer is retained in
`huesos-elf` tests.
