PROFILE ?= debug
# Set STORAGE_OFF=1 to bake `init.storage=off` into the HBI command
# line. The kernel then skips PCI/NVMe discovery so a USB boot cannot
# program MSI or bus-master a live NVMe. Default remains storage on.
STORAGE_OFF ?=
HUESOS_BOOT_SELFTEST ?=
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,) $(if $(filter 1,$(HUESOS_BOOT_SELFTEST)),--features boot-selftest,)

# Build the boot crate (which produces the final kernel ELF "huesos-boot").
# We build explicitly with -p to avoid pulling in dev tools (clap etc.)
# that require std and break no_std kernel builds.
CARGO_BUILD := cargo build -p huesos-boot $(CARGO_FLAGS) \
	-Z build-std=core,compiler_builtins,alloc \
	-Z build-std-features=compiler-builtins-mem

ISO := build/huesos.iso

.PHONY: all build build-release build-test build-test-release run run-release run-test run-test-release iso iso-release iso-test iso-test-release clean fmt fmt-check test test-hxfs-features migration-check image-check policy-check storage-gate audit audit-check bench-check clippy

all: build

build:
	bash scripts/ensure-hbi-signing-key.sh
	HUESOS_HBI_VERIFY_KEY_HEX="$$(cat build/hbi-verify-key.hex)" $(CARGO_BUILD)

build-release:
	$(MAKE) build PROFILE=release

build-test:
	$(MAKE) build PROFILE=$(PROFILE) HUESOS_BOOT_SELFTEST=1

build-test-release:
	$(MAKE) build PROFILE=release HUESOS_BOOT_SELFTEST=1

iso: build
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh $(PROFILE)

iso-release: build-release
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh release

iso-test: build-test
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh $(PROFILE)

iso-test-release: build-test-release
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh release

run: iso
	bash scripts/run.sh $(PROFILE)

run-release: iso-release
	bash scripts/run.sh release

run-test: iso-test
	bash scripts/run.sh $(PROFILE)

run-test-release: iso-test-release
	bash scripts/run.sh release

test:
	# The 16 MiB host test mounts a writer with an 8192-extent fixed
	# array on the stack; the default test-thread stack overflows
	# when the hxblob index field is also present. 16 MiB is enough.
	RUST_MIN_STACK=16777216 cargo test -p huesos-abi -p huesos-arch -p huesos-sync -p huesos-elf -p huesos-pmm -p huesos-object -p huesos-fb \
		-p huesos-syscalls -p huesos-fat -p huesos-alloc -p huesos-uacpi -p huesos-kernel \
		-p huesos-scudo \
		-p huesos-scudo-fuzz \
		-p huesos-blobfs \
		-p huesos-bootux \
		-p huesos-lifecycle \
		-p huesos-sched \
		-p huesos-ioapic \
		-p huesos-extable \
		-p huesos-waitset \
		-p huesos-proclife \
		-p huesos-handlemove \
		-p hues-async \
		-p huesos-nvme \
		-p huesos-hxfs \
		-p huesos-hxfs-proto \
		-p huesos-pci \
		-p huesos-quota \
		-p huesos-tpm \
		-p huesos-hsh \
		-p huesos-gpt \
		-p huesos-pe \
		-p huesos-net \
		-p huesos-ieee80211 \
		-p huesos-wpa \
		-p huesos-rtw88 \
		--target x86_64-unknown-linux-gnu

# The ordinary host suite builds huesos-hxfs without optional engines. This
# second gate is the production storage composition used by the encrypted
# NVMe soak: encryption + compression + Hxblob must work together, not only as
# three independently green feature sets.
test-hxfs-features:
	RUST_MIN_STACK=16777216 cargo test -p huesos-hxfs \
		--target x86_64-unknown-linux-gnu \
		--no-default-features --features crypto-aes-gcm,compression-engines,hxblob

# Current-format image generation + real writer round-trip; legacy stays read-only.
image-check:
	cargo fmt --manifest-path tools/hxfs-seed/Cargo.toml --all -- --check
	python3 tools/test-hxfs-images.py
	python3 tools/test-gpt-image.py
	RUST_MIN_STACK=16777216 cargo test --manifest-path tools/hxfs-seed/Cargo.toml \
		--target x86_64-unknown-linux-gnu
	cargo clippy --manifest-path tools/hxfs-seed/Cargo.toml --bins \
		--target x86_64-unknown-linux-gnu -- -D warnings

# Explicit HxFS v6 -> v7 migration: legacy mounts stay read-only until this
# journaled host tool publishes v7 Hxblob refcounts and format stamps.
migration-check:
	bash scripts/test-hxfs-migration.sh

audit:
	python3 tools/audit-safety.py

policy-check:
	python3 tools/check-policy-crates.py

storage-gate:
	python3 tools/check-storage-production-gate.py

audit-check:
	python3 tools/check-safety-budget.py
	python3 tools/check-lock-policy.py
	python3 tools/check-policy-crates.py
	python3 tools/check-hues-async-noalloc.py
	python3 tools/check-poll-budgets.py
	python3 tools/check-huesos-object-lock-policy.py
	python3 tools/check-kernel-no-pci.py
	python3 tools/check-doc-links.py
	python3 tools/fmt-all.py --check

# Stage E.4: the deterministic half of the storage benchmark is
# compared byte-exactly against the committed baseline, and the timing
# half is compared against a second run in the same invocation so that
# cross-machine variance cannot produce a false failure. Refresh the
# baseline deliberately with:
#   python3 tools/storage-bench.py --update-baseline tools/baselines/storage-bench.json
bench-check:
	mkdir -p build
	python3 tools/storage-bench.py --iterations 3 --blocks 256 \
		--baseline tools/baselines/storage-bench.json --self-compare \
		--output build/storage-bench.json

clippy:
	bash scripts/clippy.sh

clean:
	cargo clean
	rm -rf build

fmt:
	python3 tools/fmt-all.py

fmt-check:
	python3 tools/fmt-all.py --check
