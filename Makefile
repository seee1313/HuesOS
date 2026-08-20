PROFILE ?= debug
# Set STORAGE_OFF=1 to bake `init.storage=off` into the HBI command
# line. The kernel then skips PCI/NVMe discovery so a USB boot cannot
# program MSI or bus-master a live NVMe. Default remains storage on.
STORAGE_OFF ?=
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

# Build the boot crate (which produces the final kernel ELF "huesos-boot").
# We build explicitly with -p to avoid pulling in dev tools (clap etc.)
# that require std and break no_std kernel builds.
CARGO_BUILD := cargo build -p huesos-boot $(CARGO_FLAGS) \
	-Z build-std=core,compiler_builtins,alloc \
	-Z build-std-features=compiler-builtins-mem

ISO := build/huesos.iso

.PHONY: all build build-release run run-release iso iso-release clean fmt fmt-check test test-hxfs-features migration-check policy-check storage-gate audit audit-check bench-check clippy

all: build

build:
	bash scripts/ensure-hbi-signing-key.sh
	HUESOS_HBI_VERIFY_KEY_HEX="$$(cat build/hbi-verify-key.hex)" $(CARGO_BUILD)

build-release:
	$(MAKE) build PROFILE=release

iso: build
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh $(PROFILE)

iso-release: build-release
	STORAGE_OFF=$(STORAGE_OFF) bash scripts/mkiso.sh release

run: iso
	bash scripts/run.sh $(PROFILE)

run-release: iso-release
	bash scripts/run.sh release

test:
	# The 16 MiB host test mounts a writer with an 8192-extent fixed
	# array on the stack; the default test-thread stack overflows
	# when the hxblob index field is also present. 16 MiB is enough.
	RUST_MIN_STACK=16777216 cargo test -p huesos-abi -p huesos-arch -p huesos-elf -p huesos-pmm -p huesos-object -p huesos-fb \
		-p huesos-syscalls -p huesos-fat -p huesos-alloc -p huesos-uacpi -p huesos-kernel \
		-p huesos-scudo \
		-p huesos-scudo-fuzz \
		-p huesos-blobfs \
		-p huesos-bootux \
		-p huesos-lifecycle \
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
		--target x86_64-unknown-linux-gnu -Z build-std=

# The ordinary host suite builds huesos-hxfs without optional engines. This
# second gate is the production storage composition used by the encrypted
# NVMe soak: encryption + compression + Hxblob must work together, not only as
# three independently green feature sets.
test-hxfs-features:
	RUST_MIN_STACK=16777216 cargo test -p huesos-hxfs \
		--target x86_64-unknown-linux-gnu -Z build-std= \
		--no-default-features --features crypto-aes-gcm,compression-engines,hxblob

# Explicit HxFS v5 -> v6 migration: legacy mounts stay read-only until this
# journaled host tool publishes v6 policy roots and 64-bit generations.
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
