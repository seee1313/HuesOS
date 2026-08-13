PROFILE ?= debug
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

# Build the boot crate (which produces the final kernel ELF "huesos-boot").
# We build explicitly with -p to avoid pulling in dev tools (clap etc.)
# that require std and break no_std kernel builds.
CARGO_BUILD := cargo build -p huesos-boot $(CARGO_FLAGS)

ISO := build/huesos.iso

.PHONY: all build build-release run run-release iso iso-release clean fmt fmt-check test policy-check storage-gate audit audit-check clippy

all: build

build:
	$(CARGO_BUILD)

build-release:
	$(MAKE) build PROFILE=release

iso: build
	bash scripts/mkiso.sh $(PROFILE)

iso-release: build-release
	bash scripts/mkiso.sh release

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
		-p huesos-blobfs \
		-p huesos-lifecycle \
		-p huesos-ioapic \
		-p huesos-extable \
		-p huesos-waitset \
		-p huesos-proclife \
		-p huesos-handlemove \
		-p hues-async \
		-p huesos-nvme \
		-p huesos-hxfs \
		-p huesos-pci \
		-p huesos-quota \
		--target x86_64-unknown-linux-gnu -Z build-std=

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
	python3 tools/check-huesos-object-lock-policy.py
	python3 tools/fmt-all.py --check

clippy:
	bash scripts/clippy.sh

clean:
	cargo clean
	rm -rf build

fmt:
	python3 tools/fmt-all.py

fmt-check:
	python3 tools/fmt-all.py --check
