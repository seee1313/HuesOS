PROFILE ?= debug
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

# Build only the kernel crate explicitly.
# This prevents accidental compilation of dev tools (clap, anstyle, etc.)
# that pull in std when building for the no_std x86_64-huesos target.
CARGO_BUILD := cargo build -p huesos-kernel $(CARGO_FLAGS)

ISO := build/huesos.iso

.PHONY: all build build-release run run-release iso iso-release clean fmt test

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
	cargo test -p huesos-elf -p huesos-pmm -p huesos-object -p huesos-fb --target x86_64-unknown-linux-gnu -Z build-std=

clean:
	cargo clean
	rm -rf build

fmt:
	cargo fmt
