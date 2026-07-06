PROFILE ?= debug
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)
ISO := build/huesos.iso

.PHONY: all build build-release run run-release iso iso-release clean fmt test

all: build

build:
	cargo build $(CARGO_FLAGS)

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
