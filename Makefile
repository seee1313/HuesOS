PROFILE ?= debug
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

# Build the boot crate (which produces the final kernel ELF "huesos-boot").
# We build explicitly with -p to avoid pulling in dev tools (clap etc.)
# that require std and break no_std kernel builds.
CARGO_BUILD := cargo build -p huesos-boot $(CARGO_FLAGS)

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
	mv .cargo/config.toml .cargo/config.toml.bak && \
	cargo +nightly test -p huesos-fat -p huesos-alloc --target x86_64-unknown-linux-gnu && \
	mv .cargo/config.toml.bak .cargo/config.toml

clean:
	cargo clean
	rm -rf build

fmt:
	cargo fmt
