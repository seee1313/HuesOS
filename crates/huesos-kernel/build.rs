//! Builds the userspace `huesos-init` binary as a separate `cargo`
//! invocation (different target: ring3, low load address) and exposes its
//! path to the kernel via the `HUESOS_INIT_PATH` env var, so `huesos-kernel`
//! can `include_bytes!` it directly into the kernel image.
//!
//! This keeps the userspace program out of the kernel's own workspace/target
//! (it needs a different linker script and target spec) while still
//! producing a single bootable kernel binary with `init` baked in — no
//! initrd/module-loading machinery needed for the MVP.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/huesos-kernel -> crates/huesos-userspace/init
    let userspace_dir = manifest_dir
        .parent()
        .unwrap()
        .join("huesos-userspace")
        .join("init");

    println!("cargo:rerun-if-changed={}", userspace_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        userspace_dir.parent().unwrap().join("user_linker.ld").display()
    );

    let profile = "release";

    // Use a fixed CARGO/RUSTUP env so this nested cargo invocation doesn't
    // inherit target-dir/RUSTFLAGS meant for the kernel build.
    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(&userspace_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--release"])
        .status()
        .expect("failed to invoke cargo for huesos-init userspace build");

    if !status.success() {
        panic!("building huesos-init userspace binary failed");
    }

    let bin_path = userspace_dir
        .join("target")
        .join("x86_64-huesos-userspace")
        .join(profile)
        .join("huesos-init");

    assert!(
        bin_path.exists(),
        "expected userspace binary at {}",
        bin_path.display()
    );

    println!("cargo:rustc-env=HUESOS_INIT_PATH={}", bin_path.display());
}
