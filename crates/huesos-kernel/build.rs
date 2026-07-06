//! Builds HuesOS userspace binaries as separate `cargo` invocations
//! (different target: ring3, low load address) and exposes their paths to
//! the kernel/init build.
//!
//! `huesos-init` remains the only binary embedded directly in the kernel.
//! The next-stage userspace services are embedded into `init` so init can
//! create processes, map VMARs, create threads, and start them itself via
//! the new Zircon-like launch ABI.

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let userspace_root = manifest_dir.parent().unwrap().join("huesos-userspace");
    let profile = "release";

    track_userspace_inputs(&userspace_root);

    let driver_manager = build_userspace_program(
        &userspace_root,
        "driver-manager",
        "huesos-driver-manager",
        profile,
        &[],
    );
    let terminal = build_userspace_program(
        &userspace_root,
        "terminal",
        "huesos-terminal",
        profile,
        &[],
    );
    let init = build_userspace_program(
        &userspace_root,
        "init",
        "huesos-init",
        profile,
        &[
            ("HUESOS_DRIVER_MANAGER_PATH", driver_manager.as_os_str()),
            ("HUESOS_TERMINAL_PATH", terminal.as_os_str()),
        ],
    );

    println!("cargo:rustc-env=HUESOS_INIT_PATH={}", init.display());
}

fn track_userspace_inputs(userspace_root: &Path) {
    for program in ["init", "driver-manager", "terminal"] {
        println!(
            "cargo:rerun-if-changed={}",
            userspace_root.join(program).join("src").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            userspace_root.join(program).join("Cargo.toml").display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        userspace_root.join("libcanvas").join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        userspace_root.join("user_linker.ld").display()
    );
}

fn build_userspace_program(
    userspace_root: &Path,
    dir_name: &str,
    bin_name: &str,
    profile: &str,
    extra_env: &[(&str, &OsStr)],
) -> PathBuf {
    let program_dir = userspace_root.join(dir_name);
    let mut command = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&program_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--release"]);
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let status = command
        .status()
        .unwrap_or_else(|_| panic!("failed to invoke cargo for {bin_name} userspace build"));
    if !status.success() {
        panic!("building {bin_name} userspace binary failed");
    }

    let bin_path = program_dir
        .join("target")
        .join("x86_64-huesos-userspace")
        .join(profile)
        .join(bin_name);

    assert!(
        bin_path.exists(),
        "expected userspace binary at {}",
        bin_path.display()
    );
    bin_path
}
