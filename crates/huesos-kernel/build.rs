//! Builds HuesOS userspace binaries as separate `cargo` invocations
//! (different target: ring3, low load address) and exposes their paths to
//! the kernel/init build.
//!
//! `huesos-init` remains the only binary embedded directly in the kernel.
//! Core early services remain embedded in init for deterministic bootstrap;
//! large optional applications and assets (Doom/Freedoom) live only in the
//! HBI BOOTFS and are launched through its read-only VMO capability.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let userspace_root = manifest_dir.parent().unwrap().join("huesos-userspace");
    let profile = "release";

    track_userspace_inputs(&userspace_root);

    let input_driver_host = build_userspace_program(
        &userspace_root,
        "driver-host-input",
        "huesos-driver-host-input",
        profile,
        &[],
    );
    let driver_manager = build_userspace_program(
        &userspace_root,
        "driver-manager",
        "huesos-driver-manager",
        profile,
        &[(
            "HUESOS_INPUT_DRIVER_HOST_PATH",
            input_driver_host.as_os_str(),
        )],
    );
    let doom = build_userspace_program(&userspace_root, "doom", "huesos-doom", profile, &[]);
    let terminal =
        build_userspace_program(&userspace_root, "terminal", "huesos-terminal", profile, &[]);
    let fault_probe = build_userspace_program(
        &userspace_root,
        "fault-probe",
        "huesos-fault-probe",
        profile,
        &[],
    );
    let _bootfs = build_bootfs_image(&manifest_dir, &input_driver_host, &terminal, &doom);
    let init = build_userspace_program(
        &userspace_root,
        "init",
        "huesos-init",
        profile,
        &[
            ("HUESOS_DRIVER_MANAGER_PATH", driver_manager.as_os_str()),
            ("HUESOS_TERMINAL_PATH", terminal.as_os_str()),
            ("HUESOS_FAULT_PROBE_PATH", fault_probe.as_os_str()),
        ],
    );

    println!("cargo:rustc-env=HUESOS_INIT_PATH={}", init.display());
}

fn track_userspace_inputs(userspace_root: &Path) {
    for program in [
        "init",
        "driver-manager",
        "driver-host-input",
        "terminal",
        "doom",
        "fault-probe",
    ] {
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
    println!("cargo:rerun-if-changed=../../third_party/freedoom/freedoom1.wad");
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
    for &(key, value) in extra_env {
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

struct BootFsFile {
    path: &'static str,
    data: Vec<u8>,
}

fn build_bootfs_image(
    manifest_dir: &Path,
    input_driver_host: &Path,
    terminal: &Path,
    doom: &Path,
) -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bootfs_path = out_dir.join("huesos.bootfs");
    let files = vec![
        BootFsFile {
            path: "/welcome.txt",
            data: b"Welcome to HuesOS BOOTFS\nTry: ls /, ls /manifests, cat /welcome.txt\n".to_vec(),
        },
        BootFsFile {
            path: "/manifests/input-host.hdriver",
            data: b"name=input-host\nkind=driver-host\nprovides=keyboard\nirq=1\nioport=0x60:1\nioport=0x64:1\nelf=/drivers/input-host.elf\nheartbeat=true\n".to_vec(),
        },
        BootFsFile {
            path: "/drivers/input-host.elf",
            data: fs::read(input_driver_host).expect("failed to read input DriverHost ELF"),
        },
        BootFsFile {
            path: "/bin/terminal.elf",
            data: fs::read(terminal).expect("failed to read terminal ELF"),
        },
        BootFsFile {
            path: "/bin/doom.elf",
            data: read_build_input(doom, "Doom ELF"),
        },
        BootFsFile {
            path: "/data/freedoom1.wad",
            data: read_build_input(
                &manifest_dir.join("../../third_party/freedoom/freedoom1.wad"),
                "Freedoom WAD",
            ),
        },
    ];
    write_bootfs(&bootfs_path, &files);
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
    bootfs_path
}

fn read_build_input(path: &Path, label: &str) -> Vec<u8> {
    match fs::read(path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("failed to read {label} at {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}

fn write_bootfs(path: &Path, files: &[BootFsFile]) {
    const MAGIC: &[u8; 8] = b"HBOOTFS1";
    const HEADER_SIZE: usize = 16;
    const ENTRY_SIZE: usize = 216;
    const PATH_SIZE: usize = 192;

    let mut image = Vec::new();
    image.extend_from_slice(MAGIC);
    image.extend_from_slice(&(files.len() as u32).to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());

    let entries_offset = HEADER_SIZE;
    let data_offset = entries_offset + files.len() * ENTRY_SIZE;
    image.resize(data_offset, 0);

    let mut cursor = data_offset as u64;
    for (idx, file) in files.iter().enumerate() {
        assert!(
            file.path.starts_with('/'),
            "BOOTFS path must be absolute: {}",
            file.path
        );
        assert!(
            file.path.len() < PATH_SIZE,
            "BOOTFS path too long: {}",
            file.path
        );
        let entry = entries_offset + idx * ENTRY_SIZE;
        image[entry..entry + file.path.len()].copy_from_slice(file.path.as_bytes());
        image[entry + PATH_SIZE..entry + PATH_SIZE + 8].copy_from_slice(&cursor.to_le_bytes());
        image[entry + PATH_SIZE + 8..entry + PATH_SIZE + 16]
            .copy_from_slice(&(file.data.len() as u64).to_le_bytes());
        image[entry + PATH_SIZE + 16..entry + PATH_SIZE + 20].copy_from_slice(&0u32.to_le_bytes());
        image[entry + PATH_SIZE + 20..entry + PATH_SIZE + 24].copy_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&file.data);
        cursor += file.data.len() as u64;
    }

    fs::write(path, image).expect("failed to write BOOTFS image");
}
