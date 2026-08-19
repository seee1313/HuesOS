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

    // Stage D bootloader key blob: the soak harness (and a real
    // bootloader chain later) feeds the volume key hex here; the
    // kernel embeds it as a static the VolumeKeyGet syscall serves
    // to the storage service. Without the variable the blob is
    // None and encrypted volumes cannot be mounted.
    emit_boot_key_blob();

    // Stage B.5: the soak harness builds the ISO with
    // HUESOS_HXFS_SERVICE_FEATURES=synthetic-key so the embedded
    // hxfs-service can mount the encrypted+compressed soak volume
    // and run its boot self-check. Production builds leave the
    // variable unset and the test wiring stays out of the binary.
    //
    // The synthetic-key build pulls the RustCrypto AES-GCM stack
    // into the no-SIMD userspace target. The `aes` and `polyval`
    // crates compile their x86 fast paths (AES-NI / CLMUL) for any
    // x86_64 target regardless of the target's SIMD features, and
    // the userspace target deliberately disables SSE2 (kernel
    // context switch does not save XMM state), so the fast paths
    // crash LLVM codegen. Both crates ship the official soft
    // escape hatch (`aes_force_soft` / `polyval_force_soft`); the
    // flags are injected only for this build invocation and only
    // when test features are requested.
    let hxfs_service_features = env::var("HUESOS_HXFS_SERVICE_FEATURES").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=HUESOS_HXFS_SERVICE_FEATURES");
    let mut hxfs_args: Vec<String> = Vec::new();
    let mut hxfs_env: Vec<(&str, &OsStr)> = Vec::new();
    if !hxfs_service_features.is_empty() {
        hxfs_args.push("--features".to_string());
        hxfs_args.push(hxfs_service_features);
        hxfs_env.push((
            "RUSTFLAGS",
            OsStr::new("--cfg aes_force_soft --cfg polyval_force_soft"),
        ));
    }
    let hxfs_args_refs: Vec<&str> = hxfs_args.iter().map(String::as_str).collect();

    let input_driver_host = build_userspace_program(
        &userspace_root,
        "driver-host-input",
        "huesos-driver-host-input",
        profile,
        &[],
        &[],
    );
    let nvme_driver_host = build_userspace_program(
        &userspace_root,
        "driver-host-nvme",
        "huesos-driver-host-nvme",
        profile,
        &[],
        &[],
    );
    let hxfs_service = build_userspace_program(
        &userspace_root,
        "hxfs-service",
        "huesos-hxfs-service",
        profile,
        &hxfs_env,
        &hxfs_args_refs,
    );
    println!("cargo:rerun-if-env-changed=HUESOS_ACPI_RESTART_SMOKE");
    let acpi_restart_smoke = env::var_os("HUESOS_ACPI_RESTART_SMOKE").is_some();
    let driver_manager_args = if acpi_restart_smoke {
        ["--features", "acpi-restart-smoke"].as_slice()
    } else {
        [].as_slice()
    };
    let acpi_manager_args = if acpi_restart_smoke {
        ["--features", "restart-smoke"].as_slice()
    } else {
        [].as_slice()
    };
    let driver_manager = build_userspace_program(
        &userspace_root,
        "driver-manager",
        "huesos-driver-manager",
        profile,
        &[(
            "HUESOS_INPUT_DRIVER_HOST_PATH",
            input_driver_host.as_os_str(),
        )],
        driver_manager_args,
    );
    let acpi_manager = build_userspace_program(
        &userspace_root,
        "acpi-manager",
        "huesos-acpi-manager",
        profile,
        &[],
        acpi_manager_args,
    );
    let pci_manager = build_userspace_program(
        &userspace_root,
        "pci-manager",
        "huesos-pci-manager",
        profile,
        &[],
        &[],
    );
    let shutdown_broker = build_userspace_program(
        &userspace_root,
        "shutdown-broker",
        "huesos-shutdown-broker",
        profile,
        &[],
        &[],
    );
    let doom = build_userspace_program(&userspace_root, "doom", "huesos-doom", profile, &[], &[]);
    // Soak shutdown-cycle wiring (qemu-nvme-soak inject=3): the
    // harness exports HUESOS_TERMINAL_FEATURES=soak-shutdown so the
    // terminal auto-triggers an orderly userspace shutdown after a
    // few idle seconds. Production builds leave it unset.
    let terminal_features = env::var("HUESOS_TERMINAL_FEATURES").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=HUESOS_TERMINAL_FEATURES");
    let mut terminal_args: Vec<String> = Vec::new();
    if !terminal_features.is_empty() {
        terminal_args.push("--features".to_string());
        terminal_args.push(terminal_features);
    }
    let terminal_args_refs: Vec<&str> = terminal_args.iter().map(String::as_str).collect();
    let terminal = build_userspace_program(
        &userspace_root,
        "terminal",
        "huesos-terminal",
        profile,
        &[],
        &terminal_args_refs,
    );
    let fault_probe = build_userspace_program(
        &userspace_root,
        "fault-probe",
        "huesos-fault-probe",
        profile,
        &[],
        &[],
    );
    let _bootfs = build_bootfs_image(
        &manifest_dir,
        BootfsInputs {
            input_driver_host: &input_driver_host,
            nvme_driver_host: &nvme_driver_host,
            hxfs_service: &hxfs_service,
            acpi_manager: &acpi_manager,
            pci_manager: &pci_manager,
            shutdown_broker: &shutdown_broker,
            terminal: &terminal,
            doom: &doom,
        },
    );
    let init = build_userspace_program(
        &userspace_root,
        "init",
        "huesos-init",
        profile,
        &[
            ("HUESOS_DRIVER_MANAGER_PATH", driver_manager.as_os_str()),
            ("HUESOS_TERMINAL_PATH", terminal.as_os_str()),
            ("HUESOS_FAULT_PROBE_PATH", fault_probe.as_os_str()),
            ("HUESOS_ACPI_MANAGER_PATH", acpi_manager.as_os_str()),
            ("HUESOS_SHUTDOWN_BROKER_PATH", shutdown_broker.as_os_str()),
        ],
        &[],
    );

    println!("cargo:rustc-env=HUESOS_INIT_PATH={}", init.display());
}

/// Emit `$OUT_DIR/boot_key.rs` from `HUESOS_VOLUME_KEY_HEX` (64
/// hex chars -> `Some([u8; 32])`, absent/invalid -> `None`).
/// The kernel's `boot_key` module `include!`s it.
fn emit_boot_key_blob() {
    use std::io::Write;
    println!("cargo:rerun-if-env-changed=HUESOS_VOLUME_KEY_HEX");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_default());
    let path = out_dir.join("boot_key.rs");
    let value = env::var("HUESOS_VOLUME_KEY_HEX").unwrap_or_default();
    let trimmed = value.trim();
    let mut contents =
        String::from("// Generated by build.rs from HUESOS_VOLUME_KEY_HEX. Do not edit.\n");
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = Vec::with_capacity(32);
        let mut index = 0usize;
        while index < 32 {
            // Unreachable error: the hex-digit check above passed.
            let byte =
                u8::from_str_radix(&trimmed[index * 2..index * 2 + 2], 16).unwrap_or_default();
            bytes.push(byte);
            index += 1;
        }
        contents.push_str("pub const BOOT_VOLUME_KEY_BLOB: Option<[u8; 32]> = Some([\n");
        let mut line = String::from("    ");
        for byte in &bytes {
            line.push_str(&format!("0x{byte:02x}, "));
            if line.len() > 60 {
                contents.push_str(&line);
                contents.push('\n');
                line = String::from("    ");
            }
        }
        contents.push_str(&line);
        contents.push_str("\n]);\n");
    } else {
        contents.push_str("pub const BOOT_VOLUME_KEY_BLOB: Option<[u8; 32]> = None;\n");
    }
    emit_sealed_key_blob(&mut contents);
    if let Err(error) = std::fs::File::create(&path).and_then(|mut file| {
        file.write_all(contents.as_bytes())?;
        Ok(())
    }) {
        eprintln!("failed to write {}: {error}", path.display());
        std::process::exit(1);
    }
}

fn track_userspace_inputs(userspace_root: &Path) {
    for program in [
        "init",
        "driver-manager",
        "driver-host-input",
        "driver-host-nvme",
        "hxfs-service",
        "acpi-manager",
        "pci-manager",
        "shutdown-broker",
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
    // The userspace binaries embed workspace crates (huesos-hxfs,
    // huesos-abi, huesos-scudo); a change there must re-run
    // this build script so the recompiled binaries are re-embedded.
    // Without this, cargo considers the build script fresh (its
    // side-effect outputs are invisible to fingerprints) and the
    // ISO silently ships a stale service binary.
    for crate_dir in [
        "crates/huesos-hxfs",
        "crates/huesos-abi",
        "crates/huesos-scudo",
    ] {
        println!("cargo:rerun-if-changed={crate_dir}");
        println!("cargo:rerun-if-changed={crate_dir}/src");
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
    extra_args: &[&str],
) -> PathBuf {
    let program_dir = userspace_root.join(dir_name);
    let mut command = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&program_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--release"]);
    command.args(extra_args);
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

struct BootfsInputs<'a> {
    input_driver_host: &'a Path,
    nvme_driver_host: &'a Path,
    hxfs_service: &'a Path,
    acpi_manager: &'a Path,
    pci_manager: &'a Path,
    shutdown_broker: &'a Path,
    terminal: &'a Path,
    doom: &'a Path,
}

fn build_bootfs_image(manifest_dir: &Path, inputs: BootfsInputs<'_>) -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bootfs_path = out_dir.join("huesos.bootfs");
    let files = vec![
        BootFsFile {
            path: "/welcome.txt",
            data: b"Welcome to HuesOS BOOTFS\nTry: ls /, ls /manifests, cat /welcome.txt\n".to_vec(),
        },
        BootFsFile {
            // Boot UX configuration. Shipped with every value commented
            // out: the built-in defaults are the intended experience,
            // and the file exists so an operator can see what is
            // tunable without reading the source. Kernel command-line
            // `init.` keys override anything set here.
            path: "/etc/init.conf",
            data: br#"# HuesOS init boot configuration.
#
# Every setting below is shown at its built-in default. Uncomment to
# change. Kernel command-line keys of the form init.<key>=<value>
# override this file, which is the escape hatch when a machine will
# not boot far enough to rebuild an image.
#
# Serial (UART) logging is always full and is deliberately not
# configurable here: it is the only channel that survives a machine
# that dies before the terminal starts, and CI greps it.

# Show technical log text on screen instead of the splash.
# log.screen = off

# Draw the graphical splash. Turning it off implies log.screen=on,
# because a blank screen with no diagnostics helps nobody.
# splash = on
# splash.spinner = on

# Gradient and accent colours, #RRGGBB or RRGGBB.
# splash.top = #0A0E22
# splash.bottom = #04060E
# splash.accent = #5AC8FF

# Progress weights. Relative, not percentages: the bar divides its
# width in proportion to these. Storage dominates because NVMe
# enumeration plus the Hxfs mount takes longer than everything else
# combined, and an unweighted bar would stall mid-boot then jump.
# stage.selftest = 5
# stage.driver-manager = 10
# stage.storage = 30
# stage.shutdown-broker = 8
# stage.terminal = 12

# Labels shown under the bar.
# stage.storage.label = Probing storage controller

# Per-stage deadlines in seconds. On expiry the stage is marked
# failed, the indicator turns red, and the boot continues visibly
# rather than hanging in silence.
# timeout.default = 30
# timeout.storage = 60

# A stage that is not listed above can be declared here and it will
# appear on the bar with no code change:
# stage.network = 20
# stage.network.label = Bringing up network
# timeout.network = 45
"#
            .to_vec(),
        },
        BootFsFile {
            path: "/manifests/input-host.hdriver",
            // Legacy `irq=`/`ioport=` fields are retained for parser
            // back-compat during the manifest-driven-grants rollout;
            // the new `resource=` lines are the source of truth for
            // the kernel-minted Resource handles. `critical=false` is
            // the default; explicit here for review clarity.
            //
            // 8042 port map (see IBM PS/2 spec):
            //   0x60 — data port (scancodes + keyboard replies)
            //   0x64 — status + command port
            // The input driver reads scancodes off 0x60 and only
            // *observes* 0x64's status bits to know when a byte is
            // ready; it never issues an 8042 command itself. That's
            // why we grant IoPort 0x60 exclusive (data belongs to
            // the driver) but leave 0x64 to shutdown-broker (which
            // is the sole issuer of 8042 commands). Granting 0x64
            // to both hosts would collide as `Resource::Conflict`.
            data: b"name=input-host\nkind=driver-host\nprovides=keyboard\nirq=1\nioport=0x60:1\nresource=ioport:0x60:1:excl\nresource=irq:1:1:excl\ncritical=false\nelf=/drivers/input-host.elf\nheartbeat=true\n".to_vec(),
        },
        BootFsFile {
            path: "/manifests/shutdown-broker.hdriver",
            // shutdown-broker owns the 8042 command port (0x64) and a
            // PowerControl resource. `critical=true` so a broker crash
            // before it delivers the atomic halt triggers the kernel's
            // critical-exit fallback (docs/ARCHITECTURE_ROADMAP.md §3).
            // IoPort 0x60 is intentionally not granted: only the
            // command port is needed for quiesce.
            data: b"name=shutdown-broker\nkind=service\nresource=ioport:0x64:1:excl\nresource=pwr:0x0:0x0:excl\ncritical=true\nelf=/services/shutdown-broker.elf\n".to_vec(),
        },
        BootFsFile {
            path: "/manifests/nvme.hdriver",
            // Stage-A NVMe resources are dynamic (PCI BAR, IRQ metadata, and
            // reserved DMA pool) so init mints them from the kernel-produced
            // storage boot-info VMO rather than static resource= lines.
            data: b"name=driver-host-nvme\nkind=driver-host\nprovides=block:nvme\ncritical=false\nelf=/drivers/driver-host-nvme.elf\nheartbeat=false\n".to_vec(),
        },
        BootFsFile {
            path: "/storage/boot-drivers.manifest",
            data: build_boot_driver_manifest(),
        },
        BootFsFile {
            path: "/drivers/input-host.elf",
            data: fs::read(inputs.input_driver_host).expect("failed to read input DriverHost ELF"),
        },
        BootFsFile {
            path: "/drivers/driver-host-nvme.elf",
            data: read_build_input(inputs.nvme_driver_host, "NVMe DriverHost ELF"),
        },
        BootFsFile {
            path: "/services/hxfs.elf",
            data: read_build_input(inputs.hxfs_service, "Hxfs service ELF"),
        },
        BootFsFile {
            path: "/services/acpi-manager.elf",
            data: read_build_input(inputs.acpi_manager, "ACPI manager ELF"),
        },
        BootFsFile {
            path: "/services/pci-manager.elf",
            data: read_build_input(inputs.pci_manager, "PCI manager ELF"),
        },
        BootFsFile {
            path: "/services/shutdown-broker.elf",
            data: read_build_input(inputs.shutdown_broker, "shutdown-broker ELF"),
        },
        BootFsFile {
            path: "/bin/terminal.elf",
            data: fs::read(inputs.terminal).expect("failed to read terminal ELF"),
        },
        BootFsFile {
            path: "/bin/doom.elf",
            data: read_build_input(inputs.doom, "Doom ELF"),
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

fn build_boot_driver_manifest() -> Vec<u8> {
    const MAGIC: u32 = 0x4844_5242;
    const VERSION: u16 = 1;
    const PATH_BYTES: usize = 64;
    const ENTRY_BYTES: usize = PATH_BYTES * 2 + 4;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC.to_le_bytes());
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    let mut entry = [0u8; ENTRY_BYTES];
    write_padded_path(&mut entry[..PATH_BYTES], b"/drivers/driver-host-nvme.elf");
    write_padded_path(
        &mut entry[PATH_BYTES..PATH_BYTES * 2],
        b"/manifests/nvme.hdriver",
    );
    entry[PATH_BYTES * 2..PATH_BYTES * 2 + 4].copy_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&entry);
    bytes
}

fn write_padded_path(dst: &mut [u8], path: &[u8]) {
    let len = path.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&path[..len]);
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

/// Emit the sealed volume-key blob from `HUESOS_SEALED_KEY_HEX`.
///
/// Format: `<parent-handle-hex>:<public-hex>:<private-hex>`, as
/// produced by `tools/tpm-seal.sh`. Absent or malformed -> `None`,
/// and the kernel falls back to whatever `HUESOS_VOLUME_KEY_HEX`
/// provided (nothing, on a production build).
fn emit_sealed_key_blob(contents: &mut String) {
    println!("cargo:rerun-if-env-changed=HUESOS_SEALED_KEY_HEX");
    contents.push_str(
        "/// A volume key sealed to a TPM PCR policy.\n\
         pub struct SealedKeyBlob {\n\
         \x20   /// Persistent handle of the sealing parent.\n\
         \x20   pub parent: u32,\n\
         \x20   /// TPM2B_PUBLIC area.\n\
         \x20   pub public: &'static [u8],\n\
         \x20   /// TPM2B_PRIVATE area.\n\
         \x20   pub private: &'static [u8],\n\
         }\n",
    );
    let value = env::var("HUESOS_SEALED_KEY_HEX").unwrap_or_default();
    let trimmed = value.trim();
    let mut parts = trimmed.split(':');
    let parsed = (|| {
        let parent = u32::from_str_radix(parts.next()?.trim_start_matches("0x"), 16).ok()?;
        let public = decode_hex(parts.next()?)?;
        let private = decode_hex(parts.next()?)?;
        if parts.next().is_some() || public.is_empty() || private.is_empty() {
            return None;
        }
        Some((parent, public, private))
    })();
    match parsed {
        Some((parent, public, private)) => {
            contents.push_str(
                "pub const SEALED_VOLUME_KEY_BLOB: Option<SealedKeyBlob> = Some(SealedKeyBlob {\n",
            );
            contents.push_str(&format!("    parent: 0x{parent:08x},\n"));
            contents.push_str("    public: &[");
            for byte in &public {
                contents.push_str(&format!("0x{byte:02x},"));
            }
            contents.push_str("],\n    private: &[");
            for byte in &private {
                contents.push_str(&format!("0x{byte:02x},"));
            }
            contents.push_str("],\n});\n");
        }
        None => {
            contents.push_str("pub const SEALED_VOLUME_KEY_BLOB: Option<SealedKeyBlob> = None;\n");
        }
    }
}

/// Decode an even-length hex string.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut index = 0usize;
    while index < text.len() {
        bytes.push(u8::from_str_radix(&text[index..index + 2], 16).ok()?);
        index += 2;
    }
    Some(bytes)
}
