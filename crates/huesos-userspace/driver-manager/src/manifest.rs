//! Driver manifest definitions and parser.
//!
//! Manifests are the driver-manager's (proto-`component_manager`'s)
//! declarative description of what a driver process needs from the
//! kernel: which IRQs, which I/O port ranges, which MMIO regions,
//! and whether the driver is critical to system liveness.
//! See `docs/ARCHITECTURE_ROADMAP.md` §1 and §4.

// `resources` and `critical` on DriverHostManifest and
// DynamicDriverHostManifest are consumed by init (through the shared
// `libcanvas::manifest` parser); the compile-time static path retained
// here is a duplicate view kept so the existing manifest-describe /
// registry logic in driver-manager keeps building. Dead-code lint would
// otherwise fire because driver-manager does not itself act on these
// fields yet — the manifest-driven grants wiring runs in init.
#![allow(dead_code)]

/// DriverHost trust/isolation grouping.
#[derive(Clone, Copy)]
pub struct DriverHostManifest {
    /// Human-readable DriverHost name.
    pub name: &'static str,
    /// Services this host is expected to provide.
    pub services: &'static [ServiceManifest],
    /// IRQ capabilities requested by the host.
    pub irqs: &'static [u32],
    /// I/O port capabilities requested by the host.
    pub io_ports: &'static [IoPortRange],
    /// Fine-grained `Resource` grants requested by the host, used by
    /// the manifest-driven grants path. When present, the kernel mints
    /// one `Resource` per entry and installs its handle in the driver
    /// process's handle table at spawn time.
    pub resources: &'static [ResourceGrantManifest],
    /// If `true`, the driver process is marked critical: its abnormal
    /// exit will trigger a kernel-driven hard halt of the whole system.
    /// See `docs/ARCHITECTURE_ROADMAP.md` §3.
    pub critical: bool,
}

/// One service provided by a DriverHost.
#[derive(Clone, Copy)]
pub struct ServiceManifest {
    /// Stable service name used in the DriverManager registry.
    pub name: &'static str,
    /// Whether this service is required for the host to be considered ready.
    pub required: bool,
}

/// Requested I/O port range.
#[derive(Clone, Copy)]
pub struct IoPortRange {
    /// First I/O port.
    pub base: u16,
    /// Number of I/O ports in the range.
    pub len: u16,
}

/// Kind of a fine-grained `Resource` grant. Wire-compatible with
/// `huesos_abi::ResourceKindAbi` and duplicated here so the manifest
/// parser can stay usable in the driver-manager crate without pulling
/// the full ABI enum into every consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResourceGrantKind {
    /// x86 port I/O space.
    IoPort = 1,
    /// Physical memory-mapped I/O region.
    Mmio = 2,
    /// Physical interrupt vector / IRQ line.
    Irq = 3,
    /// Atomic-halt / power-off capability. See
    /// `docs/ARCHITECTURE_ROADMAP.md` §3.
    PowerControl = 4,
}

// Note: numeric conversion to `huesos_abi::ResourceKindAbi` is intentionally
// **not** exposed from this crate. `driver-manager` does not link
// `huesos-abi` directly; all cross-boundary manifest work is done via the
// shared parser in `libcanvas::manifest`, which owns the ABI mapping.

/// One resource grant requested by a driver in its manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceGrantManifest {
    /// Kind of resource.
    pub kind: ResourceGrantKind,
    /// Inclusive lower bound of the range.
    pub base: u64,
    /// Length of the range in `kind`-native units.
    pub len: u64,
    /// `true` for exclusive-allocation grants; `false` for shared.
    pub exclusive: bool,
}

/// Dynamic DriverHost manifest parsed from a file.
#[derive(Clone, Copy)]
pub struct DynamicDriverHostManifest {
    pub name: [u8; 32],
    pub name_len: usize,
    pub elf_path: [u8; 64],
    pub elf_path_len: usize,
    pub irqs: [u32; 8],
    pub irq_count: usize,
    pub io_ports: [IoPortRange; 8],
    pub io_port_count: usize,
    pub services: [ServiceManifestDynamic; 8],
    pub service_count: usize,
    pub resources: [ResourceGrantManifest; 8],
    pub resource_count: usize,
    pub critical: bool,
}

#[derive(Clone, Copy)]
pub struct ServiceManifestDynamic {
    pub name: [u8; 32],
    pub name_len: usize,
    pub required: bool,
}

impl DynamicDriverHostManifest {
    pub const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            elf_path: [0; 64],
            elf_path_len: 0,
            irqs: [0; 8],
            irq_count: 0,
            io_ports: [IoPortRange { base: 0, len: 0 }; 8],
            io_port_count: 0,
            services: [ServiceManifestDynamic {
                name: [0; 32],
                name_len: 0,
                required: false,
            }; 8],
            service_count: 0,
            resources: [ResourceGrantManifest {
                kind: ResourceGrantKind::IoPort,
                base: 0,
                len: 0,
                exclusive: false,
            }; 8],
            resource_count: 0,
            critical: false,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn elf_path_as_str(&self) -> &str {
        core::str::from_utf8(&self.elf_path[..self.elf_path_len]).unwrap_or("")
    }
}

/// Simple parser for .hdriver files (key=value).
pub fn parse_hdriver(data: &[u8]) -> Option<DynamicDriverHostManifest> {
    let mut manifest = DynamicDriverHostManifest::empty();
    let mut line_start = 0;

    while line_start < data.len() {
        let mut line_end = line_start;
        while line_end < data.len() && data[line_end] != b'\n' {
            line_end += 1;
        }

        let line = &data[line_start..line_end];
        if let Some(pos) = line.iter().position(|&b| b == b'=') {
            let key = &line[..pos];
            let val = &line[pos + 1..];

            if key == b"name" {
                let len = val.len().min(32);
                manifest.name[..len].copy_from_slice(&val[..len]);
                manifest.name_len = len;
            } else if key == b"elf" {
                let len = val.len().min(64);
                manifest.elf_path[..len].copy_from_slice(&val[..len]);
                manifest.elf_path_len = len;
            } else if key == b"irq" {
                if manifest.irq_count < 8 {
                    if let Ok(irq) = core::str::from_utf8(val).ok()?.parse::<u32>() {
                        manifest.irqs[manifest.irq_count] = irq;
                        manifest.irq_count += 1;
                    }
                }
            } else if key == b"ioport" {
                if manifest.io_port_count < 8 {
                    if let Some(colon_pos) = val.iter().position(|&b| b == b':') {
                        let base_str = core::str::from_utf8(&val[..colon_pos]).ok()?;
                        let len_str = core::str::from_utf8(&val[colon_pos + 1..]).ok()?;

                        let base = if let Some(hex) = base_str.strip_prefix("0x") {
                            u16::from_str_radix(hex, 16).ok()?
                        } else {
                            base_str.parse::<u16>().ok()?
                        };
                        let len = len_str.parse::<u16>().ok()?;

                        manifest.io_ports[manifest.io_port_count] = IoPortRange { base, len };
                        manifest.io_port_count += 1;
                    }
                }
            } else if key == b"provides" && manifest.service_count < 8 {
                let len = val.len().min(32);
                manifest.services[manifest.service_count].name[..len].copy_from_slice(&val[..len]);
                manifest.services[manifest.service_count].name_len = len;
                manifest.services[manifest.service_count].required = true;
                manifest.service_count += 1;
            } else if key == b"critical" {
                // Accept a small allow-list of truthy tokens; anything
                // else leaves the default `false` in place. Keeps the
                // parser strict without pulling in a full bool parser.
                manifest.critical = matches!(val, b"true" | b"1" | b"yes" | b"on");
            } else if key == b"resource" && manifest.resource_count < 8 {
                // Format: <kind>:<base>:<len>:<mode>
                //   kind := "ioport" | "mmio" | "irq"
                //   base := decimal or 0x-prefixed hex
                //   len  := decimal
                //   mode := "excl" | "shared"
                if let Some(grant) = parse_resource_grant(val) {
                    manifest.resources[manifest.resource_count] = grant;
                    manifest.resource_count += 1;
                }
            }
        }

        line_start = line_end + 1;
    }

    Some(manifest)
}

fn parse_resource_grant(val: &[u8]) -> Option<ResourceGrantManifest> {
    let mut parts = val.split(|&b| b == b':');
    let kind_bytes = parts.next()?;
    let base_bytes = parts.next()?;
    let len_bytes = parts.next()?;
    let mode_bytes = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let kind = match kind_bytes {
        b"ioport" => ResourceGrantKind::IoPort,
        b"mmio" => ResourceGrantKind::Mmio,
        b"irq" => ResourceGrantKind::Irq,
        b"pwr" | b"powercontrol" => ResourceGrantKind::PowerControl,
        _ => return None,
    };

    let base = parse_u64_lit(base_bytes)?;
    let len = parse_u64_lit(len_bytes)?;

    // For IoPort the ABI address space is 16-bit; reject early rather
    // than silently truncating in the kernel.
    if matches!(kind, ResourceGrantKind::IoPort) && (base > 0xffff || len > 0xffff) {
        return None;
    }

    let exclusive = match mode_bytes {
        b"excl" | b"exclusive" => true,
        b"shared" => false,
        _ => return None,
    };

    Some(ResourceGrantManifest {
        kind,
        base,
        len,
        exclusive,
    })
}

fn parse_u64_lit(bytes: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(bytes).ok()?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Keyboard service manifest.
pub const KEYBOARD_SERVICE: ServiceManifest = ServiceManifest {
    name: "keyboard",
    required: true,
};

/// Input DriverHost manifest.
pub const INPUT_HOST: DriverHostManifest = DriverHostManifest {
    name: "input-host",
    services: &[KEYBOARD_SERVICE],
    irqs: &[1],
    io_ports: &[
        IoPortRange { base: 0x60, len: 1 },
        IoPortRange { base: 0x64, len: 1 },
    ],
    resources: &[
        ResourceGrantManifest {
            kind: ResourceGrantKind::IoPort,
            base: 0x60,
            len: 1,
            exclusive: true,
        },
        ResourceGrantManifest {
            kind: ResourceGrantKind::IoPort,
            base: 0x64,
            len: 1,
            exclusive: true,
        },
        ResourceGrantManifest {
            kind: ResourceGrantKind::Irq,
            base: 1,
            len: 1,
            exclusive: true,
        },
    ],
    critical: false,
};

/// Static DriverHost manifest table.
pub const DRIVER_HOSTS: &[DriverHostManifest] = &[INPUT_HOST];
