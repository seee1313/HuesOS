//! Driver manifest definitions and parser.

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
            }
        }

        line_start = line_end + 1;
    }

    Some(manifest)
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
};

/// Static DriverHost manifest table.
pub const DRIVER_HOSTS: &[DriverHostManifest] = &[INPUT_HOST];
