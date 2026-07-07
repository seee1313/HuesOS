//! Static DriverManager manifest table for the MVP.

/// DriverHost trust/isolation grouping.
#[derive(Clone, Copy)]
pub struct DriverHostManifest {
    /// Human-readable DriverHost name.
    pub name: &'static str,
    /// Services this host is expected to provide.
    pub services: &'static [ServiceManifest],
    /// IRQ capabilities requested by the host.
    pub irqs: &'static [u32],
    /// I/O port capabilities requested by the host. Not implemented by the
    /// kernel yet; recorded here so the manifest shape is ready.
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
