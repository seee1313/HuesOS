//! Proto-manifest parser for `.hdriver` files.
//!
//! This is the userspace-side reader for the current
//! text/key=value driver manifest format. Both `init`
//! (proto-`component_manager`) and `driver-manager` consume it, so it
//! lives here in `libcanvas` as the single source of truth until the
//! HuesOS Manifest Compiler (HMC) and binary `.cm` format land — see
//! `docs/ARCHITECTURE_ROADMAP.md` §1 and §7.
//!
//! Only the fields the manifest-driven grants path needs are parsed
//! here: `name`, `elf`, `critical`, and `resource=<kind>:<base>:<len>:<mode>`.
//! `irq=`/`ioport=`/`provides=`/`heartbeat=` lines are recognised
//! syntactically but currently ignored by this reader; driver-manager
//! keeps its own richer parser for legacy fields it still consumes.

use huesos_abi::ResourceKindAbi;

/// Maximum number of resource grants a single manifest may declare.
pub const MAX_RESOURCE_GRANTS: usize = 8;
/// Maximum name length copied out of a manifest.
pub const MAX_NAME_LEN: usize = 32;
/// Maximum ELF path length copied out of a manifest.
pub const MAX_ELF_PATH_LEN: usize = 64;

/// One resource grant read from a manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceGrant {
    /// Kind of resource.
    pub kind: ResourceKindAbi,
    /// Inclusive lower bound of the range.
    pub base: u64,
    /// Length of the range in `kind`-native units.
    pub len: u64,
    /// `true` for exclusive-allocation grants; `false` for shared.
    pub exclusive: bool,
}

/// Subset of a driver manifest sufficient to mint kernel-side
/// `Resource` handles at spawn time.
#[derive(Clone, Copy)]
pub struct ManifestForGrants {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    elf_path: [u8; MAX_ELF_PATH_LEN],
    elf_path_len: usize,
    resources: [ResourceGrant; MAX_RESOURCE_GRANTS],
    resource_count: usize,
    /// Whether the driver process should be marked critical after spawn.
    pub critical: bool,
}

impl ManifestForGrants {
    /// Empty manifest with all fields defaulted.
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            elf_path: [0; MAX_ELF_PATH_LEN],
            elf_path_len: 0,
            resources: [ResourceGrant {
                kind: ResourceKindAbi::IoPort,
                base: 0,
                len: 0,
                exclusive: false,
            }; MAX_RESOURCE_GRANTS],
            resource_count: 0,
            critical: false,
        }
    }

    /// Driver name as a UTF-8 slice (or "unknown" on malformed input).
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    /// Driver ELF path within BOOTFS.
    pub fn elf_path(&self) -> &str {
        core::str::from_utf8(&self.elf_path[..self.elf_path_len]).unwrap_or("")
    }

    /// Resource grants declared by this manifest.
    pub fn grants(&self) -> &[ResourceGrant] {
        &self.resources[..self.resource_count]
    }
}

/// Parse the fields of a `.hdriver` file relevant to the
/// manifest-driven grants path. Unknown lines are ignored; malformed
/// `resource=` lines are silently dropped so a corrupt entry cannot
/// make the whole manifest unparsable, matching the legacy
/// `driver-manager::manifest::parse_hdriver` behaviour.
pub fn parse_for_grants(data: &[u8]) -> ManifestForGrants {
    let mut manifest = ManifestForGrants::empty();
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
            match key {
                b"name" => {
                    let len = val.len().min(MAX_NAME_LEN);
                    manifest.name[..len].copy_from_slice(&val[..len]);
                    manifest.name_len = len;
                }
                b"elf" => {
                    let len = val.len().min(MAX_ELF_PATH_LEN);
                    manifest.elf_path[..len].copy_from_slice(&val[..len]);
                    manifest.elf_path_len = len;
                }
                b"critical" => {
                    manifest.critical = matches!(val, b"true" | b"1" | b"yes" | b"on");
                }
                b"resource" => {
                    if manifest.resource_count < MAX_RESOURCE_GRANTS {
                        if let Some(grant) = parse_resource_grant(val) {
                            manifest.resources[manifest.resource_count] = grant;
                            manifest.resource_count += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        line_start = line_end + 1;
    }
    manifest
}

fn parse_resource_grant(val: &[u8]) -> Option<ResourceGrant> {
    let mut parts = val.split(|&b| b == b':');
    let kind = parts.next()?;
    let base = parts.next()?;
    let len = parts.next()?;
    let mode = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let kind = match kind {
        b"ioport" => ResourceKindAbi::IoPort,
        b"mmio" => ResourceKindAbi::Mmio,
        b"irq" => ResourceKindAbi::Irq,
        _ => return None,
    };
    let base = parse_u64_lit(base)?;
    let len = parse_u64_lit(len)?;
    if matches!(kind, ResourceKindAbi::IoPort) && (base > 0xffff || len > 0xffff) {
        return None;
    }
    let exclusive = match mode {
        b"excl" | b"exclusive" => true,
        b"shared" => false,
        _ => return None,
    };
    Some(ResourceGrant {
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
