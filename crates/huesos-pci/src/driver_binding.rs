//! Manifest-driven PCI driver binding, interrupt transaction planning, and
//! unified DMA pool descriptors (Stages H.3 + I.1 + I.2).
//!
//! Pure policy core: contains no kernel handle or raw MMIO/config pointer
//! dereference. Produces deterministic binding verdicts, B.4-typed capability
//! write plans, and explicit DMA isolation descriptors strictly after a
//! `DeviceLease` and `ResourcePlan` are active.

use alloc::{vec, vec::Vec};

use crate::capability::ConventionalCapability;
use crate::lease::{DeviceLeasePolicy, DmaIsolation, LeaseGeneration, RelocationClass};
use crate::resource_planner::{PlannedResource, ResourcePlan};
use crate::resource_validation::{ResourceClass, ResourceRegister};
use crate::topology::DiscoveredFunction;
use crate::write_policy::{
    ConfigReadWriteTransport, HeaderKind, WriteClass, WriteRequest, OFFSET_COMMAND,
};
use crate::{ClassCode, ConfigWidth, PciAddress, CONVENTIONAL_CONFIG_BYTES};

/// Conventional PCI capability ID for MSI.
pub const PCI_CAP_ID_MSI: u8 = 0x05;
/// Conventional PCI capability ID for MSI-X.
pub const PCI_CAP_ID_MSIX: u8 = 0x11;
/// Command register Interrupt Disable bit (bit 10).
pub const COMMAND_INTERRUPT_DISABLE: u32 = 1 << 10;

/// Full identity extracted for manifest matching (Stage H.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionIdentity<'a> {
    /// Core topology function descriptor.
    pub function: DiscoveredFunction,
    /// PCI Revision ID (`0x08`).
    pub revision_id: u8,
    /// PCI Subsystem Vendor ID (`0x2C`, 0 for Type 1 bridges).
    pub subsystem_vendor_id: u16,
    /// PCI Subsystem ID (`0x2E`, 0 for Type 1 bridges).
    pub subsystem_id: u16,
    /// Interrupt Pin (`0x3D`, `0=none, 1=INTA#..4=INTD#`).
    pub interrupt_pin: u8,
    /// Parsed conventional capabilities list.
    pub capabilities: &'a [ConventionalCapability],
}

/// Optional class/subclass/prog-if match rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassMatch {
    /// Base class code (`ClassCode::base`).
    pub base: u8,
    /// Sub-class code (`ClassCode::sub`).
    pub sub: u8,
    /// Optional programming interface (`None` matches any `prog_if`).
    pub prog_if: Option<u8>,
}

/// Structured manifest match predicate (Stage H.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceMatchRule {
    /// Optional Vendor ID filter.
    pub vendor_id: Option<u16>,
    /// Optional Device ID filter (valid only with `vendor_id`).
    pub device_id: Option<u16>,
    /// Optional Subsystem Vendor ID filter.
    pub subsystem_vendor_id: Option<u16>,
    /// Optional Subsystem ID filter.
    pub subsystem_id: Option<u16>,
    /// Optional Revision ID filter.
    pub revision_id: Option<u8>,
    /// Optional PCI class triple filter.
    pub class: Option<ClassMatch>,
    /// Optional required conventional capability ID (e.g. `PCI_CAP_ID_MSIX`).
    pub required_capability_id: Option<u8>,
}

impl DeviceMatchRule {
    /// Return `true` if the rule specifies at least one non-empty match axis
    /// (prevents dangerous wildcard catch-all rules).
    pub const fn is_valid(&self) -> bool {
        if self.device_id.is_some() && self.vendor_id.is_none() {
            return false;
        }
        if self.subsystem_id.is_some() && self.subsystem_vendor_id.is_none() {
            return false;
        }
        self.vendor_id.is_some()
            || self.subsystem_vendor_id.is_some()
            || self.class.is_some()
            || self.required_capability_id.is_some()
    }

    /// Check whether `ident` satisfies every predicate and return a
    /// deterministic specificity score (`None` when unmatched or invalid rule).
    pub fn match_score(&self, ident: &FunctionIdentity<'_>) -> Option<u32> {
        if !self.is_valid() {
            return None;
        }
        let mut score = 0u32;
        if let Some(vendor) = self.vendor_id {
            if ident.function.vendor_id != vendor {
                return None;
            }
            score += 100;
        }
        if let Some(device) = self.device_id {
            if ident.function.device_id != device {
                return None;
            }
            score += 100;
        }
        if let Some(sub_vendor) = self.subsystem_vendor_id {
            if ident.subsystem_vendor_id != sub_vendor {
                return None;
            }
            score += 50;
        }
        if let Some(sub_id) = self.subsystem_id {
            if ident.subsystem_id != sub_id {
                return None;
            }
            score += 50;
        }
        if let Some(rev) = self.revision_id {
            if ident.revision_id != rev {
                return None;
            }
            score += 10;
        }
        if let Some(class) = self.class {
            let fc: ClassCode = ident.function.class_code;
            if fc.class != class.base || fc.subclass != class.sub {
                return None;
            }
            score += 20;
            if let Some(pif) = class.prog_if {
                if fc.prog_if != pif {
                    return None;
                }
                score += 10;
            }
        }
        if let Some(cap_id) = self.required_capability_id {
            if !ident.capabilities.iter().any(|c| c.id == cap_id) {
                return None;
            }
            score += 5;
        }
        Some(score)
    }
}

/// Driver interrupt preference policy (Stage I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqPreference {
    /// Prefer MSI-X, fall back to MSI, then `_PRT` INTx, then optional polling.
    MsixThenMsiThenIntx,
    /// Prefer MSI, fall back to `_PRT` INTx, then optional polling.
    MsiThenIntx,
    /// Use `_PRT` INTx only, then optional polling.
    IntxOnly,
}

/// Driver manifest specification used by PCI Manager binding (Stage H.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverManifestSpec {
    /// Logical driver name (e.g. `"nvme-host"`, `"ahci-host"`).
    pub driver_name: &'static str,
    /// Match rule.
    pub match_rule: DeviceMatchRule,
    /// Relocation contract declared by the manifest.
    pub relocation: RelocationClass,
    /// Preferred interrupt order.
    pub irq_preference: IrqPreference,
    /// Maximum interrupt vectors requested (e.g. 1..=16).
    pub max_vectors: u16,
    /// Whether polling fallback is allowed when no interrupt path is usable.
    pub allow_polling_fallback: bool,
}

/// Binding decision for one discovered PCI function (Stage H.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingDecision {
    /// Function remains visible and safely unbound (no matching manifest).
    Unbound,
    /// Function matched `manifest_index` with `score`.
    Matched {
        /// Index into the supplied manifest slice.
        manifest_index: usize,
        /// Deterministic specificity score.
        score: u32,
    },
}

/// Match a function against registered driver manifests.
///
/// Requires an active, mint-capable `DeviceLeasePolicy` at `expected_generation`
/// so no driver receives authority before a lease and resource plan exist.
pub fn match_driver(
    ident: &FunctionIdentity<'_>,
    lease: &DeviceLeasePolicy,
    expected_generation: LeaseGeneration,
    manifests: &[DriverManifestSpec],
) -> Result<BindingDecision, BindingError> {
    if !lease.can_mint_resources(expected_generation) {
        return Err(BindingError::LeaseNotMintable);
    }
    if lease.address() != ident.function.address {
        return Err(BindingError::AddressMismatch);
    }
    let mut best: Option<(usize, u32)> = None;
    for (index, manifest) in manifests.iter().enumerate() {
        let Some(score) = manifest.match_rule.match_score(ident) else {
            continue;
        };
        match best {
            None => best = Some((index, score)),
            Some((_, best_score)) if score > best_score => best = Some((index, score)),
            Some((best_idx, best_score)) if score == best_score && index < best_idx => {
                best = Some((index, score));
            }
            _ => {}
        }
    }
    Ok(match best {
        Some((manifest_index, score)) => BindingDecision::Matched {
            manifest_index,
            score,
        },
        None => BindingDecision::Unbound,
    })
}

/// Reason driver binding was refused before minting resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// Lease is missing, revoked, or not in `Configured | DriverStarting | Online`.
    LeaseNotMintable,
    /// Lease address does not match the function being bound.
    AddressMismatch,
}

/// Decoded MSI-X capability parameters from PCI config space (Stage I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsixCapabilityInfo {
    /// Byte offset of the MSI-X capability in conventional config space.
    pub cap_offset: u8,
    /// Table size (`N`, decoded from `(msg_ctl & 0x7FF) + 1`).
    pub table_entries: u16,
    /// BAR index (`0..=5`) holding the MSI-X table.
    pub table_bir: u8,
    /// Byte offset inside `table_bir`.
    pub table_offset: u32,
    /// BAR index (`0..=5`) holding the MSI-X PBA.
    pub pba_bir: u8,
    /// Byte offset inside `pba_bir`.
    pub pba_offset: u32,
}

/// Decoded MSI capability parameters from PCI config space (Stage I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsiCapabilityInfo {
    /// Byte offset of the MSI capability in conventional config space.
    pub cap_offset: u8,
    /// True if 64-bit message address is supported.
    pub is_64bit: bool,
    /// True if per-vector masking is supported.
    pub per_vector_masking: bool,
    /// Maximum supported vectors (`1, 2, 4, 8, 16, or 32`).
    pub max_vectors: u16,
}

/// Decode an MSI capability (`PCI_CAP_ID_MSI`) from read-only config space.
pub fn decode_msi_capability<T: ConfigReadWriteTransport>(
    transport: &mut T,
    address: PciAddress,
    cap: ConventionalCapability,
) -> Option<MsiCapabilityInfo> {
    if cap.id != PCI_CAP_ID_MSI || u16::from(cap.offset) + 4 > CONVENTIONAL_CONFIG_BYTES {
        return None;
    }
    let dw0 = transport.read_width(address, u16::from(cap.offset), ConfigWidth::Dword)?;
    let msg_ctl = (dw0 >> 16) as u16;
    let mmc = ((msg_ctl >> 1) & 0x7).min(5);
    let max_vectors = 1u16 << mmc;
    Some(MsiCapabilityInfo {
        cap_offset: cap.offset,
        is_64bit: (msg_ctl & (1 << 7)) != 0,
        per_vector_masking: (msg_ctl & (1 << 8)) != 0,
        max_vectors,
    })
}

/// Decode an MSI-X capability (`PCI_CAP_ID_MSIX`) from read-only config space.
pub fn decode_msix_capability<T: ConfigReadWriteTransport>(
    transport: &mut T,
    address: PciAddress,
    cap: ConventionalCapability,
) -> Option<MsixCapabilityInfo> {
    if cap.id != PCI_CAP_ID_MSIX || u16::from(cap.offset) + 12 > CONVENTIONAL_CONFIG_BYTES {
        return None;
    }
    let dw0 = transport.read_width(address, u16::from(cap.offset), ConfigWidth::Dword)?;
    let table_dw = transport.read_width(address, u16::from(cap.offset) + 4, ConfigWidth::Dword)?;
    let pba_dw = transport.read_width(address, u16::from(cap.offset) + 8, ConfigWidth::Dword)?;
    let msg_ctl = (dw0 >> 16) as u16;
    let table_entries = (msg_ctl & 0x07FF) + 1;
    Some(MsixCapabilityInfo {
        cap_offset: cap.offset,
        table_entries,
        table_bir: (table_dw & 0x7) as u8,
        table_offset: table_dw & !0x7,
        pba_bir: (pba_dw & 0x7) as u8,
        pba_offset: pba_dw & !0x7,
    })
}

/// Resolved ACPI `_PRT` INTx route entry (Stage C.3 + I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrtRouteInfo {
    /// Global System Interrupt number.
    pub gsi: u32,
    /// `0 = edge, 1 = level`.
    pub triggering: u8,
    /// `0 = active-high, 1 = active-low`.
    pub polarity: u8,
}

/// Selected interrupt mode for a driver binding (Stage I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptMode {
    /// MSI-X vectors mapped via the device's MSI-X table BAR.
    Msix {
        /// Number of allocated vectors.
        vector_count: u16,
        /// Starting CPU/IOAPIC vector number.
        base_vector: u32,
        /// BAR index holding the MSI-X table.
        table_bir: u8,
        /// Byte offset of the MSI-X table inside `table_bir`.
        table_offset: u32,
    },
    /// Legacy/64-bit MSI programmed in PCI capability space.
    Msi {
        /// Number of allocated vectors.
        vector_count: u16,
        /// Starting vector number.
        base_vector: u32,
        /// Capability offset.
        cap_offset: u8,
    },
    /// Level/edge-triggered INTx GSI routed through ACPI `_PRT`.
    Intx {
        /// Resolved GSI.
        gsi: u32,
        /// `0 = edge, 1 = level`.
        triggering: u8,
        /// `0 = active-high, 1 = active-low`.
        polarity: u8,
    },
    /// Polling mode (explicitly allowed by manifest when no IRQ is usable).
    Polling,
}

/// Planned interrupt configuration and B.4 writes (Stage I.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterruptPlan {
    /// Target function address.
    pub address: PciAddress,
    /// Selected delivery mode.
    pub mode: InterruptMode,
    /// Destination APIC ID (`<= 0xFF` without interrupt remapping).
    pub destination_apic_id: u32,
    /// B.4-audited config writes required to arm the selected mode.
    pub writes: Vec<WriteRequest>,
}

/// Platform interrupt allocation capabilities passed into [`plan_interrupt_transaction`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptAllocatorContext {
    /// Target destination APIC ID.
    pub destination_apic_id: u32,
    /// Whether hardware interrupt remapping (VT-d IR / AMD-Vi) is active.
    pub interrupt_remapping_active: bool,
    /// Number of contiguous CPU vectors still available for MSI/MSI-X.
    pub available_vectors: u16,
    /// Base vector number to assign if `available_vectors > 0`.
    pub next_base_vector: u32,
}

/// Failure planning an interrupt transaction (Stage I.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptPlanError {
    /// Lease is not active/mintable.
    LeaseNotMintable,
    /// MSI-X destination APIC ID exceeds 8-bit physical mode (`> 0xFF`) without remapping.
    X2ApicDestinationRequiresRemapping,
    /// MSI-X table/PBA BIR or byte range is invalid against the committed BARs.
    InvalidMsixTableBounds,
    /// No interrupt mode succeeded and polling fallback was disallowed.
    NoInterruptPathAvailable,
}

/// Plan an interrupt transaction for one leased device without letting any
/// DriverHost write MSI/MSI-X registers itself (Stage I.1).
#[allow(clippy::too_many_arguments)]
pub fn plan_interrupt_transaction(
    address: PciAddress,
    lease: &DeviceLeasePolicy,
    expected_generation: LeaseGeneration,
    manifest: &DriverManifestSpec,
    plan: &ResourcePlan,
    msix: Option<MsixCapabilityInfo>,
    msi: Option<MsiCapabilityInfo>,
    intx: Option<PrtRouteInfo>,
    ctx: InterruptAllocatorContext,
    current_command: u16,
) -> Result<InterruptPlan, InterruptPlanError> {
    if !lease.can_mint_resources(expected_generation) {
        return Err(InterruptPlanError::LeaseNotMintable);
    }

    let wants_msi_or_msix = matches!(
        manifest.irq_preference,
        IrqPreference::MsixThenMsiThenIntx | IrqPreference::MsiThenIntx
    );
    if wants_msi_or_msix && !ctx.interrupt_remapping_active && ctx.destination_apic_id > 0xFF {
        return Err(InterruptPlanError::X2ApicDestinationRequiresRemapping);
    }

    // 1. Validate MSI-X if present and preferred.
    if manifest.irq_preference == IrqPreference::MsixThenMsiThenIntx {
        if let Some(msix_info) = msix {
            validate_msix_bounds(address, plan, msix_info)?;
            if ctx.available_vectors > 0 && manifest.max_vectors > 0 {
                let count = msix_info
                    .table_entries
                    .min(manifest.max_vectors)
                    .min(ctx.available_vectors);
                if count > 0 {
                    let writes = build_msix_enable_writes(address, msix_info, current_command);
                    return Ok(InterruptPlan {
                        address,
                        mode: InterruptMode::Msix {
                            vector_count: count,
                            base_vector: ctx.next_base_vector,
                            table_bir: msix_info.table_bir,
                            table_offset: msix_info.table_offset,
                        },
                        destination_apic_id: ctx.destination_apic_id,
                        writes,
                    });
                }
            }
        }
    }

    // 2. Fall back to MSI if present, preferred, and vectors remain.
    if matches!(
        manifest.irq_preference,
        IrqPreference::MsixThenMsiThenIntx | IrqPreference::MsiThenIntx
    ) {
        if let Some(msi_info) = msi {
            if ctx.available_vectors > 0 && manifest.max_vectors > 0 && msi_info.max_vectors > 0 {
                let requested = msi_info
                    .max_vectors
                    .min(manifest.max_vectors)
                    .min(ctx.available_vectors);
                let count = requested.next_power_of_two().min(msi_info.max_vectors);
                let count = if count > ctx.available_vectors {
                    1
                } else {
                    count
                };
                if count > 0 && count <= ctx.available_vectors {
                    let writes = build_msi_enable_writes(
                        address,
                        msi_info,
                        ctx.destination_apic_id,
                        ctx.next_base_vector,
                        count,
                        current_command,
                    );
                    return Ok(InterruptPlan {
                        address,
                        mode: InterruptMode::Msi {
                            vector_count: count,
                            base_vector: ctx.next_base_vector,
                            cap_offset: msi_info.cap_offset,
                        },
                        destination_apic_id: ctx.destination_apic_id,
                        writes,
                    });
                }
            }
        }
    }

    // 3. Fall back to `_PRT` INTx GSI.
    if let Some(route) = intx {
        let mut writes = Vec::new();
        let enabled_cmd = u32::from(current_command) & !COMMAND_INTERRUPT_DISABLE;
        writes.push(WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: enabled_cmd,
            write_mask: COMMAND_INTERRUPT_DISABLE,
            expected_readback_mask: COMMAND_INTERRUPT_DISABLE,
            allowlist_entry: None,
        });
        return Ok(InterruptPlan {
            address,
            mode: InterruptMode::Intx {
                gsi: route.gsi,
                triggering: route.triggering,
                polarity: route.polarity,
            },
            destination_apic_id: ctx.destination_apic_id,
            writes,
        });
    }

    // 4. Optional polling fallback.
    if manifest.allow_polling_fallback {
        let mut writes = Vec::new();
        let masked_cmd = u32::from(current_command) | COMMAND_INTERRUPT_DISABLE;
        writes.push(WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: masked_cmd,
            write_mask: COMMAND_INTERRUPT_DISABLE,
            expected_readback_mask: COMMAND_INTERRUPT_DISABLE,
            allowlist_entry: None,
        });
        return Ok(InterruptPlan {
            address,
            mode: InterruptMode::Polling,
            destination_apic_id: ctx.destination_apic_id,
            writes,
        });
    }

    Err(InterruptPlanError::NoInterruptPathAvailable)
}

fn validate_msix_bounds(
    address: PciAddress,
    plan: &ResourcePlan,
    msix: MsixCapabilityInfo,
) -> Result<(), InterruptPlanError> {
    if msix.table_entries == 0 || msix.table_bir > 5 || msix.pba_bir > 5 {
        return Err(InterruptPlanError::InvalidMsixTableBounds);
    }
    let table_bytes = u64::from(msix.table_entries) * 16;
    let pba_qwords = u64::from(msix.table_entries).div_ceil(64);
    let pba_bytes = pba_qwords * 8;

    let table_bar = find_mmio_bar(plan, address, msix.table_bir)
        .ok_or(InterruptPlanError::InvalidMsixTableBounds)?;
    let table_end = u64::from(msix.table_offset)
        .checked_add(table_bytes)
        .ok_or(InterruptPlanError::InvalidMsixTableBounds)?;
    if table_end > table_bar.len {
        return Err(InterruptPlanError::InvalidMsixTableBounds);
    }

    let pba_bar = find_mmio_bar(plan, address, msix.pba_bir)
        .ok_or(InterruptPlanError::InvalidMsixTableBounds)?;
    let pba_end = u64::from(msix.pba_offset)
        .checked_add(pba_bytes)
        .ok_or(InterruptPlanError::InvalidMsixTableBounds)?;
    if pba_end > pba_bar.len {
        return Err(InterruptPlanError::InvalidMsixTableBounds);
    }
    Ok(())
}

fn find_mmio_bar(plan: &ResourcePlan, address: PciAddress, bir: u8) -> Option<PlannedResource> {
    plan.resources().iter().copied().find(|res| {
        res.owner == address
            && res.register == ResourceRegister::Bar(bir)
            && matches!(
                res.class,
                ResourceClass::Mmio32 | ResourceClass::Mmio64 | ResourceClass::PrefetchableMemory
            )
    })
}

fn build_msix_enable_writes(
    address: PciAddress,
    msix: MsixCapabilityInfo,
    current_command: u16,
) -> Vec<WriteRequest> {
    vec![
        // Disable legacy INTx while enabling MSI-X.
        WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: u32::from(current_command) | COMMAND_INTERRUPT_DISABLE,
            write_mask: COMMAND_INTERRUPT_DISABLE,
            expected_readback_mask: COMMAND_INTERRUPT_DISABLE,
            allowlist_entry: None,
        },
        // MSI-X Message Control is at cap_offset + 2 (Enable bit 15 = 0x8000).
        WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CapabilityControl,
            offset: u16::from(msix.cap_offset) + 2,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: 0x8000,
            write_mask: 0xC000,
            expected_readback_mask: 0x8000,
            allowlist_entry: None,
        },
    ]
}

fn build_msi_enable_writes(
    address: PciAddress,
    msi: MsiCapabilityInfo,
    destination_apic_id: u32,
    base_vector: u32,
    vector_count: u16,
    current_command: u16,
) -> Vec<WriteRequest> {
    let mut writes = Vec::new();
    let cap = u16::from(msi.cap_offset);
    let mme_bits = vector_count.trailing_zeros().min(5) << 4;
    let msi_addr_lo = 0xFEE0_0000 | ((destination_apic_id & 0xFF) << 12);
    let msi_data = base_vector & 0xFF;

    // Disable legacy INTx.
    writes.push(WriteRequest {
        address,
        header_kind: HeaderKind::Type0Endpoint,
        class: WriteClass::CommandControl,
        offset: OFFSET_COMMAND,
        width: ConfigWidth::Word,
        max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
        value: u32::from(current_command) | COMMAND_INTERRUPT_DISABLE,
        write_mask: COMMAND_INTERRUPT_DISABLE,
        expected_readback_mask: COMMAND_INTERRUPT_DISABLE,
        allowlist_entry: None,
    });
    // Program Message Address Low (cap + 4).
    writes.push(WriteRequest {
        address,
        header_kind: HeaderKind::Type0Endpoint,
        class: WriteClass::CapabilityControl,
        offset: cap + 4,
        width: ConfigWidth::Dword,
        max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
        value: msi_addr_lo,
        write_mask: 0xFFFF_FFFC,
        expected_readback_mask: 0xFFFF_FFFC,
        allowlist_entry: None,
    });
    if msi.is_64bit {
        writes.push(WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CapabilityControl,
            offset: cap + 8,
            width: ConfigWidth::Dword,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: 0,
            write_mask: 0xFFFF_FFFF,
            expected_readback_mask: 0xFFFF_FFFF,
            allowlist_entry: None,
        });
        writes.push(WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CapabilityControl,
            offset: cap + 12,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: msi_data,
            write_mask: 0xFFFF,
            expected_readback_mask: 0x00FF,
            allowlist_entry: None,
        });
    } else {
        writes.push(WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CapabilityControl,
            offset: cap + 8,
            width: ConfigWidth::Word,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: msi_data,
            write_mask: 0xFFFF,
            expected_readback_mask: 0x00FF,
            allowlist_entry: None,
        });
    }
    // Enable MSI in Message Control (cap + 2, bit 0 = Enable, bits [6:4] = MME).
    writes.push(WriteRequest {
        address,
        header_kind: HeaderKind::Type0Endpoint,
        class: WriteClass::CapabilityControl,
        offset: cap + 2,
        width: ConfigWidth::Word,
        max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
        value: 0x0001 | mme_bits,
        write_mask: 0x0071,
        expected_readback_mask: 0x0001,
        allowlist_entry: None,
    });
    writes
}

/// Unified DMA pool descriptor explicitly separating device-visible DMA
/// address space from CPU physical addresses (Stage I.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaPoolGrant {
    /// Owning function's `DeviceLease` identity.
    pub device_id: u64,
    /// Lease generation authorizing this pool.
    pub lease_generation: u64,
    /// Explicit isolation mode (Trusted vs per-device IOMMU domain).
    pub isolation: DmaIsolation,
    /// Device-visible DMA base address (equals IOVA under IOMMU, or physical under Trusted).
    pub device_addr_base: u64,
    /// CPU physical pool base address.
    pub cpu_phys_base: u64,
    /// Pool length in bytes.
    pub len: u64,
}

impl DmaPoolGrant {
    /// Construct a validated DMA grant bound to an active `DeviceLeasePolicy`.
    pub const fn try_new(
        lease: &DeviceLeasePolicy,
        expected_generation: LeaseGeneration,
        device_addr_base: u64,
        cpu_phys_base: u64,
        len: u64,
    ) -> Result<Self, BindingError> {
        if !lease.can_mint_resources(expected_generation) {
            return Err(BindingError::LeaseNotMintable);
        }
        if len == 0
            || device_addr_base.checked_add(len).is_none()
            || cpu_phys_base.checked_add(len).is_none()
        {
            return Err(BindingError::AddressMismatch);
        }
        Ok(Self {
            device_id: lease.device_id().get(),
            lease_generation: expected_generation.get(),
            isolation: lease.dma_isolation(),
            device_addr_base,
            cpu_phys_base,
            len,
        })
    }

    /// Stable isolation mode string for structured boot logs (Stage I.2).
    pub const fn isolation_label(&self) -> &'static str {
        match self.isolation {
            DmaIsolation::Trusted => "Trusted",
            DmaIsolation::IommuDomain(_) => "IommuDomain",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{DeviceId, LeaseEvent};
    use crate::resource_planner::plan_firmware_preserving;
    use crate::resource_validation::{validate_firmware_resources, FirmwareResource, RootAperture};
    use crate::topology::{build_snapshot, FunctionKind, RootBus, TopologySnapshot};

    fn pci_addr(dev: u8, func: u8) -> PciAddress {
        PciAddress::try_new(0, 0, dev, func).unwrap_or(PciAddress::ZERO)
    }

    fn configured_lease(addr: PciAddress, isolation: DmaIsolation) -> DeviceLeasePolicy {
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());
        let mut lease = DeviceLeasePolicy::try_new(
            DeviceId::try_new(1).unwrap_or_else(|_| unreachable!()),
            gen1,
            addr,
            RelocationClass::Fixed,
            isolation,
        )
        .unwrap_or_else(|_| unreachable!());
        let _ = lease.apply(gen1, LeaseEvent::Configure);
        lease
    }

    fn nvme_manifest() -> DriverManifestSpec {
        DriverManifestSpec {
            driver_name: "nvme-host",
            match_rule: DeviceMatchRule {
                vendor_id: None,
                device_id: None,
                subsystem_vendor_id: None,
                subsystem_id: None,
                revision_id: None,
                class: Some(ClassMatch {
                    base: 0x01,
                    sub: 0x08,
                    prog_if: Some(0x02),
                }),
                required_capability_id: None,
            },
            relocation: RelocationClass::Fixed,
            irq_preference: IrqPreference::MsixThenMsiThenIntx,
            max_vectors: 4,
            allow_polling_fallback: true,
        }
    }

    fn ahci_manifest() -> DriverManifestSpec {
        DriverManifestSpec {
            driver_name: "ahci-host",
            match_rule: DeviceMatchRule {
                vendor_id: None,
                device_id: None,
                subsystem_vendor_id: None,
                subsystem_id: None,
                revision_id: None,
                class: Some(ClassMatch {
                    base: 0x01,
                    sub: 0x06,
                    prog_if: Some(0x01),
                }),
                required_capability_id: None,
            },
            relocation: RelocationClass::Fixed,
            irq_preference: IrqPreference::MsiThenIntx,
            max_vectors: 1,
            allow_polling_fallback: false,
        }
    }

    fn make_plan(addr: PciAddress, bar0_len: u64) -> (TopologySnapshot, ResourcePlan) {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        }];
        let fns = [DiscoveredFunction {
            address: addr,
            vendor_id: 0x8086,
            device_id: 0x2922,
            class_code: ClassCode {
                class: 0x01,
                subclass: 0x08,
                prog_if: 0x02,
            },
            kind: FunctionKind::Endpoint,
        }];
        let snapshot = build_snapshot(1, &roots, &fns).unwrap_or_else(|_| unreachable!());
        let apertures = [RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x1000_0000,
        }];
        let fw = [FirmwareResource {
            owner: addr,
            register: ResourceRegister::Bar(0),
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            len: bar0_len,
            assigned: true,
            fixed: false,
        }];
        let report = validate_firmware_resources(&snapshot, &apertures, &fw)
            .unwrap_or_else(|_| unreachable!());
        let plan = plan_firmware_preserving(&snapshot, &apertures, &report)
            .unwrap_or_else(|_| unreachable!());
        (snapshot, plan)
    }

    #[test]
    fn h3_unknown_devices_stay_unbound_and_specificity_wins() {
        let addr = pci_addr(4, 0);
        let lease = configured_lease(addr, DmaIsolation::Trusted);
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());

        let unknown = FunctionIdentity {
            function: DiscoveredFunction {
                address: addr,
                vendor_id: 0x1234,
                device_id: 0x9999,
                class_code: ClassCode {
                    class: 0x0C,
                    subclass: 0x05,
                    prog_if: 0x00,
                },
                kind: FunctionKind::Endpoint,
            },
            revision_id: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_pin: 1,
            capabilities: &[],
        };
        let manifests = [nvme_manifest(), ahci_manifest()];
        assert_eq!(
            match_driver(&unknown, &lease, gen1, &manifests),
            Ok(BindingDecision::Unbound)
        );

        let specific_nvme = DriverManifestSpec {
            driver_name: "nvme-specific",
            match_rule: DeviceMatchRule {
                vendor_id: Some(0x1b36),
                device_id: Some(0x0010),
                ..nvme_manifest().match_rule
            },
            ..nvme_manifest()
        };
        let nvme_fn = FunctionIdentity {
            function: DiscoveredFunction {
                address: addr,
                vendor_id: 0x1b36,
                device_id: 0x0010,
                class_code: ClassCode {
                    class: 0x01,
                    subclass: 0x08,
                    prog_if: 0x02,
                },
                kind: FunctionKind::Endpoint,
            },
            revision_id: 2,
            subsystem_vendor_id: 0x1af4,
            subsystem_id: 0x1100,
            interrupt_pin: 1,
            capabilities: &[],
        };
        let manifests_with_specific = [nvme_manifest(), specific_nvme];
        assert_eq!(
            match_driver(&nvme_fn, &lease, gen1, &manifests_with_specific),
            Ok(BindingDecision::Matched {
                manifest_index: 1,
                score: 230
            })
        );
    }

    #[test]
    fn h3_refuses_binding_before_lease_configured_or_after_revoke() {
        let addr = pci_addr(4, 0);
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());
        let mut lease = DeviceLeasePolicy::try_new(
            DeviceId::try_new(1).unwrap_or_else(|_| unreachable!()),
            gen1,
            addr,
            RelocationClass::Fixed,
            DmaIsolation::Trusted,
        )
        .unwrap_or_else(|_| unreachable!());
        let ident = FunctionIdentity {
            function: DiscoveredFunction {
                address: addr,
                vendor_id: 0x1b36,
                device_id: 0x0010,
                class_code: ClassCode {
                    class: 0x01,
                    subclass: 0x08,
                    prog_if: 0x02,
                },
                kind: FunctionKind::Endpoint,
            },
            revision_id: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_pin: 1,
            capabilities: &[],
        };
        assert_eq!(
            match_driver(&ident, &lease, gen1, &[nvme_manifest()]),
            Err(BindingError::LeaseNotMintable)
        );
        let _ = lease.apply(gen1, LeaseEvent::Configure);
        assert!(match_driver(&ident, &lease, gen1, &[nvme_manifest()]).is_ok());
        let _ = lease.apply(gen1, LeaseEvent::SurpriseRemove);
        assert_eq!(
            match_driver(&ident, &lease, gen1, &[nvme_manifest()]),
            Err(BindingError::LeaseNotMintable)
        );
    }

    #[test]
    fn i1_msix_bounds_x2apic_guard_and_fallbacks() {
        let addr = pci_addr(4, 0);
        let lease = configured_lease(addr, DmaIsolation::Trusted);
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());
        let (_snap, plan) = make_plan(addr, 0x4000);
        let manifest = nvme_manifest();

        // Bad MSI-X table BIR or out-of-bounds table offset rejected.
        let bad_msix = MsixCapabilityInfo {
            cap_offset: 0x60,
            table_entries: 4,
            table_bir: 1, // BAR1 not in plan!
            table_offset: 0,
            pba_bir: 0,
            pba_offset: 0x2000,
        };
        let good_ctx = InterruptAllocatorContext {
            destination_apic_id: 0,
            interrupt_remapping_active: false,
            available_vectors: 8,
            next_base_vector: 0xD0,
        };
        assert_eq!(
            plan_interrupt_transaction(
                addr,
                &lease,
                gen1,
                &manifest,
                &plan,
                Some(bad_msix),
                None,
                None,
                good_ctx,
                0x0006,
            ),
            Err(InterruptPlanError::InvalidMsixTableBounds)
        );

        // x2APIC destination > 255 without remapping refused.
        let x2apic_ctx = InterruptAllocatorContext {
            destination_apic_id: 0x102,
            interrupt_remapping_active: false,
            available_vectors: 8,
            next_base_vector: 0xD0,
        };
        assert_eq!(
            plan_interrupt_transaction(
                addr, &lease, gen1, &manifest, &plan, None, None, None, x2apic_ctx, 0x0006,
            ),
            Err(InterruptPlanError::X2ApicDestinationRequiresRemapping)
        );

        // Valid MSI-X selects MSI-X with CapabilityControl + CommandControl writes.
        let good_msix = MsixCapabilityInfo {
            cap_offset: 0x60,
            table_entries: 8,
            table_bir: 0,
            table_offset: 0x1000,
            pba_bir: 0,
            pba_offset: 0x2000,
        };
        let msix_plan = plan_interrupt_transaction(
            addr,
            &lease,
            gen1,
            &manifest,
            &plan,
            Some(good_msix),
            None,
            None,
            good_ctx,
            0x0006,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            msix_plan.mode,
            InterruptMode::Msix {
                vector_count: 4,
                base_vector: 0xD0,
                table_bir: 0,
                table_offset: 0x1000,
            }
        );

        // Vector exhaustion falls back cleanly to _PRT INTx GSI.
        let exhausted_ctx = InterruptAllocatorContext {
            destination_apic_id: 0,
            interrupt_remapping_active: false,
            available_vectors: 0,
            next_base_vector: 0,
        };
        let msi = MsiCapabilityInfo {
            cap_offset: 0x50,
            is_64bit: true,
            per_vector_masking: false,
            max_vectors: 4,
        };
        let prt = PrtRouteInfo {
            gsi: 19,
            triggering: 1,
            polarity: 1,
        };
        let intx_plan = plan_interrupt_transaction(
            addr,
            &lease,
            gen1,
            &manifest,
            &plan,
            Some(good_msix),
            Some(msi),
            Some(prt),
            exhausted_ctx,
            0x0406,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            intx_plan.mode,
            InterruptMode::Intx {
                gsi: 19,
                triggering: 1,
                polarity: 1,
            }
        );
    }

    #[test]
    fn i1_msi_fallback_polling_and_revoke_while_pending() {
        use crate::write_policy::validate_write_request;

        let addr = pci_addr(4, 0);
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());
        let mut lease = configured_lease(addr, DmaIsolation::Trusted);
        let (_snap, plan) = make_plan(addr, 0x4000);
        let msi = MsiCapabilityInfo {
            cap_offset: 0x50,
            is_64bit: true,
            per_vector_masking: false,
            max_vectors: 4,
        };
        let good_ctx = InterruptAllocatorContext {
            destination_apic_id: 1,
            interrupt_remapping_active: false,
            available_vectors: 2,
            next_base_vector: 0xC0,
        };
        let msi_plan = plan_interrupt_transaction(
            addr,
            &lease,
            gen1,
            &ahci_manifest(),
            &plan,
            None,
            Some(msi),
            None,
            good_ctx,
            0x0006,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            msi_plan.mode,
            InterruptMode::Msi {
                vector_count: 1,
                base_vector: 0xC0,
                cap_offset: 0x50,
            }
        );
        for req in &msi_plan.writes {
            assert!(validate_write_request(req).is_ok());
        }

        // Polling fallback refused when allow_polling_fallback == false, allowed when true.
        let exhausted_ctx = InterruptAllocatorContext {
            available_vectors: 0,
            ..good_ctx
        };
        assert_eq!(
            plan_interrupt_transaction(
                addr,
                &lease,
                gen1,
                &ahci_manifest(),
                &plan,
                None,
                None,
                None,
                exhausted_ctx,
                0x0006,
            ),
            Err(InterruptPlanError::NoInterruptPathAvailable)
        );
        let poll_plan = plan_interrupt_transaction(
            addr,
            &lease,
            gen1,
            &nvme_manifest(),
            &plan,
            None,
            None,
            None,
            exhausted_ctx,
            0x0006,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(poll_plan.mode, InterruptMode::Polling);

        // Revoking the lease while an interrupt transaction is pending causes immediate refusal.
        let _ = lease.apply(gen1, LeaseEvent::SurpriseRemove);
        assert_eq!(
            plan_interrupt_transaction(
                addr,
                &lease,
                gen1,
                &ahci_manifest(),
                &plan,
                None,
                Some(msi),
                None,
                good_ctx,
                0x0006,
            ),
            Err(InterruptPlanError::LeaseNotMintable)
        );
    }

    #[test]
    fn i2_dma_pool_grant_separates_device_and_cpu_addresses() {
        let addr = pci_addr(4, 0);
        let gen1 = LeaseGeneration::try_new(1).unwrap_or_else(|_| unreachable!());
        let iommu_lease = configured_lease(addr, DmaIsolation::IommuDomain(7));
        let grant = DmaPoolGrant::try_new(&iommu_lease, gen1, 0x0000_1000, 0x0380_0000, 0x10_0000)
            .unwrap_or_else(|_| unreachable!());
        assert_ne!(grant.device_addr_base, grant.cpu_phys_base);
        assert_eq!(grant.isolation_label(), "IommuDomain");
    }
}
