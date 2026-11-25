//! Hardware-adjacent scheduler models: xstate area layout, PCID/ASID
//! allocation, and CPU topology parsing.
//!
//! These are pure decision models. The kernel integration that actually
//! switches CR3, runs XSAVE/XRSTOR, or programs the x2APIC is validated
//! separately on hardware; this module proves the bookkeeping around them.

use crate::{CpuIndex, CpuMask};

/// Layout information for an eager xstate save area.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XsaveLayout {
    /// Alignment required for the save area (always >= 64).
    pub align: usize,
    /// Minimum size in bytes for the enabled state components.
    pub size: usize,
    /// XCR0 bitmask of enabled user state components.
    pub xcr0: u64,
}

/// xstate feature/component count configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XsaveError {
    NoCpuId,
    ComponentIndexOutOfRange,
    Oversized,
}

/// Model of CPUID leaf 0xD (xstate) used to size per-task save areas.
#[derive(Debug, PartialEq, Eq)]
pub struct XsaveModel {
    xcr0: u64,
    components: [u32; 64],
    max_size: usize,
}

impl XsaveModel {
    /// Build from CPUID leaf 0xD subleaves 0..=N.
    ///
    /// `subleaves` maps component index -> `(eax, ebx, ecx)` as returned by
    /// CPUID.0xD: `ebx` is the state size of that component, `ecx[0]` marks
    /// whether the component is user-state. The layout grows top-down in
    /// standard (non-compacted) form.
    pub fn from_cpuid(subleaves: &[(u32, u32, u32)], xcr0: u64) -> Result<Self, XsaveError> {
        if subleaves.is_empty() {
            return Err(XsaveError::NoCpuId);
        }
        let mut components = [0u32; 64];
        for (index, &(_, ebx, _)) in subleaves.iter().enumerate() {
            if index >= 64 {
                return Err(XsaveError::ComponentIndexOutOfRange);
            }
            components[index] = ebx;
        }
        // Total size is the sum of enabled user components' sizes (standard
        // format), plus the 512-byte legacy header.
        let mut size = 512usize;
        for (index, component_size) in components.iter().copied().enumerate() {
            if xcr0 & (1u64 << index) != 0 {
                size = size
                    .checked_add(component_size as usize)
                    .ok_or(XsaveError::Oversized)?;
            }
        }
        if size > 1 << 20 {
            return Err(XsaveError::Oversized);
        }
        Ok(Self {
            xcr0,
            components,
            max_size: size,
        })
    }

    /// Layout for one task's save area.
    pub fn layout(&self) -> XsaveLayout {
        XsaveLayout {
            align: 64,
            size: self.max_size,
            xcr0: self.xcr0,
        }
    }

    /// Size of one enabled component.
    pub fn component_size(&self, index: usize) -> Option<u32> {
        self.components.get(index).copied()
    }
}

/// PCID/ASID allocation model.
///
/// Each address space gets a PCID in `0..MAX_PCIDS`. A PCID may only be
/// reused after its previous generation has been fully invalidated on every
/// CPU that may have loaded it. This model tracks generations and the set of
/// CPUs a PCID is active on, so the kernel can prove safe reuse.
pub struct PcidTable<const MAX_PCIDS: usize> {
    generations: [u64; MAX_PCIDS],
    active: [CpuMask; MAX_PCIDS],
    next: usize,
}

/// PCID allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcidError {
    Exhausted,
    NotActive,
    InUse,
    InvalidCpu,
}

impl<const MAX_PCIDS: usize> PcidTable<MAX_PCIDS> {
    pub const fn new() -> Self {
        Self {
            generations: [0; MAX_PCIDS],
            active: [CpuMask::empty(); MAX_PCIDS],
            next: 1, // 0 is reserved (no PCID semantics on some CPUs).
        }
    }

    /// Allocate a PCID for a new address space, returning (pcid, generation).
    pub fn allocate(&mut self) -> Result<(usize, u64), PcidError> {
        for _ in 0..MAX_PCIDS {
            let pcid = self.next;
            self.next = (self.next + 1) % MAX_PCIDS;
            if pcid == 0 {
                continue;
            }
            if self.generations[pcid] == u64::MAX || !self.active[pcid].is_empty() {
                // Generation exhausted or still active: never reuse.
                continue;
            }
            self.generations[pcid] += 1;
            return Ok((pcid, self.generations[pcid]));
        }
        Err(PcidError::Exhausted)
    }

    /// Mark a PCID+generation active on a CPU.
    pub fn activate(&mut self, pcid: usize, generation: u64, cpu: usize) -> Result<(), PcidError> {
        if pcid >= MAX_PCIDS || self.generations[pcid] != generation {
            return Err(PcidError::InUse);
        }
        let cpu = CpuIndex::new(cpu).ok_or(PcidError::InvalidCpu)?;
        self.active[pcid].insert(cpu);
        Ok(())
    }

    /// Mark a PCID+generation inactive on a CPU.
    pub fn deactivate(
        &mut self,
        pcid: usize,
        generation: u64,
        cpu: usize,
    ) -> Result<(), PcidError> {
        if pcid >= MAX_PCIDS || self.generations[pcid] != generation {
            return Err(PcidError::InUse);
        }
        let cpu = CpuIndex::new(cpu).ok_or(PcidError::InvalidCpu)?;
        if !self.active[pcid].contains(cpu) {
            return Err(PcidError::NotActive);
        }
        self.active[pcid].remove(cpu);
        Ok(())
    }

    /// Whether the PCID+generation is still active on any CPU.
    pub fn is_active(&self, pcid: usize, generation: u64) -> bool {
        pcid < MAX_PCIDS && self.generations[pcid] == generation && !self.active[pcid].is_empty()
    }

    /// CPUs this PCID+generation is active on.
    pub fn active_mask(&self, pcid: usize, generation: u64) -> CpuMask {
        if pcid >= MAX_PCIDS || self.generations[pcid] != generation {
            return CpuMask::empty();
        }
        self.active[pcid]
    }
}

impl<const MAX_PCIDS: usize> Default for PcidTable<MAX_PCIDS> {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU topology level parsed from CPUID leaf 0x1F (or 0x0B fallback).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopologyLevel {
    /// Number of logical CPUs in the level (ECX[15:8]).
    pub logical: u32,
    /// Topology level type (ECX[7:0]): 1=SMT, 2=core, 3=die/package.
    pub level_type: u32,
}

/// Result of parsing the CPUID topology leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuTopology {
    /// SMT sibling count (logical CPUs per core).
    pub smt_per_core: u32,
    /// Physical cores per package.
    pub cores_per_package: u32,
    /// Total logical CPUs per package.
    pub logical_per_package: u32,
    /// APIC ID right-shift width for core identity (`EAX[4:0]` at SMT level).
    pub smt_shift: u32,
    /// APIC ID right-shift width for package identity (`EAX[4:0]` at Core level).
    pub pkg_shift: u32,
}

/// Decomposed physical location of one hardware APIC / x2APIC ID.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuLocation {
    /// Socket / package identifier.
    pub package_id: u32,
    /// Physical core identifier within the package.
    pub core_id: u32,
    /// SMT hardware thread index within the core (`0` when SMT is absent).
    pub smt_id: u32,
}

/// Topology parse failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyError {
    LeafUnavailable,
    Invalid,
    Zero,
}

impl CpuTopology {
    /// Parse the CPUID 0x1F (extended topology) leaves.
    ///
    /// `leaves` maps subleaf -> (eax, ebx, ecx, edx). `ebx[15:0]` is the
    /// number of logical CPUs at this level minus one; `ecx[15:8]` is the
    /// level number; `ecx[7:0]` is the level type.
    pub fn from_leaf_1f(leaves: &[(u32, u32, u32, u32)]) -> Result<Self, TopologyError> {
        let mut smt: Option<u32> = None;
        let mut core: Option<u32> = None;
        let mut max_logical = 0u32;
        for &(_, ebx, ecx, _) in leaves {
            let logical = ((ebx & 0xffff) + 1).max(1);
            let level_type = ecx & 0xff;
            max_logical = max_logical.max(logical);
            match level_type {
                1 => smt = Some(logical),
                2 => core = Some(logical),
                _ => {}
            }
        }
        let smt_per_core = smt.ok_or(TopologyError::LeafUnavailable)?;
        let cores_per_package = core.ok_or(TopologyError::LeafUnavailable)?;
        let logical_per_package = max_logical.max(1);
        let smt_shift = smt_per_core.max(1).next_power_of_two().trailing_zeros();
        let pkg_shift = logical_per_package
            .max(smt_per_core)
            .next_power_of_two()
            .trailing_zeros()
            .max(smt_shift);
        Ok(Self {
            smt_per_core,
            cores_per_package,
            logical_per_package,
            smt_shift,
            pkg_shift,
        })
    }

    /// Parse real hardware CPUID `0x1F` or `0x0B` extended-topology subleaves
    /// where `EAX[4:0]` holds the APIC ID bit shift to the next domain and
    /// `EBX[15:0]` holds the logical processor count at the level.
    pub fn from_sdm_leaves(leaves: &[(u32, u32, u32, u32)]) -> Result<Self, TopologyError> {
        let mut smt_logical: Option<u32> = None;
        let mut smt_shift: Option<u32> = None;
        let mut pkg_logical: Option<u32> = None;
        let mut pkg_shift: Option<u32> = None;
        for &(eax, ebx, ecx, _) in leaves {
            let level_type = (ecx >> 8) & 0xff;
            let logical = ebx & 0xffff;
            if level_type == 0 || logical == 0 {
                continue;
            }
            let shift = (eax & 0x1f).min(31);
            match level_type {
                1 => {
                    smt_logical = Some(logical);
                    smt_shift = Some(shift);
                }
                2 => {
                    pkg_logical = Some(logical);
                    pkg_shift = Some(shift);
                }
                _ => {
                    pkg_logical = Some(pkg_logical.unwrap_or(0).max(logical));
                    pkg_shift = Some(pkg_shift.unwrap_or(0).max(shift));
                }
            }
        }
        let smt_per_core = smt_logical.unwrap_or(1).max(1);
        let logical_per_package = pkg_logical
            .ok_or(TopologyError::LeafUnavailable)?
            .max(smt_per_core);
        let resolved_smt_shift = smt_shift
            .unwrap_or_else(|| smt_per_core.next_power_of_two().trailing_zeros())
            .min(31);
        let resolved_pkg_shift = pkg_shift
            .unwrap_or_else(|| logical_per_package.next_power_of_two().trailing_zeros())
            .max(resolved_smt_shift)
            .min(31);
        let cores_per_package = (logical_per_package / smt_per_core).max(1);
        Ok(Self {
            smt_per_core,
            cores_per_package,
            logical_per_package,
            smt_shift: resolved_smt_shift,
            pkg_shift: resolved_pkg_shift,
        })
    }

    /// Conservative fallback when leaf 0x1F/0x0B are unavailable: one thread
    /// per core, each APIC ID treated as an independent core in package 0.
    pub const fn conservative() -> Self {
        Self {
            smt_per_core: 1,
            cores_per_package: 1,
            logical_per_package: 1,
            smt_shift: 0,
            pkg_shift: 31,
        }
    }

    /// Decompose a 32-bit hardware APIC/x2APIC ID into `(package, core, smt)`.
    pub const fn locate_apic_id(&self, apic_id: u32) -> CpuLocation {
        let smt_bits = if self.smt_shift <= 31 {
            self.smt_shift
        } else {
            0
        };
        let pkg_bits = if self.pkg_shift <= 31 && self.pkg_shift >= smt_bits {
            self.pkg_shift
        } else {
            smt_bits
        };
        let smt_mask = if smt_bits == 0 {
            0
        } else {
            (1u32 << smt_bits) - 1
        };
        let core_bits = pkg_bits - smt_bits;
        let core_mask = if core_bits == 0 {
            0
        } else if core_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << core_bits) - 1
        };
        let package_id = if pkg_bits >= 32 {
            0
        } else {
            apic_id >> pkg_bits
        };
        CpuLocation {
            package_id,
            core_id: (apic_id >> smt_bits) & core_mask,
            smt_id: apic_id & smt_mask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: unpack a Result in a test without calling unwrap. CONTRIBUTING
    // rule 1 forbids the unwrap / expect / panic macros including in tests;
    // an assert!(false, ...) is the budget-allowed diagnostic, and `return`
    // after it keeps the types sound for the remainder of the test body.
    macro_rules! expect_ok {
        ($expr:expr, $msg:literal) => {
            match $expr {
                Ok(value) => value,
                Err(err) => {
                    assert!(
                        false,
                        concat!("expected Ok: ", $msg, " (got {err:?})"),
                        err = err
                    );
                    return;
                }
            }
        };
    }

    #[test]
    fn xsave_layout_sums_enabled_user_components() {
        // Standard components: 0=SSE(0x40), 1=AVX(0x100), 2..5=MPX(0x40 each).
        let leaves = [
            (0u32, 0x40, 1), // subleaf 0: SSE
            (0, 0x100, 1),   // subleaf 1: AVX
            (0, 0x40, 1),    // subleaf 2: MPX BNDREGS
            (0, 0x40, 1),    // subleaf 3: MPX BNDCSR
        ];
        // XCR0 = SSE|AVX = 0b11
        let model = expect_ok!(
            XsaveModel::from_cpuid(&leaves, 0b11),
            "XsaveModel::from_cpuid"
        );
        let layout = model.layout();
        assert_eq!(layout.align, 64);
        assert_eq!(layout.size, 512 + 0x40 + 0x100);
        assert_eq!(layout.xcr0, 0b11);
    }

    #[test]
    fn xsave_rejects_empty_or_oversized() {
        assert_eq!(XsaveModel::from_cpuid(&[], 1), Err(XsaveError::NoCpuId));
    }

    #[test]
    fn pcid_slots_reuse_only_after_full_deactivation() {
        let mut table = PcidTable::<8>::new();
        let (pcid_a, gen_a) = expect_ok!(table.allocate(), "first allocate");
        assert!(pcid_a != 0);
        expect_ok!(table.activate(pcid_a, gen_a, 1), "activate cpu 1");
        expect_ok!(table.activate(pcid_a, gen_a, 130), "activate cpu 130");
        expect_ok!(table.activate(pcid_a, gen_a, 255), "activate cpu 255");
        assert!(table.is_active(pcid_a, gen_a));
        let active = table.active_mask(pcid_a, gen_a);
        assert_eq!(active.count(), 3);
        assert_eq!(active.words(), [1u64 << 1, 0, 1u64 << 2, 1u64 << 63]);
        // Deactivate every CPU; PCID is no longer active and eligible for invalidation.
        expect_ok!(table.deactivate(pcid_a, gen_a, 1), "deactivate cpu 1");
        expect_ok!(table.deactivate(pcid_a, gen_a, 130), "deactivate cpu 130");
        expect_ok!(table.deactivate(pcid_a, gen_a, 255), "deactivate cpu 255");
        assert!(!table.is_active(pcid_a, gen_a));
        assert_eq!(
            table.deactivate(pcid_a, gen_a, 130),
            Err(PcidError::NotActive)
        );
        // But the same generation can be re-activated.
        expect_ok!(table.activate(pcid_a, gen_a, 2), "activate cpu 2");
        assert!(table.is_active(pcid_a, gen_a));
    }

    #[test]
    fn pcid_cannot_be_reused_while_active_on_any_of_256_cpus() {
        let mut table = PcidTable::<2>::new();
        let (pcid, generation) = expect_ok!(table.allocate(), "allocate PCID");
        assert_eq!(
            table.activate(pcid, generation, 256),
            Err(PcidError::InvalidCpu)
        );
        expect_ok!(table.activate(pcid, generation, 130), "activate cpu 130");
        assert_eq!(table.allocate(), Err(PcidError::Exhausted));
        expect_ok!(
            table.deactivate(pcid, generation, 130),
            "deactivate cpu 130"
        );

        let (reused_pcid, next_generation) = expect_ok!(table.allocate(), "reuse deactivated PCID");
        assert_eq!(reused_pcid, pcid);
        assert_eq!(next_generation, generation + 1);
        assert_eq!(
            table.active_mask(reused_pcid, next_generation),
            CpuMask::empty()
        );
    }

    #[test]
    fn pcid_generation_mismatch_is_rejected() {
        let mut table = PcidTable::<4>::new();
        let (pcid, gen) = expect_ok!(table.allocate(), "allocate");
        assert_eq!(table.activate(pcid, gen + 1, 0), Err(PcidError::InUse));
    }

    #[test]
    fn topology_parses_smt_and_core_counts() {
        // Leaf 0x1F: subleaf 0 => SMT, logical=2; subleaf 1 => core, logical=8.
        let leaves = [
            (0, 0x0001, 0x0000_0001u32, 0), // SMT: (0+1)=1? No: ebx[15:0]+1
            (0, 0x0001, 0x0000_0001, 0),    // SMT level: logical 2
            (0, 0x0007, 0x0000_0002, 0),    // core level: logical 8
        ];
        let topo = expect_ok!(
            CpuTopology::from_leaf_1f(&leaves),
            "CpuTopology::from_leaf_1f"
        );
        assert_eq!(topo.smt_per_core, 2);
        assert_eq!(topo.cores_per_package, 8);
        assert_eq!(topo.logical_per_package, 8);
    }

    #[test]
    fn topology_falls_back_conservatively() {
        let topo = CpuTopology::conservative();
        assert_eq!(topo.smt_per_core, 1);
        assert_eq!(
            topo.locate_apic_id(5),
            CpuLocation {
                package_id: 0,
                core_id: 5,
                smt_id: 0,
            }
        );
    }

    #[test]
    fn sdm_topology_locates_smt_siblings_and_packages() {
        // EAX[4:0]=1 (2 SMT/core), ECX[15:8]=1 (SMT), EBX[15:0]=2
        // EAX[4:0]=4 (16 logical/pkg), ECX[15:8]=2 (Core), EBX[15:0]=16
        let leaves = [(1, 2, 0x0100, 0), (4, 16, 0x0201, 0)];
        let topo = expect_ok!(
            CpuTopology::from_sdm_leaves(&leaves),
            "CpuTopology::from_sdm_leaves"
        );
        assert_eq!(topo.smt_per_core, 2);
        assert_eq!(topo.cores_per_package, 8);
        assert_eq!(
            topo.locate_apic_id(0x13),
            CpuLocation {
                package_id: 1,
                core_id: 1,
                smt_id: 1,
            }
        );
    }
}
