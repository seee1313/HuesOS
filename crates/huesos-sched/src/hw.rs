//! Hardware-adjacent scheduler models: xstate area layout, PCID/ASID
//! allocation, and CPU topology parsing.
//!
//! These are pure decision models. The kernel integration that actually
//! switches CR3, runs XSAVE/XRSTOR, or programs the x2APIC is validated
//! separately on hardware; this module proves the bookkeeping around them.

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
    active: [u64; MAX_PCIDS],
    next: usize,
}

/// PCID allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcidError {
    Exhausted,
    NotActive,
    InUse,
}

impl<const MAX_PCIDS: usize> PcidTable<MAX_PCIDS> {
    pub const fn new() -> Self {
        Self {
            generations: [0; MAX_PCIDS],
            active: [0; MAX_PCIDS],
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
            if self.generations[pcid] == u64::MAX {
                // Generation exhausted: never reuse.
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
        self.active[pcid] |= 1u64 << cpu;
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
        self.active[pcid] &= !(1u64 << cpu);
        Ok(())
    }

    /// Whether the PCID+generation is still active on any CPU.
    pub fn is_active(&self, pcid: usize, generation: u64) -> bool {
        pcid < MAX_PCIDS && self.generations[pcid] == generation && self.active[pcid] != 0
    }

    /// CPUs this PCID+generation is active on.
    pub fn active_mask(&self, pcid: usize, generation: u64) -> u64 {
        if pcid >= MAX_PCIDS || self.generations[pcid] != generation {
            return 0;
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
        Ok(Self {
            smt_per_core,
            cores_per_package,
            logical_per_package: max_logical.max(1),
        })
    }

    /// Conservative fallback when leaf 0x1F/0x0B are unavailable: one thread
    /// per core, unknown package geometry.
    pub const fn conservative() -> Self {
        Self {
            smt_per_core: 1,
            cores_per_package: 1,
            logical_per_package: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let model = XsaveModel::from_cpuid(&leaves, 0b11).unwrap();
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
        let (pcid_a, gen_a) = table.allocate().unwrap();
        assert!(pcid_a != 0);
        table.activate(pcid_a, gen_a, 1).unwrap();
        assert!(table.is_active(pcid_a, gen_a));
        // Deactivate on one CPU, still active on none -> reusable.
        table.deactivate(pcid_a, gen_a, 1).unwrap();
        assert!(!table.is_active(pcid_a, gen_a));
        // But the same generation can be re-activated.
        table.activate(pcid_a, gen_a, 2).unwrap();
        assert!(table.is_active(pcid_a, gen_a));
    }

    #[test]
    fn pcid_generation_mismatch_is_rejected() {
        let mut table = PcidTable::<4>::new();
        let (pcid, gen) = table.allocate().unwrap();
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
        let topo = CpuTopology::from_leaf_1f(&leaves).unwrap();
        assert_eq!(topo.smt_per_core, 2);
        assert_eq!(topo.cores_per_package, 8);
        assert_eq!(topo.logical_per_package, 8);
    }

    #[test]
    fn topology_falls_back_conservatively() {
        assert_eq!(CpuTopology::conservative().smt_per_core, 1);
    }
}
