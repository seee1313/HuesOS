//! Pure, `#![forbid(unsafe_code)]` Intel VT-d DMA remapping policy and codecs.
//!
//! This crate owns every deterministic decision and bit-level encoding for
//! Stage N.2 (`PCI Isolated Profile`) hardware DMA isolation:
//! - Intel VT-d capability validation (`CAP_REG` / `ECAP_REG`), adjusted guest
//!   address width (`39-bit` 3-level and `48-bit` 4-level second-stage page
//!   tables), caching-mode (`CM=1`) domain reservation, and register-window
//!   bounds calculation;
//! - Root Entry (`128-bit`), Context Entry (`128-bit`), and Second-Stage Page
//!   Table Entry (`SlPte`, `64-bit`) codecs;
//! - Global Command (`GCMD_REG` from `GSTS_REG` persistent mask), Context-Cache
//!   invalidation (`CCMD_REG`), and IOTLB invalidation (`IOTLB_REG`) command
//!   builders;
//! - Primary Fault Recording (`FSTS_REG` / `FRCD_REG`) decoding;
//! - Fixed-capacity per-lease domain allocation, isolation-group tracking, and
//!   mapped physical DMA range accounting.
//!
//! Privileged MMIO register reads/writes, HHDM page-table frame initialization,
//! and `clflush` cache-line eviction live exclusively in
//! `huesos-arch::x86_64::vtd`. See `docs/IOMMU_VTD.md`.

#![no_std]
#![forbid(unsafe_code)]

/// Standard 4 KiB IOMMU page size.
pub const PAGE_SIZE_4K: u64 = 4096;
/// Mask for 4 KiB page offset bits.
pub const PAGE_OFFSET_MASK: u64 = PAGE_SIZE_4K - 1;
/// Physical address mask (`bits[51:12]`) used in Root, Context, and SLPT entries.
pub const PHYS_ADDR_MASK_52: u64 = 0x000F_FFFF_FFFF_F000;

/// VT-d Version Register (`32-bit`, RO).
pub const REG_VER: usize = 0x00;
/// VT-d Capability Register (`64-bit`, RO).
pub const REG_CAP: usize = 0x08;
/// VT-d Extended Capability Register (`64-bit`, RO).
pub const REG_ECAP: usize = 0x10;
/// VT-d Global Command Register (`32-bit`, WO).
pub const REG_GCMD: usize = 0x18;
/// VT-d Global Status Register (`32-bit`, RO).
pub const REG_GSTS: usize = 0x1C;
/// VT-d Root Table Address Register (`64-bit`, RW).
pub const REG_RTADDR: usize = 0x20;
/// VT-d Context Command Register (`64-bit`, RW).
pub const REG_CCMD: usize = 0x28;
/// VT-d Fault Status Register (`32-bit`, RW1C/RO).
pub const REG_FSTS: usize = 0x34;
/// VT-d Fault Event Control Register (`32-bit`, RW).
pub const REG_FECTL: usize = 0x38;

/// `GCMD_REG` / `GSTS_REG`: Translation Enable (`TE` / `TES`).
pub const GCMD_TE: u32 = 1 << 31;
/// `GCMD_REG` / `GSTS_REG`: Set Root Table Pointer (`SRTP` / `RTPS`).
pub const GCMD_SRTP: u32 = 1 << 30;
/// `GCMD_REG` / `GSTS_REG`: Write Buffer Flush (`WBF` / `WBFS`).
pub const GCMD_WBF: u32 = 1 << 27;
/// Mask of persistent stateful `GSTS_REG` bits preserved when writing `GCMD_REG`
/// (clears one-shot status bits `RTPS`, `FLS`, `WBFS`, `IRTPS`, `CFIS` per VT-d §11.4.4.1).
pub const GSTS_PERSISTENT_MASK: u32 = 0x96FF_FFFF;

/// `CCMD_REG`: Invalidate Context-Cache trigger bit (`ICC`).
pub const CCMD_ICC: u64 = 1 << 63;
/// `CCMD_REG`: Global Context-Cache invalidation (`CIRG = 01` in `bits[62:61]`).
pub const CCMD_CIRG_GLOBAL: u64 = 1 << 61;
/// `CCMD_REG`: Domain-selective Context-Cache invalidation (`CIRG = 10` in `bits[62:61]`).
pub const CCMD_CIRG_DOMAIN: u64 = 2 << 61;
/// `CCMD_REG`: Device-selective Context-Cache invalidation (`CIRG = 11` in `bits[62:61]`).
pub const CCMD_CIRG_DEVICE: u64 = 3 << 61;

/// `IOTLB_REG`: Invalidate IOTLB trigger bit (`IVT`).
pub const IOTLB_IVT: u64 = 1 << 63;
/// `IOTLB_REG`: Global IOTLB invalidation (`IIRG = 01` in `bits[61:60]`).
pub const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
/// `IOTLB_REG`: Domain-selective IOTLB invalidation (`IIRG = 10` in `bits[61:60]`).
pub const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
/// `IOTLB_REG`: Drain Reads (`DR`).
pub const IOTLB_DR: u64 = 1 << 49;
/// `IOTLB_REG`: Drain Writes (`DW`).
pub const IOTLB_DW: u64 = 1 << 48;

/// `FSTS_REG`: Primary Fault Overflow (`PFO`, RW1C).
pub const FSTS_PFO: u32 = 1 << 0;
/// `FSTS_REG`: Primary Pending Fault (`PPF`, RO).
pub const FSTS_PPF: u32 = 1 << 1;
/// `FSTS_REG`: Mask of all RW1C status bits (`PFO | AFO | APE | ICE | ITE | PRO`).
pub const FSTS_CLEAR_MASK: u32 = 0x7D;

/// `FECTL_REG`: Interrupt Mask (`IM = 1` masks fault MSI generation).
pub const FECTL_IM: u32 = 1 << 31;

/// `FRCD_REG` upper 64-bit word: Fault record valid (`F`, RW1C).
pub const FRCD_HI_F: u64 = 1 << 63;
/// `FRCD_REG` upper 64-bit word: Type bit 1 (`T1`, `1` = read/page request).
pub const FRCD_HI_T1: u64 = 1 << 62;

/// Second-stage page-table read permission (`R`).
pub const SL_PTE_READ: u64 = 1 << 0;
/// Second-stage page-table write permission (`W`).
pub const SL_PTE_WRITE: u64 = 1 << 1;
/// Second-stage superpage marker (`PS`, rejected in 4 KiB leaf mode).
pub const SL_PTE_SUPERPAGE: u64 = 1 << 7;

/// Maximum active PCI lease domains tracked simultaneously.
pub const MAX_ACTIVE_DOMAINS: usize = 64;
/// Maximum disjoint physical DMA ranges attached to one lease domain.
pub const MAX_RANGES_PER_DOMAIN: usize = 8;

/// Errors returned by VT-d capability validation, entry encoding, or domain policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    /// `CAP_REG.ND` encoded reserved domain count `0b111`.
    ReservedDomainEncoding,
    /// Hardware supports neither 39-bit (3-level) nor 48-bit (4-level) second-stage tables.
    UnsupportedAddressWidth,
    /// `CAP_REG` or `ECAP_REG` offset fields overflowed a reasonable MMIO window (`> 64 KiB`).
    InvalidRegisterOffset,
    /// Physical or IOVA address is not 4 KiB-aligned or exceeds 52-bit/AGAW bounds.
    InvalidAddress,
    /// Range length is zero, unaligned, or overflows `u64`.
    InvalidRange,
    /// Domain ID `0` is reserved (mandatory when `CAP.CM == 1`, enforced unconditionally).
    ReservedDomainId,
    /// Domain ID exceeds the hardware unit's `CAP.ND` limit.
    DomainIdOutOfRange,
    /// All software or hardware domain slots are currently in use.
    DomainTableFull,
    /// Too many disjoint DMA ranges attached to a single domain.
    RangeTableFull,
    /// Candidate DMA range overlaps an already mapped range in the domain.
    RangeOverlap,
    /// Another active lease already owns a conflicting domain in the same isolation group.
    IsolationGroupConflict,
    /// Requested lease `(koid, generation)` was not found.
    DomainNotFound,
}

/// Supported Intel VT-d Second-Stage Adjusted Guest Address Widths (`AGAW`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressWidth {
    /// 39-bit IOVA space walked via 3 page-table levels (`ContextEntry.AW = 0b001`).
    Aw39Bit3Level,
    /// 48-bit IOVA space walked via 4 page-table levels (`ContextEntry.AW = 0b010`).
    Aw48Bit4Level,
}

impl AddressWidth {
    /// Context-entry `AW` field encoding (`bits[66:64]`, i.e. `hi[2:0]`).
    pub const fn context_aw_bits(self) -> u8 {
        match self {
            Self::Aw39Bit3Level => 0b001,
            Self::Aw48Bit4Level => 0b010,
        }
    }

    /// Number of 4 KiB page-table walk levels (`3` for 39-bit, `4` for 48-bit).
    pub const fn levels(self) -> u8 {
        match self {
            Self::Aw39Bit3Level => 3,
            Self::Aw48Bit4Level => 4,
        }
    }

    /// Width in bits (`39` or `48`).
    pub const fn bits(self) -> u8 {
        match self {
            Self::Aw39Bit3Level => 39,
            Self::Aw48Bit4Level => 48,
        }
    }

    /// Exclusive upper IOVA bound addressable by this page-table width.
    pub const fn max_iova_exclusive(self) -> u64 {
        1u64 << self.bits()
    }
}

/// Validated capability summary of one hardware `DRHD` unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdCapabilities {
    /// Architecture major version (`VER_REG[7:4]`).
    pub ver_major: u8,
    /// Architecture minor version (`VER_REG[3:0]`).
    pub ver_minor: u8,
    /// Selected second-stage address width (prefers 48-bit when supported, else 39-bit).
    pub address_width: AddressWidth,
    /// Hardware Maximum Guest Address Width (`MGAW`, in bits `1..=64`).
    pub mgaw_bits: u8,
    /// Maximum number of hardware domains supported (`16..=65536`).
    pub max_domains: u32,
    /// `CAP_REG.CM`: Caching Mode active (`DomainId 0` reserved; map requires IOTLB flush).
    pub caching_mode: bool,
    /// `CAP_REG.RWBF`: Required Write-Buffer Flushing before translation/invalidation.
    pub rwbf: bool,
    /// `CAP_REG.DRD`: Hardware supports Drain Reads on IOTLB invalidation.
    pub drain_reads: bool,
    /// `CAP_REG.DWD`: Hardware supports Drain Writes on IOTLB invalidation.
    pub drain_writes: bool,
    /// `ECAP_REG.C`: Hardware page-walk is cache-coherent (`false` requires CPU `clflush`).
    pub page_walk_coherent: bool,
    /// `ECAP_REG.IR`: Hardware supports Interrupt Remapping.
    pub interrupt_remapping_supported: bool,
    /// Byte offset of `IVA_REG` from `register_base` (`ECAP.IRO * 16`).
    pub iva_reg_offset: usize,
    /// Byte offset of `IOTLB_REG` from `register_base` (`ECAP.IRO * 16 + 8`).
    pub iotlb_reg_offset: usize,
    /// Byte offset of `FRCD_REG[0]` from `register_base` (`CAP.FRO * 16`).
    pub frcd_reg_offset: usize,
    /// Number of 128-bit Fault Recording Registers (`CAP.NFR + 1`).
    pub num_fault_regs: usize,
}

impl VtdCapabilities {
    /// Parse and validate hardware `VER_REG`, `CAP_REG`, and `ECAP_REG` values.
    pub const fn parse(ver: u32, cap: u64, ecap: u64) -> Result<Self, VtdError> {
        let max_domains = match cap & 0x7 {
            0 => 16,
            1 => 64,
            2 => 256,
            3 => 1024,
            4 => 4096,
            5 => 16_384,
            6 => 65_536,
            _ => return Err(VtdError::ReservedDomainEncoding),
        };

        let sagaw = ((cap >> 8) & 0x1F) as u8;
        let address_width = if (sagaw & (1 << 2)) != 0 {
            AddressWidth::Aw48Bit4Level
        } else if (sagaw & (1 << 1)) != 0 {
            AddressWidth::Aw39Bit3Level
        } else {
            return Err(VtdError::UnsupportedAddressWidth);
        };

        let mgaw_bits = (((cap >> 16) & 0x3F) as u8).saturating_add(1);
        let fro = ((cap >> 24) & 0x3FF) as usize;
        let nfr = (((cap >> 40) & 0xFF) as usize).saturating_add(1);
        let iro = ((ecap >> 8) & 0x3FF) as usize;

        let iva_reg_offset = iro * 16;
        let iotlb_reg_offset = iva_reg_offset + 8;
        let frcd_reg_offset = fro * 16;
        let frcd_end = frcd_reg_offset + nfr * 16;
        let iotlb_end = iotlb_reg_offset + 8;

        if iva_reg_offset < 0x40
            || frcd_reg_offset < 0x40
            || frcd_end > 65_536
            || iotlb_end > 65_536
        {
            return Err(VtdError::InvalidRegisterOffset);
        }

        Ok(Self {
            ver_major: ((ver >> 4) & 0xF) as u8,
            ver_minor: (ver & 0xF) as u8,
            address_width,
            mgaw_bits,
            max_domains,
            caching_mode: (cap & (1 << 7)) != 0,
            rwbf: (cap & (1 << 4)) != 0,
            drain_reads: (cap & (1 << 55)) != 0,
            drain_writes: (cap & (1 << 54)) != 0,
            page_walk_coherent: (ecap & (1 << 0)) != 0,
            interrupt_remapping_supported: (ecap & (1 << 3)) != 0,
            iva_reg_offset,
            iotlb_reg_offset,
            frcd_reg_offset,
            num_fault_regs: nfr,
        })
    }

    /// Page-aligned MMIO byte span required to access standard, IOTLB, and FRCD registers.
    pub const fn required_mmio_bytes(&self) -> u64 {
        let iotlb_end = (self.iotlb_reg_offset + 8) as u64;
        let frcd_end = (self.frcd_reg_offset + self.num_fault_regs * 16) as u64;
        let max_end = if iotlb_end > frcd_end {
            iotlb_end
        } else {
            frcd_end
        };
        let min_window = if max_end < PAGE_SIZE_4K {
            PAGE_SIZE_4K
        } else {
            max_end
        };
        (min_window + PAGE_OFFSET_MASK) & !PAGE_OFFSET_MASK
    }

    /// Exclusive upper IOVA limit permitted by both `address_width` and `mgaw_bits`.
    pub const fn effective_iova_limit(&self) -> u64 {
        let aw_bits = self.address_width.bits();
        let eff_bits = if self.mgaw_bits < aw_bits {
            self.mgaw_bits
        } else {
            aw_bits
        };
        if eff_bits >= 64 {
            u64::MAX
        } else {
            1u64 << eff_bits
        }
    }

    /// Build a global IOTLB invalidation command word respecting `DRD`/`DWD` support.
    pub const fn iotlb_global_invalidate_cmd(&self) -> u64 {
        let mut cmd = IOTLB_IVT | IOTLB_IIRG_GLOBAL;
        if self.drain_reads {
            cmd |= IOTLB_DR;
        }
        if self.drain_writes {
            cmd |= IOTLB_DW;
        }
        cmd
    }

    /// Build a domain-selective IOTLB invalidation command word for `domain_id`.
    pub const fn iotlb_domain_invalidate_cmd(&self, domain_id: u16) -> u64 {
        let mut cmd = IOTLB_IVT | IOTLB_IIRG_DOMAIN | ((domain_id as u64) << 32);
        if self.drain_reads {
            cmd |= IOTLB_DR;
        }
        if self.drain_writes {
            cmd |= IOTLB_DW;
        }
        cmd
    }
}

/// Build a `GCMD_REG` value from the current `GSTS_REG` snapshot, preserving
/// persistent state bits while asserting `set_bits` and clearing `clear_bits`.
pub const fn build_gcmd(gsts: u32, set_bits: u32, clear_bits: u32) -> u32 {
    ((gsts & GSTS_PERSISTENT_MASK) & !clear_bits) | set_bits
}

/// Build a global Context-Cache invalidation command word (`CCMD_REG`).
pub const fn ccmd_global_invalidate() -> u64 {
    CCMD_ICC | CCMD_CIRG_GLOBAL
}

/// Build a domain-selective Context-Cache invalidation command word (`CCMD_REG`).
pub const fn ccmd_domain_invalidate(domain_id: u16) -> u64 {
    CCMD_ICC | CCMD_CIRG_DOMAIN | (domain_id as u64)
}

/// Build a device-selective Context-Cache invalidation command word (`CCMD_REG`).
pub const fn ccmd_device_invalidate(domain_id: u16, source_bdf: u16) -> u64 {
    CCMD_ICC | CCMD_CIRG_DEVICE | ((source_bdf as u64) << 16) | (domain_id as u64)
}

/// 128-bit Intel VT-d Root Table Entry (`Bus 0..=255`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootEntry {
    /// Lower 64 bits (`CTP` physical pointer + `Present` bit 0).
    pub lo: u64,
    /// Upper 64 bits (`0` in legacy Root Table mode).
    pub hi: u64,
}

impl RootEntry {
    /// Empty (`Present = 0`) root entry.
    pub const EMPTY: Self = Self { lo: 0, hi: 0 };

    /// Encode a present Root Entry pointing to a 4 KiB-aligned Context Table physical frame.
    pub const fn present(context_table_phys: u64) -> Result<Self, VtdError> {
        if context_table_phys == 0 || (context_table_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self {
            lo: context_table_phys | 1,
            hi: 0,
        })
    }

    /// Whether the Root Entry is marked present (`P == 1`).
    pub const fn is_present(self) -> bool {
        (self.lo & 1) != 0
    }

    /// Physical base address of the 4 KiB Context Table, if present.
    pub const fn context_table_phys(self) -> Option<u64> {
        if self.is_present() {
            Some(self.lo & PHYS_ADDR_MASK_52)
        } else {
            None
        }
    }
}

/// 128-bit Intel VT-d Context Table Entry (`DevFn 0..=255`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContextEntry {
    /// Lower 64 bits (`SLPTPTR` + `TT=00` + `Present` bit 0).
    pub lo: u64,
    /// Upper 64 bits (`DID` in `bits[23:8]` + `AW` in `bits[2:0]`).
    pub hi: u64,
}

impl ContextEntry {
    /// Empty (`Present = 0`) context entry: hardware blocks all DMA from this BDF.
    pub const EMPTY: Self = Self { lo: 0, hi: 0 };

    /// Encode a present Second-Stage translation Context Entry (`TT = 0b00`).
    pub const fn present(
        slpt_root_phys: u64,
        address_width: AddressWidth,
        domain_id: u16,
        max_domains: u32,
    ) -> Result<Self, VtdError> {
        if domain_id == 0 {
            return Err(VtdError::ReservedDomainId);
        }
        if (domain_id as u32) >= max_domains {
            return Err(VtdError::DomainIdOutOfRange);
        }
        if slpt_root_phys == 0 || (slpt_root_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self {
            lo: slpt_root_phys | 1,
            hi: ((domain_id as u64) << 8) | (address_width.context_aw_bits() as u64),
        })
    }

    /// Whether the Context Entry is marked present (`P == 1`).
    pub const fn is_present(self) -> bool {
        (self.lo & 1) != 0
    }

    /// Physical address of the Second-Stage Page Table root (`SLPTPTR`), if present.
    pub const fn slpt_root_phys(self) -> Option<u64> {
        if self.is_present() {
            Some(self.lo & PHYS_ADDR_MASK_52)
        } else {
            None
        }
    }

    /// Bound VT-d Domain ID (`DID`), if present.
    pub const fn domain_id(self) -> Option<u16> {
        if self.is_present() {
            Some(((self.hi >> 8) & 0xFFFF) as u16)
        } else {
            None
        }
    }
}

/// 64-bit Intel VT-d Second-Stage Page Table Entry (`SlPte`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct SlPte(pub u64);

impl SlPte {
    /// Unmapped (`R=0, W=0`) entry.
    pub const EMPTY: Self = Self(0);

    /// Encode a non-leaf directory entry (`R=1, W=1`) pointing to a 4 KiB child table.
    pub const fn directory(next_table_phys: u64) -> Result<Self, VtdError> {
        if next_table_phys == 0 || (next_table_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self(next_table_phys | SL_PTE_READ | SL_PTE_WRITE))
    }

    /// Encode a 4 KiB leaf entry granting `read` and/or `write` DMA access to `frame_phys`.
    pub const fn leaf_4k(frame_phys: u64, read: bool, write: bool) -> Result<Self, VtdError> {
        if (!read && !write) || (frame_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        let mut perm = 0u64;
        if read {
            perm |= SL_PTE_READ;
        }
        if write {
            perm |= SL_PTE_WRITE;
        }
        Ok(Self(frame_phys | perm))
    }

    /// True if either `R` or `W` permission is set.
    pub const fn is_present(self) -> bool {
        (self.0 & (SL_PTE_READ | SL_PTE_WRITE)) != 0
    }

    /// True if the superpage bit (`PS`) is set.
    pub const fn is_superpage(self) -> bool {
        (self.0 & SL_PTE_SUPERPAGE) != 0
    }

    /// Extract the 4 KiB-aligned target physical address when present.
    pub const fn addr_4k(self) -> Option<u64> {
        if self.is_present() {
            Some(self.0 & PHYS_ADDR_MASK_52)
        } else {
            None
        }
    }
}

/// Compute the 9-bit page-table slot index (`0..512`) for `iova` at `level`
/// (`level = 1` is the 4 KiB PT leaf, `2` = PD, `3` = PDPT, `4` = PML4).
pub const fn iova_level_index(iova: u64, level: u8) -> Result<usize, VtdError> {
    if level == 0 || level > 4 {
        return Err(VtdError::InvalidAddress);
    }
    let shift = 12 + (level as u32 - 1) * 9;
    Ok(((iova >> shift) & 0x1FF) as usize)
}

/// Decoded hardware fault reason categories from `FRCD_REG.FR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// `0x01`: Root-entry `Present` bit is clear.
    RootNotPresent,
    /// `0x02`: Context-entry `Present` bit is clear (unbound or revoked BDF).
    ContextNotPresent,
    /// `0x03`: Invalid field in Context-entry.
    ContextInvalid,
    /// `0x04`: DMA address exceeded `MGAW` / `AGAW`.
    AddressOutOfBounds,
    /// `0x05`: Write/AtomicOp attempted to a Second-Stage PTE with `W == 0`.
    WriteNotPermitted,
    /// `0x06`: Read attempted to a Second-Stage PTE with `R == 0`.
    ReadNotPermitted,
    /// `0x07` or `0x08`: Invalid Second-Stage page-table/root pointer.
    PageTableInvalid,
    /// Any other architectural fault reason byte.
    Other(u8),
}

impl FaultKind {
    /// Classify a raw 8-bit VT-d fault reason code (`FR`).
    pub const fn from_reason_code(code: u8) -> Self {
        match code {
            0x01 => Self::RootNotPresent,
            0x02 => Self::ContextNotPresent,
            0x03 => Self::ContextInvalid,
            0x04 => Self::AddressOutOfBounds,
            0x05 => Self::WriteNotPermitted,
            0x06 => Self::ReadNotPermitted,
            0x07 | 0x08 => Self::PageTableInvalid,
            other => Self::Other(other),
        }
    }
}

/// Decoded 128-bit Intel VT-d Primary Fault Recording entry (`FRCD_REG`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRecord {
    /// Hardware `DRHD` engine index that recorded the fault.
    pub unit_index: u8,
    /// Raw 8-bit VT-d fault reason (`FR`).
    pub reason_code: u8,
    /// Classified fault kind.
    pub kind: FaultKind,
    /// True if the faulting request was a read/page request (`T != 0`); false for write.
    pub is_read: bool,
    /// PCI requester Source-ID `(bus << 8) | devfn`.
    pub source_bdf: u16,
    /// 4 KiB-aligned faulting IOVA (`FI`).
    pub fault_iova: u64,
}

impl FaultRecord {
    /// Decode one `(lo, hi)` pair read from `FRCD_REG[slot]`. Returns `None` if `F == 0`.
    pub const fn decode(unit_index: u8, lo: u64, hi: u64) -> Option<Self> {
        if (hi & FRCD_HI_F) == 0 {
            return None;
        }
        let reason_code = ((hi >> 32) & 0xFF) as u8;
        let t1 = (hi & FRCD_HI_T1) != 0;
        let t2 = ((hi >> 28) & 0xF) != 0;
        Some(Self {
            unit_index,
            reason_code,
            kind: FaultKind::from_reason_code(reason_code),
            is_read: t1 || t2,
            source_bdf: (hi & 0xFFFF) as u16,
            fault_iova: lo & !PAGE_OFFSET_MASK,
        })
    }
}

/// One validated 4 KiB-aligned DMA range `[base, base + len)` mapped in a domain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MappedDmaRange {
    /// Page-aligned base IOVA / physical address.
    pub base: u64,
    /// Page-aligned byte length (`> 0`).
    pub len: u64,
}

impl MappedDmaRange {
    /// Construct and validate a 4 KiB-aligned range within `iova_limit_exclusive`.
    pub const fn try_new(
        base: u64,
        len: u64,
        iova_limit_exclusive: u64,
    ) -> Result<Self, VtdError> {
        if len == 0
            || (base & PAGE_OFFSET_MASK) != 0
            || (len & PAGE_OFFSET_MASK) != 0
            || (base & !PHYS_ADDR_MASK_52) != 0
        {
            return Err(VtdError::InvalidRange);
        }
        let Some(end) = base.checked_add(len) else {
            return Err(VtdError::InvalidRange);
        };
        if end > iova_limit_exclusive {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self { base, len })
    }

    /// Exclusive end address (`base + len`).
    pub const fn end_exclusive(self) -> u64 {
        self.base + self.len
    }

    /// True if `self` and `other` intersect by at least one byte.
    pub const fn overlaps(self, other: Self) -> bool {
        self.base < other.end_exclusive() && other.base < self.end_exclusive()
    }

    /// Number of 4 KiB pages covered by this range.
    pub const fn page_count(self) -> u64 {
        self.len / PAGE_SIZE_4K
    }
}

/// Pure, fixed-capacity tracker for active `DeviceLease` VT-d domains and isolation groups.
#[derive(Clone, Copy, Debug)]
pub struct DomainRecord {
    /// Whether this slot holds an active lease domain.
    pub active: bool,
    /// Hardware `DRHD` unit index (`0..MAX_DRHD`).
    pub unit_index: u8,
    /// Allocated non-zero VT-d `DomainId` (`1..max_domains`).
    pub domain_id: u16,
    /// Canonical packed PCI address `(seg << 16) | (bus << 8) | devfn`.
    pub pci_address_packed: u64,
    /// Isolation-group identifier (functions sharing a non-ACS legacy bridge share this ID).
    pub isolation_group_id: u32,
    /// Owning `DeviceLease` kernel object ID.
    pub lease_koid: u64,
    /// Owning `DeviceLease` active generation.
    pub lease_generation: u64,
    /// Root 4 KiB physical address of the domain's Second-Stage Page Table (`SLPTPTR`).
    pub slpt_root_phys: u64,
    /// Number of active mapped user `DmaPool` ranges in [`Self::ranges`].
    pub range_count: usize,
    /// Validated `DmaPool` ranges mapped into this domain.
    pub ranges: [MappedDmaRange; MAX_RANGES_PER_DOMAIN],
}

impl DomainRecord {
    /// Empty inactive slot.
    pub const EMPTY: Self = Self {
        active: false,
        unit_index: 0,
        domain_id: 0,
        pci_address_packed: 0,
        isolation_group_id: 0,
        lease_koid: 0,
        lease_generation: 0,
        slpt_root_phys: 0,
        range_count: 0,
        ranges: [MappedDmaRange { base: 0, len: 0 }; MAX_RANGES_PER_DOMAIN],
    };

    /// Total 4 KiB pages mapped across all attached `DmaPool` ranges in this domain.
    pub fn mapped_pages(&self) -> u64 {
        let mut pages = 0u64;
        let mut idx = 0usize;
        while idx < self.range_count {
            pages = pages.saturating_add(self.ranges[idx].page_count());
            idx += 1;
        }
        pages
    }
}

/// Derive the default requester isolation-group ID for a packed PCI address.
///
/// Under Stage N.2, each PCIe function with distinct `(segment, bus, devfn)` forms
/// its own requester isolation group unless topology aliasing collapses subordinate
/// legacy-PCI functions onto an upstream bridge BDF (`alias_bridge_bdf`).
pub const fn derive_isolation_group(pci_address_packed: u64, alias_bridge_bdf: Option<u16>) -> u32 {
    let segment = ((pci_address_packed >> 16) & 0xFFFF) as u32;
    let bdf = match alias_bridge_bdf {
        Some(bridge_bdf) => bridge_bdf as u32,
        None => (pci_address_packed & 0xFFFF) as u32,
    };
    (segment << 16) | bdf
}

/// Fixed-capacity allocator and policy state machine for VT-d domains.
pub struct DomainTable {
    slots: [DomainRecord; MAX_ACTIVE_DOMAINS],
    active_count: u32,
    mapped_pages_total: u64,
    teardown_count: u64,
}

impl Default for DomainTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainTable {
    /// Create an empty domain table with zero active domains.
    pub const fn new() -> Self {
        Self {
            slots: [DomainRecord::EMPTY; MAX_ACTIVE_DOMAINS],
            active_count: 0,
            mapped_pages_total: 0,
            teardown_count: 0,
        }
    }

    /// Number of currently active domains.
    pub const fn active_count(&self) -> u32 {
        self.active_count
    }

    /// Total 4 KiB `DmaPool` pages currently mapped across all active domains.
    pub const fn mapped_pages_total(&self) -> u64 {
        self.mapped_pages_total
    }

    /// Monotonic count of completed domain teardowns (`revoke` / `drop`).
    pub const fn teardown_count(&self) -> u64 {
        self.teardown_count
    }

    /// Borrow all domain slots for inspection.
    pub const fn slots(&self) -> &[DomainRecord; MAX_ACTIVE_DOMAINS] {
        &self.slots
    }

    /// Look up an existing domain slot for `(lease_koid, lease_generation)`.
    pub fn find_by_lease(&self, lease_koid: u64, lease_generation: u64) -> Option<usize> {
        let mut idx = 0usize;
        while idx < MAX_ACTIVE_DOMAINS {
            let rec = &self.slots[idx];
            if rec.active
                && rec.lease_koid == lease_koid
                && rec.lease_generation == lease_generation
            {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }

    /// Allocate a fresh domain ID (`1..max_domains`) on `unit_index`, enforcing
    /// isolation-group exclusivity across distinct leases.
    #[allow(clippy::too_many_arguments)]
    pub fn allocate_domain(
        &mut self,
        unit_index: u8,
        max_domains: u32,
        pci_address_packed: u64,
        isolation_group_id: u32,
        lease_koid: u64,
        lease_generation: u64,
        slpt_root_phys: u64,
    ) -> Result<(usize, u16), VtdError> {
        if slpt_root_phys == 0 || (slpt_root_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        // Reject conflicting active leases targeting the same BDF or isolation group.
        let mut idx = 0usize;
        while idx < MAX_ACTIVE_DOMAINS {
            let rec = &self.slots[idx];
            if rec.active
                && (rec.pci_address_packed == pci_address_packed
                    || rec.isolation_group_id == isolation_group_id)
                && (rec.lease_koid != lease_koid || rec.lease_generation != lease_generation)
            {
                return Err(VtdError::IsolationGroupConflict);
            }
            idx += 1;
        }

        let mut free_slot = None;
        let mut s = 0usize;
        while s < MAX_ACTIVE_DOMAINS {
            if !self.slots[s].active {
                free_slot = Some(s);
                break;
            }
            s += 1;
        }
        let Some(slot_idx) = free_slot else {
            return Err(VtdError::DomainTableFull);
        };

        // Domain ID 0 is permanently reserved (required for Caching Mode `CM=1`).
        let cap_limit = if max_domains > 65_535 {
            65_535u32
        } else {
            max_domains
        };
        let mut candidate: u32 = 1;
        let mut chosen_did: Option<u16> = None;
        while candidate < cap_limit {
            let did = candidate as u16;
            let mut in_use = false;
            let mut j = 0usize;
            while j < MAX_ACTIVE_DOMAINS {
                if self.slots[j].active
                    && self.slots[j].unit_index == unit_index
                    && self.slots[j].domain_id == did
                {
                    in_use = true;
                    break;
                }
                j += 1;
            }
            if !in_use {
                chosen_did = Some(did);
                break;
            }
            candidate += 1;
        }
        let Some(domain_id) = chosen_did else {
            return Err(VtdError::DomainIdOutOfRange);
        };

        self.slots[slot_idx] = DomainRecord {
            active: true,
            unit_index,
            domain_id,
            pci_address_packed,
            isolation_group_id,
            lease_koid,
            lease_generation,
            slpt_root_phys,
            range_count: 0,
            ranges: [MappedDmaRange { base: 0, len: 0 }; MAX_RANGES_PER_DOMAIN],
        };
        self.active_count = self.active_count.saturating_add(1);
        Ok((slot_idx, domain_id))
    }

    /// Validate and record a newly mapped `DmaPool` range in `slot_idx`.
    /// Idempotent if the exact `(base, len)` range is already recorded.
    pub fn record_range(
        &mut self,
        slot_idx: usize,
        range: MappedDmaRange,
    ) -> Result<bool, VtdError> {
        if slot_idx >= MAX_ACTIVE_DOMAINS || !self.slots[slot_idx].active {
            return Err(VtdError::DomainNotFound);
        }
        let rec = &mut self.slots[slot_idx];
        let mut i = 0usize;
        while i < rec.range_count {
            if rec.ranges[i] == range {
                return Ok(false);
            }
            if rec.ranges[i].overlaps(range) {
                return Err(VtdError::RangeOverlap);
            }
            i += 1;
        }
        if rec.range_count >= MAX_RANGES_PER_DOMAIN {
            return Err(VtdError::RangeTableFull);
        }
        rec.ranges[rec.range_count] = range;
        rec.range_count += 1;
        self.mapped_pages_total = self.mapped_pages_total.saturating_add(range.page_count());
        Ok(true)
    }

    /// Remove and return the active `DomainRecord` for `(lease_koid, lease_generation)`.
    pub fn release_lease(
        &mut self,
        lease_koid: u64,
        lease_generation: u64,
    ) -> Option<DomainRecord> {
        let idx = self.find_by_lease(lease_koid, lease_generation)?;
        let removed = self.slots[idx];
        self.slots[idx] = DomainRecord::EMPTY;
        self.active_count = self.active_count.saturating_sub(1);
        self.mapped_pages_total = self.mapped_pages_total.saturating_sub(removed.mapped_pages());
        self.teardown_count = self.teardown_count.saturating_add(1);
        Some(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_qemu_vtd_capabilities_39bit_caching_mode() {
        // QEMU `-device intel-iommu,intremap=off,caching-mode=on` typical values:
        // ND=2 (256 domains), CM=1 (bit 7), SAGAW=0x02 (39-bit, bit 1), MGAW=38 (39 bits),
        // FRO=0x10 (offset 0x100), NFR=0 (1 fault reg), DRD=1, DWD=1; ECAP IRO=0x08 (0x80).
        let cap: u64 = 2
            | (1 << 7)
            | (0b00010 << 8)
            | (38 << 16)
            | (0x10 << 24)
            | (1 << 54)
            | (1 << 55);
        let ecap: u64 = 0x08 << 8;
        let parsed = VtdCapabilities::parse(0x10, cap, ecap);
        assert_eq!(
            parsed,
            Ok(VtdCapabilities {
                ver_major: 1,
                ver_minor: 0,
                address_width: AddressWidth::Aw39Bit3Level,
                mgaw_bits: 39,
                max_domains: 256,
                caching_mode: true,
                rwbf: false,
                drain_reads: true,
                drain_writes: true,
                page_walk_coherent: false,
                interrupt_remapping_supported: false,
                iva_reg_offset: 0x80,
                iotlb_reg_offset: 0x88,
                frcd_reg_offset: 0x100,
                num_fault_regs: 1,
            })
        );
        if let Ok(c) = parsed {
            assert_eq!(c.required_mmio_bytes(), 0x1000);
            assert_eq!(c.effective_iova_limit(), 1u64 << 39);
            assert_eq!(
                c.iotlb_domain_invalidate_cmd(5),
                IOTLB_IVT | IOTLB_IIRG_DOMAIN | (5u64 << 32) | IOTLB_DR | IOTLB_DW
            );
        }
    }

    #[test]
    fn test_parse_48bit_prefers_4level_and_rejects_bad_caps() {
        let cap_48: u64 = 4 | (0b00110 << 8) | (47 << 16) | (0x20 << 24);
        let ecap_coherent: u64 = 1 | (1 << 3) | (0x10 << 8);
        let parsed = VtdCapabilities::parse(0x10, cap_48, ecap_coherent);
        assert!(parsed.is_ok());
        if let Ok(c) = parsed {
            assert_eq!(c.address_width, AddressWidth::Aw48Bit4Level);
            assert_eq!(c.max_domains, 4096);
            assert!(c.page_walk_coherent);
            assert!(c.interrupt_remapping_supported);
            assert_eq!(
                c.iotlb_global_invalidate_cmd(),
                IOTLB_IVT | IOTLB_IIRG_GLOBAL
            );
        }

        // Reserved ND=7 rejected.
        assert_eq!(
            VtdCapabilities::parse(0x10, 7 | (0b00010 << 8) | (0x10 << 24), 0x08 << 8),
            Err(VtdError::ReservedDomainEncoding)
        );
        // SAGAW=0 rejected.
        assert_eq!(
            VtdCapabilities::parse(0x10, 2 | (0x10 << 24), 0x08 << 8),
            Err(VtdError::UnsupportedAddressWidth)
        );
        // IRO overlapping fixed registers (< 0x40) rejected.
        assert_eq!(
            VtdCapabilities::parse(0x10, 2 | (0b00010 << 8) | (0x10 << 24), 0x02 << 8),
            Err(VtdError::InvalidRegisterOffset)
        );
    }

    #[test]
    fn test_gcmd_masks_oneshot_status_bits() {
        // Suppose RTPS (bit 30) and WBFS (bit 27) are set in GSTS; enabling TE (bit 31)
        // must NOT re-trigger SRTP or WBF.
        let gsts = GCMD_SRTP | GCMD_WBF;
        let cmd = build_gcmd(gsts, GCMD_TE, 0);
        assert_eq!(cmd, GCMD_TE);

        // Once TES (bit 31) is active, pulsing WBF preserves TE.
        let gsts_te = GCMD_TE | GCMD_SRTP;
        let cmd_wbf = build_gcmd(gsts_te, GCMD_WBF, 0);
        assert_eq!(cmd_wbf, GCMD_TE | GCMD_WBF);
    }

    #[test]
    fn test_root_context_and_slpte_encodings() {
        assert_eq!(RootEntry::present(0), Err(VtdError::InvalidAddress));
        assert_eq!(RootEntry::present(0x1234), Err(VtdError::InvalidAddress));
        let root = RootEntry::present(0x0010_2000);
        assert_eq!(root, Ok(RootEntry { lo: 0x0010_2001, hi: 0 }));
        if let Ok(r) = root {
            assert_eq!(r.context_table_phys(), Some(0x0010_2000));
        }

        // Domain ID 0 must be rejected unconditionally (CM=1 safety).
        assert_eq!(
            ContextEntry::present(0x0020_0000, AddressWidth::Aw39Bit3Level, 0, 256),
            Err(VtdError::ReservedDomainId)
        );
        assert_eq!(
            ContextEntry::present(0x0020_0000, AddressWidth::Aw39Bit3Level, 256, 256),
            Err(VtdError::DomainIdOutOfRange)
        );
        let ctx = ContextEntry::present(0x0020_0000, AddressWidth::Aw48Bit4Level, 7, 256);
        assert_eq!(
            ctx,
            Ok(ContextEntry {
                lo: 0x0020_0001,
                hi: (7 << 8) | 0b010,
            })
        );
        if let Ok(c) = ctx {
            assert_eq!(c.slpt_root_phys(), Some(0x0020_0000));
            assert_eq!(c.domain_id(), Some(7));
        }

        // SlPte checks.
        assert_eq!(SlPte::leaf_4k(0x4000, false, false), Err(VtdError::InvalidAddress));
        let pte = SlPte::leaf_4k(0x0100_0000, true, true);
        assert_eq!(pte, Ok(SlPte(0x0100_0003)));
    }

    #[test]
    fn test_iova_level_indices_and_fault_decoding() {
        let iova = (3u64 << 39) | (5u64 << 30) | (7u64 << 21) | (9u64 << 12);
        assert_eq!(iova_level_index(iova, 4), Ok(3));
        assert_eq!(iova_level_index(iova, 3), Ok(5));
        assert_eq!(iova_level_index(iova, 2), Ok(7));
        assert_eq!(iova_level_index(iova, 1), Ok(9));
        assert_eq!(iova_level_index(iova, 0), Err(VtdError::InvalidAddress));

        let lo = 0xDEAD_5000 | 0x123;
        let hi = FRCD_HI_F | (0x05u64 << 32) | 0x0020; // BDF 00:04.0 write fault
        let fault = FaultRecord::decode(0, lo, hi);
        assert_eq!(
            fault,
            Some(FaultRecord {
                unit_index: 0,
                reason_code: 0x05,
                kind: FaultKind::WriteNotPermitted,
                is_read: false,
                source_bdf: 0x0020,
                fault_iova: 0xDEAD_5000,
            })
        );
        assert_eq!(FaultRecord::decode(0, lo, hi & !FRCD_HI_F), None);
    }

    #[test]
    fn test_domain_lifecycle_isolation_group_and_teardown() {
        let mut table = DomainTable::new();
        let bdf_nvme = 0x0020u64; // 00:04.0
        let grp_nvme = derive_isolation_group(bdf_nvme, None);

        let alloc1 = table.allocate_domain(0, 256, bdf_nvme, grp_nvme, 101, 1, 0x10_0000);
        assert_eq!(alloc1, Ok((0, 1)));

        // Conflicting lease in the same isolation group is rejected fail-closed.
        let conflict = table.allocate_domain(0, 256, 0x0021, grp_nvme, 102, 1, 0x11_0000);
        assert_eq!(conflict, Err(VtdError::IsolationGroupConflict));

        // Valid 64 MiB DmaPool range recorded and accounted.
        let r1 = MappedDmaRange::try_new(0x0200_0000, 64 * 1024 * 1024, 1u64 << 39);
        assert!(r1.is_ok());
        if let Ok(range) = r1 {
            assert_eq!(table.record_range(0, range), Ok(true));
            // Idempotent re-registration returns Ok(false).
            assert_eq!(table.record_range(0, range), Ok(false));
            assert_eq!(table.mapped_pages_total(), 16_384);
        }

        // Overlapping range rejected.
        let overlap = MappedDmaRange::try_new(0x0300_0000, 4096, 1u64 << 39);
        if let Ok(ov) = overlap {
            assert_eq!(table.record_range(0, ov), Err(VtdError::RangeOverlap));
        }

        // Synchronous teardown releases the BDF/group for generation 2 reuse!
        let released = table.release_lease(101, 1);
        assert!(released.is_some());
        assert_eq!(table.active_count(), 0);
        assert_eq!(table.mapped_pages_total(), 0);
        assert_eq!(table.teardown_count(), 1);

        let alloc_gen2 = table.allocate_domain(0, 256, bdf_nvme, grp_nvme, 101, 2, 0x12_0000);
        assert_eq!(alloc_gen2, Ok((0, 1)));
    }
}
