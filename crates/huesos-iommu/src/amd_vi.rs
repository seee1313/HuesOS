//! Pure, `#![forbid(unsafe_code)]` AMD-Vi (`I/O Virtualization`, `IVRS`) codecs.
//!
//! Encodes and decodes AMD-Vi hardware data structures per the *AMD I/O
//! Virtualization Technology (IOMMU) Specification* (Pub `48882`):
//! - MMIO register layout (`0x0000..0x2028`, `16 KiB` window);
//! - `256`-bit (`32`-byte) Device Table Entries (`AmdViDte`), including a
//!   hardware default-deny `blocked` profile (`V = 1, TV = 1, Mode = 4`
//!   pointing to an all-zero 4 KiB page table under reserved `DomainId = 1`
//!   because `V = 0` in AMD-Vi means *pass-through*);
//! - `64`-bit 4-level (`48`-bit IOVA) Host I/O Page Table Entries (`AmdViPte`,
//!   `PR = 1`, `NextLevel = 3..=0`, `IR`/`IW` in `bits[62:61]`);
//! - `128`-bit Command Buffer entries (`INVALIDATE_DEVTAB_ENTRY`,
//!   `INVALIDATE_IOMMU_PAGES`, `COMPLETION_WAIT`);
//! - `128`-bit Event Log entries (`IO_PAGE_FAULT` -> [`crate::FaultRecord`]).

use crate::{FaultKind, FaultRecord, VtdError, PAGE_OFFSET_MASK, PAGE_SIZE_4K, PHYS_ADDR_MASK_52};

/// Total uncached MMIO window mapped per AMD-Vi hardware unit (`16 KiB`).
pub const AMD_VI_MMIO_BYTES: u64 = 0x4000;
/// Full single-segment AMD-Vi Device Table size (`65,536 * 32 B = 2 MiB`).
pub const AMD_VI_DEVTAB_BYTES: u64 = 65_536 * 32;
/// `DevTab` `Size` field (`bits[8:0]` = `512_pages - 1 = 0x1FF`).
pub const AMD_VI_DEVTAB_SIZE_BITS: u64 = (AMD_VI_DEVTAB_BYTES / PAGE_SIZE_4K) - 1;
/// Command / Event ring entry size in bytes (`128` bits).
pub const AMD_VI_RING_ENTRY_BYTES: usize = 16;
/// Number of 16-byte entries in one 4 KiB Command or Event ring (`256`).
pub const AMD_VI_RING_CAPACITY: usize = 256;
/// `ComLen` / `EvtLen` 4-bit power-of-two encoding (`2^8 = 256` entries = `4 KiB`).
pub const AMD_VI_RING_LEN_EXP_256: u64 = 8;
/// Byte mask for wrapping 4 KiB Command/Event ring offsets (`bits[11:4]`).
pub const AMD_VI_RING_OFFSET_MASK: u64 = 0x0FF0;

/// Reserved AMD-Vi `DomainId` assigned to unattached / revoked PCI functions
/// pointing at an empty 4 KiB root page table (`FaultKind::ContextNotPresent`).
pub const AMD_VI_BLOCKED_DOMAIN_ID: u16 = 1;
/// Reserved AMD-Vi `DomainId` used for firmware `IVMD` unity scopes.
pub const AMD_VI_IVMD_DOMAIN_ID: u16 = 2;
/// First AMD-Vi `DomainId` available to `DeviceLease` DMA domains.
pub const AMD_VI_FIRST_LEASE_DOMAIN_ID: u16 = 3;
/// Maximum hardware `DomainId` count in 16-bit AMD-Vi (`0..=65535`).
pub const AMD_VI_MAX_DOMAINS: u32 = 65_536;
/// 4-level (`Mode = 4`) AMD-Vi IOVA upper bound (`256 TiB`, `48`-bit).
pub const AMD_VI_MAX_IOVA_48BIT: u64 = 1u64 << 48;

/// MMIO `0x0000`: Device Table Base Address Register (`64-bit`).
pub const MMIO_DEVTAB_BASE: usize = 0x0000;
/// MMIO `0x0008`: Command Buffer Base Address Register (`64-bit`).
pub const MMIO_CMDBUF_BASE: usize = 0x0008;
/// MMIO `0x0010`: Event Log Base Address Register (`64-bit`).
pub const MMIO_EVTLOG_BASE: usize = 0x0010;
/// MMIO `0x0018`: IOMMU Control Register (`64-bit`).
pub const MMIO_CONTROL: usize = 0x0018;
/// MMIO `0x0020`: IOMMU Exclusion Base Register (`64-bit`).
pub const MMIO_EXCL_BASE: usize = 0x0020;
/// MMIO `0x0028`: IOMMU Exclusion Range Limit Register (`64-bit`).
pub const MMIO_EXCL_LIMIT: usize = 0x0028;
/// MMIO `0x0030`: IOMMU Extended Feature Register (`64-bit`, RO).
pub const MMIO_EXT_FEATURES: usize = 0x0030;
/// MMIO `0x2000`: Command Buffer Head Pointer Register (`64-bit`).
pub const MMIO_CMD_HEAD: usize = 0x2000;
/// MMIO `0x2008`: Command Buffer Tail Pointer Register (`64-bit`).
pub const MMIO_CMD_TAIL: usize = 0x2008;
/// MMIO `0x2010`: Event Log Head Pointer Register (`64-bit`).
pub const MMIO_EVT_HEAD: usize = 0x2010;
/// MMIO `0x2018`: Event Log Tail Pointer Register (`64-bit`).
pub const MMIO_EVT_TAIL: usize = 0x2018;
/// MMIO `0x2020`: IOMMU Status Register (`64-bit`, RW1C / RO).
pub const MMIO_STATUS: usize = 0x2020;

/// `MMIO_CONTROL` bit 0: Master IOMMU translation enable (`IommuEn`).
pub const CTRL_IOMMU_EN: u64 = 1 << 0;
/// `MMIO_CONTROL` bit 2: Event Log enable (`EventLogEn`).
pub const CTRL_EVENT_LOG_EN: u64 = 1 << 2;
/// `MMIO_CONTROL` bit 10: Coherent table/buffer accesses (`Coherent`).
pub const CTRL_COHERENT: u64 = 1 << 10;
/// `MMIO_CONTROL` bit 12: Command Buffer enable (`CmdBufEn`).
pub const CTRL_CMD_BUF_EN: u64 = 1 << 12;

/// `MMIO_STATUS` bit 0: Event Log overflow (`EventOverflow`, RW1C).
pub const STATUS_EVENT_OVERFLOW: u64 = 1 << 0;
/// `MMIO_STATUS` bit 1: Event Log interrupt status (`EventLogInt`, RW1C).
pub const STATUS_EVENT_LOG_INT: u64 = 1 << 1;
/// `MMIO_STATUS` bit 2: Completion-Wait status (`ComWaitInt`, RW1C).
pub const STATUS_COM_WAIT_INT: u64 = 1 << 2;
/// Mask of RW1C status bits cleared during bring-up.
pub const STATUS_RW1C_ALL: u64 = STATUS_EVENT_OVERFLOW | STATUS_EVENT_LOG_INT | STATUS_COM_WAIT_INT;

const DTE_VALID: u64 = 1 << 0;
const DTE_TRANSLATION_VALID: u64 = 1 << 1;
const DTE_MODE_4LEVEL: u64 = 4 << 9;
const DTE_IR: u64 = 1 << 61;
const DTE_IW: u64 = 1 << 62;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_IR: u64 = 1 << 61;
const PTE_IW: u64 = 1 << 62;

const CMD_OPCODE_COMPLETION_WAIT: u64 = 0x1 << 60;
const CMD_OPCODE_INVAL_DEVTAB_ENTRY: u64 = 0x2 << 60;
const CMD_OPCODE_INVAL_IOMMU_PAGES: u64 = 0x3 << 60;

const EVT_CODE_IO_PAGE_FAULT: u8 = 0x2;
const EVT_IOPF_RW_WRITE: u64 = 1 << 53;
/// QEMU `hw/i386/amd_iommu.c` encodes `AMDVI_PERM_WRITE` (`1 << 1`) in `info[1]` (`word0` bit `49`).
const QEMU_EVT_IOPF_PERM_WRITE: u64 = 1 << 49;

/// Encode `MMIO_DEVTAB_BASE` (`0x0000`) for a 2 MiB (`65,536` DTE) Device Table.
pub const fn encode_devtab_base(phys_4k: u64) -> Result<u64, VtdError> {
    if phys_4k == 0 || (phys_4k & !PHYS_ADDR_MASK_52) != 0 {
        return Err(VtdError::InvalidAddress);
    }
    Ok(phys_4k | AMD_VI_DEVTAB_SIZE_BITS)
}

/// Encode `MMIO_CMDBUF_BASE` (`0x0008`) or `MMIO_EVTLOG_BASE` (`0x0010`) for a
/// 4 KiB (`256`-entry) ring buffer.
pub const fn encode_ring_base_4k(phys_4k: u64) -> Result<u64, VtdError> {
    if phys_4k == 0 || (phys_4k & !PHYS_ADDR_MASK_52) != 0 {
        return Err(VtdError::InvalidAddress);
    }
    Ok(phys_4k | (AMD_VI_RING_LEN_EXP_256 << 56))
}

/// 256-bit (`32`-byte) AMD-Vi Device Table Entry (`[u64; 4]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmdViDte {
    /// Four 64-bit words (`words[0]` carries `V`/`TV`/`Mode`/`PtRoot`/`IR`/`IW`;
    /// `words[1][15:0]` carries `DomainID`).
    pub words: [u64; 4],
}

impl AmdViDte {
    /// Hardware default-deny DTE (`V = 1, TV = 1, Mode = 4, IR = 0, IW = 0`)
    /// pointing at an empty (all-zero) 4 KiB root page table under
    /// [`AMD_VI_BLOCKED_DOMAIN_ID`].
    ///
    /// Note: in AMD-Vi, `V = 0` means *untranslated pass-through*, so default-deny
    /// MUST set `V = 1, TV = 1, Mode = 4`; clearing `IR`/`IW` aborts DMA at the DTE
    /// and logs `IO_PAGE_FAULT` on both real AMD-Vi silicon and QEMU `amd-iommu`.
    pub const fn blocked(empty_pt_root_phys: u64) -> Result<Self, VtdError> {
        if empty_pt_root_phys == 0 || (empty_pt_root_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self {
            words: [
                DTE_VALID | DTE_TRANSLATION_VALID | DTE_MODE_4LEVEL | empty_pt_root_phys,
                AMD_VI_BLOCKED_DOMAIN_ID as u64,
                0,
                0,
            ],
        })
    }

    /// Active 4-level (`48`-bit IOVA) translated DTE for `domain_id >= 2`.
    pub const fn translated(pt_root_phys: u64, domain_id: u16) -> Result<Self, VtdError> {
        if pt_root_phys == 0 || (pt_root_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        if domain_id <= AMD_VI_BLOCKED_DOMAIN_ID {
            return Err(VtdError::ReservedDomainId);
        }
        Ok(Self {
            words: [
                DTE_VALID
                    | DTE_TRANSLATION_VALID
                    | DTE_MODE_4LEVEL
                    | pt_root_phys
                    | DTE_IR
                    | DTE_IW,
                domain_id as u64,
                0,
                0,
            ],
        })
    }

    /// Extract 16-bit `DomainID`.
    pub const fn domain_id(&self) -> u16 {
        (self.words[1] & 0xFFFF) as u16
    }
}

/// 64-bit AMD-Vi Host I/O Page Table Entry (`PR`, `NextLevel`, `IR`, `IW`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmdViPte(pub u64);

impl AmdViPte {
    /// Non-present PTE (`0`).
    pub const EMPTY: Self = Self(0);

    /// Directory PTE at `level` (`4 -> next=3`, `3 -> next=2`, `2 -> next=1`).
    ///
    /// Sets `IR | IW` because AMD-Vi ANDs read/write permissions across every
    /// level of the page-table walk.
    pub const fn directory(child_table_phys: u64, next_level: u8) -> Result<Self, VtdError> {
        if child_table_phys == 0
            || (child_table_phys & !PHYS_ADDR_MASK_52) != 0
            || next_level == 0
            || next_level > 3
        {
            return Err(VtdError::InvalidAddress);
        }
        Ok(Self(
            PTE_PRESENT | ((next_level as u64) << 9) | child_table_phys | PTE_IR | PTE_IW,
        ))
    }

    /// 4 KiB leaf PTE (`NextLevel = 0`).
    pub const fn leaf_4k(page_phys: u64, readable: bool, writable: bool) -> Result<Self, VtdError> {
        if !readable && !writable {
            return Err(VtdError::InvalidRange);
        }
        if (page_phys & !PHYS_ADDR_MASK_52) != 0 {
            return Err(VtdError::InvalidAddress);
        }
        let mut raw = PTE_PRESENT | page_phys;
        if readable {
            raw |= PTE_IR;
        }
        if writable {
            raw |= PTE_IW;
        }
        Ok(Self(raw))
    }

    /// True if `PR` (`bit 0`) is set.
    pub const fn is_present(self) -> bool {
        (self.0 & PTE_PRESENT) != 0
    }

    /// `NextLevel` (`bits[11:9]`): `1..=3` for directories, `0` for 4 KiB leaves.
    pub const fn next_level(self) -> u8 {
        ((self.0 >> 9) & 0x7) as u8
    }

    /// Referenced 4 KiB physical address when present.
    pub const fn addr_4k(self) -> Option<u64> {
        if self.is_present() {
            Some(self.0 & PHYS_ADDR_MASK_52)
        } else {
            None
        }
    }
}

/// 128-bit (`16`-byte) AMD-Vi Command Buffer entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmdViCommand {
    /// Lower 64-bit word (`word0[63:60]` = opcode).
    pub lo: u64,
    /// Upper 64-bit word.
    pub hi: u64,
}

impl AmdViCommand {
    /// `INVALIDATE_DEVTAB_ENTRY` (`Opcode = 0x2`) for `bdf`.
    pub const fn invalidate_devtab_entry(bdf: u16) -> Self {
        Self {
            lo: CMD_OPCODE_INVAL_DEVTAB_ENTRY | (bdf as u64),
            hi: 0,
        }
    }

    /// `INVALIDATE_IOMMU_PAGES` (`Opcode = 0x3`) covering the entire 52-bit
    /// IOVA space (`Address[50:12] = all 1s`, `bit 51 = 0`, `PDE = 1`, `S = 1`)
    /// of `domain_id`.
    pub const fn invalidate_domain_all(domain_id: u16) -> Self {
        Self {
            lo: CMD_OPCODE_INVAL_IOMMU_PAGES | ((domain_id as u64) << 32),
            hi: 0x0007_FFFF_FFFF_F000 | (1 << 1) | (1 << 0),
        }
    }

    /// `COMPLETION_WAIT` (`Opcode = 0x1`) with `f = 1` (flush) and `i = 1`
    /// (assert `MMIO_STATUS.ComWaitInt` when prior commands retire).
    pub const fn completion_wait_status() -> Self {
        Self {
            lo: CMD_OPCODE_COMPLETION_WAIT | (1 << 2) | (1 << 1),
            hi: 0,
        }
    }
}

/// Advance a 4 KiB AMD-Vi ring byte offset (`0, 16, ..., 4080 -> 0`).
pub const fn advance_ring_offset_4k(offset: u64) -> u64 {
    (offset.wrapping_add(AMD_VI_RING_ENTRY_BYTES as u64)) & AMD_VI_RING_OFFSET_MASK
}

/// Decode one 128-bit AMD-Vi Event Log entry (`word0`, `word1`) into a
/// unified [`FaultRecord`].
pub const fn decode_amd_vi_event(unit_index: u8, word0: u64, word1: u64) -> Option<FaultRecord> {
    let code = ((word0 >> 60) & 0xF) as u8;
    if code == 0 {
        return None;
    }
    let source_bdf = (word0 & 0xFFFF) as u16;
    let domain_id = ((word0 >> 32) & 0xFFFF) as u16;
    let is_write = (word0 & (EVT_IOPF_RW_WRITE | QEMU_EVT_IOPF_PERM_WRITE)) != 0;
    let kind = if code == EVT_CODE_IO_PAGE_FAULT {
        if domain_id == AMD_VI_BLOCKED_DOMAIN_ID {
            FaultKind::ContextNotPresent
        } else if is_write {
            FaultKind::WriteNotPermitted
        } else {
            FaultKind::ReadNotPermitted
        }
    } else {
        FaultKind::Other(code)
    };
    Some(FaultRecord {
        unit_index,
        reason_code: code,
        kind,
        is_read: !is_write,
        source_bdf,
        fault_iova: word1 & !PAGE_OFFSET_MASK,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amd_vi_dte_blocked_and_translated_invariants() -> Result<(), VtdError> {
        let blocked = AmdViDte::blocked(0x0010_2000)?;
        assert_eq!(blocked.words[0] & 0x3, 0x3); // V=1, TV=1
        assert_eq!((blocked.words[0] >> 9) & 0x7, 4); // 4-level mode
        assert_eq!(blocked.words[0] & (DTE_IR | DTE_IW), 0);
        assert_eq!(blocked.domain_id(), AMD_VI_BLOCKED_DOMAIN_ID);

        assert_eq!(
            AmdViDte::translated(0x0020_0000, 0),
            Err(VtdError::ReservedDomainId)
        );
        assert_eq!(
            AmdViDte::translated(0x0020_0000, AMD_VI_BLOCKED_DOMAIN_ID),
            Err(VtdError::ReservedDomainId)
        );
        let active = AmdViDte::translated(0x0020_0000, 3)?;
        assert_eq!(active.domain_id(), 3);
        assert_eq!(active.words[0] & PHYS_ADDR_MASK_52, 0x0020_0000);
        Ok(())
    }

    #[test]
    fn test_amd_vi_pte_levels_and_permissions() -> Result<(), VtdError> {
        let l4 = AmdViPte::directory(0x0040_0000, 3)?;
        assert!(l4.is_present());
        assert_eq!(l4.next_level(), 3);
        assert_eq!(l4.addr_4k(), Some(0x0040_0000));
        assert_ne!(l4.0 & PTE_IR, 0);
        assert_ne!(l4.0 & PTE_IW, 0);

        let leaf = AmdViPte::leaf_4k(0x0480_0000, true, true)?;
        assert!(leaf.is_present());
        assert_eq!(leaf.next_level(), 0);
        assert_eq!(leaf.addr_4k(), Some(0x0480_0000));
        Ok(())
    }

    #[test]
    fn test_amd_vi_commands_and_event_decoding() -> Result<(), &'static str> {
        let dte_inv = AmdViCommand::invalidate_devtab_entry(0x0018);
        assert_eq!(dte_inv.lo >> 60, 0x2);
        assert_eq!(dte_inv.lo & 0xFFFF, 0x0018);

        let dom_inv = AmdViCommand::invalidate_domain_all(3);
        assert_eq!(dom_inv.lo >> 60, 0x3);
        assert_eq!((dom_inv.lo >> 32) & 0xFFFF, 3);
        assert_eq!(dom_inv.hi & 0x3, 0x3);

        // IO_PAGE_FAULT write on lease domain 3 -> WriteNotPermitted
        let w0_canary = (2u64 << 60) | EVT_IOPF_RW_WRITE | (3u64 << 32) | 0x0020;
        let rec = decode_amd_vi_event(0, w0_canary, 0x1234_5678).ok_or("fault")?;
        assert_eq!(rec.kind, FaultKind::WriteNotPermitted);
        assert!(!rec.is_read);
        assert_eq!(rec.source_bdf, 0x0020);
        assert_eq!(rec.fault_iova, 0x1234_5000);

        // IO_PAGE_FAULT on blocked domain 1 (revoked/unattached) -> ContextNotPresent
        let w0_revoked = (2u64 << 60) | EVT_IOPF_RW_WRITE | (1u64 << 32) | 0x0020;
        let rev = decode_amd_vi_event(0, w0_revoked, 0x0080_0080).ok_or("revoked fault")?;
        assert_eq!(rev.kind, FaultKind::ContextNotPresent);
        assert_eq!(rev.fault_iova, 0x0080_0000);
        Ok(())
    }
}
