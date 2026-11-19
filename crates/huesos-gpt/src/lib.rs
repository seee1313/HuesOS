//! Pure `no_std + alloc` Protective MBR & GPT partition table engine for HuesOS.
//!
//! Used both by `/bin/fdisk.elf` and host unit tests (`make test`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Standard 512-byte LBA size used by MBR and GPT headers.
pub const LBA_SIZE: usize = 512;
/// GPT signature bytes `"EFI PART"`.
pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";
/// GPT revision 1.0.
pub const GPT_REVISION_1_0: u32 = 0x0001_0000;
/// Standard GPT header size in bytes.
pub const GPT_HEADER_SIZE: u32 = 92;
/// Standard GPT partition entry size in bytes.
pub const GPT_ENTRY_SIZE: usize = 128;
/// Default number of GPT partition entries (32 sectors * 4 entries/sector).
pub const DEFAULT_ENTRY_COUNT: u32 = 128;
/// Number of 512B sectors occupied by 128 entries.
pub const DEFAULT_ENTRY_SECTORS: u64 = 32;
/// Default 1 MiB alignment in 512B LBAs.
pub const ALIGN_1MIB_LBAS: u64 = 2048;
/// 4 KiB alignment in 512B LBAs.
pub const ALIGN_4KIB_LBAS: u64 = 8;

/// Well-known UEFI / HuesOS partition type GUIDs (canonical RFC 4122 big-endian fields,
/// converted to mixed-endian on disk by [`Guid`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const ZERO: Self = Self([0; 16]);

    /// Construct from standard big-endian UUID components (`a-b-c-d-e`).
    pub const fn from_fields(a: u32, b: u16, c: u16, d: [u8; 8]) -> Self {
        let ab = a.to_le_bytes();
        let bb = b.to_le_bytes();
        let cb = c.to_le_bytes();
        Self([
            ab[0], ab[1], ab[2], ab[3], bb[0], bb[1], cb[0], cb[1], d[0], d[1], d[2], d[3], d[4],
            d[5], d[6], d[7],
        ])
    }

    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Parse standard UUID string `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` or friendly alias.
    pub fn parse_type(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hxfs" | "hxfs7" | "huesos" => Some(GUID_HXFS_V7),
            "esp" | "efi" => Some(GUID_ESP),
            "linux" | "linux-fs" => Some(GUID_LINUX_FS),
            "swap" | "linux-swap" => Some(GUID_LINUX_SWAP),
            "basic" | "msdata" | "fat" | "ntfs" => Some(GUID_MS_BASIC_DATA),
            _ => Self::parse_uuid(s),
        }
    }

    pub fn parse_uuid(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        if parts.len() != 5 {
            return None;
        }
        let a = u32::from_str_radix(parts[0], 16).ok()?;
        let b = u16::from_str_radix(parts[1], 16).ok()?;
        let c = u16::from_str_radix(parts[2], 16).ok()?;
        if parts[3].len() != 4 || parts[4].len() != 12 {
            return None;
        }
        let d0 = u16::from_str_radix(parts[3], 16).ok()?.to_be_bytes();
        let mut d = [0u8; 8];
        d[0] = d0[0];
        d[1] = d0[1];
        for i in 0..6 {
            d[2 + i] = u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self::from_fields(a, b, c, d))
    }

    pub fn format_uuid(&self) -> String {
        let a = u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let b = u16::from_le_bytes([self.0[4], self.0[5]]);
        let c = u16::from_le_bytes([self.0[6], self.0[7]]);
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            a,
            b,
            c,
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        )
    }

    pub fn type_label(&self) -> String {
        if *self == GUID_HXFS_V7 {
            String::from("hxfs")
        } else if *self == GUID_ESP {
            String::from("esp")
        } else if *self == GUID_LINUX_FS {
            String::from("linux")
        } else if *self == GUID_LINUX_SWAP {
            String::from("swap")
        } else if *self == GUID_MS_BASIC_DATA {
            String::from("basic")
        } else {
            self.format_uuid()
        }
    }
}

/// HuesOS HxFS v7 partition type GUID (`48584653-0007-4855-4553-4f5356374750`).
pub const GUID_HXFS_V7: Guid = Guid::from_fields(
    0x4858_4653,
    0x0007,
    0x4855,
    [0x45, 0x53, 0x4f, 0x53, 0x56, 0x37, 0x47, 0x50],
);
/// EFI System Partition GUID (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`).
pub const GUID_ESP: Guid = Guid::from_fields(
    0xC12A_7328,
    0xF81F,
    0x11D2,
    [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);
/// Linux Filesystem Data GUID (`0FC63DAF-8483-4772-8E79-3D69D8477DE4`).
pub const GUID_LINUX_FS: Guid = Guid::from_fields(
    0x0FC6_3DAF,
    0x8483,
    0x4772,
    [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
);
/// Linux Swap GUID (`0657FD6D-A4AB-43C4-84E5-0933C84B4F4F`).
pub const GUID_LINUX_SWAP: Guid = Guid::from_fields(
    0x0657_FD6D,
    0xA4AB,
    0x43C4,
    [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F],
);
/// Microsoft Basic Data GUID (`EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`).
pub const GUID_MS_BASIC_DATA: Guid = Guid::from_fields(
    0xEBD0_A0A2,
    0xB9E5,
    0x4433,
    [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
);

/// IEEE 802.3 CRC32 (reflected polynomial `0xEDB8_8320`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Protective / Legacy MBR partition record (`16` bytes at `0x1BE..0x1FE`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MbrEntry {
    pub boot_indicator: u8,
    pub os_type: u8,
    pub start_lba: u32,
    pub size_lbas: u32,
}

/// Decoded LBA 0 MBR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mbr {
    pub entries: [MbrEntry; 4],
    pub valid_sig: bool,
}

impl Mbr {
    pub fn protective(disk_lbas: u64) -> Self {
        let clamped = disk_lbas.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
        let zero = MbrEntry {
            boot_indicator: 0,
            os_type: 0,
            start_lba: 0,
            size_lbas: 0,
        };
        Self {
            entries: [
                MbrEntry {
                    boot_indicator: 0,
                    os_type: 0xEE,
                    start_lba: 1,
                    size_lbas: clamped,
                },
                zero,
                zero,
                zero,
            ],
            valid_sig: true,
        }
    }

    pub fn decode(sector: &[u8; LBA_SIZE]) -> Self {
        let valid_sig = sector[510] == 0x55 && sector[511] == 0xAA;
        let empty = MbrEntry {
            boot_indicator: 0,
            os_type: 0,
            start_lba: 0,
            size_lbas: 0,
        };
        let mut entries = [empty; 4];
        for (i, slot) in entries.iter_mut().enumerate() {
            let off = 446 + i * 16;
            *slot = MbrEntry {
                boot_indicator: sector[off],
                os_type: sector[off + 4],
                start_lba: u32::from_le_bytes([
                    sector[off + 8],
                    sector[off + 9],
                    sector[off + 10],
                    sector[off + 11],
                ]),
                size_lbas: u32::from_le_bytes([
                    sector[off + 12],
                    sector[off + 13],
                    sector[off + 14],
                    sector[off + 15],
                ]),
            };
        }
        Self { entries, valid_sig }
    }

    pub fn encode(&self) -> [u8; LBA_SIZE] {
        let mut sec = [0u8; LBA_SIZE];
        for (i, ent) in self.entries.iter().enumerate() {
            let off = 446 + i * 16;
            sec[off] = ent.boot_indicator;
            sec[off + 1] = 0x00;
            sec[off + 2] = if ent.os_type == 0xEE { 0x02 } else { 0x00 };
            sec[off + 3] = 0x00;
            sec[off + 4] = ent.os_type;
            if ent.os_type == 0xEE {
                sec[off + 5] = 0xFF;
                sec[off + 6] = 0xFF;
                sec[off + 7] = 0xFF;
            }
            sec[off + 8..off + 12].copy_from_slice(&ent.start_lba.to_le_bytes());
            sec[off + 12..off + 16].copy_from_slice(&ent.size_lbas.to_le_bytes());
        }
        sec[510] = 0x55;
        sec[511] = 0xAA;
        sec
    }

    pub fn is_protective_gpt(&self) -> bool {
        self.valid_sig
            && self
                .entries
                .iter()
                .any(|e| e.os_type == 0xEE && e.start_lba == 1)
    }
}

/// Decoded GPT header (92 bytes inside a 512-byte sector).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Guid,
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}

impl GptHeader {
    pub fn decode(sector: &[u8; LBA_SIZE]) -> Result<Self, String> {
        let sig: [u8; 8] = sector[0..8].try_into().unwrap_or([0; 8]);
        if sig != GPT_SIGNATURE {
            return Err(String::from("bad GPT signature (expected EFI PART)"));
        }
        let revision = u32::from_le_bytes([sector[8], sector[9], sector[10], sector[11]]);
        let header_size = u32::from_le_bytes([sector[12], sector[13], sector[14], sector[15]]);
        if !(92..=512).contains(&header_size) {
            return Err(format!("invalid GPT header_size {header_size}"));
        }
        let header_crc32 = u32::from_le_bytes([sector[16], sector[17], sector[18], sector[19]]);
        let mut copy = [0u8; LBA_SIZE];
        copy[..header_size as usize].copy_from_slice(&sector[..header_size as usize]);
        copy[16..20].fill(0);
        let actual_crc = crc32(&copy[..header_size as usize]);
        if actual_crc != header_crc32 {
            return Err(format!(
                "GPT header CRC32 mismatch: header={header_crc32:#010x} computed={actual_crc:#010x}"
            ));
        }
        let my_lba = u64::from_le_bytes(sector[24..32].try_into().unwrap_or([0; 8]));
        let alternate_lba = u64::from_le_bytes(sector[32..40].try_into().unwrap_or([0; 8]));
        let first_usable_lba = u64::from_le_bytes(sector[40..48].try_into().unwrap_or([0; 8]));
        let last_usable_lba = u64::from_le_bytes(sector[48..56].try_into().unwrap_or([0; 8]));
        let disk_guid = Guid(sector[56..72].try_into().unwrap_or([0; 16]));
        let partition_entry_lba = u64::from_le_bytes(sector[72..80].try_into().unwrap_or([0; 8]));
        let num_partition_entries =
            u32::from_le_bytes([sector[80], sector[81], sector[82], sector[83]]);
        let size_of_partition_entry =
            u32::from_le_bytes([sector[84], sector[85], sector[86], sector[87]]);
        let partition_entry_array_crc32 =
            u32::from_le_bytes([sector[88], sector[89], sector[90], sector[91]]);

        Ok(Self {
            signature: sig,
            revision,
            header_size,
            header_crc32,
            my_lba,
            alternate_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entry_lba,
            num_partition_entries,
            size_of_partition_entry,
            partition_entry_array_crc32,
        })
    }

    pub fn encode(&mut self) -> [u8; LBA_SIZE] {
        let mut sec = [0u8; LBA_SIZE];
        sec[0..8].copy_from_slice(&self.signature);
        sec[8..12].copy_from_slice(&self.revision.to_le_bytes());
        sec[12..16].copy_from_slice(&self.header_size.to_le_bytes());
        // 16..20 zeroed for CRC
        sec[24..32].copy_from_slice(&self.my_lba.to_le_bytes());
        sec[32..40].copy_from_slice(&self.alternate_lba.to_le_bytes());
        sec[40..48].copy_from_slice(&self.first_usable_lba.to_le_bytes());
        sec[48..56].copy_from_slice(&self.last_usable_lba.to_le_bytes());
        sec[56..72].copy_from_slice(&self.disk_guid.0);
        sec[72..80].copy_from_slice(&self.partition_entry_lba.to_le_bytes());
        sec[80..84].copy_from_slice(&self.num_partition_entries.to_le_bytes());
        sec[84..88].copy_from_slice(&self.size_of_partition_entry.to_le_bytes());
        sec[88..92].copy_from_slice(&self.partition_entry_array_crc32.to_le_bytes());
        let crc = crc32(&sec[..self.header_size as usize]);
        self.header_crc32 = crc;
        sec[16..20].copy_from_slice(&crc.to_le_bytes());
        sec
    }
}

/// Decoded GPT partition entry (`128` bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GptEntry {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl GptEntry {
    pub fn is_unused(&self) -> bool {
        self.type_guid.is_zero()
    }

    pub fn size_lbas(&self) -> u64 {
        if self.ending_lba >= self.starting_lba {
            self.ending_lba - self.starting_lba + 1
        } else {
            0
        }
    }

    pub fn decode(raw: &[u8]) -> Self {
        let type_guid = Guid(raw[0..16].try_into().unwrap_or([0; 16]));
        let unique_guid = Guid(raw[16..32].try_into().unwrap_or([0; 16]));
        let starting_lba = u64::from_le_bytes(raw[32..40].try_into().unwrap_or([0; 8]));
        let ending_lba = u64::from_le_bytes(raw[40..48].try_into().unwrap_or([0; 8]));
        let attributes = u64::from_le_bytes(raw[48..56].try_into().unwrap_or([0; 8]));
        let mut units = [0u16; 36];
        for (i, u) in units.iter_mut().enumerate() {
            let off = 56 + i * 2;
            *u = u16::from_le_bytes([raw[off], raw[off + 1]]);
        }
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        let name = String::from_utf16_lossy(&units[..end]);
        Self {
            type_guid,
            unique_guid,
            starting_lba,
            ending_lba,
            attributes,
            name,
        }
    }

    pub fn encode(&self) -> [u8; GPT_ENTRY_SIZE] {
        let mut raw = [0u8; GPT_ENTRY_SIZE];
        raw[0..16].copy_from_slice(&self.type_guid.0);
        raw[16..32].copy_from_slice(&self.unique_guid.0);
        raw[32..40].copy_from_slice(&self.starting_lba.to_le_bytes());
        raw[40..48].copy_from_slice(&self.ending_lba.to_le_bytes());
        raw[48..56].copy_from_slice(&self.attributes.to_le_bytes());
        for (i, code) in self.name.encode_utf16().take(36).enumerate() {
            let off = 56 + i * 2;
            raw[off..off + 2].copy_from_slice(&code.to_le_bytes());
        }
        raw
    }
}

/// Abstract 512-byte LBA block I/O backend.
pub trait BlockIo512 {
    fn total_lbas(&self) -> u64;
    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String>;
    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String>;
    fn flush(&mut self) -> Result<(), String>;
}

/// Complete GPT disk state (Protective MBR + Primary/Backup headers + entries).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GptDisk {
    pub disk_lbas: u64,
    pub mbr: Mbr,
    pub primary: GptHeader,
    pub entries: Vec<GptEntry>,
}

/// Verification report returned by [`verify_disk_io`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyReport {
    pub ok: bool,
    pub protective_mbr: bool,
    pub primary_crc_ok: bool,
    pub backup_crc_ok: bool,
    pub entries_crc_ok: bool,
    pub overlaps: usize,
    pub alignment_warnings: usize,
    pub errors: Vec<String>,
}

impl GptDisk {
    /// Initialize a clean Protective MBR + GPT layout for a disk of `disk_lbas` 512B sectors.
    pub fn init_empty(disk_lbas: u64, seed: u64) -> Result<Self, String> {
        if disk_lbas < 100 {
            return Err(format!("disk too small for GPT ({disk_lbas} LBAs)"));
        }
        let mbr = Mbr::protective(disk_lbas);
        let first_usable = 2 + DEFAULT_ENTRY_SECTORS; // 34
        let backup_entries_lba = disk_lbas - 1 - DEFAULT_ENTRY_SECTORS;
        let last_usable = backup_entries_lba - 1;
        let disk_guid = deterministic_guid(seed, 0);
        let empty_entry = GptEntry {
            type_guid: Guid::ZERO,
            unique_guid: Guid::ZERO,
            starting_lba: 0,
            ending_lba: 0,
            attributes: 0,
            name: String::new(),
        };
        let entries = vec![empty_entry; DEFAULT_ENTRY_COUNT as usize];
        let array_crc = compute_entries_crc(&entries);
        let mut primary = GptHeader {
            signature: GPT_SIGNATURE,
            revision: GPT_REVISION_1_0,
            header_size: GPT_HEADER_SIZE,
            header_crc32: 0,
            my_lba: 1,
            alternate_lba: disk_lbas - 1,
            first_usable_lba: first_usable,
            last_usable_lba: last_usable,
            disk_guid,
            partition_entry_lba: 2,
            num_partition_entries: DEFAULT_ENTRY_COUNT,
            size_of_partition_entry: GPT_ENTRY_SIZE as u32,
            partition_entry_array_crc32: array_crc,
        };
        let _ = primary.encode();
        Ok(Self {
            disk_lbas,
            mbr,
            primary,
            entries,
        })
    }

    /// Read and validate Protective MBR + Primary GPT from `io`.
    pub fn read_from(io: &dyn BlockIo512) -> Result<Self, String> {
        let disk_lbas = io.total_lbas();
        let mut sec0 = [0u8; LBA_SIZE];
        io.read_lba(0, &mut sec0)?;
        let mbr = Mbr::decode(&sec0);

        let mut sec1 = [0u8; LBA_SIZE];
        io.read_lba(1, &mut sec1)?;
        let primary = GptHeader::decode(&sec1)?;
        if primary.size_of_partition_entry != GPT_ENTRY_SIZE as u32 {
            return Err(format!(
                "unsupported GPT entry size {}",
                primary.size_of_partition_entry
            ));
        }

        let entries = read_entry_array(
            io,
            primary.partition_entry_lba,
            primary.num_partition_entries,
        )?;
        let actual_arr_crc = compute_entries_crc(&entries);
        if actual_arr_crc != primary.partition_entry_array_crc32 {
            return Err(format!(
                "GPT partition array CRC32 mismatch: expected={:#010x} computed={:#010x}",
                primary.partition_entry_array_crc32, actual_arr_crc
            ));
        }

        Ok(Self {
            disk_lbas,
            mbr,
            primary,
            entries,
        })
    }

    /// Active (non-zero type GUID) partitions with 1-based partition number.
    pub fn active_partitions(&self) -> Vec<(usize, &GptEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_unused())
            .map(|(idx, e)| (idx + 1, e))
            .collect()
    }

    /// Format active partitions as TSV (`part\tstart\tend\tsize_mib\ttype\tname\tguid`).
    pub fn format_list_tsv(&self) -> String {
        let mut out = String::from("part\tstart\tend\tsize_mib\ttype\tname\tguid\n");
        for (part_num, ent) in self.active_partitions() {
            let size_mib = (ent.size_lbas() * LBA_SIZE as u64) / (1024 * 1024);
            let name = if ent.name.is_empty() {
                "-"
            } else {
                ent.name.as_str()
            };
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                part_num,
                ent.starting_lba,
                ent.ending_lba,
                size_mib,
                ent.type_guid.type_label(),
                name,
                ent.unique_guid.format_uuid()
            ));
        }
        out
    }

    /// Add a new partition aligned to 1 MiB (`2048` LBAs) by default.
    pub fn add_partition(
        &mut self,
        type_guid: Guid,
        requested_start: Option<u64>,
        size_lbas: u64,
        name: &str,
        seed: u64,
    ) -> Result<usize, String> {
        if size_lbas == 0 {
            return Err(String::from("partition size must be > 0"));
        }
        let slot_idx = self
            .entries
            .iter()
            .position(GptEntry::is_unused)
            .ok_or_else(|| String::from("GPT partition table is full"))?;

        let start = match requested_start {
            Some(s) => s,
            None => self.find_free_aligned(size_lbas, ALIGN_1MIB_LBAS)?,
        };
        let end = start
            .checked_add(size_lbas - 1)
            .ok_or_else(|| String::from("LBA overflow"))?;

        if start < self.primary.first_usable_lba || end > self.primary.last_usable_lba {
            return Err(format!(
                "range {}..={} outside usable LBAs {}..={}",
                start, end, self.primary.first_usable_lba, self.primary.last_usable_lba
            ));
        }
        if !start.is_multiple_of(ALIGN_4KIB_LBAS) {
            return Err(format!(
                "start LBA {start} is not 4 KiB-aligned (multiple of {ALIGN_4KIB_LBAS})"
            ));
        }

        for (i, existing) in self.entries.iter().enumerate() {
            if !existing.is_unused()
                && ranges_overlap(start, end, existing.starting_lba, existing.ending_lba)
            {
                return Err(format!(
                    "range {start}..={end} overlaps partition {} ({}..={})",
                    i + 1,
                    existing.starting_lba,
                    existing.ending_lba
                ));
            }
        }

        self.entries[slot_idx] = GptEntry {
            type_guid,
            unique_guid: deterministic_guid(seed, (slot_idx + 1) as u64),
            starting_lba: start,
            ending_lba: end,
            attributes: 0,
            name: String::from(name),
        };
        self.recompute_crcs();
        Ok(slot_idx + 1)
    }

    /// Delete 1-based partition index.
    pub fn delete_partition(&mut self, part_num: usize) -> Result<(), String> {
        let idx = part_num
            .checked_sub(1)
            .ok_or_else(|| String::from("partition numbers are 1-based"))?;
        let ent = self
            .entries
            .get_mut(idx)
            .ok_or_else(|| format!("invalid partition number {part_num}"))?;
        if ent.is_unused() {
            return Err(format!("partition {part_num} is already empty"));
        }
        *ent = GptEntry {
            type_guid: Guid::ZERO,
            unique_guid: Guid::ZERO,
            starting_lba: 0,
            ending_lba: 0,
            attributes: 0,
            name: String::new(),
        };
        self.recompute_crcs();
        Ok(())
    }

    /// Resize 1-based partition to `new_size_lbas`, verifying free space and no overlaps.
    pub fn resize_partition(&mut self, part_num: usize, new_size_lbas: u64) -> Result<(), String> {
        if new_size_lbas == 0 {
            return Err(String::from("new size must be > 0"));
        }
        let idx = part_num
            .checked_sub(1)
            .ok_or_else(|| String::from("partition numbers are 1-based"))?;
        let start = {
            let ent = self
                .entries
                .get(idx)
                .ok_or_else(|| format!("invalid partition number {part_num}"))?;
            if ent.is_unused() {
                return Err(format!("partition {part_num} is empty"));
            }
            ent.starting_lba
        };
        let new_end = start
            .checked_add(new_size_lbas - 1)
            .ok_or_else(|| String::from("LBA overflow"))?;
        if new_end > self.primary.last_usable_lba {
            return Err(format!(
                "new end {new_end} exceeds last_usable_lba {}",
                self.primary.last_usable_lba
            ));
        }
        for (i, existing) in self.entries.iter().enumerate() {
            if i != idx
                && !existing.is_unused()
                && ranges_overlap(start, new_end, existing.starting_lba, existing.ending_lba)
            {
                return Err(format!(
                    "resized partition overlaps partition {} ({}..={})",
                    i + 1,
                    existing.starting_lba,
                    existing.ending_lba
                ));
            }
        }
        self.entries[idx].ending_lba = new_end;
        self.recompute_crcs();
        Ok(())
    }

    fn find_free_aligned(&self, size_lbas: u64, align: u64) -> Result<u64, String> {
        let mut occupied: Vec<(u64, u64)> = self
            .entries
            .iter()
            .filter(|e| !e.is_unused())
            .map(|e| (e.starting_lba, e.ending_lba))
            .collect();
        occupied.sort_by_key(|&(s, _)| s);

        let mut candidate = align_up(self.primary.first_usable_lba, align);
        for (occ_start, occ_end) in occupied {
            if candidate + size_lbas - 1 < occ_start {
                return Ok(candidate);
            }
            if candidate <= occ_end {
                candidate = align_up(occ_end + 1, align);
            }
        }
        if candidate + size_lbas - 1 <= self.primary.last_usable_lba {
            Ok(candidate)
        } else {
            Err(String::from("insufficient contiguous free space on disk"))
        }
    }

    fn recompute_crcs(&mut self) {
        self.primary.partition_entry_array_crc32 = compute_entries_crc(&self.entries);
        let _ = self.primary.encode();
    }

    /// Write Protective MBR, Primary GPT, and Backup GPT (skipped if `dry_run == true`).
    pub fn write_to(&mut self, io: &mut dyn BlockIo512, dry_run: bool) -> Result<(), String> {
        self.recompute_crcs();
        if dry_run {
            return Ok(());
        }
        let sec0 = self.mbr.encode();
        io.write_lba(0, &sec0)?;

        let entry_sectors = entry_sector_bytes(&self.entries);
        let mut primary = self.primary;
        let p_sec = primary.encode();
        io.write_lba(primary.my_lba, &p_sec)?;
        for (i, chunk) in entry_sectors.iter().enumerate() {
            io.write_lba(primary.partition_entry_lba + i as u64, chunk)?;
        }

        let backup_lba = primary.alternate_lba;
        let backup_entries_lba = backup_lba
            .checked_sub(entry_sectors.len() as u64)
            .ok_or_else(|| String::from("invalid backup header LBA"))?;
        let mut backup = primary;
        backup.my_lba = backup_lba;
        backup.alternate_lba = primary.my_lba;
        backup.partition_entry_lba = backup_entries_lba;
        let b_sec = backup.encode();
        for (i, chunk) in entry_sectors.iter().enumerate() {
            io.write_lba(backup_entries_lba + i as u64, chunk)?;
        }
        io.write_lba(backup_lba, &b_sec)?;
        io.flush()?;
        Ok(())
    }
}

/// Verify Protective MBR + Primary GPT + Backup GPT + overlaps + alignment on `io`.
pub fn verify_disk_io(io: &dyn BlockIo512) -> VerifyReport {
    let mut errors = Vec::new();
    let mut sec0 = [0u8; LBA_SIZE];
    let protective_mbr = match io.read_lba(0, &mut sec0) {
        Ok(()) => {
            let mbr = Mbr::decode(&sec0);
            if !mbr.is_protective_gpt() {
                errors.push(String::from("LBA 0 is not a Protective MBR (0xEE)"));
                false
            } else {
                true
            }
        }
        Err(e) => {
            errors.push(e);
            false
        }
    };

    let mut sec1 = [0u8; LBA_SIZE];
    let primary = match io.read_lba(1, &mut sec1) {
        Ok(()) => match GptHeader::decode(&sec1) {
            Ok(h) => Some(h),
            Err(e) => {
                errors.push(format!("primary: {e}"));
                None
            }
        },
        Err(e) => {
            errors.push(format!("primary read: {e}"));
            None
        }
    };
    let primary_crc_ok = primary.is_some();

    let mut entries_crc_ok = false;
    let mut backup_crc_ok = false;
    let mut overlaps = 0usize;
    let mut alignment_warnings = 0usize;

    if let Some(p) = primary {
        match read_entry_array(io, p.partition_entry_lba, p.num_partition_entries) {
            Ok(entries) => {
                let actual_crc = compute_entries_crc(&entries);
                if actual_crc == p.partition_entry_array_crc32 {
                    entries_crc_ok = true;
                } else {
                    errors.push(format!(
                        "primary entry CRC32 mismatch: {:#010x} != {:#010x}",
                        actual_crc, p.partition_entry_array_crc32
                    ));
                }

                let active: Vec<(usize, &GptEntry)> = entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| !e.is_unused())
                    .map(|(i, e)| (i + 1, e))
                    .collect();

                for (idx, (_, a)) in active.iter().enumerate() {
                    if a.starting_lba < p.first_usable_lba
                        || a.ending_lba > p.last_usable_lba
                        || a.ending_lba < a.starting_lba
                    {
                        errors.push(format!(
                            "partition out of usable bounds ({}..={})",
                            a.starting_lba, a.ending_lba
                        ));
                    }
                    if !a.starting_lba.is_multiple_of(ALIGN_1MIB_LBAS) {
                        alignment_warnings += 1;
                    }
                    for (_, b) in active.iter().skip(idx + 1) {
                        if ranges_overlap(
                            a.starting_lba,
                            a.ending_lba,
                            b.starting_lba,
                            b.ending_lba,
                        ) {
                            overlaps += 1;
                            errors.push(format!(
                                "overlapping partitions ({}..={}) and ({}..={})",
                                a.starting_lba, a.ending_lba, b.starting_lba, b.ending_lba
                            ));
                        }
                    }
                }
            }
            Err(e) => errors.push(e),
        }

        let mut b_sec = [0u8; LBA_SIZE];
        match io.read_lba(p.alternate_lba, &mut b_sec) {
            Ok(()) => match GptHeader::decode(&b_sec) {
                Ok(b) => {
                    if b.disk_guid != p.disk_guid
                        || b.partition_entry_array_crc32 != p.partition_entry_array_crc32
                    {
                        errors.push(String::from("backup GPT header disagrees with primary"));
                    } else {
                        backup_crc_ok = true;
                    }
                }
                Err(e) => errors.push(format!("backup: {e}")),
            },
            Err(e) => errors.push(format!("backup read: {e}")),
        }
    }

    let ok =
        protective_mbr && primary_crc_ok && backup_crc_ok && entries_crc_ok && errors.is_empty();
    VerifyReport {
        ok,
        protective_mbr,
        primary_crc_ok,
        backup_crc_ok,
        entries_crc_ok,
        overlaps,
        alignment_warnings,
        errors,
    }
}

/// Parse size strings like `"64M"`, `"1G"`, `"4096K"`, or raw LBA count `"2048"`.
pub fn parse_size_lbas(spec: &str) -> Result<u64, String> {
    let s = spec.trim();
    if let Some(num) = s.strip_suffix(['G', 'g']).or_else(|| s.strip_suffix("GiB")) {
        let v = num
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid size '{spec}'"))?;
        return Ok(v * (1024 * 1024 * 1024 / LBA_SIZE as u64));
    }
    if let Some(num) = s.strip_suffix(['M', 'm']).or_else(|| s.strip_suffix("MiB")) {
        let v = num
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid size '{spec}'"))?;
        return Ok(v * (1024 * 1024 / LBA_SIZE as u64));
    }
    if let Some(num) = s.strip_suffix(['K', 'k']).or_else(|| s.strip_suffix("KiB")) {
        let v = num
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid size '{spec}'"))?;
        return Ok((v * 1024).div_ceil(LBA_SIZE as u64));
    }
    s.parse::<u64>()
        .map_err(|_| format!("invalid LBA count '{spec}'"))
}

fn align_up(v: u64, align: u64) -> u64 {
    if align <= 1 {
        v
    } else {
        v.div_ceil(align) * align
    }
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start <= b_end && b_start <= a_end
}

fn compute_entries_crc(entries: &[GptEntry]) -> u32 {
    let mut raw = Vec::with_capacity(entries.len() * GPT_ENTRY_SIZE);
    for ent in entries {
        raw.extend_from_slice(&ent.encode());
    }
    crc32(&raw)
}

fn entry_sector_bytes(entries: &[GptEntry]) -> Vec<[u8; LBA_SIZE]> {
    let mut raw = Vec::with_capacity(entries.len() * GPT_ENTRY_SIZE);
    for ent in entries {
        raw.extend_from_slice(&ent.encode());
    }
    let sector_count = raw.len().div_ceil(LBA_SIZE);
    let mut out = vec![[0u8; LBA_SIZE]; sector_count];
    for (i, sec) in out.iter_mut().enumerate() {
        let start = i * LBA_SIZE;
        let end = (start + LBA_SIZE).min(raw.len());
        sec[..end - start].copy_from_slice(&raw[start..end]);
    }
    out
}

fn read_entry_array(
    io: &dyn BlockIo512,
    start_lba: u64,
    count: u32,
) -> Result<Vec<GptEntry>, String> {
    let total_bytes = (count as usize) * GPT_ENTRY_SIZE;
    let sectors = total_bytes.div_ceil(LBA_SIZE);
    let mut raw = Vec::with_capacity(sectors * LBA_SIZE);
    let mut buf = [0u8; LBA_SIZE];
    for i in 0..sectors {
        io.read_lba(start_lba + i as u64, &mut buf)?;
        raw.extend_from_slice(&buf);
    }
    let mut entries = Vec::with_capacity(count as usize);
    for idx in 0..count as usize {
        let off = idx * GPT_ENTRY_SIZE;
        entries.push(GptEntry::decode(&raw[off..off + GPT_ENTRY_SIZE]));
    }
    Ok(entries)
}

fn deterministic_guid(seed: u64, index: u64) -> Guid {
    let x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ index.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let y = x.rotate_left(27).wrapping_add(0x94D0_49BB_1331_11EB);
    let a = (x as u32) | 1;
    let b = (x >> 32) as u16;
    let c = (((y >> 16) as u16) & 0x0FFF) | 0x4000;
    let mut d = y.to_le_bytes();
    d[0] = (d[0] & 0x3F) | 0x80;
    Guid::from_fields(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemDisk {
        sectors: Vec<[u8; LBA_SIZE]>,
        writes: usize,
    }

    impl MemDisk {
        fn new(lbas: usize) -> Self {
            Self {
                sectors: vec![[0u8; LBA_SIZE]; lbas],
                writes: 0,
            }
        }
    }

    impl BlockIo512 for MemDisk {
        fn total_lbas(&self) -> u64 {
            self.sectors.len() as u64
        }

        fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String> {
            let sec = self
                .sectors
                .get(lba as usize)
                .ok_or_else(|| String::from("read out of bounds"))?;
            *out = *sec;
            Ok(())
        }

        fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String> {
            let sec = self
                .sectors
                .get_mut(lba as usize)
                .ok_or_else(|| String::from("write out of bounds"))?;
            *sec = *data;
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_gpt_lifecycle_verify_add_resize_delete_and_dry_run() {
        // 64 MiB virtual disk = 131072 512B LBAs
        let mut disk = MemDisk::new(131_072);
        let Ok(mut gpt) = GptDisk::init_empty(disk.total_lbas(), 0x1234_5678) else {
            assert!(false, "init_empty");
            return;
        };
        assert!(gpt.write_to(&mut disk, false).is_ok());

        let report = verify_disk_io(&disk);
        assert!(report.ok);
        assert!(report.protective_mbr);
        assert!(report.primary_crc_ok);
        assert!(report.backup_crc_ok);
        assert!(report.entries_crc_ok);
        assert_eq!(report.overlaps, 0);

        // Add ESP (8 MiB) + HxFS v7 (16 MiB)
        let Ok(p1) = gpt.add_partition(GUID_ESP, None, 16_384, "EFI", 1) else {
            assert!(false, "add ESP");
            return;
        };
        assert_eq!(p1, 1);
        let Ok(p2) = gpt.add_partition(GUID_HXFS_V7, None, 32_768, "HxFS-Root", 2) else {
            assert!(false, "add HxFS");
            return;
        };
        assert_eq!(p2, 2);

        // Dry run must NOT write sectors
        let writes_before = disk.writes;
        assert!(gpt.write_to(&mut disk, true).is_ok());
        assert_eq!(disk.writes, writes_before);

        assert!(gpt.write_to(&mut disk, false).is_ok());
        let Ok(reloaded) = GptDisk::read_from(&disk) else {
            assert!(false, "reload gpt");
            return;
        };
        assert_eq!(reloaded.active_partitions().len(), 2);
        assert!(verify_disk_io(&disk).ok);

        // Overlap rejection
        let overlap_res = gpt.add_partition(GUID_LINUX_SWAP, Some(2048), 4096, "bad", 3);
        assert!(overlap_res.is_err());

        // Resize partition 2 smaller then larger, delete partition 1
        assert!(gpt.resize_partition(2, 40_960).is_ok());
        assert!(gpt.delete_partition(1).is_ok());
        assert!(gpt.write_to(&mut disk, false).is_ok());
        assert!(verify_disk_io(&disk).ok);

        // Corrupt primary header byte -> verify detects CRC failure
        disk.sectors[1][24] ^= 0xFF;
        let bad = verify_disk_io(&disk);
        assert!(!bad.ok);
        assert!(!bad.primary_crc_ok);
    }
}
