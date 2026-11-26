//! `#![forbid(unsafe_code)]` FAT16 / FAT32 + VFAT Long File Name (`LFN`)
//! filesystem driver with automatic GPT / MBR / superfloppy partition discovery.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// 512-byte sector block device trait consumed by [`FatFileSystem`].
pub trait BlockDevice {
    fn read_sector(&self, sector: u32, buf: &mut [u8]) -> Result<(), DriverError>;
    fn write_sector(&self, sector: u32, buf: &[u8]) -> Result<(), DriverError>;
    fn sector_size(&self) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    ReadError,
    WriteError,
    InvalidSector,
    FileNotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    DiskFull,
    InvalidFat,
    PathTooLong,
    InvalidPath,
    BufferTooSmall,
}

/// Decoded BIOS Parameter Block for FAT16 / FAT32 boot sectors.
#[derive(Debug, Clone, Copy)]
pub struct FatBpb {
    pub jump: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_ent_count: u16,
    pub total_sectors_16: u16,
    pub media_type: u8,
    pub fat_size_16: u16,
    pub sectors_per_track: u16,
    pub head_count: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub fat_size_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
}

impl FatBpb {
    pub fn decode(boot: &[u8; 512]) -> Option<Self> {
        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
        let sectors_per_cluster = boot[13];
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]);
        let num_fats = boot[16];
        let root_ent_count = u16::from_le_bytes([boot[17], boot[18]]);
        let total_sectors_16 = u16::from_le_bytes([boot[19], boot[20]]);
        let media_type = boot[21];
        let fat_size_16 = u16::from_le_bytes([boot[22], boot[23]]);
        let sectors_per_track = u16::from_le_bytes([boot[24], boot[25]]);
        let head_count = u16::from_le_bytes([boot[26], boot[27]]);
        let hidden_sectors = u32::from_le_bytes([boot[28], boot[29], boot[30], boot[31]]);
        let total_sectors_32 = u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]);
        let fat_size_32 = u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]]);
        let ext_flags = u16::from_le_bytes([boot[40], boot[41]]);
        let fs_version = u16::from_le_bytes([boot[42], boot[43]]);
        let root_cluster = u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]);
        let fs_info_sector = u16::from_le_bytes([boot[48], boot[49]]);
        let backup_boot_sector = u16::from_le_bytes([boot[50], boot[51]]);

        if bytes_per_sector != 512
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || reserved_sectors == 0
            || num_fats == 0
            || (fat_size_16 == 0 && fat_size_32 == 0)
            || (total_sectors_16 == 0 && total_sectors_32 == 0)
        {
            return None;
        }
        if fat_size_16 == 0 && root_cluster < 2 {
            return None;
        }

        let mut jump = [0u8; 3];
        jump.copy_from_slice(&boot[0..3]);
        let mut oem_name = [0u8; 8];
        oem_name.copy_from_slice(&boot[3..11]);

        Some(Self {
            jump,
            oem_name,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_ent_count,
            total_sectors_16,
            media_type,
            fat_size_16,
            sectors_per_track,
            head_count,
            hidden_sectors,
            total_sectors_32,
            fat_size_32,
            ext_flags,
            fs_version,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
        })
    }

    /// True when the BPB describes a FAT32 volume (`BPB_FATSz16 == 0`).
    pub const fn is_fat32(&self) -> bool {
        self.fat_size_16 == 0
    }
}

/// Decoded 32-byte 8.3 directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: [u8; 8],
    pub ext: [u8; 3],
    pub attr: u8,
    pub reserved: u8,
    pub create_time_tenth: u8,
    pub create_time: u16,
    pub create_date: u16,
    pub last_access_date: u16,
    pub first_cluster_hi: u16,
    pub write_time: u16,
    pub write_date: u16,
    pub first_cluster_lo: u16,
    pub file_size: u32,
}

impl DirectoryEntry {
    pub const ATTR_READ_ONLY: u8 = 0x01;
    pub const ATTR_HIDDEN: u8 = 0x02;
    pub const ATTR_SYSTEM: u8 = 0x04;
    pub const ATTR_VOLUME_ID: u8 = 0x08;
    pub const ATTR_DIRECTORY: u8 = 0x10;
    pub const ATTR_ARCHIVE: u8 = 0x20;
    pub const ATTR_LFN: u8 = 0x0F;

    pub fn decode(raw: &[u8]) -> Self {
        let mut name = [0u8; 8];
        let mut ext = [0u8; 3];
        name.copy_from_slice(&raw[0..8]);
        ext.copy_from_slice(&raw[8..11]);
        Self {
            name,
            ext,
            attr: raw[11],
            reserved: raw[12],
            create_time_tenth: raw[13],
            create_time: u16::from_le_bytes([raw[14], raw[15]]),
            create_date: u16::from_le_bytes([raw[16], raw[17]]),
            last_access_date: u16::from_le_bytes([raw[18], raw[19]]),
            first_cluster_hi: u16::from_le_bytes([raw[20], raw[21]]),
            write_time: u16::from_le_bytes([raw[22], raw[23]]),
            write_date: u16::from_le_bytes([raw[24], raw[25]]),
            first_cluster_lo: u16::from_le_bytes([raw[26], raw[27]]),
            file_size: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
        }
    }

    pub fn encode(&self) -> [u8; 32] {
        let mut raw = [0u8; 32];
        raw[0..8].copy_from_slice(&self.name);
        raw[8..11].copy_from_slice(&self.ext);
        raw[11] = self.attr;
        raw[12] = self.reserved;
        raw[13] = self.create_time_tenth;
        raw[14..16].copy_from_slice(&self.create_time.to_le_bytes());
        raw[16..18].copy_from_slice(&self.create_date.to_le_bytes());
        raw[18..20].copy_from_slice(&self.last_access_date.to_le_bytes());
        raw[20..22].copy_from_slice(&self.first_cluster_hi.to_le_bytes());
        raw[22..24].copy_from_slice(&self.write_time.to_le_bytes());
        raw[24..26].copy_from_slice(&self.write_date.to_le_bytes());
        raw[26..28].copy_from_slice(&self.first_cluster_lo.to_le_bytes());
        raw[28..32].copy_from_slice(&self.file_size.to_le_bytes());
        raw
    }

    pub fn is_free(&self) -> bool {
        self.name[0] == 0x00 || self.name[0] == 0xE5
    }

    pub fn is_lfn(&self) -> bool {
        self.attr == Self::ATTR_LFN
    }

    pub fn is_directory(&self) -> bool {
        (self.attr & Self::ATTR_DIRECTORY) != 0
    }

    pub fn is_volume_label(&self) -> bool {
        !self.is_lfn() && (self.attr & Self::ATTR_VOLUME_ID) != 0
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    pub fn set_first_cluster(&mut self, cluster: u32, is_fat32: bool) {
        self.first_cluster_lo = (cluster & 0xFFFF) as u16;
        self.first_cluster_hi = if is_fat32 {
            ((cluster >> 16) & 0x0FFF) as u16
        } else {
            0
        };
    }

    pub fn short_name_11(&self) -> [u8; 11] {
        let mut out = [0u8; 11];
        out[0..8].copy_from_slice(&self.name);
        out[8..11].copy_from_slice(&self.ext);
        out
    }
}

/// High-level metadata for a resolved FAT file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatNodeInfo {
    pub is_dir: bool,
    pub size: u32,
    pub first_cluster: u32,
}

/// Single entry returned by [`FatFileSystem::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u32,
}

#[derive(Clone, Copy)]
struct EntrySlotLoc {
    sector: u32,
    slot: usize,
}

struct ResolvedRecord {
    entry: DirectoryEntry,
    loc: EntrySlotLoc,
    lfn_locs: Vec<EntrySlotLoc>,
}

#[derive(Clone, Copy)]
enum DirTarget {
    Fat16Root,
    ClusterChain(u32),
}

pub struct FatFileSystem<'a, D: BlockDevice> {
    device: &'a D,
    base_sector: u32,
    bpb: FatBpb,
    is_fat32: bool,
}

impl<'a, D: BlockDevice> FatFileSystem<'a, D> {
    /// Mount a FAT16/FAT32 volume starting at sector `0` of `device`.
    pub fn mount(device: &'a D) -> Result<Self, DriverError> {
        Self::mount_at(device, 0)
    }

    /// Mount a FAT16/FAT32 volume starting at `base_sector` of `device`.
    pub fn mount_at(device: &'a D, base_sector: u32) -> Result<Self, DriverError> {
        let mut boot = [0u8; 512];
        device.read_sector(base_sector, &mut boot)?;
        let bpb = FatBpb::decode(&boot).ok_or(DriverError::InvalidFat)?;
        Ok(Self {
            device,
            base_sector,
            bpb,
            is_fat32: bpb.fat_size_16 == 0,
        })
    }

    /// Automatically detect GPT, MBR, or raw superfloppy layout on `device` and
    /// mount the first valid FAT16/FAT32 partition (or LBA `0`).
    pub fn mount_auto(device: &'a D) -> Result<Self, DriverError> {
        let mut sec0 = [0u8; 512];
        device.read_sector(0, &mut sec0)?;

        // 1. Check GPT header at LBA 1 ("EFI PART").
        let mut sec1 = [0u8; 512];
        if device.read_sector(1, &mut sec1).is_ok() && &sec1[0..8] == b"EFI PART" {
            let entry_lba = u64::from_le_bytes([
                sec1[72], sec1[73], sec1[74], sec1[75], sec1[76], sec1[77], sec1[78], sec1[79],
            ]);
            let raw_num = u32::from_le_bytes([sec1[80], sec1[81], sec1[82], sec1[83]]);
            let num_entries = raw_num.min(128);
            let entry_size = u32::from_le_bytes([sec1[84], sec1[85], sec1[86], sec1[87]]) as usize;
            let lba_ok = (2..=u32::MAX as u64).contains(&entry_lba);
            if lba_ok && (128..=512).contains(&entry_size) {
                let per_sec = 512 / entry_size;
                if per_sec > 0 {
                    let mut idx = 0usize;
                    while idx < num_entries as usize {
                        let lba = (entry_lba as u32).saturating_add((idx / per_sec) as u32);
                        let off = (idx % per_sec) * entry_size;
                        let mut ebuf = [0u8; 512];
                        if device.read_sector(lba, &mut ebuf).is_err() {
                            break;
                        }
                        let type_guid = &ebuf[off..off + 16];
                        if type_guid.iter().any(|&b| b != 0) {
                            let first_lba = u64::from_le_bytes([
                                ebuf[off + 32],
                                ebuf[off + 33],
                                ebuf[off + 34],
                                ebuf[off + 35],
                                ebuf[off + 36],
                                ebuf[off + 37],
                                ebuf[off + 38],
                                ebuf[off + 39],
                            ]);
                            if first_lba > 0 && first_lba <= u32::MAX as u64 {
                                if let Ok(fs) = Self::mount_at(device, first_lba as u32) {
                                    return Ok(fs);
                                }
                            }
                        }
                        idx += 1;
                    }
                }
            }
        }

        // 2. Check MBR primary partitions at LBA 0 (446..510) when 0x55AA is present.
        if sec0[510] == 0x55 && sec0[511] == 0xAA {
            for p in 0..4usize {
                let off = 446 + p * 16;
                let ptype = sec0[off + 4];
                let start_lba = u32::from_le_bytes([
                    sec0[off + 8],
                    sec0[off + 9],
                    sec0[off + 10],
                    sec0[off + 11],
                ]);
                let count = u32::from_le_bytes([
                    sec0[off + 12],
                    sec0[off + 13],
                    sec0[off + 14],
                    sec0[off + 15],
                ]);
                if ptype != 0 && ptype != 0xEE && start_lba > 0 && count > 0 {
                    if let Ok(fs) = Self::mount_at(device, start_lba) {
                        return Ok(fs);
                    }
                }
            }
        }

        // 3. Superfloppy BPB directly at LBA 0.
        Self::mount_at(device, 0)
    }

    pub fn is_fat32(&self) -> bool {
        self.is_fat32
    }

    pub fn base_sector(&self) -> u32 {
        self.base_sector
    }

    /// Return `(total_bytes, free_bytes, fat_label)` across the FAT data region.
    pub fn volume_stats(&self) -> Result<(u64, u64, &'static str), DriverError> {
        let cluster_bytes = u64::from(self.bpb.sectors_per_cluster) * 512;
        let max_cluster = self.max_data_clusters();
        let data_clusters = u64::from(max_cluster.saturating_sub(2));
        let total_bytes = data_clusters.saturating_mul(cluster_bytes);
        let mut free_clusters = 0u64;
        let mut cached_sec = u32::MAX;
        let mut sec_buf = [0u8; 512];
        for cl in 2..max_cluster {
            let entry = if self.is_fat32 {
                let off = cl * 4;
                let rel = u32::from(self.bpb.reserved_sectors) + (off / 512);
                let idx = (off % 512) as usize;
                if rel != cached_sec {
                    self.read_vol_sector(rel, &mut sec_buf)?;
                    cached_sec = rel;
                }
                u32::from_le_bytes([
                    sec_buf[idx],
                    sec_buf[idx + 1],
                    sec_buf[idx + 2],
                    sec_buf[idx + 3],
                ]) & 0x0FFF_FFFF
            } else {
                let off = cl * 2;
                let rel = u32::from(self.bpb.reserved_sectors) + (off / 512);
                let idx = (off % 512) as usize;
                if rel != cached_sec {
                    self.read_vol_sector(rel, &mut sec_buf)?;
                    cached_sec = rel;
                }
                u32::from(u16::from_le_bytes([sec_buf[idx], sec_buf[idx + 1]]))
            };
            if entry == 0 {
                free_clusters += 1;
            }
        }
        let label = if self.is_fat32 { "fat32" } else { "fat16" };
        Ok((
            total_bytes,
            free_clusters.saturating_mul(cluster_bytes),
            label,
        ))
    }

    fn read_vol_sector(&self, rel_sector: u32, buf: &mut [u8; 512]) -> Result<(), DriverError> {
        let abs = self
            .base_sector
            .checked_add(rel_sector)
            .ok_or(DriverError::InvalidSector)?;
        self.device.read_sector(abs, buf)
    }

    fn write_vol_sector(&self, rel_sector: u32, buf: &[u8; 512]) -> Result<(), DriverError> {
        let abs = self
            .base_sector
            .checked_add(rel_sector)
            .ok_or(DriverError::InvalidSector)?;
        self.device.write_sector(abs, buf)
    }

    fn fat_offset(&self) -> u32 {
        self.bpb.reserved_sectors as u32
    }

    fn sectors_per_fat(&self) -> u32 {
        if self.is_fat32 {
            self.bpb.fat_size_32
        } else {
            self.bpb.fat_size_16 as u32
        }
    }

    fn total_sectors(&self) -> u32 {
        if self.bpb.total_sectors_16 != 0 {
            self.bpb.total_sectors_16 as u32
        } else {
            self.bpb.total_sectors_32
        }
    }

    fn max_data_clusters(&self) -> u32 {
        let sectors = self.total_sectors().saturating_sub(self.data_offset());
        sectors / self.bpb.sectors_per_cluster as u32 + 2
    }

    fn root_dir_offset(&self) -> u32 {
        self.fat_offset() + (self.bpb.num_fats as u32 * self.sectors_per_fat())
    }

    fn root_dir_sectors(&self) -> u32 {
        if self.is_fat32 {
            0
        } else {
            (self.bpb.root_ent_count as u32 * 32).div_ceil(self.bpb.bytes_per_sector as u32)
        }
    }

    fn data_offset(&self) -> u32 {
        self.root_dir_offset() + self.root_dir_sectors()
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_offset() + (cluster.saturating_sub(2) * self.bpb.sectors_per_cluster as u32)
    }

    fn root_target(&self) -> DirTarget {
        if self.is_fat32 {
            DirTarget::ClusterChain(self.bpb.root_cluster)
        } else {
            DirTarget::Fat16Root
        }
    }

    fn eoc_value(&self) -> u32 {
        if self.is_fat32 {
            0x0FFF_FFFF
        } else {
            0xFFFF
        }
    }

    fn is_end_of_chain(&self, cluster: u32) -> bool {
        if cluster < 2 {
            return true;
        }
        if self.is_fat32 {
            (cluster & 0x0FFF_FFFF) >= 0x0FFF_FFF8
        } else {
            cluster >= 0xFFF8
        }
    }

    fn get_next_cluster(&self, cluster: u32) -> Result<u32, DriverError> {
        let entry_size = if self.is_fat32 { 4u32 } else { 2u32 };
        let entries_per_sec = 512 / entry_size;
        let fat_sec = self.fat_offset() + (cluster / entries_per_sec);
        let off = ((cluster % entries_per_sec) * entry_size) as usize;

        let mut buf = [0u8; 512];
        self.read_vol_sector(fat_sec, &mut buf)?;
        let next = if self.is_fat32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) & 0x0FFF_FFFF
        } else {
            u16::from_le_bytes([buf[off], buf[off + 1]]) as u32
        };
        Ok(next)
    }

    fn set_fat_entry(&self, cluster: u32, value: u32) -> Result<(), DriverError> {
        let entry_size = if self.is_fat32 { 4u32 } else { 2u32 };
        let entries_per_sec = 512 / entry_size;
        let sec_in_fat = cluster / entries_per_sec;
        let off = ((cluster % entries_per_sec) * entry_size) as usize;

        for fat_idx in 0..self.bpb.num_fats as u32 {
            let sec = self.fat_offset() + fat_idx * self.sectors_per_fat() + sec_in_fat;
            let mut buf = [0u8; 512];
            self.read_vol_sector(sec, &mut buf)?;
            if self.is_fat32 {
                let prev_hi =
                    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                        & 0xF000_0000;
                let merged = prev_hi | (value & 0x0FFF_FFFF);
                buf[off..off + 4].copy_from_slice(&merged.to_le_bytes());
            } else {
                buf[off..off + 2].copy_from_slice(&(value as u16).to_le_bytes());
            }
            self.write_vol_sector(sec, &buf)?;
        }
        Ok(())
    }

    fn zero_cluster(&self, cluster: u32) -> Result<(), DriverError> {
        let zero = [0u8; 512];
        let base = self.cluster_to_sector(cluster);
        for s in 0..self.bpb.sectors_per_cluster as u32 {
            self.write_vol_sector(base + s, &zero)?;
        }
        Ok(())
    }

    fn allocate_cluster(&self, zero_init: bool) -> Result<u32, DriverError> {
        let max_cluster = self.max_data_clusters();
        let mut c = 2u32;
        while c < max_cluster {
            if self.get_next_cluster(c)? == 0 {
                self.set_fat_entry(c, self.eoc_value())?;
                if zero_init {
                    self.zero_cluster(c)?;
                }
                return Ok(c);
            }
            c += 1;
        }
        Err(DriverError::DiskFull)
    }

    fn free_cluster_chain(&self, start_cluster: u32) -> Result<(), DriverError> {
        if start_cluster < 2 {
            return Ok(());
        }
        let mut cluster = start_cluster;
        let mut visited = 0u32;
        let max_clusters = self.max_data_clusters();
        while !self.is_end_of_chain(cluster) {
            if visited >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            visited += 1;
            let next = self.get_next_cluster(cluster)?;
            self.set_fat_entry(cluster, 0)?;
            cluster = next;
        }
        Ok(())
    }

    fn dir_sectors(&self, target: DirTarget) -> Result<Vec<u32>, DriverError> {
        let mut out = Vec::new();
        match target {
            DirTarget::Fat16Root => {
                let start = self.root_dir_offset();
                for s in 0..self.root_dir_sectors() {
                    out.push(start + s);
                }
            }
            DirTarget::ClusterChain(start_cluster) => {
                let mut cluster = start_cluster;
                let mut visited = 0u32;
                let max_clusters = self.max_data_clusters();
                while !self.is_end_of_chain(cluster) {
                    if visited >= max_clusters {
                        return Err(DriverError::InvalidFat);
                    }
                    visited += 1;
                    let base = self.cluster_to_sector(cluster);
                    for s in 0..self.bpb.sectors_per_cluster as u32 {
                        out.push(base + s);
                    }
                    cluster = self.get_next_cluster(cluster)?;
                }
            }
        }
        Ok(out)
    }

    fn scan_directory(
        &self,
        target: DirTarget,
    ) -> Result<Vec<(String, ResolvedRecord)>, DriverError> {
        let sectors = self.dir_sectors(target)?;
        let mut results = Vec::new();
        let mut lfn_parts: Vec<(u8, [u16; 13], EntrySlotLoc)> = Vec::new();
        let mut lfn_checksum: Option<u8> = None;

        'outer: for sector in sectors {
            let mut buf = [0u8; 512];
            self.read_vol_sector(sector, &mut buf)?;
            for slot in 0..16usize {
                let raw = &buf[slot * 32..(slot + 1) * 32];
                if raw[0] == 0x00 {
                    break 'outer;
                }
                if raw[0] == 0xE5 {
                    lfn_parts.clear();
                    lfn_checksum = None;
                    continue;
                }
                if raw[11] == DirectoryEntry::ATTR_LFN {
                    let ord = raw[0] & 0x3F;
                    let is_first = (raw[0] & 0x40) != 0;
                    let csum = raw[13];
                    if is_first {
                        lfn_parts.clear();
                        lfn_checksum = Some(csum);
                    }
                    if ord >= 1 && lfn_checksum == Some(csum) {
                        let loc = EntrySlotLoc { sector, slot };
                        lfn_parts.push((ord, decode_lfn_chars(raw), loc));
                    } else {
                        lfn_parts.clear();
                        lfn_checksum = None;
                    }
                    continue;
                }

                let entry = DirectoryEntry::decode(raw);
                let mut lfn_locs = Vec::new();
                let mut long_name: Option<String> = None;
                if let Some(expected_csum) = lfn_checksum {
                    if expected_csum == lfn_short_checksum(&entry.short_name_11())
                        && !lfn_parts.is_empty()
                    {
                        lfn_parts.sort_by_key(|p| p.0);
                        let mut utf16 = Vec::with_capacity(lfn_parts.len() * 13);
                        for (_, chars, loc) in &lfn_parts {
                            lfn_locs.push(*loc);
                            for &ch in chars {
                                if ch == 0x0000 || ch == 0xFFFF {
                                    break;
                                }
                                utf16.push(ch);
                            }
                        }
                        if !utf16.is_empty() {
                            long_name = Some(String::from_utf16_lossy(&utf16));
                        }
                    }
                }
                lfn_parts.clear();
                lfn_checksum = None;

                if entry.is_volume_label() {
                    continue;
                }
                let short_str = format_short_name(&entry);
                if short_str == "." || short_str == ".." {
                    continue;
                }
                let display_name = long_name.unwrap_or(short_str);
                results.push((
                    display_name,
                    ResolvedRecord {
                        entry,
                        loc: EntrySlotLoc { sector, slot },
                        lfn_locs,
                    },
                ));
            }
        }
        Ok(results)
    }

    fn find_in_dir(
        &self,
        target: DirTarget,
        component: &str,
    ) -> Result<ResolvedRecord, DriverError> {
        if component.len() > 255 {
            return Err(DriverError::PathTooLong);
        }
        let entries = self.scan_directory(target)?;
        for (name, rec) in entries {
            if name.eq_ignore_ascii_case(component) || short_name_matches(&rec.entry, component) {
                return Ok(rec);
            }
        }
        Err(DriverError::FileNotFound)
    }

    fn split_components(path: &str) -> Result<Vec<&str>, DriverError> {
        if path.is_empty() {
            return Err(DriverError::InvalidPath);
        }
        let parts: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        for &p in &parts {
            if p.len() > 255 || p == ".." {
                return Err(DriverError::InvalidPath);
            }
        }
        Ok(parts)
    }

    fn resolve_parent_and_leaf<'p>(
        &self,
        path: &'p str,
    ) -> Result<(DirTarget, &'p str), DriverError> {
        let parts = Self::split_components(path)?;
        let Some((&leaf, parents)) = parts.split_last() else {
            return Err(DriverError::InvalidPath);
        };
        let mut dir = self.root_target();
        for &comp in parents {
            let rec = self.find_in_dir(dir, comp)?;
            if !rec.entry.is_directory() {
                return Err(DriverError::NotADirectory);
            }
            dir = DirTarget::ClusterChain(rec.entry.first_cluster());
        }
        Ok((dir, leaf))
    }

    fn resolve_record(&self, path: &str) -> Result<ResolvedRecord, DriverError> {
        let (parent, leaf) = self.resolve_parent_and_leaf(path)?;
        self.find_in_dir(parent, leaf)
    }

    /// Resolve a file entry (legacy compatible signature).
    pub fn find_entry(&self, path: &str) -> Result<DirectoryEntry, DriverError> {
        let parts = Self::split_components(path)?;
        if parts.is_empty() {
            return Err(DriverError::InvalidPath);
        }
        let rec = self.resolve_record(path)?;
        if rec.entry.is_directory() {
            return Err(DriverError::NotADirectory);
        }
        Ok(rec.entry)
    }

    /// Query metadata for `"/"` or any nested file/directory.
    pub fn stat(&self, path: &str) -> Result<FatNodeInfo, DriverError> {
        let parts = Self::split_components(path)?;
        if parts.is_empty() {
            let root_cl = if self.is_fat32 {
                self.bpb.root_cluster
            } else {
                0
            };
            return Ok(FatNodeInfo {
                is_dir: true,
                size: 0,
                first_cluster: root_cl,
            });
        }
        let rec = self.resolve_record(path)?;
        Ok(FatNodeInfo {
            is_dir: rec.entry.is_directory(),
            size: rec.entry.file_size,
            first_cluster: rec.entry.first_cluster(),
        })
    }

    /// List entries inside directory `path` (`"/"` or subdirectory).
    pub fn list_dir(&self, path: &str) -> Result<Vec<FatDirEntry>, DriverError> {
        let parts = Self::split_components(path)?;
        let target = if parts.is_empty() {
            self.root_target()
        } else {
            let rec = self.resolve_record(path)?;
            if !rec.entry.is_directory() {
                return Err(DriverError::NotADirectory);
            }
            DirTarget::ClusterChain(rec.entry.first_cluster())
        };
        let records = self.scan_directory(target)?;
        let mut out = Vec::with_capacity(records.len());
        for (name, rec) in records {
            out.push(FatDirEntry {
                name,
                is_dir: rec.entry.is_directory(),
                size: rec.entry.file_size,
            });
        }
        Ok(out)
    }

    pub fn file_size(&self, path: &str) -> Result<u64, DriverError> {
        let entry = self.find_entry(path)?;
        Ok(entry.file_size as u64)
    }

    pub fn read_file(&self, path: &str, buf: &mut [u8]) -> Result<usize, DriverError> {
        let entry = self.find_entry(path)?;
        let file_size = entry.file_size as usize;
        if file_size > buf.len() {
            return Err(DriverError::BufferTooSmall);
        }
        self.read_at_entry(&entry, 0, &mut buf[..file_size])
    }

    /// Random-offset read from regular file `path`.
    pub fn read_at(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, DriverError> {
        let rec = self.resolve_record(path)?;
        if rec.entry.is_directory() {
            return Err(DriverError::IsADirectory);
        }
        self.read_at_entry(&rec.entry, offset, buf)
    }

    fn read_at_entry(
        &self,
        entry: &DirectoryEntry,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, DriverError> {
        let size = entry.file_size as u64;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let avail = (size - offset).min(buf.len() as u64) as usize;
        let cluster_bytes = (self.bpb.sectors_per_cluster as u64) * 512;
        let skip_clusters = offset / cluster_bytes;
        let mut byte_in_cluster = (offset % cluster_bytes) as usize;

        let mut cluster = entry.first_cluster();
        let mut visited = 0u32;
        let max_clusters = self.max_data_clusters();

        let mut skipped = 0u64;
        while skipped < skip_clusters {
            if self.is_end_of_chain(cluster) || visited >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            visited += 1;
            cluster = self.get_next_cluster(cluster)?;
            skipped += 1;
        }

        let mut copied = 0usize;
        while copied < avail {
            if self.is_end_of_chain(cluster) || visited >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            visited += 1;
            let base_sec = self.cluster_to_sector(cluster);
            let start_s = (byte_in_cluster / 512) as u32;
            let mut off_in_sec = byte_in_cluster % 512;
            for s in start_s..self.bpb.sectors_per_cluster as u32 {
                if copied >= avail {
                    break;
                }
                let mut sec_buf = [0u8; 512];
                self.read_vol_sector(base_sec + s, &mut sec_buf)?;
                let take = (512 - off_in_sec).min(avail - copied);
                buf[copied..copied + take].copy_from_slice(&sec_buf[off_in_sec..off_in_sec + take]);
                copied += take;
                off_in_sec = 0;
            }
            byte_in_cluster = 0;
            if copied < avail {
                cluster = self.get_next_cluster(cluster)?;
            }
        }
        Ok(copied)
    }

    fn write_entry_slot(&self, loc: EntrySlotLoc, raw: &[u8; 32]) -> Result<(), DriverError> {
        let mut sec = [0u8; 512];
        self.read_vol_sector(loc.sector, &mut sec)?;
        let off = loc.slot * 32;
        sec[off..off + 32].copy_from_slice(raw);
        self.write_vol_sector(loc.sector, &sec)
    }

    fn find_or_grow_free_slots(
        &self,
        target: DirTarget,
        needed: usize,
    ) -> Result<Vec<EntrySlotLoc>, DriverError> {
        let mut sectors = self.dir_sectors(target)?;
        let mut run: Vec<EntrySlotLoc> = Vec::with_capacity(needed);

        for &sector in &sectors {
            let mut buf = [0u8; 512];
            self.read_vol_sector(sector, &mut buf)?;
            for slot in 0..16usize {
                let first = buf[slot * 32];
                if first == 0x00 || first == 0xE5 {
                    run.push(EntrySlotLoc { sector, slot });
                    if run.len() == needed {
                        return Ok(run);
                    }
                } else {
                    run.clear();
                }
            }
        }

        // Extend cluster-backed directories when full.
        if let DirTarget::ClusterChain(start_cluster) = target {
            let mut last = start_cluster;
            let mut visited = 0u32;
            let max_clusters = self.max_data_clusters();
            while !self.is_end_of_chain(last) {
                if visited >= max_clusters {
                    return Err(DriverError::InvalidFat);
                }
                visited += 1;
                let next = self.get_next_cluster(last)?;
                if self.is_end_of_chain(next) {
                    break;
                }
                last = next;
            }
            let new_cluster = self.allocate_cluster(true)?;
            self.set_fat_entry(last, new_cluster)?;
            let base = self.cluster_to_sector(new_cluster);
            for s in 0..self.bpb.sectors_per_cluster as u32 {
                sectors.push(base + s);
                for slot in 0..16usize {
                    run.push(EntrySlotLoc {
                        sector: base + s,
                        slot,
                    });
                    if run.len() == needed {
                        return Ok(run);
                    }
                }
            }
        }
        Err(DriverError::DiskFull)
    }

    fn insert_dir_entry(
        &self,
        parent: DirTarget,
        leaf: &str,
        attr: u8,
        first_cluster: u32,
        file_size: u32,
    ) -> Result<EntrySlotLoc, DriverError> {
        if leaf.is_empty() || leaf.len() > 255 || leaf == "." || leaf == ".." {
            return Err(DriverError::InvalidPath);
        }
        if self.find_in_dir(parent, leaf).is_ok() {
            return Err(DriverError::AlreadyExists);
        }

        let existing = self.scan_directory(parent)?;
        let (short_name, need_lfn) = generate_short_alias(leaf, &existing);
        let lfn_slots = if need_lfn {
            build_lfn_entries(leaf, &short_name)?
        } else {
            Vec::new()
        };

        let total_slots = lfn_slots.len() + 1;
        let locs = self.find_or_grow_free_slots(parent, total_slots)?;

        for (i, raw_lfn) in lfn_slots.iter().enumerate() {
            self.write_entry_slot(locs[i], raw_lfn)?;
        }

        let mut short_entry = DirectoryEntry {
            name: [b' '; 8],
            ext: [b' '; 3],
            attr,
            reserved: 0,
            create_time_tenth: 0,
            create_time: 0,
            create_date: 0x5977, // 2026-11-23
            last_access_date: 0x5977,
            first_cluster_hi: 0,
            write_time: 0,
            write_date: 0x5977,
            first_cluster_lo: 0,
            file_size,
        };
        short_entry.name.copy_from_slice(&short_name[0..8]);
        short_entry.ext.copy_from_slice(&short_name[8..11]);
        short_entry.set_first_cluster(first_cluster, self.is_fat32);
        let main_loc = locs[total_slots - 1];
        self.write_entry_slot(main_loc, &short_entry.encode())?;
        Ok(main_loc)
    }

    /// Create an empty regular file at `path` (error if it already exists).
    pub fn create_file(&self, path: &str) -> Result<(), DriverError> {
        let (parent, leaf) = self.resolve_parent_and_leaf(path)?;
        let _ = self.insert_dir_entry(parent, leaf, DirectoryEntry::ATTR_ARCHIVE, 0, 0)?;
        Ok(())
    }

    /// Create a directory at `path` with `.` and `..` entries.
    pub fn mkdir(&self, path: &str) -> Result<(), DriverError> {
        let (parent, leaf) = self.resolve_parent_and_leaf(path)?;
        if self.find_in_dir(parent, leaf).is_ok() {
            return Err(DriverError::AlreadyExists);
        }
        let cluster = self.allocate_cluster(true)?;
        let parent_dotdot_cluster = match parent {
            DirTarget::Fat16Root => 0,
            DirTarget::ClusterChain(c) => {
                if self.is_fat32 && c == self.bpb.root_cluster {
                    0
                } else {
                    c
                }
            }
        };

        let mut sec0 = [0u8; 512];
        let mut dot = DirectoryEntry {
            name: *b".       ",
            ext: *b"   ",
            attr: DirectoryEntry::ATTR_DIRECTORY,
            reserved: 0,
            create_time_tenth: 0,
            create_time: 0,
            create_date: 0x5977,
            last_access_date: 0x5977,
            first_cluster_hi: 0,
            write_time: 0,
            write_date: 0x5977,
            first_cluster_lo: 0,
            file_size: 0,
        };
        dot.set_first_cluster(cluster, self.is_fat32);
        let mut dotdot = dot;
        dotdot.name = *b"..      ";
        dotdot.set_first_cluster(parent_dotdot_cluster, self.is_fat32);
        sec0[0..32].copy_from_slice(&dot.encode());
        sec0[32..64].copy_from_slice(&dotdot.encode());
        self.write_vol_sector(self.cluster_to_sector(cluster), &sec0)?;

        if let Err(err) =
            self.insert_dir_entry(parent, leaf, DirectoryEntry::ATTR_DIRECTORY, cluster, 0)
        {
            let _ = self.free_cluster_chain(cluster);
            return Err(err);
        }
        Ok(())
    }

    /// Truncate or zero-extend regular file `path` to `new_size` bytes.
    pub fn truncate(&self, path: &str, new_size: u64) -> Result<(), DriverError> {
        let target_u32 = u32::try_from(new_size).map_err(|_| DriverError::DiskFull)?;
        let mut rec = self.resolve_record(path)?;
        if rec.entry.is_directory() {
            return Err(DriverError::IsADirectory);
        }
        let cur_size = rec.entry.file_size;
        if target_u32 == cur_size {
            return Ok(());
        }
        if target_u32 == 0 {
            let start = rec.entry.first_cluster();
            if start >= 2 {
                self.free_cluster_chain(start)?;
            }
            rec.entry.set_first_cluster(0, self.is_fat32);
            rec.entry.file_size = 0;
            return self.write_entry_slot(rec.loc, &rec.entry.encode());
        }
        if target_u32 < cur_size {
            let cluster_bytes = (self.bpb.sectors_per_cluster as u32) * 512;
            let keep_clusters = target_u32.div_ceil(cluster_bytes);
            let mut cur = rec.entry.first_cluster();
            for _ in 1..keep_clusters {
                if self.is_end_of_chain(cur) {
                    return Err(DriverError::InvalidFat);
                }
                cur = self.get_next_cluster(cur)?;
            }
            let tail = self.get_next_cluster(cur)?;
            self.set_fat_entry(cur, self.eoc_value())?;
            if !self.is_end_of_chain(tail) {
                self.free_cluster_chain(tail)?;
            }
            rec.entry.file_size = target_u32;
            return self.write_entry_slot(rec.loc, &rec.entry.encode());
        }

        // Zero-extend `cur_size .. target_u32`.
        let zeros = [0u8; 512];
        let mut pos = cur_size as u64;
        while pos < new_size {
            let step = ((new_size - pos).min(512)) as usize;
            let _ = self.write_at(path, pos, &zeros[..step])?;
            pos += step as u64;
        }
        Ok(())
    }

    /// Write `data` at `offset` in regular file `path`, growing the cluster chain as needed.
    pub fn write_at(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize, DriverError> {
        let mut rec = self.resolve_record(path)?;
        if rec.entry.is_directory() {
            return Err(DriverError::IsADirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end_u64 = offset
            .checked_add(data.len() as u64)
            .ok_or(DriverError::DiskFull)?;
        let end_u32 = u32::try_from(end_u64).map_err(|_| DriverError::DiskFull)?;

        // Zero-fill any hole if `offset > current_size`.
        if offset > rec.entry.file_size as u64 {
            self.truncate(path, offset)?;
            rec = self.resolve_record(path)?;
        }

        let cluster_bytes = (self.bpb.sectors_per_cluster as u64) * 512;
        let needed_clusters = (end_u64.div_ceil(cluster_bytes)) as u32;

        let mut chain: Vec<u32> = Vec::with_capacity(needed_clusters as usize);
        let mut cur = rec.entry.first_cluster();
        let max_clusters = self.max_data_clusters();
        while !self.is_end_of_chain(cur) {
            if chain.len() as u32 >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            chain.push(cur);
            cur = self.get_next_cluster(cur)?;
        }

        while (chain.len() as u32) < needed_clusters {
            let fresh = self.allocate_cluster(true)?;
            if let Some(&prev) = chain.last() {
                self.set_fat_entry(prev, fresh)?;
            } else {
                rec.entry.set_first_cluster(fresh, self.is_fat32);
            }
            chain.push(fresh);
        }

        let mut written = 0usize;
        while written < data.len() {
            let file_off = offset + written as u64;
            let c_idx = (file_off / cluster_bytes) as usize;
            let in_c = (file_off % cluster_bytes) as usize;
            let sec_in_c = (in_c / 512) as u32;
            let off_in_sec = in_c % 512;
            let take = (512 - off_in_sec).min(data.len() - written);

            let target_sec = self.cluster_to_sector(chain[c_idx]) + sec_in_c;
            let mut sec_buf = [0u8; 512];
            if off_in_sec != 0 || take < 512 {
                self.read_vol_sector(target_sec, &mut sec_buf)?;
            }
            let src = &data[written..written + take];
            sec_buf[off_in_sec..off_in_sec + take].copy_from_slice(src);
            self.write_vol_sector(target_sec, &sec_buf)?;
            written += take;
        }

        if end_u32 > rec.entry.file_size {
            rec.entry.file_size = end_u32;
        }
        rec.entry.attr |= DirectoryEntry::ATTR_ARCHIVE;
        self.write_entry_slot(rec.loc, &rec.entry.encode())?;
        Ok(written)
    }

    /// Remove a regular file or an empty directory at `path`.
    pub fn unlink(&self, path: &str) -> Result<(), DriverError> {
        let rec = self.resolve_record(path)?;
        if rec.entry.is_directory() {
            let children =
                self.scan_directory(DirTarget::ClusterChain(rec.entry.first_cluster()))?;
            if !children.is_empty() {
                return Err(DriverError::DirectoryNotEmpty);
            }
        }
        let start = rec.entry.first_cluster();
        if start >= 2 {
            self.free_cluster_chain(start)?;
        }
        self.mark_record_deleted(&rec)
    }

    /// Rename or move `from` to `to` (overwriting an existing regular file at `to` if present).
    pub fn rename(&self, from: &str, to: &str) -> Result<(), DriverError> {
        if from == to {
            return Ok(());
        }
        let rec = self.resolve_record(from)?;
        let (dst_parent, dst_leaf) = self.resolve_parent_and_leaf(to)?;
        if let Ok(existing_dst) = self.find_in_dir(dst_parent, dst_leaf) {
            if existing_dst.entry.is_directory() {
                return Err(DriverError::IsADirectory);
            }
            let start = existing_dst.entry.first_cluster();
            if start >= 2 {
                self.free_cluster_chain(start)?;
            }
            self.mark_record_deleted(&existing_dst)?;
        }

        let _ = self.insert_dir_entry(
            dst_parent,
            dst_leaf,
            rec.entry.attr,
            rec.entry.first_cluster(),
            rec.entry.file_size,
        )?;
        if rec.entry.is_directory() && rec.entry.first_cluster() >= 2 {
            let parent_dotdot = match dst_parent {
                DirTarget::Fat16Root => 0,
                DirTarget::ClusterChain(c) => {
                    if self.is_fat32 && c == self.bpb.root_cluster {
                        0
                    } else {
                        c
                    }
                }
            };
            let dir_sec0 = self.cluster_to_sector(rec.entry.first_cluster());
            let mut sec_buf = [0u8; 512];
            self.read_vol_sector(dir_sec0, &mut sec_buf)?;
            let mut dotdot = DirectoryEntry::decode(&sec_buf[32..64]);
            if &dotdot.name[0..2] == b".." {
                dotdot.set_first_cluster(parent_dotdot, self.is_fat32);
                sec_buf[32..64].copy_from_slice(&dotdot.encode());
                self.write_vol_sector(dir_sec0, &sec_buf)?;
            }
        }
        self.mark_record_deleted(&rec)
    }

    fn mark_record_deleted(&self, rec: &ResolvedRecord) -> Result<(), DriverError> {
        for &lfn_loc in &rec.lfn_locs {
            let mut sec = [0u8; 512];
            self.read_vol_sector(lfn_loc.sector, &mut sec)?;
            sec[lfn_loc.slot * 32] = 0xE5;
            self.write_vol_sector(lfn_loc.sector, &sec)?;
        }
        let mut sec = [0u8; 512];
        self.read_vol_sector(rec.loc.sector, &mut sec)?;
        sec[rec.loc.slot * 32] = 0xE5;
        self.write_vol_sector(rec.loc.sector, &sec)
    }
}

fn lfn_short_checksum(short_11: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short_11 {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

fn decode_lfn_chars(raw: &[u8]) -> [u16; 13] {
    const OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut out = [0u16; 13];
    for (i, &off) in OFFSETS.iter().enumerate() {
        out[i] = u16::from_le_bytes([raw[off], raw[off + 1]]);
    }
    out
}

fn encode_lfn_slot(ord: u8, checksum: u8, chunk: &[u16; 13]) -> [u8; 32] {
    const OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut raw = [0u8; 32];
    raw[0] = ord;
    raw[11] = DirectoryEntry::ATTR_LFN;
    raw[12] = 0;
    raw[13] = checksum;
    raw[26] = 0;
    raw[27] = 0;
    for (i, &off) in OFFSETS.iter().enumerate() {
        let bytes = chunk[i].to_le_bytes();
        raw[off] = bytes[0];
        raw[off + 1] = bytes[1];
    }
    raw
}

fn build_lfn_entries(name: &str, short_11: &[u8; 11]) -> Result<Vec<[u8; 32]>, DriverError> {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    if utf16.is_empty() || utf16.len() > 255 {
        return Err(DriverError::PathTooLong);
    }
    let checksum = lfn_short_checksum(short_11);
    let slot_count = utf16.len().div_ceil(13);
    let mut out = Vec::with_capacity(slot_count);

    for rev_idx in (0..slot_count).rev() {
        let mut chunk = [0xFFFFu16; 13];
        let base = rev_idx * 13;
        for j in 0..13usize {
            let pos = base + j;
            if pos < utf16.len() {
                chunk[j] = utf16[pos];
            } else if pos == utf16.len() {
                chunk[j] = 0x0000;
            }
        }
        let mut ord = (rev_idx + 1) as u8;
        if rev_idx + 1 == slot_count {
            ord |= 0x40;
        }
        out.push(encode_lfn_slot(ord, checksum, &chunk));
    }
    Ok(out)
}

fn format_short_name(entry: &DirectoryEntry) -> String {
    let base_end = entry
        .name
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    let ext_end = entry
        .ext
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    let mut out = String::with_capacity(base_end + 1 + ext_end);
    for &b in &entry.name[..base_end] {
        out.push(b as char);
    }
    if ext_end > 0 {
        out.push('.');
        for &b in &entry.ext[..ext_end] {
            out.push(b as char);
        }
    }
    out
}

fn short_name_matches(entry: &DirectoryEntry, query: &str) -> bool {
    let Some(parsed) = try_exact_83_uppercase(query) else {
        return false;
    };
    entry.short_name_11() == parsed
}

fn is_valid_short_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&b)
}

fn try_exact_83_uppercase(name: &str) -> Option<[u8; 11]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes[0] == b'.' {
        return None;
    }
    let mut out = [b' '; 11];
    let mut n_len = 0usize;
    let mut e_len = 0usize;
    let mut in_ext = false;
    for &b in bytes {
        if b == b'.' {
            if in_ext || n_len == 0 {
                return None;
            }
            in_ext = true;
            continue;
        }
        if !is_valid_short_char(b) {
            return None;
        }
        let up = b.to_ascii_uppercase();
        if in_ext {
            if e_len >= 3 {
                return None;
            }
            out[8 + e_len] = up;
            e_len += 1;
        } else {
            if n_len >= 8 {
                return None;
            }
            out[n_len] = up;
            n_len += 1;
        }
    }
    if n_len == 0 {
        None
    } else {
        Some(out)
    }
}

fn generate_short_alias(name: &str, existing: &[(String, ResolvedRecord)]) -> ([u8; 11], bool) {
    let has_lowercase = name.bytes().any(|b| b.is_ascii_lowercase());
    if !has_lowercase {
        if let Some(exact) = try_exact_83_uppercase(name) {
            let collision = existing
                .iter()
                .any(|(_, r)| r.entry.short_name_11() == exact);
            if !collision {
                return (exact, false);
            }
        }
    }

    let (stem_part, ext_part) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot + 1..]),
        _ => (name, ""),
    };

    let mut clean_stem = [b'_'; 6];
    let mut s_len = 0usize;
    for b in stem_part.bytes() {
        if b == b' ' || b == b'.' {
            continue;
        }
        clean_stem[s_len] = if is_valid_short_char(b) {
            b.to_ascii_uppercase()
        } else {
            b'_'
        };
        s_len += 1;
        if s_len == 6 {
            break;
        }
    }
    if s_len == 0 {
        clean_stem[0] = b'F';
        s_len = 1;
    }

    let mut clean_ext = [b' '; 3];
    let mut e_len = 0usize;
    for b in ext_part.bytes() {
        if b == b' ' || b == b'.' {
            continue;
        }
        clean_ext[e_len] = if is_valid_short_char(b) {
            b.to_ascii_uppercase()
        } else {
            b'_'
        };
        e_len += 1;
        if e_len == 3 {
            break;
        }
    }

    for idx in 1..=999usize {
        let mut cand = [b' '; 11];
        cand[8..11].copy_from_slice(&clean_ext);
        let suffix = alloc::format!("~{idx}");
        let suf_bytes = suffix.as_bytes();
        let keep = s_len.min(8usize.saturating_sub(suf_bytes.len()));
        cand[..keep].copy_from_slice(&clean_stem[..keep]);
        cand[keep..keep + suf_bytes.len()].copy_from_slice(suf_bytes);
        if !existing
            .iter()
            .any(|(_, r)| r.entry.short_name_11() == cand)
        {
            return (cand, true);
        }
    }
    let mut fallback = [b'X'; 11];
    fallback[8..11].copy_from_slice(&clean_ext);
    (fallback, true)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;

    struct RamDisk {
        data: RefCell<Vec<u8>>,
    }

    impl RamDisk {
        fn new(sectors: usize) -> Self {
            Self {
                data: RefCell::new(alloc::vec![0u8; sectors * 512]),
            }
        }

        fn put_sector(&self, sec: u32, buf: &[u8; 512]) {
            let mut d = self.data.borrow_mut();
            let start = (sec as usize) * 512;
            d[start..start + 512].copy_from_slice(buf);
        }
    }

    impl BlockDevice for RamDisk {
        fn read_sector(&self, sec: u32, buf: &mut [u8]) -> Result<(), DriverError> {
            let d = self.data.borrow();
            let start = (sec as usize) * 512;
            if start + 512 > d.len() {
                return Err(DriverError::InvalidSector);
            }
            buf.copy_from_slice(&d[start..start + 512]);
            Ok(())
        }

        fn write_sector(&self, sec: u32, buf: &[u8]) -> Result<(), DriverError> {
            let mut d = self.data.borrow_mut();
            let start = (sec as usize) * 512;
            if start + 512 > d.len() {
                return Err(DriverError::InvalidSector);
            }
            d[start..start + 512].copy_from_slice(buf);
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            512
        }
    }

    fn format_fat32_in_ram(disk: &RamDisk, base_sector: u32, total_sectors: u32) {
        let mut bpb = [0u8; 512];
        bpb[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        bpb[3..11].copy_from_slice(b"HUESOS32");
        bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
        bpb[13] = 2; // 2 sectors/cluster = 1 KiB
        bpb[14..16].copy_from_slice(&4u16.to_le_bytes()); // reserved = 4
        bpb[16] = 2; // 2 FATs
        bpb[21] = 0xF8;
        bpb[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        bpb[36..40].copy_from_slice(&4u32.to_le_bytes()); // 4 sectors/FAT
        bpb[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster = 2
        bpb[48..50].copy_from_slice(&1u16.to_le_bytes());
        bpb[510] = 0x55;
        bpb[511] = 0xAA;
        disk.put_sector(base_sector, &bpb);

        // Initialize FAT1 (base+4) and FAT2 (base+8): clusters 0, 1, and root cluster 2 = EOC.
        let mut fat0 = [0u8; 512];
        fat0[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
        fat0[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        fat0[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        disk.put_sector(base_sector + 4, &fat0);
        disk.put_sector(base_sector + 8, &fat0);
    }

    #[test]
    fn test_mount_invalid_sector_size() {
        let d = RamDisk::new(64);
        let err = FatFileSystem::mount(&d).err();
        assert_eq!(err, Some(DriverError::InvalidFat));
    }

    #[test]
    fn test_mbr_partition_fat32_lfn_rw_mkdir_rename_unlink() -> Result<(), DriverError> {
        let disk = RamDisk::new(512);
        // Write MBR at LBA 0 with bootstrap tag + FAT32 LBA partition at LBA 64..464.
        let mut mbr = [0u8; 512];
        mbr[0..21].copy_from_slice(b"HUESOS-USB3-BOT-SMOKE");
        mbr[446 + 4] = 0x0C; // FAT32 LBA
        mbr[446 + 8..446 + 12].copy_from_slice(&64u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&400u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        disk.put_sector(0, &mbr);
        format_fat32_in_ram(&disk, 64, 400);

        let fs = FatFileSystem::mount_auto(&disk)?;
        assert!(fs.is_fat32());
        assert_eq!(fs.base_sector(), 64);

        // Create subdirectory + long-filename file spanning multiple 1 KiB clusters.
        fs.mkdir("/usb_logs")?;
        fs.create_file("/usb_logs/session_report_2026.txt")?;
        let payload = alloc::vec![b'A'; 2500];
        assert_eq!(
            fs.write_at("/usb_logs/session_report_2026.txt", 0, &payload),
            Ok(2500)
        );
        assert_eq!(
            fs.write_at("/usb_logs/session_report_2026.txt", 10, b"HUESOS"),
            Ok(6)
        );

        let listing = fs.list_dir("/usb_logs")?;
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].name, "session_report_2026.txt");
        assert_eq!(listing[0].size, 2500);

        let mut readback = alloc::vec![0u8; 2500];
        assert_eq!(
            fs.read_file("/usb_logs/session_report_2026.txt", &mut readback),
            Ok(2500)
        );
        assert_eq!(&readback[10..16], b"HUESOS");

        // Rename across directories + truncate + unlink.
        fs.rename("/usb_logs/session_report_2026.txt", "/README.TXT")?;
        fs.truncate("/README.TXT", 16)?;
        assert_eq!(fs.file_size("/readme.txt"), Ok(16));

        let mut short_buf = [0u8; 16];
        assert_eq!(fs.read_at("/readme.txt", 0, &mut short_buf), Ok(16));
        assert_eq!(&short_buf[10..16], b"HUESOS");

        fs.unlink("/README.TXT")?;
        fs.unlink("/usb_logs")?;
        assert!(fs.list_dir("/")?.is_empty());
        Ok(())
    }
}
