//! FAT16/32 Filesystem Driver for HuesOS.
//! Real path traversal + fully Result-based (no .expect / .unwrap in lib code).

#![no_std]

extern crate alloc;

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
    NotADirectory,
    DiskFull,
    InvalidFat,
    PathTooLong,
    InvalidPath,
    /// The caller-supplied buffer is smaller than the file. The read is
    /// abandoned without copying any bytes so the caller can retry with a
    /// larger buffer instead of receiving a silently truncated file that
    /// looks indistinguishable from a legitimately smaller one.
    BufferTooSmall,
}

/// BIOS Parameter Block layout matching the on-disk FAT12/16/32 boot sector.
///
/// Common BPB ends at `total_sectors_32` (offset 36). FAT32-specific fields
/// follow with the sizes mandated by the Microsoft FAT specification:
/// `ext_flags`/`fs_version` are u16, `fs_info_sector`/`backup_boot_sector`
/// are u16. Incorrect widths shift `root_cluster` and break FAT32 mounts.
#[repr(C, packed)]
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
    // --- FAT32 extended BPB (also present, zeroed, on FAT16 images) ---
    pub fat_size_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub reserved: [u8; 12],
    /// Remainder of the 512-byte boot sector (drive number, boot code, 0x55AA, ...).
    /// Offset of this field is 64; size is 512 - 64 = 448.
    pub boot_signature: [u8; 512 - 64],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
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
    pub fn is_free(&self) -> bool {
        self.name[0] == 0x00 || self.name[0] == 0xE5
    }
    pub fn is_directory(&self) -> bool {
        (self.attr & 0x10) != 0
    }
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }
    pub fn is_volume_label(&self) -> bool {
        (self.attr & 0x08) != 0
    }
}

pub struct FatFileSystem<'a, D: BlockDevice> {
    device: &'a D,
    bpb: FatBpb,
    is_fat32: bool,
}

impl<'a, D: BlockDevice> FatFileSystem<'a, D> {
    pub fn mount(device: &'a D) -> Result<Self, DriverError> {
        let mut boot = [0u8; 512];
        device.read_sector(0, &mut boot)?;

        let bpb = unsafe { core::ptr::read_unaligned(boot.as_ptr() as *const FatBpb) };
        if bpb.bytes_per_sector != 512
            || bpb.sectors_per_cluster == 0
            || bpb.num_fats == 0
            || (bpb.fat_size_16 == 0 && bpb.fat_size_32 == 0)
            || (bpb.total_sectors_16 == 0 && bpb.total_sectors_32 == 0)
        {
            return Err(DriverError::InvalidFat);
        }

        Ok(Self {
            device,
            bpb,
            is_fat32: bpb.fat_size_16 == 0,
        })
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

    fn data_offset(&self) -> u32 {
        let root_sectors = if self.is_fat32 {
            0
        } else {
            (self.bpb.root_ent_count as u32 * 32).div_ceil(self.bpb.bytes_per_sector as u32)
        };
        self.fat_offset() + (self.bpb.num_fats as u32 * self.sectors_per_fat()) + root_sectors
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_offset() + (cluster.saturating_sub(2) * self.bpb.sectors_per_cluster as u32)
    }

    // ==================== REAL PATH TRAVERSAL ====================

    /// Walks the path and returns the final DirectoryEntry.
    pub fn find_entry(&self, path: &str) -> Result<DirectoryEntry, DriverError> {
        if path.is_empty() {
            return Err(DriverError::InvalidPath);
        }

        let mut current_cluster = if self.is_fat32 {
            self.bpb.root_cluster
        } else {
            // FAT16 root is special (fixed location), we use 0 as marker
            0
        };

        let components: alloc::vec::Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let Some(&last_component) = components.last() else {
            return Err(DriverError::InvalidPath);
        };

        // For FAT16 we start from fixed root
        let mut is_root_special = !self.is_fat32;

        for component in components {
            if component.len() > 255 {
                return Err(DriverError::PathTooLong);
            }

            let entry = if is_root_special {
                self.find_entry_in_fat16_root(component)?
            } else {
                self.find_entry_in_dir(current_cluster, component)?
            };

            if entry.is_directory() {
                if component == last_component {
                    return Err(DriverError::NotADirectory);
                }
                current_cluster = entry.first_cluster();
                is_root_special = false;
            } else {
                // A file entry is only valid as the last component of the
                // path. If more components follow, the caller tried to
                // traverse through a file as if it were a directory.
                return if component == last_component {
                    Ok(entry)
                } else {
                    Err(DriverError::NotADirectory)
                };
            }
        }

        // If we finished the loop on a directory, the caller asked for a
        // directory path rather than a file. read_file needs a full path
        // to a regular file.
        let _ = last_component;
        Err(DriverError::FileNotFound)
    }

    fn root_dir_offset(&self) -> u32 {
        self.fat_offset() + (self.bpb.num_fats as u32 * self.sectors_per_fat())
    }

    fn find_entry_in_fat16_root(&self, name: &str) -> Result<DirectoryEntry, DriverError> {
        let root_start = self.root_dir_offset();
        let root_entries = self.bpb.root_ent_count as u32;
        let root_sectors = (root_entries * 32).div_ceil(512);

        for s in 0..root_sectors {
            let mut buf = [0u8; 512];
            self.device.read_sector(root_start + s, &mut buf)?;

            for i in 0..(512 / 32) {
                let entry = unsafe {
                    core::ptr::read_unaligned(buf.as_ptr().add(i * 32) as *const DirectoryEntry)
                };
                if !entry.is_free() && !entry.is_volume_label() && self.name_matches(&entry, name) {
                    return Ok(entry);
                }
            }
        }
        Err(DriverError::FileNotFound)
    }

    fn find_entry_in_dir(
        &self,
        dir_cluster: u32,
        name: &str,
    ) -> Result<DirectoryEntry, DriverError> {
        let mut cluster = dir_cluster;
        let mut visited = 0u32;
        let max_clusters = self.max_data_clusters();

        while !self.is_end_of_chain(cluster) {
            if visited >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            visited += 1;
            let sector = self.cluster_to_sector(cluster);
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;

            for s in 0..sectors_per_cluster {
                let mut buf = [0u8; 512];
                self.device.read_sector(sector + s, &mut buf)?;

                for i in 0..(512 / 32) {
                    let entry = unsafe {
                        core::ptr::read_unaligned(buf.as_ptr().add(i * 32) as *const DirectoryEntry)
                    };
                    if !entry.is_free()
                        && !entry.is_volume_label()
                        && self.name_matches(&entry, name)
                    {
                        return Ok(entry);
                    }
                }
            }

            // next cluster in chain
            cluster = self.get_next_cluster(cluster)?;
        }
        Err(DriverError::FileNotFound)
    }

    fn name_matches(&self, entry: &DirectoryEntry, name: &str) -> bool {
        let mut entry_name = [0u8; 11];
        entry_name[..8].copy_from_slice(&entry.name);
        entry_name[8..].copy_from_slice(&entry.ext);

        let mut search = [b' '; 11];
        let mut name_len = 0usize;
        let mut ext_len = 0usize;
        let mut in_ext = false;
        for &b in name.as_bytes() {
            if b == b'.' {
                if in_ext || name_len == 0 {
                    return false;
                }
                in_ext = true;
                continue;
            }
            if b == b' ' || b == b'/' || b == b'\\' {
                return false;
            }
            if in_ext {
                if ext_len >= 3 {
                    return false;
                }
                search[8 + ext_len] = b.to_ascii_uppercase();
                ext_len += 1;
            } else {
                if name_len >= 8 {
                    return false;
                }
                search[name_len] = b.to_ascii_uppercase();
                name_len += 1;
            }
        }
        name_len != 0 && entry_name == search
    }

    // ==================== FILE READING ====================

    /// Return the on-disk size of the file at `path` without reading any
    /// data. Useful to size a buffer before [`Self::read_file`], which
    /// refuses to truncate.
    pub fn file_size(&self, path: &str) -> Result<u64, DriverError> {
        let entry = self.find_entry(path)?;
        if entry.is_directory() {
            return Err(DriverError::NotADirectory);
        }
        Ok(entry.file_size as u64)
    }

    /// Read the entire file at `path` into `buf`.
    ///
    /// Contract: on success, exactly `entry.file_size` bytes are written to
    /// `buf[..entry.file_size]` and that value is returned. If `buf` is
    /// smaller than the file, this returns [`DriverError::BufferTooSmall`]
    /// **without** copying any bytes; the caller is expected to consult
    /// [`Self::file_size`] first (or grow the buffer and retry). The
    /// previous behavior silently truncated the read at `buf.len()`, which
    /// is indistinguishable from a legitimately smaller file and led to
    /// data-loss bugs in higher-level callers (e.g. an ELF loader that
    /// received a truncated program header table).
    pub fn read_file(&self, path: &str, buf: &mut [u8]) -> Result<usize, DriverError> {
        let entry = self.find_entry(path)?;

        if entry.is_directory() {
            return Err(DriverError::NotADirectory);
        }

        let file_size = entry.file_size as usize;
        if file_size > buf.len() {
            return Err(DriverError::BufferTooSmall);
        }

        let mut bytes_read = 0usize;
        let mut cluster = entry.first_cluster();
        let mut remaining = file_size;
        let mut visited = 0u32;
        let max_clusters = self.max_data_clusters();

        while remaining > 0 && !self.is_end_of_chain(cluster) {
            if visited >= max_clusters {
                return Err(DriverError::InvalidFat);
            }
            visited += 1;
            let sector = self.cluster_to_sector(cluster);
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;

            for s in 0..sectors_per_cluster {
                if remaining == 0 {
                    break;
                }
                let mut sector_buf = [0u8; 512];
                self.device.read_sector(sector + s, &mut sector_buf)?;

                let copy_len = core::cmp::min(remaining, 512);
                // The pre-flight check above guarantees `bytes_read +
                // copy_len <= buf.len()`; a defensive assertion here would
                // catch a future regression that broke the pre-flight
                // invariant but has no effect on today's control flow.
                debug_assert!(bytes_read + copy_len <= buf.len());
                buf[bytes_read..bytes_read + copy_len].copy_from_slice(&sector_buf[..copy_len]);
                bytes_read += copy_len;
                remaining -= copy_len;
            }

            cluster = self.get_next_cluster(cluster)?;
        }

        if remaining == 0 {
            Ok(bytes_read)
        } else {
            Err(DriverError::InvalidFat)
        }
    }

    // ==================== FAT CHAIN HELPERS ====================

    /// True for free (0), reserved, or end-of-chain markers.
    ///
    /// FAT16 EOC is `0xFFF8..=0xFFFF`; FAT32 EOC is `0x0FFFFFF8..=0x0FFFFFFF`
    /// (top nibble ignored on disk, but we only store the low 28 bits here).
    /// The previous code used the FAT32 threshold for both, so a FAT16 EOC
    /// value like `0xFFFF` was treated as a valid data cluster.
    fn is_end_of_chain(&self, cluster: u32) -> bool {
        if cluster < 2 {
            return true;
        }
        if self.is_fat32 {
            cluster >= 0x0FFF_FFF8
        } else {
            cluster >= 0xFFF8
        }
    }

    fn get_next_cluster(&self, cluster: u32) -> Result<u32, DriverError> {
        let bytes_per_sec = self.bpb.bytes_per_sector as u32;
        let entry_size = if self.is_fat32 { 4u32 } else { 2u32 };
        let entries_per_sec = bytes_per_sec / entry_size;

        let fat_sec = self.fat_offset() + (cluster / entries_per_sec);
        let idx = (cluster % entries_per_sec) as usize;
        let off = idx * entry_size as usize;

        let mut buf = [0u8; 512];
        self.device.read_sector(fat_sec, &mut buf)?;

        let next = if self.is_fat32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        } else {
            u16::from_le_bytes([buf[off], buf[off + 1]]) as u32
        };

        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;

    struct RamDisk {
        data: Mutex<[u8; 40 * 1024]>,
        sector_size: u32,
    }
    impl RamDisk {
        fn new() -> Self {
            Self {
                data: Mutex::new([0u8; 40 * 1024]),
                sector_size: 512,
            }
        }
        fn write_sector(&self, sec: u32, b: &[u8]) {
            let mut d = self.data.lock();
            let start = (sec as usize) * 512;
            d[start..start + 512].copy_from_slice(b);
        }
    }
    impl BlockDevice for RamDisk {
        fn read_sector(&self, sec: u32, buf: &mut [u8]) -> Result<(), DriverError> {
            let d = self.data.lock();
            let start = (sec as usize) * 512;
            if start + 512 > d.len() {
                return Err(DriverError::InvalidSector);
            }
            buf.copy_from_slice(&d[start..start + 512]);
            Ok(())
        }
        fn write_sector(&self, sec: u32, buf: &[u8]) -> Result<(), DriverError> {
            let mut d = self.data.lock();
            let start = (sec as usize) * 512;
            d[start..start + 512].copy_from_slice(buf);
            Ok(())
        }
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    #[test]
    fn test_mount_invalid_sector_size() {
        let d = RamDisk::new();
        assert!(FatFileSystem::mount(&d).is_err());
    }

    #[test]
    fn test_read_file_multi_sector_cluster() {
        let d = RamDisk::new();

        // Build a minimal FAT16 image: 2 sectors per cluster.
        let bpb = FatBpb {
            jump: [0xEB, 0x3C, 0x90],
            oem_name: *b"MSDOS5.0",
            bytes_per_sector: 512,
            sectors_per_cluster: 2,
            reserved_sectors: 1,
            num_fats: 1,
            root_ent_count: 16,
            total_sectors_16: 20,
            media_type: 0xF0,
            fat_size_16: 1,
            sectors_per_track: 1,
            head_count: 1,
            hidden_sectors: 0,
            total_sectors_32: 0,
            fat_size_32: 0,
            ext_flags: 0,
            fs_version: 0,
            root_cluster: 0,
            fs_info_sector: 0,
            backup_boot_sector: 0,
            reserved: [0; 12],
            boot_signature: [0; 448],
        };
        let bpb_bytes =
            unsafe { core::slice::from_raw_parts(&bpb as *const FatBpb as *const u8, 512) };
        d.write_sector(0, bpb_bytes);

        // FAT16 table (sector 1): entry0 = 0xFFF0, entry1 = 0xFFFF, entry2 = 0xFFFF
        let mut fat = [0u8; 512];
        fat[0..2].copy_from_slice(&0xFFF0u16.to_le_bytes());
        fat[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        fat[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
        d.write_sector(1, &fat);

        // Root directory (sector 2): one entry for TEST.TXT
        let mut root = [0u8; 512];
        let entry = DirectoryEntry {
            name: *b"TEST    ",
            ext: *b"TXT",
            attr: 0x00,
            reserved: 0,
            create_time_tenth: 0,
            create_time: 0,
            create_date: 0,
            last_access_date: 0,
            first_cluster_hi: 0,
            write_time: 0,
            write_date: 0,
            first_cluster_lo: 2,
            file_size: 600,
        };
        let entry_bytes = unsafe {
            core::slice::from_raw_parts(&entry as *const DirectoryEntry as *const u8, 32)
        };
        root[0..32].copy_from_slice(entry_bytes);
        d.write_sector(2, &root);

        // Data cluster 2 starts at sector 3 (data_offset = 1 + 1 + 1 = 3)
        let data1 = [0xABu8; 512];
        let mut data2 = [0x00u8; 512];
        data2[0..88].fill(0xAB);
        d.write_sector(3, &data1);
        d.write_sector(4, &data2);

        let fs = FatFileSystem::mount(&d).unwrap();
        let mut buf = [0u8; 1024];
        let n = fs.read_file("TEST.TXT", &mut buf).unwrap();
        assert_eq!(n, 600);
        assert!(buf[..600].iter().all(|&b| b == 0xAB));
    }

    /// Test-only fixture builder that lays down a minimal FAT16 image
    /// (BPB in sector 0, single-FAT table in sector 1, one directory
    /// entry for TEST.TXT in sector 2, one cluster of 0xAB payload in
    /// sectors 3-4). Uses byte-by-byte writes rather than a
    /// reinterpret-cast on the packed record types so the fixture is
    /// entirely `unsafe`-free and keeps the crate's unsafe budget stable.
    ///
    /// Field layout of BPB/DirEntry is fixed by the on-disk FAT spec;
    /// see `FatBpb` / `DirectoryEntry` in the parent module.
    fn build_test_image(d: &RamDisk, file_size: u32) {
        // ----- Sector 0: BPB (only the fields our mount() reads). -----
        let mut bpb = [0u8; 512];
        bpb[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        bpb[3..11].copy_from_slice(b"MSDOS5.0");
        bpb[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        bpb[13] = 2; // sectors_per_cluster
        bpb[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved_sectors
        bpb[16] = 1; // num_fats
        bpb[17..19].copy_from_slice(&16u16.to_le_bytes()); // root_ent_count
        bpb[19..21].copy_from_slice(&20u16.to_le_bytes()); // total_sectors_16
        bpb[21] = 0xF0; // media_type
        bpb[22..24].copy_from_slice(&1u16.to_le_bytes()); // fat_size_16 (nonzero => FAT16)
                                                          // The remaining BPB fields are zero, matching the historical
                                                          // fixture.
        d.write_sector(0, &bpb);

        // ----- Sector 1: FAT table. Entry 0 = media descriptor, entry 1
        //       = EOC, entry 2 (our file's start cluster) = EOC. -----
        let mut fat = [0u8; 512];
        fat[0..2].copy_from_slice(&0xFFF0u16.to_le_bytes());
        fat[2..4].copy_from_slice(&0xFFF8u16.to_le_bytes());
        d.write_sector(1, &fat);

        // ----- Sector 2: root dir, first 32-byte slot is TEST.TXT. -----
        let mut root = [0u8; 512];
        root[0..8].copy_from_slice(b"TEST    ");
        root[8..11].copy_from_slice(b"TXT");
        root[11] = 0x00; // attr (regular file)
                         // reserved..last_access_date all zero.
        root[20..22].copy_from_slice(&0u16.to_le_bytes()); // first_cluster_hi
        root[26..28].copy_from_slice(&2u16.to_le_bytes()); // first_cluster_lo
        root[28..32].copy_from_slice(&file_size.to_le_bytes());
        d.write_sector(2, &root);

        // ----- Sectors 3+: payload. `sectors_per_cluster == 2` and the
        //       chain terminates after cluster 2, so we need at most
        //       cluster 2's two sectors (3 and 4). -----
        let payload = [0xABu8; 512];
        d.write_sector(3, &payload);
        d.write_sector(4, &payload);
    }

    #[test]
    fn read_file_refuses_to_truncate_when_buffer_too_small() {
        // Regression: read_file used to silently truncate at buf.len(),
        // returning a byte count smaller than the file with no diagnostic.
        // Higher-level callers (e.g. an ELF loader that received a
        // truncated program header table) had no way to distinguish this
        // from a legitimately shorter file. Contract now: too-small
        // buffer -> BufferTooSmall, no partial write.
        let d = RamDisk::new();
        build_test_image(&d, 512);
        let Ok(fs) = FatFileSystem::mount(&d) else {
            assert!(false, "mount must succeed on well-formed image");
            return;
        };
        let mut buf = [0u8; 100];
        let sentinel = buf;
        let result = fs.read_file("TEST.TXT", &mut buf);
        assert_eq!(result, Err(DriverError::BufferTooSmall));
        assert_eq!(buf, sentinel, "no bytes must be copied on BufferTooSmall");
    }

    #[test]
    fn file_size_reports_on_disk_size_without_reading_data() {
        let d = RamDisk::new();
        build_test_image(&d, 512);
        let Ok(fs) = FatFileSystem::mount(&d) else {
            assert!(false, "mount must succeed");
            return;
        };
        assert_eq!(fs.file_size("TEST.TXT"), Ok(512));
        assert_eq!(fs.file_size("NOSUCH.TXT"), Err(DriverError::FileNotFound));
    }

    #[test]
    fn read_file_succeeds_when_buffer_is_exactly_file_size() {
        // The boundary case that BufferTooSmall must NOT trigger for.
        let d = RamDisk::new();
        build_test_image(&d, 512);
        let Ok(fs) = FatFileSystem::mount(&d) else {
            assert!(false, "mount must succeed");
            return;
        };
        let mut buf = [0u8; 512];
        let result = fs.read_file("TEST.TXT", &mut buf);
        assert_eq!(result, Ok(512));
        assert!(buf.iter().all(|&b| b == 0xAB));
    }
}
