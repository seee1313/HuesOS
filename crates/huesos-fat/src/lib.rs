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
}

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
    pub fat_size_32: u32,
    pub ext_flags: u32,
    pub fs_version: u32,
    pub root_cluster: u32,
    pub fs_info_sector: u32,
    pub backup_boot_sector: u32,
    pub reserved: [u8; 12],
    pub boot_signature: [u8; 512 - 72],
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
    pub fn is_directory(&self) -> bool { (self.attr & 0x10) != 0 }
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }
    pub fn is_volume_label(&self) -> bool { (self.attr & 0x08) != 0 }
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
        if bpb.bytes_per_sector != 512 { return Err(DriverError::InvalidFat); }

        Ok(Self { device, bpb, is_fat32: bpb.fat_size_16 == 0 })
    }

    fn fat_offset(&self) -> u32 { self.bpb.reserved_sectors as u32 }

    fn sectors_per_fat(&self) -> u32 {
        if self.is_fat32 { self.bpb.fat_size_32 } else { self.bpb.fat_size_16 as u32 }
    }

    fn data_offset(&self) -> u32 {
        let root_sectors = if self.is_fat32 {
            0
        } else {
            ((self.bpb.root_ent_count as u32 * 32) + (self.bpb.bytes_per_sector as u32 - 1))
                / self.bpb.bytes_per_sector as u32
        };
        self.fat_offset() + (self.bpb.num_fats as u32 * self.sectors_per_fat()) + root_sectors
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_offset() + (cluster.saturating_sub(2) * self.bpb.sectors_per_cluster as u32)
    }

    // ==================== REAL PATH TRAVERSAL ====================

    /// Walks the path and returns the final DirectoryEntry.
    pub fn find_entry(&self, path: &str) -> Result<DirectoryEntry, DriverError> {
        if path.is_empty() { return Err(DriverError::InvalidPath); }

        let mut current_cluster = if self.is_fat32 {
            self.bpb.root_cluster
        } else {
            // FAT16 root is special (fixed location), we use 0 as marker
            0
        };

        let components = path.split('/').filter(|c| !c.is_empty());

        // For FAT16 we start from fixed root
        let mut is_root_special = !self.is_fat32;

        for component in components {
            if component.len() > 255 { return Err(DriverError::PathTooLong); }

            let entry = if is_root_special {
                self.find_entry_in_fat16_root(component)?
            } else {
                self.find_entry_in_dir(current_cluster, component)?
            };

            if entry.is_directory() {
                current_cluster = entry.first_cluster();
                is_root_special = false;
            } else {
                // last component must be file
                return Ok(entry);
            }
        }

        // If we finished loop on a directory, return last dir entry
        // (for now we return the last traversed entry)
        // Better to have open_dir, but for read_file compatibility:
        Err(DriverError::FileNotFound) // caller should have used full path to file
    }

    fn root_dir_offset(&self) -> u32 {
        self.fat_offset() + (self.bpb.num_fats as u32 * self.sectors_per_fat())
    }

    fn find_entry_in_fat16_root(&self, name: &str) -> Result<DirectoryEntry, DriverError> {
        let root_start = self.root_dir_offset();
        let root_entries = self.bpb.root_ent_count as u32;
        let root_sectors = (root_entries * 32 + 511) / 512;

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

    fn find_entry_in_dir(&self, dir_cluster: u32, name: &str) -> Result<DirectoryEntry, DriverError> {
        let mut cluster = dir_cluster;

        while cluster != 0 && cluster < 0x0FFFFFF8 {
            let sector = self.cluster_to_sector(cluster);
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;

            for s in 0..sectors_per_cluster {
                let mut buf = [0u8; 512];
                self.device.read_sector(sector + s, &mut buf)?;

                for i in 0..(512 / 32) {
                    let entry = unsafe {
                        core::ptr::read_unaligned(buf.as_ptr().add(i * 32) as *const DirectoryEntry)
                    };
                    if !entry.is_free() && !entry.is_volume_label() && self.name_matches(&entry, name) {
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
        let mut i = 0;
        for &b in name.as_bytes() {
            if b == b'.' {
                i = 8;
                continue;
            }
            if i < 11 {
                search[i] = b.to_ascii_uppercase();
                i += 1;
            }
        }
        entry_name == search
    }

    // ==================== FILE READING ====================

    pub fn read_file(&self, path: &str, buf: &mut [u8]) -> Result<usize, DriverError> {
        let entry = self.find_entry(path)?;

        if entry.is_directory() {
            return Err(DriverError::NotADirectory);
        }

        let mut bytes_read = 0usize;
        let mut cluster = entry.first_cluster();
        let mut remaining = entry.file_size as usize;

        while remaining > 0 && cluster != 0 && cluster < 0x0FFFFFF8 {
            let sector = self.cluster_to_sector(cluster);
            let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;

            for s in 0..sectors_per_cluster {
                if remaining == 0 { break; }
                let mut sector_buf = [0u8; 512];
                self.device.read_sector(sector + s, &mut sector_buf)?;

                let copy_len = core::cmp::min(remaining, 512);
                if bytes_read + copy_len > buf.len() {
                    remaining = 0;
                    break;
                }
                buf[bytes_read..bytes_read + copy_len].copy_from_slice(&sector_buf[..copy_len]);
                bytes_read += copy_len;
                remaining -= copy_len;
            }

            cluster = self.get_next_cluster(cluster)?;
        }

        Ok(bytes_read)
    }

    // ==================== FAT CHAIN HELPERS ====================

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
            u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
        } else {
            u16::from_le_bytes([buf[off], buf[off+1]]) as u32
        };

        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;

    struct RamDisk { data: Mutex<[u8; 40*1024]>, sector_size: u32 }
    impl RamDisk {
        fn new() -> Self { Self { data: Mutex::new([0u8; 40*1024]), sector_size: 512 } }
        fn write_sector(&self, sec: u32, b: &[u8]) {
            let mut d = self.data.lock();
            let start = (sec as usize) * 512;
            d[start..start+512].copy_from_slice(b);
        }
    }
    impl BlockDevice for RamDisk {
        fn read_sector(&self, sec: u32, buf: &mut [u8]) -> Result<(), DriverError> {
            let d = self.data.lock();
            let start = (sec as usize)*512;
            if start + 512 > d.len() { return Err(DriverError::InvalidSector); }
            buf.copy_from_slice(&d[start..start+512]);
            Ok(())
        }
        fn write_sector(&self, sec: u32, buf: &[u8]) -> Result<(), DriverError> {
            let mut d = self.data.lock();
            let start = (sec as usize)*512;
            d[start..start+512].copy_from_slice(buf);
            Ok(())
        }
        fn sector_size(&self) -> u32 { self.sector_size }
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
        let mut bpb = FatBpb {
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
            boot_signature: [0; 440],
        };
        let bpb_bytes = unsafe {
            core::slice::from_raw_parts(&bpb as *const FatBpb as *const u8, 512)
        };
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
}
