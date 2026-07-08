//! FAT16/32 Filesystem Driver for HuesOS.
//!
//! This driver provides low-level access to FAT formatted storage,
//! supporting directory traversal and file reading.

#![no_std]

use core::ptr::NonNull;

/// Interface for the underlying block device (e.g., RAM disk from HBI, Disk Drive).
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
}

/// BIOS Parameter Block (BPB) for FAT12/16/32.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FatBpb {
    pub jump: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_ent_count: u16, // 0 for FAT32
    pub total_sectors_16: u16, // 0 for FAT32
    pub media_type: u8,
    pub fat_size_16: u16, // 0 for FAT32
    pub sectors_per_fat_16: u16, // 0 for FAT32
    pub sectors_per_track: u16,
    pub head_count: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub fat_size_32: u32,
    pub sectors_per_fat_32: u32,
    pub ext_flags: u32,
    pub fs_version: u32,
    pub root_cluster: u32,
    pub fs_info_sector: u32,
    pub backup_boot_sector: u32,
    pub reserved: [u8; 12],
    pub boot_signature: [u8; 512 - 0x40], // Padding to sector size
}

/// Directory Entry in FAT.
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
        self.name[0] == 0x00
    }

    pub fn is_directory(&self) -> bool {
        (self.attr & 0x10) != 0
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }
}

pub struct FatFileSystem<'a, D: BlockDevice> {
    device: &'a D,
    bpb: FatBpb,
    is_fat32: bool,
}

impl<'a, D: BlockDevice> FatFileSystem<'a, D> {
    /// Mount a FAT filesystem from a block device.
    pub fn mount(device: &'a D) -> Result<Self, DriverError> {
        let mut boot_sector = [0u8; 512];
        device.read_sector(0, &mut boot_sector)?;

        let bpb = unsafe { core::ptr::read(boot_sector.as_ptr() as *const FatBpb) };
        
        if bpb.bytes_per_sector != 512 {
            return Err(DriverError::InvalidFat);
        }

        let is_fat32 = bpb.fat_size_16 == 0;

        Ok(Self {
            device,
            bpb,
            is_fat32,
        })
    }

    /// Get the sector offset of the FAT table.
    fn fat_offset(&self) -> u32 {
        self.bpb.reserved_sectors as u32
    }

    /// Get the sector offset of the data region.
    fn data_offset(&self) -> u32 {
        let fat_sectors = if self.is_fat32 {
            self.bpb.sectors_per_fat_32
        } else {
            self.bpb.sectors_per_fat_16 as u32
        };
        self.fat_offset() + (self.bpb.num_fats as u32 * fat_sectors)
    }

    /// Translate a cluster number to a sector number.
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        let sectors_per_cluster = self.bpb.sectors_per_cluster as u32;
        let first_data_sector = self.data_offset();
        
        let cluster_offset = if self.is_fat32 {
            cluster - 2
        } else {
            cluster - 2
        };

        first_data_sector + (cluster_offset * sectors_per_cluster)
    }

    /// Read a file's contents into a buffer.
    pub fn read_file(&self, path: &str, buf: &mut [u8]) -> Result<usize, DriverError> {
        // Simplified implementation: only read from root for now.
        // In a full version, we would traverse the path.
        let entry = self.find_entry_in_root(path)?;
        
        if entry.is_directory() {
            return Err(DriverError::NotADirectory);
        }

        let mut bytes_read = 0;
        let mut cluster = entry.first_cluster();
        let mut size_left = entry.file_size as usize;

        while size_left > 0 {
            let sector = self.cluster_to_sector(cluster);
            let mut sector_buf = [0u8; 512];
            self.device.read_sector(sector, &mut sector_buf)?;

            let to_copy = core::cmp::min(size_left, 512);
            if bytes_read + to_copy > buf.len() {
                break;
            }

            buf[bytes_read..bytes_read + to_copy].copy_from_slice(&sector_buf[..to_copy]);
            bytes_read += to_copy;
            size_left -= to_copy;

            // Find next cluster in FAT
            cluster = self.get_next_cluster(cluster)?;
            if cluster == 0 || cluster == 0x0FFFFFFF {
                break;
            }
        }

        Ok(bytes_read)
    }

    fn find_entry_in_root(&self, name: &str) -> Result<DirectoryEntry, DriverError> {
        let mut sector = 0;
        let root_sectors = if self.is_fat32 {
            // In FAT32, root is a cluster chain. For MVP, we assume it starts at cluster 2.
            let root_cluster = self.bpb.root_cluster;
            // We'll just check the first sector of the root cluster for the MVP.
            let start_sector = self.cluster_to_sector(root_cluster);
            let mut buf = [0u8; 512];
            self.device.read_sector(start_sector, &mut buf)?;
            
            let entries = unsafe {
                core::slice::from_raw_parts(buf.as_ptr() as *const DirectoryEntry, 512 / core::mem::size_of::<DirectoryEntry>())
            };
            
            for entry in entries {
                if !entry.is_free() && self.match_name(entry, name) {
                    return Ok(*entry);
                }
            }
            return Err(DriverError::FileNotFound);
        } else {
            // FAT16: Root directory is at a fixed location.
            let root_start = self.data_offset();
            let root_entries = self.bpb.root_ent_count as u32;
            let root_sectors = (root_entries * 32 + 511) / 512;
            
            for s in 0..root_sectors {
                let mut buf = [0u8; 512];
                self.device.read_sector(root_start + s, &mut buf)?;
                let entries = unsafe {
                    core::slice::from_raw_parts(buf.as_ptr() as *const DirectoryEntry, 512 / core::mem::size_of::<DirectoryEntry>())
                };
                for entry in entries {
                    if !entry.is_free() && self.match_name(entry, name) {
                        return Ok(*entry);
                    }
                }
            }
            return Err(DriverError::FileNotFound);
        };
    }

    fn match_name(&self, entry: &DirectoryEntry, name: &str) -> bool {
        // Simplified: just check first few chars.
        let name_bytes = &entry.name;
        let search = name.as_bytes();
        if search.len() > 8 { return false; }
        for i in 0..search.len() {
            if name_bytes[i] != search[i] { return false; }
        }
        true
    }

// ... (previous content) ...
    fn get_next_cluster(&self, cluster: u32) -> Result<u32, DriverError> {
        let fat_sector = self.fat_offset() + (cluster / (512 / 4));
        let offset = (cluster % (512 / 4)) as usize * 4;
        
        let mut buf = [0u8; 512];
        self.device.read_sector(fat_sector, &mut buf)?;
        
        let next_cluster = u32::from_le_bytes(buf[offset..offset+4].try_into().unwrap());
        Ok(next_cluster)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;

    struct RamDisk {
        data: Mutex<[u8; 1024 * 10]>,
        sector_size: u32,
    }

    impl RamDisk {
        fn new() -> Self {
            Self {
                data: Mutex::new([0u8; 1024 * 10]),
                sector_size: 512,
            }
        }

        fn write_sector(&self, sector: u32, buf: &[u8]) {
            let mut data = self.data.lock();
            let start = (sector * 512) as usize;
            data[start..start + 512].copy_from_slice(buf);
        }
    }

    impl BlockDevice for RamDisk {
        fn read_sector(&self, sector: u32, buf: &mut [u8]) -> Result<(), DriverError> {
            let data = self.data.lock();
            let start = (sector * 512) as usize;
            if start + 512 > data.len() {
                return Err(DriverError::InvalidSector);
            }
            buf.copy_from_slice(&data[start..start + 512]);
            Ok(())
        }

        fn write_sector(&self, sector: u32, buf: &[u8]) -> Result<(), DriverError> {
            let mut data = self.data.lock();
            let start = (sector * 512) as usize;
            if start + 512 > data.len() {
                return Err(DriverError::InvalidSector);
            }
            data[start..start + 512].copy_from_slice(buf);
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    #[test]
    fn test_fat_mount_invalid() {
        let disk = RamDisk::new();
        let result = FatFileSystem::mount(&disk);
        assert!(result.is_err());
    }

    #[test]
    fn test_fat_mount_valid_bpb() {
        let disk = RamDisk::new();
        let bpb = FatBpb {
            jump: [0, 0, 0],
            oem_name: [0; 8],
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 1,
            num_fats: 2,
            root_ent_count: 512,
            total_sectors_16: 100,
            media_type: 0,
            fat_size_16: 10,
            sectors_per_fat_16: 10,
            sectors_per_track: 0,
            head_count: 0,
            hidden_sectors: 0,
            total_sectors_32: 100,
            fat_size_32: 0,
            sectors_per_fat_32: 0,
            ext_flags: 0,
            fs_version: 0,
            root_cluster: 2,
            fs_info_sector: 0,
            backup_boot_sector: 0,
            reserved: [0; 12],
            boot_signature: [0; 512 - 0x40],
        };
        
        let buf = unsafe {
            core::slice::from_raw_parts(&bpb as *const FatBpb as *const u8, 512)
        };
        disk.write_sector(0, buf);
        
        let result = FatFileSystem::mount(&disk);
        assert!(result.is_ok());
    }
}
