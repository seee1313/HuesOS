use clap::Parser;
use crc32fast::Hasher;
use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "HuesOS Boot Image Generator v2.1")]
struct Args {
    #[arg(short, long)]
    kernel: PathBuf,
    #[arg(short, long)]
    bootfs: PathBuf,
    #[arg(short, long)]
    cmdline: PathBuf,
    #[arg(short, long)]
    platform: PathBuf,
    #[arg(short, long)]
    output: PathBuf,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct GlobalHeader {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    num_entries: u32,
    header_size: u32,
    image_size: u64,
    arch_id: u32,
    reserved: [u8; 36],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DirectoryEntry {
    type_id: u32,
    offset: u32,
    length: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EntryHeader {
    type_id: u32,
    flags: u32,
    length: u32,
    extra: u32,
    crc32: u32,
    reserved: u32,
}

const TYPE_KERNEL: u32 = 0x00000001;
const TYPE_BOOTFS: u32 = 0x00000002;
const TYPE_CMDLINE: u32 = 0x00000003;
const TYPE_PLATFORM: u32 = 0x00000004;

const FLAG_REQUIRED: u32 = 0x80000000;
const FLAG_CRITICAL: u32 = 0x40000000;
const FLAG_EXECUTABLE: u32 = 0x00000004;

fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let kernel_data = fs::read(&args.kernel)?;
    let bootfs_data = fs::read(&args.bootfs)?;
    let cmdline_data = fs::read_to_string(&args.cmdline)?;
    let platform_data = fs::read(&args.platform)?;

    let payloads = [
        (TYPE_KERNEL, kernel_data.as_slice(), FLAG_REQUIRED | FLAG_CRITICAL | FLAG_EXECUTABLE, 0),
        (TYPE_BOOTFS, bootfs_data.as_slice(), FLAG_REQUIRED | FLAG_CRITICAL, 0),
        (TYPE_CMDLINE, cmdline_data.as_bytes(), 0, 0),
        (TYPE_PLATFORM, platform_data.as_slice(), FLAG_REQUIRED | FLAG_CRITICAL, 0),
    ];

    let num_entries = payloads.len() as u32;
    let header_size = core::mem::size_of::<GlobalHeader>()
        + (num_entries as usize * core::mem::size_of::<DirectoryEntry>());
    let mut current_offset = align_up(header_size as u64, 8);
    let mut directory = Vec::new();

    for (type_id, data, flags, extra) in &payloads {
        let length = data.len() as u32;
        let mut hasher = Hasher::new();
        hasher.update(data);
        let crc = hasher.finalize();

        directory.push(DirectoryEntry {
            type_id: *type_id,
            offset: current_offset as u32,
            length,
            flags: *flags,
        });

        // EntryHeader is 24 bytes (6 × u32). Must match size_of::<EntryHeader>()
        // and the kernel parser in huesos-kernel::boot::hbi.
        current_offset += core::mem::size_of::<EntryHeader>() as u64
            + align_up(length as u64, 8);
    }

    let file = File::create(&args.output)?;
    let mut writer = BufWriter::new(file);

    let global_header = GlobalHeader {
        magic: *b"HUESOS_H",
        version: 0x0002_0001,
        flags: 0,
        num_entries,
        header_size: header_size as u32,
        image_size: current_offset,
        arch_id: 0,
        reserved: [0; 36],
    };

    unsafe {
        let header_ptr = &global_header as *const GlobalHeader as *const u8;
        let header_slice = std::slice::from_raw_parts(header_ptr, core::mem::size_of::<GlobalHeader>());
        writer.write_all(header_slice)?;
    }

    for entry in &directory {
        unsafe {
            let entry_ptr = entry as *const DirectoryEntry as *const u8;
            let entry_slice = std::slice::from_raw_parts(entry_ptr, core::mem::size_of::<DirectoryEntry>());
            writer.write_all(entry_slice)?;
        }
    }

    for (type_id, data, flags, extra) in &payloads {
        let length = data.len() as u32;
        let mut hasher = Hasher::new();
        hasher.update(data);
        let crc = hasher.finalize();

        let entry_header = EntryHeader {
            type_id: *type_id,
            flags: *flags,
            length,
            extra: *extra,
            crc32: crc,
            reserved: 0,
        };

        unsafe {
            let eh_ptr = &entry_header as *const EntryHeader as *const u8;
            let eh_slice = std::slice::from_raw_parts(eh_ptr, core::mem::size_of::<EntryHeader>());
            writer.write_all(eh_slice)?;
        }

        writer.write_all(data)?;
        
        let padding = (8 - (length % 8)) % 8;
        if padding > 0 {
            writer.write_all(&[0u8; 8][..padding as usize])?;
        }
    }

    writer.flush()?;
    println!("HBI v2.1 image created successfully at {:?}", args.output);
    println!("Total size: {} bytes", current_offset);
    Ok(())
}
