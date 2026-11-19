//! `/bin/fdisk.elf` — Protective MBR + GPT partitioning utility for HuesOS.
//!
//! Dynamic `ET_DYN` ELF (`PT_INTERP=/lib/ld-huesos.so`, `DT_NEEDED=libcanvas.so`).
//! Reads `argc`/`argv` and `@caps(...)` mask from `libcanvas::stdio`, writes
//! TSV/text to `stdout`/`stderr`, and enforces `@caps(hxfs=none|ro)` fail-closed.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::panic::PanicInfo;

use huesos_abi::auxv::caps_mask;
use huesos_gpt::{
    parse_size_lbas, verify_disk_io, BlockIo512, GptDisk, Guid, GUID_ESP, GUID_HXFS_V7,
    GUID_LINUX_SWAP, LBA_SIZE,
};
use huesos_hxfs::{probe_bare_volume, BareVolume, BlockReader as HxfsBlockReader, HxfsError};
use libcanvas::block::BlockDevice;
use libcanvas::heap::ScudoHeap;
use libcanvas::hxfs::{Hxfs, HxfsFile};
use libcanvas::stdio::{self, CapKind};
use libcanvas::Channel;

#[global_allocator]
static ALLOCATOR: ScudoHeap = ScudoHeap;

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym fdisk_entry,
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = stdio::stderr_str("fdisk: fatal panic\n");
    stdio::exit(99)
}

extern "C" fn fdisk_entry() -> ! {
    let code = run();
    stdio::exit(code)
}

struct NvmeBlockIo {
    dev: RefCell<BlockDevice>,
    total_lbas: u64,
    block_size: u32,
}

impl NvmeBlockIo {
    fn open(dev_handle: libcanvas::Handle) -> Result<Self, String> {
        let mut dev = BlockDevice::from_channel(Channel::from_handle(dev_handle))
            .map_err(|e| format!("block open failed: {}", e.as_str()))?;
        let info = dev
            .info()
            .map_err(|e| format!("block info failed: {}", e.as_str()))?;
        let block_size = info.block_size.max(LBA_SIZE as u32);
        let total_lbas = info.block_count * u64::from(block_size / LBA_SIZE as u32);
        Ok(Self {
            dev: RefCell::new(dev),
            total_lbas,
            block_size,
        })
    }
}

impl BlockIo512 for NvmeBlockIo {
    fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String> {
        let ratio = u64::from((self.block_size / LBA_SIZE as u32).max(1));
        let hw_lba = lba / ratio;
        let sub = (lba % ratio) as usize;
        let mut buf = vec![0u8; self.block_size as usize];
        self.dev
            .borrow_mut()
            .read_blocks(hw_lba, 1, &mut buf)
            .map_err(|e| format!("block read lba {lba}: {}", e.as_str()))?;
        out.copy_from_slice(&buf[sub * LBA_SIZE..(sub + 1) * LBA_SIZE]);
        Ok(())
    }

    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String> {
        let ratio = u64::from((self.block_size / LBA_SIZE as u32).max(1));
        let hw_lba = lba / ratio;
        let sub = (lba % ratio) as usize;
        let mut buf = vec![0u8; self.block_size as usize];
        if ratio > 1 {
            self.dev
                .borrow_mut()
                .read_blocks(hw_lba, 1, &mut buf)
                .map_err(|e| format!("block rmw read lba {lba}: {}", e.as_str()))?;
        }
        buf[sub * LBA_SIZE..(sub + 1) * LBA_SIZE].copy_from_slice(data);
        self.dev
            .borrow_mut()
            .write_blocks(hw_lba, 1, &buf)
            .map_err(|e| format!("block write lba {lba}: {}", e.as_str()))
    }

    fn flush(&mut self) -> Result<(), String> {
        self.dev
            .borrow_mut()
            .flush()
            .map_err(|e| format!("block flush: {}", e.as_str()))
    }
}

struct HxfsImageIo {
    file: HxfsFile,
    total_lbas: u64,
}

impl HxfsImageIo {
    fn open(path: &str, write: bool, min_lbas: u64) -> Result<Self, String> {
        let mask = stdio::caps_mask();
        if (mask & caps_mask::HXFS_RO) == 0 {
            return Err(String::from("AccessDenied (hxfs=none)"));
        }
        if write && (mask & caps_mask::HXFS_RW) == 0 {
            return Err(String::from("AccessDenied (hxfs=ro)"));
        }
        let svc_h = stdio::take_cap_handle(CapKind::HxfsService)
            .ok_or_else(|| String::from("AccessDenied (no hxfs service capability)"))?;
        let hxfs = Hxfs::from_channel(Channel::from_handle(svc_h));
        let file = match hxfs.open_file(path) {
            Ok(f) => f,
            Err(_) if write => hxfs
                .create_file(path)
                .map_err(|e| format!("hxfs create '{path}': {}", e.as_str()))?,
            Err(e) => return Err(format!("hxfs open '{path}': {}", e.as_str())),
        };
        let mut size = file
            .size()
            .map_err(|e| format!("hxfs size '{path}': {}", e.as_str()))?;
        let min_bytes = min_lbas * LBA_SIZE as u64;
        if write && size < min_bytes {
            file.truncate(min_bytes)
                .map_err(|e| format!("hxfs truncate '{path}': {}", e.as_str()))?;
            size = min_bytes;
        }
        Ok(Self {
            file,
            total_lbas: (size / LBA_SIZE as u64).max(min_lbas),
        })
    }
}

impl BlockIo512 for HxfsImageIo {
    fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String> {
        let off = lba * LBA_SIZE as u64;
        let mut tmp = [0u8; LBA_SIZE];
        let got = self
            .file
            .read_at(off, &mut tmp)
            .map_err(|e| format!("hxfs read_at {off}: {}", e.as_str()))?;
        out.fill(0);
        let n = got.len().min(LBA_SIZE);
        out[..n].copy_from_slice(&got[..n]);
        Ok(())
    }

    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String> {
        let off = lba * LBA_SIZE as u64;
        self.file
            .write_at(off, data)
            .map_err(|e| format!("hxfs write_at {off}: {}", e.as_str()))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        self.file
            .fsync()
            .map_err(|e| format!("hxfs fsync: {}", e.as_str()))
    }
}

struct SparseMemDisk {
    total_lbas: u64,
    sectors: alloc::collections::BTreeMap<u64, [u8; LBA_SIZE]>,
}

impl SparseMemDisk {
    fn seeded_demo() -> Result<Self, String> {
        let total_lbas = 2_097_152u64; // 1 GiB virtual disk
        let mut io = Self {
            total_lbas,
            sectors: alloc::collections::BTreeMap::new(),
        };
        let mut gpt = GptDisk::init_empty(total_lbas, 0x4855_4553_4f53_3033)?;
        gpt.add_partition(GUID_ESP, Some(2048), 131_072, "EFI-System", 1)?; // 64 MiB
        gpt.add_partition(GUID_HXFS_V7, None, 1_048_576, "HxFS-Root", 2)?; // 512 MiB
        gpt.add_partition(GUID_LINUX_SWAP, None, 262_144, "HuesOS-Swap", 3)?; // 128 MiB
        gpt.write_to(&mut io, false)?;
        Ok(io)
    }
}

impl BlockIo512 for SparseMemDisk {
    fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String> {
        if lba >= self.total_lbas {
            return Err(format!("read lba {lba} out of bounds"));
        }
        match self.sectors.get(&lba) {
            Some(sec) => *out = *sec,
            None => out.fill(0),
        }
        Ok(())
    }

    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String> {
        if lba >= self.total_lbas {
            return Err(format!("write lba {lba} out of bounds"));
        }
        self.sectors.insert(lba, *data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

enum Backend {
    Nvme(NvmeBlockIo),
    Hxfs(HxfsImageIo),
    Demo(SparseMemDisk),
}

impl BlockIo512 for Backend {
    fn total_lbas(&self) -> u64 {
        match self {
            Backend::Nvme(b) => b.total_lbas(),
            Backend::Hxfs(b) => b.total_lbas(),
            Backend::Demo(b) => b.total_lbas(),
        }
    }

    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> Result<(), String> {
        match self {
            Backend::Nvme(b) => b.read_lba(lba, out),
            Backend::Hxfs(b) => b.read_lba(lba, out),
            Backend::Demo(b) => b.read_lba(lba, out),
        }
    }

    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<(), String> {
        match self {
            Backend::Nvme(b) => b.write_lba(lba, data),
            Backend::Hxfs(b) => b.write_lba(lba, data),
            Backend::Demo(b) => b.write_lba(lba, data),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self {
            Backend::Nvme(b) => b.flush(),
            Backend::Hxfs(b) => b.flush(),
            Backend::Demo(b) => b.flush(),
        }
    }
}

/// HxFS stores 4 KiB blocks; the block services speak 512-byte LBAs.
const HXFS_BLOCK_SIZE: usize = 4096;
const LBAS_PER_HXFS_BLOCK: u64 = (HXFS_BLOCK_SIZE / LBA_SIZE) as u64;

/// Adapts a 512-byte-sector backend to the 4 KiB reader the HxFS validator
/// wants, so `fdisk` probes a bare volume with the *same* code the mount path
/// uses instead of a second, weaker signature check.
struct HxfsProbeIo<'a> {
    io: &'a dyn BlockIo512,
}

impl HxfsBlockReader for HxfsProbeIo<'_> {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        let bytes = (blocks as usize)
            .checked_mul(HXFS_BLOCK_SIZE)
            .ok_or(HxfsError::OutOfRange)?;
        if out.len() < bytes {
            return Err(HxfsError::BufferTooSmall);
        }
        for index in 0..u64::from(blocks) {
            let mut sector = [0u8; LBA_SIZE];
            let hw_lba = lba
                .checked_mul(LBAS_PER_HXFS_BLOCK)
                .and_then(|base| base.checked_add(index))
                .ok_or(HxfsError::OutOfRange)?;
            self.io
                .read_lba(hw_lba, &mut sector)
                .map_err(|_| HxfsError::Io)?;
            let off = (index as usize) * LBA_SIZE;
            out[off..off + LBA_SIZE].copy_from_slice(&sector);
        }
        Ok(())
    }
}

/// Probe a whole device for a bare `HxFS v7` (superfloppy) volume.
///
/// `None` means "no valid superblock at LBA 0", which is the normal answer for
/// a GPT disk, a blank disk or anything else that is not a bare HxFS volume.
fn probe_raw_hxfs(io: &dyn BlockIo512) -> Option<BareVolume> {
    let mut reader = HxfsProbeIo { io };
    probe_bare_volume(&mut reader).ok()
}

/// One-line-per-disk TSV used by `list` for a volume with no partition table.
fn format_raw_list(volume: &BareVolume, total_lbas: u64) -> String {
    let size_mib = total_lbas.saturating_mul(LBA_SIZE as u64) / (1024 * 1024);
    format!(
        "disk\tlayout\tlabel\tsize_mib\tstatus\ndisk0\t{}\t{}\t{}\tOK\n",
        volume.layout_tag(),
        volume.layout_label(),
        size_mib
    )
}

fn format_raw_inspect(volume: &BareVolume, total_lbas: u64) -> String {
    let size_mib = total_lbas.saturating_mul(LBA_SIZE as u64) / (1024 * 1024);
    format!(
        "layout={}\nlabel={}\ntotal_lbas={}\nsize_mib={}\nformat_version={}\ntype_system_version={}\nblock_size={}\ninstance_uuid={}\nsequence_number={}\nroot_state={}\ngpt=absent\nstatus=OK\n",
        volume.layout_tag(),
        volume.layout_label(),
        total_lbas,
        size_mib,
        volume.format_version,
        volume.type_system_version,
        volume.block_size,
        format_uuid(&volume.instance_uuid),
        volume.sequence_number,
        volume.root_state
    )
}

fn format_raw_verify(volume: &BareVolume, total_lbas: u64) -> String {
    let size_mib = total_lbas.saturating_mul(LBA_SIZE as u64) / (1024 * 1024);
    format!(
        "ok=true\nlayout={} {}\nformat_version={}\ntotal_lbas={}\nsize_mib={}\ngpt=absent\nsuperblock_crc=ok\n",
        volume.layout_tag(),
        volume.layout_label(),
        volume.format_version,
        total_lbas,
        size_mib
    )
}

/// Render 16 raw UUID bytes in the canonical `8-4-4-4-12` form without pulling
/// in the GPT module's private helper.
fn format_uuid(uuid: &[u8; 16]) -> String {
    let hex = |range: core::ops::Range<usize>| -> String {
        let mut out = String::new();
        for byte in &uuid[range] {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

fn collect_args() -> Vec<String> {
    let count = stdio::args_count();
    let mut args = Vec::with_capacity(count);
    let mut buf = [0u8; 256];
    for i in 0..count {
        if let Some(s) = stdio::arg_str(i, &mut buf) {
            args.push(String::from(s));
        }
    }
    args
}

fn require_write_cap(mask: u64, target_is_hxfs_file: bool) -> Result<(), String> {
    if (mask & caps_mask::HXFS_RO) == 0 && target_is_hxfs_file {
        return Err(String::from("AccessDenied (hxfs=none)"));
    }
    if (mask & caps_mask::HXFS_RW) == 0
        || (!target_is_hxfs_file && (mask & caps_mask::BLOCK_RW) == 0)
    {
        return Err(String::from("AccessDenied (read-only capability)"));
    }
    Ok(())
}

fn open_backend(target: Option<&str>, write: bool, min_lbas: u64) -> Result<Backend, String> {
    let mask = stdio::caps_mask();
    if (mask & caps_mask::HXFS_RO) == 0 && stdio::cap_handle(CapKind::BlockDev).is_none() {
        return Err(String::from(
            "AccessDenied (hxfs=none, no storage capability)",
        ));
    }
    if let Some(path) = target {
        if !path.starts_with("/dev/") {
            return HxfsImageIo::open(path, write, min_lbas).map(Backend::Hxfs);
        }
    }
    // `/dev/mem` is the scratch in-memory disk: a writable GPT fixture that
    // never touches the real device, so `gpt-init`/`add`/`del` can be
    // exercised on a machine whose only block device already holds a bare
    // HxFS volume.
    if target == Some("/dev/mem") {
        if write {
            require_write_cap(mask, false)?;
        }
        return SparseMemDisk::seeded_demo().map(Backend::Demo);
    }
    if let Some(h) = stdio::take_cap_handle(CapKind::BlockDev) {
        if write && (mask & (caps_mask::BLOCK_RW | caps_mask::HXFS_RW)) == 0 {
            return Err(String::from("AccessDenied (read-only capability)"));
        }
        return NvmeBlockIo::open(h).map(Backend::Nvme);
    }
    if write {
        require_write_cap(mask, false)?;
    }
    SparseMemDisk::seeded_demo().map(Backend::Demo)
}

fn run() -> i32 {
    let args = collect_args();
    let sub = args.get(1).map(String::as_str).unwrap_or("list");

    let mut dry_run = false;
    let mut force = false;
    let mut type_str = "hxfs";
    let mut start_str: Option<&str> = None;
    let mut size_str = "64M";
    let mut name_str = "HuesOS-Part";
    let mut part_num_arg: Option<usize> = None;
    let mut target: Option<&str> = None;

    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--force" | "-f" => force = true,
            "--type" => {
                if let Some(v) = args.get(i + 1) {
                    type_str = v.as_str();
                    i += 1;
                }
            }
            "--start" => {
                if let Some(v) = args.get(i + 1) {
                    start_str = Some(v.as_str());
                    i += 1;
                }
            }
            "--size" => {
                if let Some(v) = args.get(i + 1) {
                    size_str = v.as_str();
                    i += 1;
                }
            }
            "--name" => {
                if let Some(v) = args.get(i + 1) {
                    name_str = v.as_str();
                    i += 1;
                }
            }
            "--part" => {
                if let Some(v) = args.get(i + 1) {
                    part_num_arg = v.parse::<usize>().ok();
                    i += 1;
                }
            }
            other if !other.starts_with('-') => {
                if part_num_arg.is_none() && (sub == "del" || sub == "resize") {
                    if let Ok(n) = other.parse::<usize>() {
                        part_num_arg = Some(n);
                        i += 1;
                        continue;
                    }
                }
                target = Some(other);
            }
            _ => {}
        }
        i += 1;
    }

    let mask = stdio::caps_mask();
    let res: Result<String, String> = match sub {
        "help" | "--help" | "-h" => Ok(String::from(
            "usage: fdisk <list|--list|inspect|verify|gpt-init|add|del|resize> [opts] [target]\n  --type <hxfs|esp|linux|swap|basic|UUID>  --size <64M|1G|LBAs>  --start <LBA>  --name <label>  --dry-run  --force\n  a target without a GPT but with a bare HxFS superblock is reported as `raw-hxfs`;\n  gpt-init refuses to erase such a volume unless --force is given;\n  /dev/mem selects the writable in-memory scratch disk (never the real device)\n",
        )),
        "list" | "--list" => {
            let io = match open_backend(target, false, 4096) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            match GptDisk::read_from(&io) {
                Ok(disk) => Ok(disk.format_list_tsv()),
                // A whole-device HxFS volume (superfloppy) has no GPT by
                // design: report it as such instead of surfacing
                // "bad GPT signature" for a perfectly healthy disk.
                Err(gpt_err) => match probe_raw_hxfs(&io) {
                    Some(volume) => Ok(format_raw_list(&volume, io.total_lbas())),
                    None => Err(gpt_err),
                },
            }
        }
        "inspect" => {
            let io = match open_backend(target, false, 4096) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            let disk = match GptDisk::read_from(&io) {
                Ok(d) => d,
                Err(gpt_err) => {
                    return match probe_raw_hxfs(&io) {
                        Some(volume) => {
                            let text = format_raw_inspect(&volume, io.total_lbas());
                            let _ = stdio::stdout_str(&text);
                            0
                        }
                        None => fail_msg(&gpt_err),
                    };
                }
            };
            let mut out = format!(
                "disk_lbas={}\nmbr_protective={}\ndisk_guid={}\nfirst_usable={}\nlast_usable={}\nheader_crc32={:#010x}\nentries_crc32={:#010x}\n",
                disk.disk_lbas,
                disk.mbr.is_protective_gpt(),
                disk.primary.disk_guid.format_uuid(),
                disk.primary.first_usable_lba,
                disk.primary.last_usable_lba,
                disk.primary.header_crc32,
                disk.primary.partition_entry_array_crc32,
            );
            out.push_str(&disk.format_list_tsv());
            Ok(out)
        }
        "verify" => {
            let io = match open_backend(target, false, 4096) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            // A bare HxFS volume is not a partitioned disk; verifying it
            // means verifying the superblock it is mounted from.
            if GptDisk::read_from(&io).is_err() {
                if let Some(volume) = probe_raw_hxfs(&io) {
                    let text = format_raw_verify(&volume, io.total_lbas());
                    let _ = stdio::stdout_str(&text);
                    return 0;
                }
            }
            let r = verify_disk_io(&io);
            let mut out = format!(
                "ok={}\nprotective_mbr={}\nprimary_crc={}\nbackup_crc={}\nentries_crc={}\noverlaps={}\nalignment_warnings={}\n",
                r.ok,
                r.protective_mbr,
                r.primary_crc_ok,
                r.backup_crc_ok,
                r.entries_crc_ok,
                r.overlaps,
                r.alignment_warnings
            );
            for err in &r.errors {
                out.push_str(&format!("error: {err}\n"));
            }
            if r.ok {
                Ok(out)
            } else {
                Err(out)
            }
        }
        "gpt-init" => {
            let is_hxfs = target.is_some_and(|t| !t.starts_with("/dev/"));
            if let Err(e) = require_write_cap(mask, is_hxfs) {
                return fail_msg(&e);
            }
            let min_lbas = parse_size_lbas(size_str).unwrap_or(131_072).max(4096);
            let mut io = match open_backend(target, true, min_lbas) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            // Safety gate: `gpt-init` overwrites LBA 1 and the entry array,
            // which on a bare HxFS volume is live filesystem metadata. The
            // block-device capability is one-shot, so the probe has to run on
            // the already-open backend rather than on a second open. Opening
            // for write only ever *grows* a short file target, so probing here
            // cannot destroy data before the refusal.
            // A dry run writes nothing, so it stays available on a volume that
            // would otherwise be protected: it reports the layout it *would*
            // write together with the warning that the real run needs --force.
            let mut note = String::new();
            if let Some(volume) = probe_raw_hxfs(&io) {
                if !force && !dry_run {
                    return fail_msg(&format!(
                        "refusing to overwrite {} ({}) at {}: no GPT, the whole device is the filesystem; pass --force to erase it",
                        volume.layout_tag(),
                        volume.layout_label(),
                        target.unwrap_or("the block device")
                    ));
                }
                if dry_run {
                    note = format!(
                        "warning=raw-hxfs volume ({}) detected, the real run needs --force\n",
                        volume.layout_label()
                    );
                }
            }
            match GptDisk::init_empty(io.total_lbas(), 0x4855_4553_0001) {
                Ok(mut disk) => match disk.write_to(&mut io, dry_run) {
                    Ok(()) => Ok(format!(
                        "{}gpt-init {} total_lbas={} guid={}\n",
                        note,
                        if dry_run { "dry-run" } else { "ok" },
                        disk.disk_lbas,
                        disk.primary.disk_guid.format_uuid()
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
        "add" => {
            let is_hxfs = target.is_some_and(|t| !t.starts_with("/dev/"));
            if let Err(e) = require_write_cap(mask, is_hxfs) {
                return fail_msg(&e);
            }
            let mut io = match open_backend(target, true, 131_072) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            let mut disk = match GptDisk::read_from(&io) {
                Ok(d) => d,
                Err(e) => return fail_msg(&e),
            };
            let Some(tguid) = Guid::parse_type(type_str) else {
                return fail_msg(&format!("unknown partition type '{type_str}'"));
            };
            let size_lbas = match parse_size_lbas(size_str) {
                Ok(v) => v,
                Err(e) => return fail_msg(&e),
            };
            let start = match start_str {
                Some(s) => match s.parse::<u64>() {
                    Ok(v) => Some(v),
                    Err(_) => return fail_msg(&format!("invalid --start '{s}'")),
                },
                None => None,
            };
            match disk.add_partition(tguid, start, size_lbas, name_str, 0xA11CE) {
                Ok(num) => match disk.write_to(&mut io, dry_run) {
                    Ok(()) => Ok(format!(
                        "added partition {} ({}) {}\n",
                        num,
                        type_str,
                        if dry_run { "[dry-run]" } else { "" }
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
        "del" => {
            let is_hxfs = target.is_some_and(|t| !t.starts_with("/dev/"));
            if let Err(e) = require_write_cap(mask, is_hxfs) {
                return fail_msg(&e);
            }
            let Some(pnum) = part_num_arg else {
                return fail_msg("usage: fdisk del <part_num> [--dry-run]");
            };
            let mut io = match open_backend(target, true, 4096) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            let mut disk = match GptDisk::read_from(&io) {
                Ok(d) => d,
                Err(e) => return fail_msg(&e),
            };
            match disk.delete_partition(pnum) {
                Ok(()) => match disk.write_to(&mut io, dry_run) {
                    Ok(()) => Ok(format!(
                        "deleted partition {} {}\n",
                        pnum,
                        if dry_run { "[dry-run]" } else { "" }
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
        "resize" => {
            let is_hxfs = target.is_some_and(|t| !t.starts_with("/dev/"));
            if let Err(e) = require_write_cap(mask, is_hxfs) {
                return fail_msg(&e);
            }
            let Some(pnum) = part_num_arg else {
                return fail_msg("usage: fdisk resize <part_num> --size <new_size> [--dry-run]");
            };
            let size_lbas = match parse_size_lbas(size_str) {
                Ok(v) => v,
                Err(e) => return fail_msg(&e),
            };
            let mut io = match open_backend(target, true, 4096) {
                Ok(b) => b,
                Err(e) => return fail_msg(&e),
            };
            let mut disk = match GptDisk::read_from(&io) {
                Ok(d) => d,
                Err(e) => return fail_msg(&e),
            };
            match disk.resize_partition(pnum, size_lbas) {
                Ok(()) => match disk.write_to(&mut io, dry_run) {
                    Ok(()) => Ok(format!(
                        "resized partition {} to {} LBAs {}\n",
                        pnum,
                        size_lbas,
                        if dry_run { "[dry-run]" } else { "" }
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
        other => Err(format!("unknown fdisk subcommand '{other}'")),
    };

    match res {
        Ok(text) => {
            let _ = stdio::stdout_str(&text);
            0
        }
        Err(msg) => fail_msg(&msg),
    }
}

fn fail_msg(msg: &str) -> i32 {
    let _ = stdio::stderr_str("fdisk: ");
    let _ = stdio::stderr_str(msg);
    if !msg.ends_with('\n') {
        let _ = stdio::stderr_str("\n");
    }
    1
}
