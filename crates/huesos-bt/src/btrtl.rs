//! Realtek Bluetooth USB (`btrtl`) firmware patch parser and vendor `0xFC20`
//! download sequencer for `RTL8821CE` (`0bda:c821` / `0bda:b00a` / `0bda:c820` / `0bda:8821`).
//!
//! Follows the hardware contract of Realtek `EPATCH` (`"Realtech"` header +
//! tail `0x51 0x04 0xFD 0x77` project-ID TLV + `0x8723AB55` config blob).

use crate::hci::encode_cmd;
use alloc::vec::Vec;

/// Realtek USB Vendor ID.
pub const REALTEK_USB_VID: u16 = 0x0BDA;
/// Realtek Bluetooth Manufacturer ID in `HCI_Read_Local_Version_Information`.
pub const REALTEK_MANUFACTURER_ID: u16 = 0x005D;
/// Unpatched `RTL8821C` LMP subversion reported at cold power-on.
pub const LMP_SUBVER_8821C: u16 = 0x8821;
/// `RTL8821C` project ID stored inside the firmware tail extension TLV (`10 = 0x0A`).
pub const PROJECT_ID_8821C: u8 = 0x0A;

/// Realtek Vendor HCI command: `Download_Patch` (`OGF 0x3F, OCF 0x0020` = `0xFC20`).
pub const OP_RTL_DOWNLOAD: u16 = 0xFC20;
/// Realtek Vendor HCI command: `Read_ROM_Version` (`OGF 0x3F, OCF 0x0061` = `0xFC61`).
pub const OP_RTL_READ_ROM_VERSION: u16 = 0xFC61;

/// Maximum payload bytes per `0xFC20` fragment (`1` index byte + `252` data bytes = `253`).
pub const RTL_DOWNLOAD_CHUNK_DATA: usize = 252;

const EPATCH_SIGNATURE: &[u8; 8] = b"Realtech";
const EXTENSION_SIGNATURE: [u8; 4] = [0x51, 0x04, 0xFD, 0x77];
const CONFIG_MAGIC: u32 = 0x8723_AB55;

/// Known USB `PID`s for Realtek `RTL8821CE` M.2 combo Bluetooth interfaces.
pub const RTL8821CE_USB_PIDS: &[u16] = &[0xC821, 0xB00A, 0xB00C, 0xC820, 0xC822, 0xC81D, 0x8821];

/// Returns `true` if `(vid, pid)` is a known Realtek `RTL8821CE` USB Bluetooth controller.
pub fn is_rtl8821ce_usb_id(vid: u16, pid: u16) -> bool {
    vid == REALTEK_USB_VID && RTL8821CE_USB_PIDS.contains(&pid)
}

/// Errors produced when parsing `rtl8821c_fw.bin` / `rtl8821c_config.bin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtrtlError {
    /// Firmware image is too short or lacks `"Realtech"` magic.
    InvalidHeader,
    /// Firmware tail lacks `0x51 0x04 0xFD 0x77` extension signature or project ID mismatch.
    ProjectIdMismatch,
    /// No patch entry matched `rom_version + 1`.
    ChipRevisionNotFound,
    /// Patch slice offset/length overflows the firmware buffer.
    TruncatedPatch,
    /// Config blob lacks `0x8723AB55` signature or declared length mismatches.
    InvalidConfig,
}

/// Parsed and assembled Realtek firmware + config image ready for `0xFC20` chunk upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledRtlFirmware {
    /// 32-bit firmware version extracted from the `EPATCH` header.
    pub fw_version: u32,
    /// Decoded tail `project_id` (`0x0A` for `RTL8821C`).
    pub project_id: u8,
    /// Selected 1-based `chip_id` (`rom_version + 1`, e.g. `1` = A-cut, `2` = B-cut).
    pub chip_id: u16,
    /// Concatenated `patch_slice` (with `fw_version` stamped in the last 4 bytes) + `config_blob`.
    pub payload: Vec<u8>,
}

impl AssembledRtlFirmware {
    /// Total number of `0xFC20` HCI command fragments required to upload [`Self::payload`].
    pub fn fragment_count(&self) -> usize {
        if self.payload.is_empty() {
            0
        } else {
            self.payload.len().div_ceil(RTL_DOWNLOAD_CHUNK_DATA)
        }
    }

    /// Encode the `frag_idx`-th (`0`-based) `HCI_Vendor_Download (0xFC20)` command into `out`.
    ///
    /// Per `btrtl` hardware rules, the 1-byte fragment index wraps modulo `0x80` (`0..=127`,
    /// then `1..=127` on `>128` chunks) and sets bit 7 (`| 0x80`) on the final fragment.
    pub fn encode_download_cmd(&self, frag_idx: usize, out: &mut [u8]) -> Option<usize> {
        let total = self.fragment_count();
        if frag_idx >= total {
            return None;
        }
        let start = frag_idx * RTL_DOWNLOAD_CHUNK_DATA;
        let end = (start + RTL_DOWNLOAD_CHUNK_DATA).min(self.payload.len());
        let slice = &self.payload[start..end];

        let mut index_byte = if frag_idx < 0x80 {
            frag_idx as u8
        } else {
            ((frag_idx - 0x80) % 0x7F + 1) as u8
        };
        if frag_idx + 1 == total {
            index_byte |= 0x80;
        }

        let mut cmd_params = [0u8; 1 + RTL_DOWNLOAD_CHUNK_DATA];
        cmd_params[0] = index_byte;
        cmd_params[1..1 + slice.len()].copy_from_slice(slice);
        encode_cmd(OP_RTL_DOWNLOAD, &cmd_params[..1 + slice.len()], out)
    }
}

/// Build `HCI_Vendor_Read_ROM_Version (0xFC61)`.
pub fn cmd_read_rom_version(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_RTL_READ_ROM_VERSION, &[], out)
}

/// Extract `rom_version` from `OP_RTL_READ_ROM_VERSION` `Command_Complete` `return_params`.
pub fn parse_rom_version_return(return_params: &[u8]) -> Option<u8> {
    return_params.first().copied()
}

/// Validate a Realtek `*_config.bin` blob (`magic = 0x8723AB55`, `data_len` matches).
pub fn validate_rtl_config(cfg: &[u8]) -> Result<(), BtrtlError> {
    if cfg.is_empty() {
        return Ok(());
    }
    if cfg.len() < 6 {
        return Err(BtrtlError::InvalidConfig);
    }
    let magic = u32::from_le_bytes([cfg[0], cfg[1], cfg[2], cfg[3]]);
    let dlen = usize::from(u16::from_le_bytes([cfg[4], cfg[5]]));
    if magic != CONFIG_MAGIC || 6 + dlen != cfg.len() {
        return Err(BtrtlError::InvalidConfig);
    }
    Ok(())
}

/// Parse the tail extension TLV block (`[... 0xFF ... opcode, len, data..., 0x51, 0x04, 0xFD, 0x77]`)
/// and return the embedded `project_id` (`opcode == 0x00, len == 1`).
pub fn parse_epatch_project_id(fw: &[u8]) -> Option<u8> {
    if fw.len() < 8 {
        return None;
    }
    let tail_sig = &fw[fw.len() - 4..];
    if tail_sig != EXTENSION_SIGNATURE {
        return None;
    }
    let mut pos = fw.len() - 4;
    while pos > 14 {
        pos -= 1;
        let opcode = fw[pos];
        if opcode == 0xFF {
            break;
        }
        if pos == 0 {
            return None;
        }
        pos -= 1;
        let len = usize::from(fw[pos]);
        if pos < len {
            return None;
        }
        pos -= len;
        if opcode == 0x00 && len >= 1 {
            return Some(fw[pos]);
        }
    }
    None
}

/// Parse `rtl8821c_fw.bin` + optional `rtl8821c_config.bin` for the controller's `rom_version`
/// (`0` for A-cut -> `chip_id = 1`, `1` for B-cut -> `chip_id = 2`).
pub fn parse_and_assemble_rtl8821c(
    fw: &[u8],
    config: Option<&[u8]>,
    rom_version: u8,
) -> Result<AssembledRtlFirmware, BtrtlError> {
    if fw.len() < 14 || &fw[0..8] != EPATCH_SIGNATURE {
        return Err(BtrtlError::InvalidHeader);
    }
    let project_id = parse_epatch_project_id(fw).ok_or(BtrtlError::ProjectIdMismatch)?;
    if project_id != PROJECT_ID_8821C {
        return Err(BtrtlError::ProjectIdMismatch);
    }

    let fw_version = u32::from_le_bytes([fw[8], fw[9], fw[10], fw[11]]);
    let num_patches = usize::from(u16::from_le_bytes([fw[12], fw[13]]));
    let tables_end = 14usize.saturating_add(num_patches.saturating_mul(8));
    if num_patches == 0 || fw.len() < tables_end {
        return Err(BtrtlError::InvalidHeader);
    }

    let target_chip_id = u16::from(rom_version).saturating_add(1);
    let chip_id_base = 14usize;
    let len_base = chip_id_base + num_patches * 2;
    let off_base = len_base + num_patches * 2;

    let mut matched: Option<(usize, usize)> = None;
    for i in 0..num_patches {
        let cid = u16::from_le_bytes([fw[chip_id_base + i * 2], fw[chip_id_base + i * 2 + 1]]);
        if cid == target_chip_id {
            let plen = usize::from(u16::from_le_bytes([
                fw[len_base + i * 2],
                fw[len_base + i * 2 + 1],
            ]));
            let poff = u32::from_le_bytes([
                fw[off_base + i * 4],
                fw[off_base + i * 4 + 1],
                fw[off_base + i * 4 + 2],
                fw[off_base + i * 4 + 3],
            ]) as usize;
            matched = Some((poff, plen));
            break;
        }
    }

    let (patch_off, patch_len) = matched.ok_or(BtrtlError::ChipRevisionNotFound)?;
    if patch_len < 4 || patch_off.saturating_add(patch_len) > fw.len() {
        return Err(BtrtlError::TruncatedPatch);
    }

    let cfg_bytes = config.unwrap_or(&[]);
    validate_rtl_config(cfg_bytes)?;

    let mut payload = Vec::with_capacity(patch_len + cfg_bytes.len());
    payload.extend_from_slice(&fw[patch_off..patch_off + patch_len]);
    // Per Realtek `btrtl` specification, overwrite the trailing 4 reserve bytes of the patch
    // with `fw_version` in little-endian before appending `rtl8821c_config.bin`.
    let stamp_off = patch_len - 4;
    payload[stamp_off..stamp_off + 4].copy_from_slice(&fw_version.to_le_bytes());
    payload.extend_from_slice(cfg_bytes);

    Ok(AssembledRtlFirmware {
        fw_version,
        project_id,
        chip_id: target_chip_id,
        payload,
    })
}
