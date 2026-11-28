//! Realtek Bluetooth USB (`btrtl`) firmware patch parser and vendor command
//! sequencer for `RTL8821CE` (`0bda:c821` / `0bda:b00a` / `0bda:c820` / `0bda:8821`).
//!
//! Mirrors Linux `drivers/bluetooth/btrtl.c` & `btrtl.h` 1-to-1:
//! - `0xFC61` (`btrtl_vendor_read_reg16`: `RTL_CHIP_SUBVER`, `RTL_CHIP_REV`, `RTL_SEC_PROJ`)
//! - `0xFC66` (`drop_fw` warm-firmware reset + `200 ms` settle)
//! - `0xFC6D` (`rtl_read_rom_version`)
//! - `EPATCH` v1 (`"Realtech"`) and v2 (`"RTBTCore"`) + tail `0x51 0x04 0xFD 0x77` TLV
//! - `0x8723AB55` optional `rtl8821c_config.bin` (`config_needed = false`, loaded when `key_id == 0`)
//! - `0xFC20` (`rtl_download_firmware`: `frag_num = fw_len / 252 + 1`, `0x7F -> 1` wrap, `| 0x80` end)

use crate::hci::encode_cmd;
use alloc::vec::Vec;

/// Realtek USB Vendor ID.
pub const REALTEK_USB_VID: u16 = 0x0BDA;
/// Realtek Bluetooth Manufacturer ID in `HCI_Read_Local_Version_Information`.
pub const REALTEK_MANUFACTURER_ID: u16 = 0x005D;
/// Unpatched `RTL8821C` ROM LMP subversion (`RTL_ROM_LMP_8821A` in Linux `btrtl.c`).
pub const LMP_SUBVER_8821C: u16 = 0x8821;
/// Unpatched `RTL8821C` ROM HCI revision (`0x000C` in Linux `ic_id_table`).
pub const HCI_REV_8821C: u16 = 0x000C;
/// Unpatched `RTL8821C` ROM HCI version (`0x08` = Bluetooth 4.2 in Linux `ic_id_table`).
pub const HCI_VER_8821C: u8 = 0x08;
/// `RTL8821C` project ID stored inside the firmware tail extension TLV (`CHIP_ID_8821C = 10`).
pub const PROJECT_ID_8821C: u8 = 0x0A;

/// Realtek Vendor HCI command: `Download_Patch` (`OGF 0x3F, OCF 0x0020` = `0xFC20`).
pub const OP_RTL_DOWNLOAD: u16 = 0xFC20;
/// Realtek Vendor HCI command: `Vendor_Read_Reg16` (`OGF 0x3F, OCF 0x0061` = `0xFC61`, 5-byte param).
pub const OP_RTL_READ_REG16: u16 = 0xFC61;
/// Realtek Vendor HCI command: `Drop_Firmware` (`OGF 0x3F, OCF 0x0066` = `0xFC66`, 0-byte param).
pub const OP_RTL_DROP_FIRMWARE: u16 = 0xFC66;
/// Realtek Vendor HCI command: `Read_ROM_Version` (`OGF 0x3F, OCF 0x006D` = `0xFC6D`, 0-byte param).
pub const OP_RTL_READ_ROM_VERSION: u16 = 0xFC6D;

/// `RTL_CHIP_SUBVER` 5-byte register descriptor for `0xFC61` (`btrtl.c:41`).
pub const RTL_REG_CHIP_SUBVER: [u8; 5] = [0x10, 0x38, 0x04, 0x28, 0x80];
/// `RTL_CHIP_REV` 5-byte register descriptor for `0xFC61` (`btrtl.c:42`).
pub const RTL_REG_CHIP_REV: [u8; 5] = [0x10, 0x3A, 0x04, 0x28, 0x80];
/// `RTL_SEC_PROJ` 5-byte register descriptor for `0xFC61` (`btrtl.c:43`, reads `key_id`).
pub const RTL_REG_SEC_PROJ: [u8; 5] = [0x10, 0xA4, 0xAD, 0x00, 0xB0];

/// Maximum payload bytes per `0xFC20` fragment (`RTL_FRAG_LEN = 252`).
pub const RTL_DOWNLOAD_CHUNK_DATA: usize = 252;

const EPATCH_SIGNATURE: &[u8; 8] = b"Realtech";
const EPATCH_SIGNATURE_V2: &[u8; 8] = b"RTBTCore";
const EXTENSION_SIGNATURE: [u8; 4] = [0x51, 0x04, 0xFD, 0x77];
const CONFIG_MAGIC: u32 = 0x8723_AB55;

const RTL_PATCH_SNIPPETS: u32 = 0x01;
const RTL_PATCH_DUMMY_HEADER: u32 = 0x02;
const RTL_PATCH_SECURITY_HEADER: u32 = 0x03;

/// Known USB `PID`s for Realtek `RTL8821CE` M.2 combo Bluetooth interfaces.
pub const RTL8821CE_USB_PIDS: &[u16] = &[0xC821, 0xB00A, 0xB00C, 0xC820, 0xC822, 0xC81D, 0x8821];

/// Returns `true` if `(vid, pid)` is a known Realtek `RTL8821CE` USB Bluetooth controller.
pub fn is_rtl8821ce_usb_id(vid: u16, pid: u16) -> bool {
    vid == REALTEK_USB_VID && RTL8821CE_USB_PIDS.contains(&pid)
}

/// Match unpatched `RTL8821C` ROM identity (`btrtl_match_ic` in Linux `btrtl.c`).
pub const fn matches_rtl8821c_rom(lmp_subver: u16, hci_rev: u16, _hci_ver: u8) -> bool {
    lmp_subver == LMP_SUBVER_8821C && (hci_rev == HCI_REV_8821C || hci_rev == 0x000A)
}

/// Errors produced when parsing `rtl8821c_fw.bin` / `rtl8821c_config.bin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtrtlError {
    /// Firmware image is too short or lacks `"Realtech"` / `"RTBTCore"` magic.
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
    ///
    /// Matches Linux `rtl_download_firmware` (`frag_num = fw_len / RTL_FRAG_LEN + 1`) verbatim:
    /// when `payload.len()` is an exact multiple of `252`, a trailing `0`-byte fragment carrying
    /// `index | 0x80` terminates the download.
    pub fn fragment_count(&self) -> usize {
        if self.payload.is_empty() {
            0
        } else {
            self.payload.len() / RTL_DOWNLOAD_CHUNK_DATA + 1
        }
    }

    /// Compute the 1-byte `dl_cmd->index` value for `frag_idx` (`0..fragment_count()`),
    /// matching Linux `btrtl.c` (`0..=0x7F`, then wrapping to `1..=0x7F`, `| 0x80` on final).
    pub fn fragment_index_byte(&self, frag_idx: usize) -> Option<u8> {
        let total = self.fragment_count();
        if frag_idx >= total {
            return None;
        }
        let mut index_byte = if frag_idx < 0x80 {
            frag_idx as u8
        } else {
            ((frag_idx - 0x80) % 0x7F + 1) as u8
        };
        if frag_idx + 1 == total {
            index_byte |= 0x80;
        }
        Some(index_byte)
    }

    /// Encode the `frag_idx`-th (`0`-based) `HCI_Vendor_Download (0xFC20)` command into `out`.
    pub fn encode_download_cmd(&self, frag_idx: usize, out: &mut [u8]) -> Option<usize> {
        let total = self.fragment_count();
        let index_byte = self.fragment_index_byte(frag_idx)?;
        let frag_len = if frag_idx + 1 == total {
            self.payload.len() % RTL_DOWNLOAD_CHUNK_DATA
        } else {
            RTL_DOWNLOAD_CHUNK_DATA
        };
        let start = frag_idx * RTL_DOWNLOAD_CHUNK_DATA;
        let slice = &self.payload[start..start + frag_len];

        let mut cmd_params = [0u8; 1 + RTL_DOWNLOAD_CHUNK_DATA];
        cmd_params[0] = index_byte;
        if frag_len > 0 {
            cmd_params[1..1 + frag_len].copy_from_slice(slice);
        }
        encode_cmd(OP_RTL_DOWNLOAD, &cmd_params[..1 + frag_len], out)
    }
}

/// Build `HCI_Vendor_Read_ROM_Version (0xFC6D)` (`rtl_read_rom_version` in Linux `btrtl.c`).
pub fn cmd_read_rom_version(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_RTL_READ_ROM_VERSION, &[], out)
}

/// Build `HCI_Vendor_Read_Reg16 (0xFC61)` (`btrtl_vendor_read_reg16` in Linux `btrtl.c`).
pub fn cmd_vendor_read_reg16(reg_cmd: &[u8; 5], out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_RTL_READ_REG16, reg_cmd, out)
}

/// Build `HCI_Vendor_Drop_Firmware (0xFC66)` (`drop_fw` reset to ROM in Linux `btrtl.c`).
pub fn cmd_drop_firmware(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_RTL_DROP_FIRMWARE, &[], out)
}

/// Extract `rom_version` from `OP_RTL_READ_ROM_VERSION (0xFC6D)` `Command_Complete` `return_params`.
pub fn parse_rom_version_return(return_params: &[u8]) -> Option<u8> {
    return_params.first().copied()
}

/// Extract 16-bit register value from `OP_RTL_READ_REG16 (0xFC61)` `Command_Complete` `return_params`.
pub fn parse_reg16_return(return_params: &[u8]) -> Option<[u8; 2]> {
    if return_params.len() >= 2 {
        Some([return_params[0], return_params[1]])
    } else {
        None
    }
}

/// Validate a Realtek `*_config.bin` blob (`magic = 0x8723AB55`, `total_len <= cfg.len() - 6`).
pub fn validate_rtl_config(cfg: &[u8]) -> Result<(), BtrtlError> {
    if cfg.is_empty() {
        return Ok(());
    }
    if cfg.len() < 6 {
        return Err(BtrtlError::InvalidConfig);
    }
    let magic = u32::from_le_bytes([cfg[0], cfg[1], cfg[2], cfg[3]]);
    let dlen = usize::from(u16::from_le_bytes([cfg[4], cfg[5]]));
    if magic != CONFIG_MAGIC || cfg.len() - 6 < dlen {
        return Err(BtrtlError::InvalidConfig);
    }
    Ok(())
}

/// Parse the tail extension TLV block (`[... 0xFF ... data, len, opcode, 0x51, 0x04, 0xFD, 0x77]`)
/// matching `rtlbt_parse_firmware` in Linux `btrtl.c` verbatim.
pub fn parse_epatch_project_id(fw: &[u8]) -> Option<u8> {
    if fw.len() < 21 {
        return None;
    }
    let min_hdr = if &fw[0..8] == EPATCH_SIGNATURE {
        14usize
    } else if &fw[0..8] == EPATCH_SIGNATURE_V2 {
        20usize
    } else {
        return None;
    };
    if fw.len() < min_hdr + 7 {
        return None;
    }
    if fw[fw.len() - 4..] != EXTENSION_SIGNATURE {
        return None;
    }

    let mut fwptr = fw.len() - 4;
    while fwptr >= min_hdr + 3 {
        fwptr -= 1;
        let opcode = fw[fwptr];
        fwptr -= 1;
        let length = usize::from(fw[fwptr]);
        fwptr -= 1;
        let data = fw[fwptr];

        if opcode == 0xFF {
            break;
        }
        if length == 0 {
            return None;
        }
        if opcode == 0x00 && length == 1 {
            return Some(data);
        }
        let extra = length.saturating_sub(1);
        if fwptr < extra {
            return None;
        }
        fwptr -= extra;
    }
    None
}

fn parse_epatch_v2_payload(
    fw: &[u8],
    rom_version: u8,
    key_id: u8,
) -> Result<(u32, Vec<u8>), BtrtlError> {
    if fw.len() < 27 {
        return Err(BtrtlError::InvalidHeader);
    }
    let fw_version = u32::from_le_bytes([fw[8], fw[9], fw[10], fw[11]]);
    let num_sections = u32::from_le_bytes([fw[16], fw[17], fw[18], fw[19]]) as usize;
    let body_end = fw.len() - 7;
    let mut cursor = 20usize;
    let target_eco = rom_version.wrapping_add(1);

    let mut subsecs: Vec<(u8, &[u8])> = Vec::new();

    for _ in 0..num_sections {
        if cursor + 8 > body_end {
            break;
        }
        let opcode =
            u32::from_le_bytes([fw[cursor], fw[cursor + 1], fw[cursor + 2], fw[cursor + 3]]);
        let sec_len = u32::from_le_bytes([
            fw[cursor + 4],
            fw[cursor + 5],
            fw[cursor + 6],
            fw[cursor + 7],
        ]) as usize;
        cursor += 8;
        if cursor.saturating_add(sec_len) > body_end {
            break;
        }
        let sec = &fw[cursor..cursor + sec_len];
        cursor += sec_len;

        if opcode != RTL_PATCH_SNIPPETS
            && opcode != RTL_PATCH_DUMMY_HEADER
            && (opcode != RTL_PATCH_SECURITY_HEADER || key_id == 0)
        {
            continue;
        }
        if sec.len() < 4 {
            return Err(BtrtlError::InvalidHeader);
        }
        let num_subsecs = usize::from(u16::from_le_bytes([sec[0], sec[1]]));
        let mut sc = 4usize;
        for _ in 0..num_subsecs {
            if sc + 8 > sec.len() {
                break;
            }
            let eco = sec[sc];
            let prio = sec[sc + 1];
            let sub_key_id = sec[sc + 2];
            let sub_len =
                u32::from_le_bytes([sec[sc + 4], sec[sc + 5], sec[sc + 6], sec[sc + 7]]) as usize;
            sc += 8;
            if sc.saturating_add(sub_len) > sec.len() {
                break;
            }
            let sub_data = &sec[sc..sc + sub_len];
            sc += sub_len;

            if eco != target_eco {
                continue;
            }
            if opcode == RTL_PATCH_SECURITY_HEADER && sub_key_id != key_id {
                continue;
            }
            // Stable insertion by ascending `prio` (`btrtl_insert_ordered_subsec`).
            let ins_pos = subsecs
                .iter()
                .position(|(p, _)| *p > prio)
                .unwrap_or(subsecs.len());
            subsecs.insert(ins_pos, (prio, sub_data));
        }
    }

    let total_len: usize = subsecs.iter().map(|(_, s)| s.len()).sum();
    if total_len == 0 {
        return Err(BtrtlError::ChipRevisionNotFound);
    }
    let mut out = Vec::with_capacity(total_len);
    for (_, s) in subsecs {
        out.extend_from_slice(s);
    }
    Ok((fw_version, out))
}

/// Parse `rtl8821c_fw.bin` + optional `rtl8821c_config.bin` for `rom_version` and `key_id = 0`.
pub fn parse_and_assemble_rtl8821c(
    fw: &[u8],
    config: Option<&[u8]>,
    rom_version: u8,
) -> Result<AssembledRtlFirmware, BtrtlError> {
    parse_and_assemble_rtl8821c_with_key(fw, config, rom_version, 0)
}

/// Parse `rtl8821c_fw.bin` + optional `rtl8821c_config.bin` matching Linux `btrtl_initialize` +
/// `btrtl_setup_rtl8723b` (`cfg_data` appended only when `key_id == 0`, `config_needed = false`).
pub fn parse_and_assemble_rtl8821c_with_key(
    fw: &[u8],
    config: Option<&[u8]>,
    rom_version: u8,
    key_id: u8,
) -> Result<AssembledRtlFirmware, BtrtlError> {
    if fw.len() < 21 {
        return Err(BtrtlError::InvalidHeader);
    }
    let is_v1 = &fw[0..8] == EPATCH_SIGNATURE;
    let is_v2 = &fw[0..8] == EPATCH_SIGNATURE_V2;
    if !is_v1 && !is_v2 {
        return Err(BtrtlError::InvalidHeader);
    }

    let project_id = parse_epatch_project_id(fw).ok_or(BtrtlError::ProjectIdMismatch)?;
    if project_id != PROJECT_ID_8821C {
        return Err(BtrtlError::ProjectIdMismatch);
    }

    let target_chip_id = u16::from(rom_version).saturating_add(1);
    let cfg_bytes = if key_id == 0 {
        config.unwrap_or(&[])
    } else {
        &[]
    };
    validate_rtl_config(cfg_bytes)?;

    if is_v2 {
        let (fw_version, mut payload) = parse_epatch_v2_payload(fw, rom_version, key_id)?;
        payload.extend_from_slice(cfg_bytes);
        return Ok(AssembledRtlFirmware {
            fw_version,
            project_id,
            chip_id: target_chip_id,
            payload,
        });
    }

    let fw_version = u32::from_le_bytes([fw[8], fw[9], fw[10], fw[11]]);
    let num_patches = usize::from(u16::from_le_bytes([fw[12], fw[13]]));
    let min_size = 14usize
        .saturating_add(7)
        .saturating_add(num_patches.saturating_mul(8));
    if num_patches == 0 || fw.len() < min_size {
        return Err(BtrtlError::InvalidHeader);
    }

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
            if poff != 0 {
                matched = Some((poff, plen));
            }
            break;
        }
    }

    let (patch_off, patch_len) = matched.ok_or(BtrtlError::ChipRevisionNotFound)?;
    if patch_len < 4 || patch_off > fw.len() || patch_len > fw.len() - patch_off {
        return Err(BtrtlError::TruncatedPatch);
    }

    let mut payload = Vec::with_capacity(patch_len + cfg_bytes.len());
    payload.extend_from_slice(&fw[patch_off..patch_off + patch_len - 4]);
    payload.extend_from_slice(&fw_version.to_le_bytes());
    payload.extend_from_slice(cfg_bytes);

    Ok(AssembledRtlFirmware {
        fw_version,
        project_id,
        chip_id: target_chip_id,
        payload,
    })
}
