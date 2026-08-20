//! Domain-separated PCR 12 measurement over signed HuesOS boot content.

use sha2::{Digest, Sha256};

use super::hbi::{HbiError, HbiImage, ModuleType};

const DOMAIN: &[u8] = b"HuesOS-PCR12-v1\0";
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const ELF64_PHDR_BYTES: usize = 56;

/// Measurement construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementError {
    /// Required signed HBI module is missing or malformed.
    Hbi,
    /// Kernel module is not a bounded little-endian ELF64 image.
    KernelElf,
    /// Kernel has no executable load segment.
    NoExecutableSegment,
}

impl From<HbiError> for MeasurementError {
    fn from(_: HbiError) -> Self {
        Self::Hbi
    }
}

/// Build the digest extended into PCR 12 before volume-key unseal.
///
/// The signed HBI's kernel module contributes only executable PT_LOAD bytes,
/// avoiding a circular dependency on the sealed-key blob embedded in kernel
/// rodata. BOOTFS, command line and platform modules are included in full.
pub fn pcr12_digest(image: &HbiImage<'_>) -> Result<[u8; 32], MeasurementError> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hash_kernel_text(&mut hasher, image.get_module(ModuleType::Kernel)?)?;
    add_component(
        &mut hasher,
        b"bootfs",
        image.get_module(ModuleType::Bootfs)?,
    );
    add_component(
        &mut hasher,
        b"cmdline",
        image.get_module(ModuleType::Cmdline)?,
    );
    add_component(
        &mut hasher,
        b"platform",
        image.get_module(ModuleType::Platform)?,
    );
    Ok(hasher.finalize().into())
}

fn hash_kernel_text(hasher: &mut Sha256, elf: &[u8]) -> Result<(), MeasurementError> {
    if elf.len() < 64
        || elf.get(..4) != Some(b"\x7fELF")
        || elf[4] != 2
        || elf[5] != 1
        || elf[6] != 1
    {
        return Err(MeasurementError::KernelElf);
    }
    let phoff = read_u64(elf, 32).ok_or(MeasurementError::KernelElf)? as usize;
    let phentsize = read_u16(elf, 54).ok_or(MeasurementError::KernelElf)? as usize;
    let phnum = read_u16(elf, 56).ok_or(MeasurementError::KernelElf)? as usize;
    if phnum == 0 || phentsize != ELF64_PHDR_BYTES {
        return Err(MeasurementError::KernelElf);
    }
    let table_end = phoff
        .checked_add(
            phnum
                .checked_mul(phentsize)
                .ok_or(MeasurementError::KernelElf)?,
        )
        .ok_or(MeasurementError::KernelElf)?;
    if table_end > elf.len() {
        return Err(MeasurementError::KernelElf);
    }

    let mut executable = 0u32;
    for index in 0..phnum {
        let base = phoff + index * phentsize;
        let ty = read_u32(elf, base).ok_or(MeasurementError::KernelElf)?;
        let flags = read_u32(elf, base + 4).ok_or(MeasurementError::KernelElf)?;
        if ty != PT_LOAD || flags & PF_X == 0 {
            continue;
        }
        let offset = read_u64(elf, base + 8).ok_or(MeasurementError::KernelElf)? as usize;
        let size = read_u64(elf, base + 32).ok_or(MeasurementError::KernelElf)? as usize;
        let end = offset
            .checked_add(size)
            .ok_or(MeasurementError::KernelElf)?;
        let bytes = elf.get(offset..end).ok_or(MeasurementError::KernelElf)?;
        add_component(hasher, b"kernel.text", bytes);
        executable = executable.saturating_add(1);
    }
    if executable == 0 {
        return Err(MeasurementError::NoExecutableSegment);
    }
    Ok(())
}

fn add_component(hasher: &mut Sha256, label: &[u8], bytes: &[u8]) {
    hasher.update((label.len() as u16).to_le_bytes());
    hasher.update(label);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(text: &[u8]) -> alloc::vec::Vec<u8> {
        let offset = 128usize;
        let mut bytes = alloc::vec![0u8; offset + text.len()];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[68..72].copy_from_slice(&PF_X.to_le_bytes());
        bytes[72..80].copy_from_slice(&(offset as u64).to_le_bytes());
        bytes[96..104].copy_from_slice(&(text.len() as u64).to_le_bytes());
        bytes[offset..].copy_from_slice(text);
        bytes
    }

    #[test]
    fn executable_segment_changes_measurement() {
        let mut first = Sha256::new();
        let mut second = Sha256::new();
        assert!(hash_kernel_text(&mut first, &elf(b"kernel-a")).is_ok());
        assert!(hash_kernel_text(&mut second, &elf(b"kernel-b")).is_ok());
        assert_ne!(first.finalize().as_slice(), second.finalize().as_slice());
    }

    #[test]
    fn malformed_or_non_executable_elf_is_rejected() {
        let mut hasher = Sha256::new();
        assert_eq!(
            hash_kernel_text(&mut hasher, b"not an elf"),
            Err(MeasurementError::KernelElf)
        );
        let mut no_exec = elf(b"text");
        no_exec[68..72].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            hash_kernel_text(&mut hasher, &no_exec),
            Err(MeasurementError::NoExecutableSegment)
        );
    }
}
