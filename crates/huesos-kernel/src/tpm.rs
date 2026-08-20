//! Kernel-side TPM 2.0 CRB driver and volume-key unseal.
//!
//! Wires `huesos-tpm` to real hardware: maps the CRB MMIO window at
//! the architected address and, if a sealed volume-key blob was built
//! into the image, unseals it into `huesos_object::boot_key` before
//! userspace starts. The capability-gated `VolumeKeyTake` syscall then
//! moves it exactly once into KeyBroker; the storage service receives only a
//! generation-bound grant.
//!
//! # Why the key stops being a build-time constant
//!
//! `HUESOS_VOLUME_KEY_HEX` put the volume key in the kernel image in
//! plaintext. Anyone who could read the image could decrypt the
//! volume, which makes the encryption useful against a lost disk and
//! useless against anyone who also has the boot media. Sealing to the
//! TPM moves the secret into the chip and binds its release to the
//! measured boot state.
//!
//! # Failure is not a fallback
//!
//! If the TPM is absent, wedged, or the PCRs do not match, no key is
//! installed and encrypted volumes fail to mount. Falling back to a
//! built-in key on unseal failure would defeat the entire mechanism:
//! an attacker who tampers with the boot chain would simply be handed
//! the fallback. A plain (unencrypted) volume still boots, which is
//! the documented behaviour for machines without a TPM.

use huesos_tpm::crb::{CrbError, CrbTransport};
use huesos_tpm::pcr::{
    pcr_extend, pcr_read, volume_key_policy_selection, PCR_KERNEL_MEASUREMENT,
    PCR_SECURE_BOOT_POLICY,
};
use huesos_tpm::seal::{unseal_volume_key, SealError, SealedKey};

/// Architected CRB MMIO base for a PC Client TPM (TCG PTP).
pub const CRB_MMIO_BASE: u64 = 0xFED4_0000;

/// Size of the CRB register + buffer window.
pub const CRB_MMIO_BYTES: u64 = 0x1000;

/// Offset of the command buffer within the CRB window.
const CRB_CMD_BUFFER: usize = 0x0080;

/// Offset of the response buffer within the CRB window.
const CRB_RSP_BUFFER: usize = 0x0080;

/// Largest command/response the driver moves through the window.
const CRB_BUFFER_BYTES: usize = 0xF80;
const SEALED_MODULE_MAGIC: &[u8; 8] = b"HSEALV1\0";
const SEALED_MODULE_HEADER_BYTES: usize = 32;

struct SealedModule<'a> {
    parent: u32,
    public: &'a [u8],
    private: &'a [u8],
}

fn decode_sealed_module(bytes: &[u8]) -> Option<SealedModule<'_>> {
    if bytes.len() < SEALED_MODULE_HEADER_BYTES
        || bytes.get(..8) != Some(SEALED_MODULE_MAGIC.as_slice())
        || read_u32(bytes, 8)? != 1
        || bytes.get(24..32)?.iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let parent = read_u32(bytes, 12)?;
    let public_len = read_u32(bytes, 16)? as usize;
    let private_len = read_u32(bytes, 20)? as usize;
    let public_end = SEALED_MODULE_HEADER_BYTES.checked_add(public_len)?;
    let private_end = public_end.checked_add(private_len)?;
    if private_end != bytes.len() {
        return None;
    }
    // `tpm2_create -u/-r` writes canonical TPM2B_PUBLIC and
    // TPM2B_PRIVATE files, including each area's big-endian u16 size prefix.
    // The command marshaller below adds those prefixes itself, so retain the
    // canonical tool output in the signed module but pass only each TPM2B
    // payload into `SealedKey`.
    let public = decode_tpm2b(bytes.get(SEALED_MODULE_HEADER_BYTES..public_end)?)?;
    let private = decode_tpm2b(bytes.get(public_end..private_end)?)?;
    Some(SealedModule {
        parent,
        public,
        private,
    })
}

fn decode_tpm2b(bytes: &[u8]) -> Option<&[u8]> {
    let size = usize::from(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]));
    if size == 0
        || size > huesos_tpm::seal::SEALED_BLOB_MAX_BYTES
        || size.checked_add(2)? != bytes.len()
    {
        return None;
    }
    bytes.get(2..)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// A CRB TPM reached through a mapped MMIO window.
pub struct MmioCrb {
    base: u64,
    response_len: usize,
}

impl MmioCrb {
    /// Map the CRB window and build a transport.
    ///
    /// Returns `None` when the window cannot be mapped.
    pub fn map() -> Option<Self> {
        use x86_64::structures::paging::PageTableFlags;
        // Uncached: these are device registers, and a cached read of a
        // status register is a read of whatever the CPU saw last.
        huesos_arch::paging::map_hhdm_range_flags(
            CRB_MMIO_BASE,
            CRB_MMIO_BYTES,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_CACHE
                | PageTableFlags::NO_EXECUTE,
        )
        .ok()?;
        let base = huesos_arch::paging::phys_to_virt(CRB_MMIO_BASE).as_u64();
        Some(Self {
            base,
            response_len: 0,
        })
    }

    /// Whether a TPM appears to be present.
    ///
    /// An absent device reads back all-ones from the interface
    /// identifier; treating that as a TPM would mean waiting out every
    /// poll budget on a machine that simply has no TPM.
    pub fn present(&self) -> bool {
        // SAFETY: `base` is the HHDM alias of the CRB window mapped in
        // `map`, which is at least `CRB_MMIO_BYTES` long, so offset 0
        // is a mapped, uncached device register. A 32-bit read of the
        // interface identifier has no side effects.
        let id = unsafe { core::ptr::read_volatile(self.base as *const u32) };
        id != u32::MAX && id != 0
    }
}

impl CrbTransport for MmioCrb {
    fn read_reg(&self, offset: usize) -> u32 {
        if offset + 4 > CRB_MMIO_BYTES as usize {
            return 0;
        }
        // SAFETY: bounds-checked against the mapped window above;
        // `base` is the HHDM alias established in `map`. Device
        // registers must be read volatile so the poll loops observe
        // the device's writes instead of a hoisted value.
        unsafe { core::ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    fn write_reg(&mut self, offset: usize, value: u32) {
        if offset + 4 > CRB_MMIO_BYTES as usize {
            return;
        }
        // SAFETY: as `read_reg`; the write targets an architected
        // 32-bit control register inside the mapped window.
        unsafe {
            core::ptr::write_volatile((self.base + offset as u64) as *mut u32, value);
        }
    }

    fn write_command(&mut self, bytes: &[u8]) -> Result<(), CrbError> {
        if bytes.len() > CRB_BUFFER_BYTES {
            return Err(CrbError::CommandTooLarge);
        }
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: `index < bytes.len() <= CRB_BUFFER_BYTES`, and
            // `CRB_CMD_BUFFER + CRB_BUFFER_BYTES` is inside the mapped
            // window, so every write lands in the command buffer.
            unsafe {
                core::ptr::write_volatile(
                    (self.base + (CRB_CMD_BUFFER + index) as u64) as *mut u8,
                    *byte,
                );
            }
        }
        Ok(())
    }

    fn read_response(&mut self, out: &mut [u8]) -> Result<usize, CrbError> {
        // Read the header first to learn the real length, then copy
        // exactly that much. Copying the whole window would hand the
        // parser trailing bytes from the previous command.
        let mut header = [0u8; huesos_tpm::HEADER_BYTES];
        for (index, slot) in header.iter_mut().enumerate() {
            // SAFETY: the header lies at the start of the response
            // buffer, well inside the mapped window.
            *slot = unsafe {
                core::ptr::read_volatile((self.base + (CRB_RSP_BUFFER + index) as u64) as *const u8)
            };
        }
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if !(huesos_tpm::HEADER_BYTES..=CRB_BUFFER_BYTES).contains(&size) {
            return Err(CrbError::ResponseTooLarge);
        }
        if size > out.len() {
            return Err(CrbError::ResponseTooLarge);
        }
        for (index, slot) in out.iter_mut().enumerate().take(size) {
            // SAFETY: `size <= CRB_BUFFER_BYTES`, so every read is
            // inside the response buffer within the mapped window.
            *slot = unsafe {
                core::ptr::read_volatile((self.base + (CRB_RSP_BUFFER + index) as u64) as *const u8)
            };
        }
        self.response_len = size;
        Ok(size)
    }

    fn poll_tick(&mut self) {
        core::hint::spin_loop();
    }
}

/// Outcome of the boot-time unseal attempt, for logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsealOutcome {
    /// No sealed blob in this build; nothing to do.
    NoSealedBlob,
    /// No TPM present or the window could not be mapped.
    NoTpm,
    /// The key was unsealed and installed.
    Installed,
    /// The PCR policy did not match: the boot chain changed.
    PolicyMismatch,
    /// The TPM failed for some other reason.
    Failed,
}

/// Unseal the built-in sealed volume key and install it.
///
/// Called during kernel init, before userspace can call
/// `VolumeKeyTake`.
pub fn init_volume_key(
    boot_measurement: &[u8; 32],
    sealed_key_module: Option<&[u8]>,
) -> UnsealOutcome {
    // Probe hardware before looking at image policy so logs distinguish an
    // absent TPM from a TPM with no provisioned sealed object.
    let Some(mut tpm) = MmioCrb::map() else {
        return UnsealOutcome::NoTpm;
    };
    if !tpm.present() || huesos_tpm::crb::request_locality(&mut tpm).is_err() {
        return UnsealOutcome::NoTpm;
    }

    // PCR 12 is OS-controlled. Extend the domain-separated digest only after
    // HBI signature verification; PCR 7 was populated by firmware Secure Boot.
    if pcr_extend(&mut tpm, PCR_KERNEL_MEASUREMENT, boot_measurement).is_err() {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::Failed;
    }
    let Ok(Some(pcr7)) = pcr_read(&mut tpm, PCR_SECURE_BOOT_POLICY) else {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::Failed;
    };
    let Ok(Some(pcr12)) = pcr_read(&mut tpm, PCR_KERNEL_MEASUREMENT) else {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::Failed;
    };
    log_pcr(PCR_SECURE_BOOT_POLICY, &pcr7);
    log_pcr(PCR_KERNEL_MEASUREMENT, &pcr12);

    let Some(sealed) = sealed_key_module.and_then(decode_sealed_module) else {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::NoSealedBlob;
    };
    let Ok(blob) = SealedKey::new(sealed.public, sealed.private) else {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::Failed;
    };
    let Some(selection) = volume_key_policy_selection() else {
        huesos_tpm::crb::relinquish_locality(&mut tpm);
        return UnsealOutcome::Failed;
    };
    let outcome = match unseal_volume_key(&mut tpm, sealed.parent, &blob, &selection) {
        Ok(key) => {
            huesos_object::boot_key::set_boot_volume_key(*key.as_bytes());
            UnsealOutcome::Installed
        }
        Err(SealError::PolicyMismatch) => UnsealOutcome::PolicyMismatch,
        Err(error) => {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::SerialWriter;
            let _ = writeln!(writer, "[tpm] unseal detail: {error:?}");
            UnsealOutcome::Failed
        }
    };
    huesos_tpm::crb::relinquish_locality(&mut tpm);
    outcome
}

fn log_pcr(index: u32, value: &[u8; 32]) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = write!(writer, "[tpm] PCR{index}=");
    for byte in value {
        let _ = write!(writer, "{byte:02x}");
    }
    let _ = writeln!(writer);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(public: &[u8], private: &[u8]) -> alloc::vec::Vec<u8> {
        let mut public_tpm2b = alloc::vec::Vec::new();
        public_tpm2b.extend_from_slice(&(public.len() as u16).to_be_bytes());
        public_tpm2b.extend_from_slice(public);
        let mut private_tpm2b = alloc::vec::Vec::new();
        private_tpm2b.extend_from_slice(&(private.len() as u16).to_be_bytes());
        private_tpm2b.extend_from_slice(private);

        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(SEALED_MODULE_MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0x8100_0001u32.to_le_bytes());
        bytes.extend_from_slice(&(public_tpm2b.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(private_tpm2b.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        bytes.extend_from_slice(&public_tpm2b);
        bytes.extend_from_slice(&private_tpm2b);
        bytes
    }

    #[test]
    fn signed_sealed_module_decodes_exact_lengths() {
        let bytes = module(b"public", b"private");
        let Some(decoded) = decode_sealed_module(&bytes) else {
            assert!(false, "valid sealed module must decode");
            return;
        };
        assert_eq!(decoded.parent, 0x8100_0001);
        assert_eq!(decoded.public, b"public");
        assert_eq!(decoded.private, b"private");
    }

    #[test]
    fn sealed_module_rejects_truncation_and_reserved_bytes() {
        let mut bytes = module(b"public", b"private");
        assert!(decode_sealed_module(&bytes[..bytes.len() - 1]).is_none());
        bytes[24] = 1;
        assert!(decode_sealed_module(&bytes).is_none());
    }
}
