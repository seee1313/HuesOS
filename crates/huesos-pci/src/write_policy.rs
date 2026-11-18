//! Audited PCI configuration write policy and write/readback transactions (B.4).
//!
//! Every target-stage PCI configuration write performed by `pci-manager` must
//! declare an explicit [`WriteClass`] and a non-zero `expected_readback_mask`.
//! Forbidden or read-only classes are rejected before any hardware transport is
//! touched, and permitted writes run as read-modify-write transactions with
//! post-write readback verification and automatic rollback on readback mismatch.

use crate::{ConfigWidth, PciAddress, CONVENTIONAL_CONFIG_BYTES, ENHANCED_CONFIG_BYTES};

/// Architectural Command register writable bit mask used for [`WriteClass::CommandControl`]:
/// I/O Space (0), Memory Space (1), Bus Master (2), Parity Error Response (6),
/// SERR# Enable (8), Interrupt Disable (10).
pub const COMMAND_WRITABLE_MASK: u32 = 0x0547;

/// PCI config register offset for the Command word.
pub const OFFSET_COMMAND: u16 = 0x04;
/// First BAR register offset.
pub const OFFSET_BAR0: u16 = 0x10;
/// Last Type 0 BAR register offset.
pub const OFFSET_TYPE0_BAR5: u16 = 0x24;
/// Last Type 1 BAR register offset.
pub const OFFSET_TYPE1_BAR1: u16 = 0x14;
/// Type 1 Primary/Secondary/Subordinate Bus numbers register offset.
pub const OFFSET_BRIDGE_BUS_NUMBERS: u16 = 0x18;
/// Type 1 Bridge I/O Base/Limit register offset.
pub const OFFSET_BRIDGE_IO_BASE: u16 = 0x1C;
/// Type 1 Bridge Prefetchable Limit Upper 32 bits register offset.
pub const OFFSET_BRIDGE_PREF_LIMIT_UPPER: u16 = 0x2C;
/// Type 1 Bridge Control register offset.
pub const OFFSET_BRIDGE_CONTROL: u16 = 0x3E;
/// First capability-space offset in conventional config space.
pub const OFFSET_CAPABILITY_MIN: u16 = 0x40;

/// Policy classification for every configuration-space write (Stage B.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteClass {
    /// Immutable device/vendor/revision/class/header identity registers (`0x00..=0x03`, `0x08..=0x0F`, etc.).
    ReadOnlyIdentity,
    /// PCI Command register (`0x04`, 16-bit) control bits.
    CommandControl,
    /// Base Address Register programming (`0x10..=0x24` on Type 0, `0x10..=0x14` on Type 1).
    Bar,
    /// Type 1 bridge bus-number registers (`0x18..=0x1B`).
    BridgeBusNumbers,
    /// Type 1 bridge memory/I/O aperture window registers (`0x1C..=0x33` and Bridge Control `0x3E`).
    BridgeWindow,
    /// Conventional or PCIe extended capability control registers (`>= 0x40`).
    CapabilityControl,
    /// Explicitly allowlisted vendor/device-specific register slice.
    VendorAllowlisted,
    /// Permanently denied catch-all class (e.g. arbitrary/unclassified writes, AML writes).
    Forbidden,
}

impl WriteClass {
    /// Stable ASCII label for structured `obs` logging.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyIdentity => "ReadOnlyIdentity",
            Self::CommandControl => "CommandControl",
            Self::Bar => "BAR",
            Self::BridgeBusNumbers => "BridgeBusNumbers",
            Self::BridgeWindow => "BridgeWindow",
            Self::CapabilityControl => "CapabilityControl",
            Self::VendorAllowlisted => "VendorAllowlisted",
            Self::Forbidden => "Forbidden",
        }
    }
}

/// PCI configuration header type of the target function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderKind {
    /// Type 0 conventional endpoint header.
    Type0Endpoint,
    /// Type 1 PCI-to-PCI bridge header.
    Type1Bridge,
}

/// Narrow allowlist entry required for [`WriteClass::VendorAllowlisted`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VendorAllowlistEntry {
    /// Exact byte offset permitted.
    pub offset: u16,
    /// Exact width permitted.
    pub width: ConfigWidth,
    /// Bit mask of writable bits inside the value.
    pub writable_mask: u32,
}

/// Requested classified PCI configuration write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteRequest {
    /// Target PCI routing address.
    pub address: PciAddress,
    /// Header type of the target function.
    pub header_kind: HeaderKind,
    /// Required policy class.
    pub class: WriteClass,
    /// Configuration space byte offset.
    pub offset: u16,
    /// Access width (1, 2, or 4 bytes).
    pub width: ConfigWidth,
    /// Maximum addressable byte length (`256` for legacy, `4096` for ECAM).
    pub max_config_bytes: u16,
    /// New bit values to apply under `write_mask`.
    pub value: u32,
    /// Bits modified by this write (must be non-empty and within policy).
    pub write_mask: u32,
    /// Bits verified on post-write readback (must be non-empty).
    pub expected_readback_mask: u32,
    /// Explicit vendor allowlist policy record when `class == WriteClass::VendorAllowlisted`.
    pub allowlist_entry: Option<VendorAllowlistEntry>,
}

/// Reasons a classified write validation or transaction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritePolicyError {
    /// `WriteClass::Forbidden` is unconditionally denied.
    ForbiddenClass,
    /// `WriteClass::ReadOnlyIdentity` cannot be written.
    ReadOnlyClass,
    /// Callers must specify a non-zero `expected_readback_mask`.
    MissingReadbackMask,
    /// Callers must specify a non-zero `write_mask` contained within the width mask.
    InvalidWriteMask,
    /// Access width is not valid for the declared [`WriteClass`].
    InvalidWidth,
    /// Offset is outside the declared register range or `max_config_bytes`.
    OffsetOutOfRange,
    /// Offset is not aligned to `width`.
    MisalignedAccess,
    /// Target `header_kind` does not support the declared [`WriteClass`] or offset.
    HeaderMismatch,
    /// `write_mask` or `expected_readback_mask` touches bits forbidden by the class policy.
    MaskOutOfClassPolicy,
    /// `WriteClass::VendorAllowlisted` requires a matching [`VendorAllowlistEntry`].
    MissingVendorAllowlist,
    /// Reading the pre-write or post-write register failed.
    TransportReadFailed,
    /// Writing the register failed at the transport layer.
    TransportWriteFailed,
    /// Post-write readback differed from the expected masked value; original value restored.
    ReadbackMismatch {
        /// Masked value expected after write.
        expected: u32,
        /// Masked value observed on readback.
        observed: u32,
        /// Mask applied for comparison.
        mask: u32,
    },
    /// Post-write readback failed AND restoring the pre-write value also failed.
    RollbackFailed {
        /// Masked value expected after write.
        expected: u32,
        /// Masked value observed on readback.
        observed: u32,
    },
}

impl WritePolicyError {
    /// Stable ASCII label for structured `obs` logging.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForbiddenClass => "forbidden-class",
            Self::ReadOnlyClass => "read-only-class",
            Self::MissingReadbackMask => "missing-readback-mask",
            Self::InvalidWriteMask => "invalid-write-mask",
            Self::InvalidWidth => "invalid-width",
            Self::OffsetOutOfRange => "offset-out-of-range",
            Self::MisalignedAccess => "misaligned-access",
            Self::HeaderMismatch => "header-mismatch",
            Self::MaskOutOfClassPolicy => "mask-out-of-class-policy",
            Self::MissingVendorAllowlist => "missing-vendor-allowlist",
            Self::TransportReadFailed => "transport-read-failed",
            Self::TransportWriteFailed => "transport-write-failed",
            Self::ReadbackMismatch { .. } => "readback-mismatch",
            Self::RollbackFailed { .. } => "rollback-failed",
        }
    }
}

/// Validated write plan ready for hardware execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedWrite {
    /// Target PCI routing address.
    pub address: PciAddress,
    /// Policy class.
    pub class: WriteClass,
    /// Validated aligned offset.
    pub offset: u16,
    /// Validated access width.
    pub width: ConfigWidth,
    /// Masked new bit values.
    pub value: u32,
    /// Validated write mask.
    pub write_mask: u32,
    /// Validated non-zero readback verification mask.
    pub expected_readback_mask: u32,
}

/// Auditable record emitted for a completed write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteTransactionRecord {
    /// Target PCI routing address.
    pub address: PciAddress,
    /// Policy class.
    pub class: WriteClass,
    /// Offset written.
    pub offset: u16,
    /// Access width.
    pub width: ConfigWidth,
    /// Register value read before the write.
    pub before_value: u32,
    /// Full register value written after read-modify-write masking.
    pub written_value: u32,
    /// Register value observed immediately after the write.
    pub readback_value: u32,
    /// Readback comparison mask enforced.
    pub expected_readback_mask: u32,
}

/// Physical or simulated PCI configuration read/write transport for `pci-manager`.
pub trait ConfigReadWriteTransport {
    /// Read `width` bytes at aligned `offset` for `address`.
    fn read_width(&mut self, address: PciAddress, offset: u16, width: ConfigWidth) -> Option<u32>;

    /// Write `width` bytes at aligned `offset` for `address`.
    fn write_width(
        &mut self,
        address: PciAddress,
        offset: u16,
        width: ConfigWidth,
        value: u32,
    ) -> bool;
}

/// Validate a [`WriteRequest`] without touching hardware.
pub fn validate_write_request(request: &WriteRequest) -> Result<ValidatedWrite, WritePolicyError> {
    if request.class == WriteClass::Forbidden {
        return Err(WritePolicyError::ForbiddenClass);
    }
    if request.class == WriteClass::ReadOnlyIdentity {
        return Err(WritePolicyError::ReadOnlyClass);
    }
    let width_bytes = request.width.bytes();
    if !request.offset.is_multiple_of(width_bytes) {
        return Err(WritePolicyError::MisalignedAccess);
    }
    let limit = if request.max_config_bytes <= CONVENTIONAL_CONFIG_BYTES {
        CONVENTIONAL_CONFIG_BYTES
    } else {
        ENHANCED_CONFIG_BYTES.min(request.max_config_bytes)
    };
    let Some(end) = request.offset.checked_add(width_bytes) else {
        return Err(WritePolicyError::OffsetOutOfRange);
    };
    if end > limit {
        return Err(WritePolicyError::OffsetOutOfRange);
    }

    let width_mask = request.width.value_mask();
    if request.expected_readback_mask == 0 || (request.expected_readback_mask & !width_mask) != 0 {
        return Err(WritePolicyError::MissingReadbackMask);
    }
    if request.write_mask == 0 || (request.write_mask & !width_mask) != 0 {
        return Err(WritePolicyError::InvalidWriteMask);
    }

    let class_allowed_mask = match request.class {
        WriteClass::ReadOnlyIdentity => return Err(WritePolicyError::ReadOnlyClass),
        WriteClass::Forbidden => return Err(WritePolicyError::ForbiddenClass),
        WriteClass::CommandControl => {
            if request.width != ConfigWidth::Word {
                return Err(WritePolicyError::InvalidWidth);
            }
            if request.offset != OFFSET_COMMAND {
                return Err(WritePolicyError::OffsetOutOfRange);
            }
            COMMAND_WRITABLE_MASK
        }
        WriteClass::Bar => {
            if request.width != ConfigWidth::Dword {
                return Err(WritePolicyError::InvalidWidth);
            }
            let max_bar = match request.header_kind {
                HeaderKind::Type0Endpoint => OFFSET_TYPE0_BAR5,
                HeaderKind::Type1Bridge => OFFSET_TYPE1_BAR1,
            };
            if request.offset < OFFSET_BAR0 || request.offset > max_bar {
                return Err(if request.offset <= OFFSET_TYPE0_BAR5 {
                    WritePolicyError::HeaderMismatch
                } else {
                    WritePolicyError::OffsetOutOfRange
                });
            }
            u32::MAX
        }
        WriteClass::BridgeBusNumbers => {
            if request.header_kind != HeaderKind::Type1Bridge {
                return Err(WritePolicyError::HeaderMismatch);
            }
            if request.offset < OFFSET_BRIDGE_BUS_NUMBERS || end > OFFSET_BRIDGE_BUS_NUMBERS + 4 {
                return Err(WritePolicyError::OffsetOutOfRange);
            }
            width_mask
        }
        WriteClass::BridgeWindow => {
            if request.header_kind != HeaderKind::Type1Bridge {
                return Err(WritePolicyError::HeaderMismatch);
            }
            let in_window_range = request.offset >= OFFSET_BRIDGE_IO_BASE
                && end <= OFFSET_BRIDGE_PREF_LIMIT_UPPER + 4;
            let in_bridge_ctrl =
                request.offset == OFFSET_BRIDGE_CONTROL && request.width == ConfigWidth::Word;
            if !in_window_range && !in_bridge_ctrl {
                return Err(WritePolicyError::OffsetOutOfRange);
            }
            if request.width == ConfigWidth::Byte && request.offset > OFFSET_BRIDGE_IO_BASE + 1 {
                return Err(WritePolicyError::InvalidWidth);
            }
            width_mask
        }
        WriteClass::CapabilityControl => {
            if request.offset < OFFSET_CAPABILITY_MIN {
                return Err(WritePolicyError::OffsetOutOfRange);
            }
            width_mask
        }
        WriteClass::VendorAllowlisted => {
            let Some(entry) = request.allowlist_entry else {
                return Err(WritePolicyError::MissingVendorAllowlist);
            };
            if entry.offset != request.offset {
                return Err(WritePolicyError::OffsetOutOfRange);
            }
            if entry.width != request.width {
                return Err(WritePolicyError::InvalidWidth);
            }
            entry.writable_mask & width_mask
        }
    };

    if (request.write_mask & !class_allowed_mask) != 0 {
        return Err(WritePolicyError::MaskOutOfClassPolicy);
    }

    Ok(ValidatedWrite {
        address: request.address,
        class: request.class,
        offset: request.offset,
        width: request.width,
        value: request.value & request.write_mask,
        write_mask: request.write_mask,
        expected_readback_mask: request.expected_readback_mask,
    })
}

/// Validate `request`, perform read-modify-write through `transport`, verify
/// `expected_readback_mask`, and roll back to `before_value` if readback mismatches.
pub fn execute_checked_write(
    transport: &mut impl ConfigReadWriteTransport,
    request: &WriteRequest,
) -> Result<WriteTransactionRecord, WritePolicyError> {
    let plan = validate_write_request(request)?;
    let before_value = transport
        .read_width(plan.address, plan.offset, plan.width)
        .ok_or(WritePolicyError::TransportReadFailed)?
        & plan.width.value_mask();

    let next_value = (before_value & !plan.write_mask) | plan.value;
    if !transport.write_width(plan.address, plan.offset, plan.width, next_value) {
        return Err(WritePolicyError::TransportWriteFailed);
    }

    let Some(raw_after) = transport.read_width(plan.address, plan.offset, plan.width) else {
        let _ = transport.write_width(plan.address, plan.offset, plan.width, before_value);
        return Err(WritePolicyError::TransportReadFailed);
    };
    let readback_value = raw_after & plan.width.value_mask();
    let expected = next_value & plan.expected_readback_mask;
    let observed = readback_value & plan.expected_readback_mask;
    if observed != expected {
        if !transport.write_width(plan.address, plan.offset, plan.width, before_value) {
            return Err(WritePolicyError::RollbackFailed { expected, observed });
        }
        return Err(WritePolicyError::ReadbackMismatch {
            expected,
            observed,
            mask: plan.expected_readback_mask,
        });
    }

    Ok(WriteTransactionRecord {
        address: plan.address,
        class: plan.class,
        offset: plan.offset,
        width: plan.width,
        before_value,
        written_value: next_value,
        readback_value,
        expected_readback_mask: plan.expected_readback_mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDevice {
        bytes: [u8; 256],
        ro_mask: [u8; 256],
        fail_write: bool,
    }

    impl MockDevice {
        fn new() -> Self {
            Self {
                bytes: [0; 256],
                ro_mask: [0; 256],
                fail_write: false,
            }
        }
    }

    impl ConfigReadWriteTransport for MockDevice {
        fn read_width(
            &mut self,
            _address: PciAddress,
            offset: u16,
            width: ConfigWidth,
        ) -> Option<u32> {
            let idx = usize::from(offset);
            match width {
                ConfigWidth::Byte => self.bytes.get(idx).copied().map(u32::from),
                ConfigWidth::Word => {
                    let b0 = *self.bytes.get(idx)?;
                    let b1 = *self.bytes.get(idx + 1)?;
                    Some(u32::from(u16::from_le_bytes([b0, b1])))
                }
                ConfigWidth::Dword => {
                    let b0 = *self.bytes.get(idx)?;
                    let b1 = *self.bytes.get(idx + 1)?;
                    let b2 = *self.bytes.get(idx + 2)?;
                    let b3 = *self.bytes.get(idx + 3)?;
                    Some(u32::from_le_bytes([b0, b1, b2, b3]))
                }
            }
        }

        fn write_width(
            &mut self,
            _address: PciAddress,
            offset: u16,
            width: ConfigWidth,
            value: u32,
        ) -> bool {
            if self.fail_write {
                return false;
            }
            let idx = usize::from(offset);
            let raw = value.to_le_bytes();
            for i in 0..usize::from(width.bytes()) {
                let writable = !self.ro_mask[idx + i];
                self.bytes[idx + i] = (self.bytes[idx + i] & !writable) | (raw[i] & writable);
            }
            true
        }
    }

    fn base_req(class: WriteClass, offset: u16, width: ConfigWidth) -> WriteRequest {
        WriteRequest {
            address: PciAddress::ZERO,
            header_kind: HeaderKind::Type0Endpoint,
            class,
            offset,
            width,
            max_config_bytes: CONVENTIONAL_CONFIG_BYTES,
            value: 0,
            write_mask: width.value_mask(),
            expected_readback_mask: width.value_mask(),
            allowlist_entry: None,
        }
    }

    #[test]
    fn forbidden_and_read_only_classes_never_touch_transport() {
        let mut dev = MockDevice::new();
        dev.fail_write = true;

        let ro = base_req(WriteClass::ReadOnlyIdentity, 0x00, ConfigWidth::Word);
        assert_eq!(
            execute_checked_write(&mut dev, &ro),
            Err(WritePolicyError::ReadOnlyClass)
        );

        let forbidden = base_req(WriteClass::Forbidden, 0x04, ConfigWidth::Word);
        assert_eq!(
            execute_checked_write(&mut dev, &forbidden),
            Err(WritePolicyError::ForbiddenClass)
        );
    }

    #[test]
    fn command_control_enforces_width_offset_mask_and_readback() {
        let mut dev = MockDevice::new();
        // Existing bit 1 (Memory Space) and bit 2 (Bus Master) are preserved when we toggle bit 10.
        dev.bytes[0x04] = 0x06;
        dev.bytes[0x05] = 0x00;

        let mut req = base_req(
            WriteClass::CommandControl,
            OFFSET_COMMAND,
            ConfigWidth::Word,
        );
        req.write_mask = 1 << 10;
        req.value = 1 << 10;
        req.expected_readback_mask = 0x0407;

        let res = execute_checked_write(&mut dev, &req);
        assert!(res.is_ok());
        let Ok(rec) = res else {
            return;
        };
        assert_eq!(rec.before_value, 0x0006);
        assert_eq!(rec.written_value, 0x0406);
        assert_eq!(rec.readback_value, 0x0406);

        // Missing readback mask rejected.
        req.expected_readback_mask = 0;
        assert_eq!(
            validate_write_request(&req),
            Err(WritePolicyError::MissingReadbackMask)
        );

        // Reserved command bit outside COMMAND_WRITABLE_MASK rejected.
        req.expected_readback_mask = 0x0407;
        req.write_mask = 1 << 15;
        assert_eq!(
            validate_write_request(&req),
            Err(WritePolicyError::MaskOutOfClassPolicy)
        );
    }

    #[test]
    fn readback_mismatch_triggers_rollback() {
        let mut dev = MockDevice::new();
        dev.bytes[0x10] = 0x00;
        dev.bytes[0x11] = 0x10;
        // Hardware wires bit 4..11 hardwired zero (BAR alignment mask).
        dev.ro_mask[0x10] = 0xFF;

        let mut req = base_req(WriteClass::Bar, OFFSET_BAR0, ConfigWidth::Dword);
        req.value = 0xFFFF_FFFF;
        req.write_mask = 0xFFFF_FFFF;
        req.expected_readback_mask = 0xFFFF_FFFF;

        assert_eq!(
            execute_checked_write(&mut dev, &req),
            Err(WritePolicyError::ReadbackMismatch {
                expected: 0xFFFF_FFFF,
                observed: 0xFFFF_FF00,
                mask: 0xFFFF_FFFF,
            })
        );
        // Verify original value restored on non-readonly bytes.
        assert_eq!(dev.bytes[0x11], 0x10);
        assert_eq!(dev.bytes[0x12], 0x00);
    }

    #[test]
    fn header_type_and_vendor_allowlist_rules_are_enforced() {
        let mut bridge_req = base_req(
            WriteClass::BridgeBusNumbers,
            OFFSET_BRIDGE_BUS_NUMBERS,
            ConfigWidth::Dword,
        );
        assert_eq!(
            validate_write_request(&bridge_req),
            Err(WritePolicyError::HeaderMismatch)
        );
        bridge_req.header_kind = HeaderKind::Type1Bridge;
        assert!(validate_write_request(&bridge_req).is_ok());

        let mut vendor_req = base_req(WriteClass::VendorAllowlisted, 0x80, ConfigWidth::Byte);
        assert_eq!(
            validate_write_request(&vendor_req),
            Err(WritePolicyError::MissingVendorAllowlist)
        );
        vendor_req.allowlist_entry = Some(VendorAllowlistEntry {
            offset: 0x80,
            width: ConfigWidth::Byte,
            writable_mask: 0x0F,
        });
        vendor_req.write_mask = 0x1F;
        assert_eq!(
            validate_write_request(&vendor_req),
            Err(WritePolicyError::MaskOutOfClassPolicy)
        );
        vendor_req.write_mask = 0x03;
        assert!(validate_write_request(&vendor_req).is_ok());
    }
}
