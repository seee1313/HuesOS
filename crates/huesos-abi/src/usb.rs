//! Zero-bus-traffic USB 3.x (`xHCI`) inventory VMO wire format (`HUSB` v1).
//!
//! Published by the isolated Ring-3 `driver-host-xhci` process to
//! `DriverManager` after xHCI bring-up and on downstream port topology changes,
//! and consumed read-only by `lsusb` / `lsusb -v` without generating USB bus
//! control traffic.

/// Wire magic: ASCII `HUSB`.
pub const MAGIC: [u8; 4] = *b"HUSB";
/// Current `HUSB` wire format version.
pub const VERSION: u16 = 1;
/// Fixed header byte size.
pub const HEADER_BYTES: usize = 64;
/// Fixed per-device record byte size.
pub const DEVICE_BYTES: usize = 128;
/// Maximum USB devices serialized in one `HUSB` snapshot.
pub const MAX_DEVICES: usize = 32;
/// Maximum total encoded `HUSB` image size (`4160` bytes).
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_DEVICES * DEVICE_BYTES;
/// Byte offset of the wrapping `u32` checksum inside the header.
const CHECKSUM_OFFSET: usize = 12;

/// Controller DMA is isolated inside a hardware IOMMU domain (`DeviceLeaseAttachDma`).
pub const USB_FLAG_IOMMU_ISOLATED: u8 = 1 << 0;
/// Controller interrupt delivery uses MSI-X or MSI rather than legacy INTx/polling.
pub const USB_FLAG_MSI_ACTIVE: u8 = 1 << 1;
/// Firmware `USBLEGSUP` BIOS-to-OS semaphore handoff was executed or verified clean.
pub const USB_FLAG_BIOS_HANDOFF_DONE: u8 = 1 << 2;
/// At least one USB Mass Storage Bulk-Only (`BOT`) block device is online.
pub const USB_FLAG_BOT_ONLINE: u8 = 1 << 3;
/// Known v1 header flag mask.
pub const USB_FLAGS_V1: u8 = USB_FLAG_IOMMU_ISOLATED
    | USB_FLAG_MSI_ACTIVE
    | USB_FLAG_BIOS_HANDOFF_DONE
    | USB_FLAG_BOT_ONLINE;

/// Maximum sanitized ASCII manufacturer string bytes stored per device.
pub const MAX_MANUFACTURER_LEN: usize = 32;
/// Maximum sanitized ASCII product string bytes stored per device.
pub const MAX_PRODUCT_LEN: usize = 48;

/// Negotiated USB link speed reported by xHCI `PORTSC` / Hub status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UsbSpeedAbi {
    /// Speed unknown or uninitialized.
    Unknown = 0,
    /// Full-Speed USB (`12 Mb/s`, xHCI PSIV `1`).
    Full = 1,
    /// Low-Speed USB (`1.5 Mb/s`, xHCI PSIV `2`).
    Low = 2,
    /// High-Speed USB 2.0 (`480 Mb/s`, xHCI PSIV `3`).
    High = 3,
    /// SuperSpeed USB 3.0 Gen 1 (`5 Gb/s`, xHCI PSIV `4`).
    Super = 4,
    /// SuperSpeedPlus USB 3.1/3.2 Gen 2 (`10+ Gb/s`, xHCI PSIV `5`).
    SuperPlus = 5,
}

impl UsbSpeedAbi {
    /// Convert a raw byte discriminant into [`UsbSpeedAbi`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::Full),
            2 => Some(Self::Low),
            3 => Some(Self::High),
            4 => Some(Self::Super),
            5 => Some(Self::SuperPlus),
            _ => None,
        }
    }

    /// Short human-readable speed rate string (`lsusb` style).
    pub const fn rate_label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Full => "12M",
            Self::Low => "1.5M",
            Self::High => "480M",
            Self::Super => "5000M",
            Self::SuperPlus => "10000M",
        }
    }

    /// Returns `true` when the link negotiated USB 3.x SuperSpeed or SuperSpeedPlus.
    pub const fn is_superspeed(self) -> bool {
        matches!(self, Self::Super | Self::SuperPlus)
    }
}

/// Bound class driver role assigned to an enumerated USB device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UsbDeviceRole {
    /// Generic enumerated USB device (no active class binding).
    Generic = 0,
    /// USB 2.0 / 3.x Hub (`class 0x09`).
    Hub = 1,
    /// USB HID Boot/Report Keyboard (`class 0x03`, protocol `1`).
    HidKeyboard = 2,
    /// USB HID Boot/Report Mouse/Pointer (`class 0x03`, protocol `2`).
    HidMouse = 3,
    /// USB Mass Storage Bulk-Only Transport (`class 0x08`, subclass `0x06`, proto `0x50`).
    MassStorageBot = 4,
    /// Composite multi-interface USB device with multiple active bindings.
    Composite = 5,
}

impl UsbDeviceRole {
    /// Convert a raw byte discriminant into [`UsbDeviceRole`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Generic),
            1 => Some(Self::Hub),
            2 => Some(Self::HidKeyboard),
            3 => Some(Self::HidMouse),
            4 => Some(Self::MassStorageBot),
            5 => Some(Self::Composite),
            _ => None,
        }
    }

    /// Human-readable class driver label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Hub => "usb-hub",
            Self::HidKeyboard => "usb-hid-kbd",
            Self::HidMouse => "usb-hid-mouse",
            Self::MassStorageBot => "usb-storage-bot",
            Self::Composite => "usb-composite",
        }
    }
}

/// Wire encoding/decoding errors for `HUSB`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbInventoryError {
    /// Input or output buffer is smaller than required.
    BufferTooSmall,
    /// Magic bytes do not match `HUSB`.
    BadMagic,
    /// Wire format version is not supported.
    UnsupportedVersion,
    /// Header size, total size, device count, or reserved fields are invalid.
    InvalidLayout,
    /// Wrapping checksum mismatch.
    BadChecksum,
    /// Enum discriminant, string length, or flags are invalid.
    InvalidField,
}

/// Decoded `HUSB` controller summary header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbInventoryHeader {
    /// Monotonic topology generation incremented on each snapshot update.
    pub generation: u64,
    /// Packed PCI address of the xHCI host controller (`unpack_pci_address`).
    pub controller_bdf_packed: u32,
    /// PCI Vendor ID of the xHCI controller (`0` if unknown).
    pub controller_vendor_id: u16,
    /// PCI Device ID of the xHCI controller (`0` if unknown).
    pub controller_device_id: u16,
    /// BCD xHCI `HCIVERSION` register (e.g. `0x0100` for xHCI 1.0).
    pub hci_version: u16,
    /// Hardware `MaxSlots` from `HCSPARAMS1`.
    pub max_slots: u8,
    /// Hardware `MaxPorts` from `HCSPARAMS1`.
    pub max_ports: u8,
    /// Number of valid [`UsbInventoryDevice`] records following the header.
    pub device_count: u8,
    /// Header bitflags (`USB_FLAG_*`).
    pub flags: u8,
    /// Total xHCI Event Ring TRBs processed since bring-up.
    pub completed_trbs: u64,
    /// Total HID keyboard + mouse reports decoded since bring-up.
    pub hid_events: u64,
    /// Total 512B/block sectors transferred over BOT Mass Storage.
    pub bot_blocks_io: u64,
}

/// Fixed-size zero-alloc descriptor for one enumerated USB device in `HUSB`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbInventoryDevice {
    /// Assigned xHCI Slot ID (`1..=max_slots`).
    pub slot_id: u8,
    /// Root Hub port number (`1..=max_ports`).
    pub root_port: u8,
    /// Parent Hub Slot ID (`0` if attached directly to root hub).
    pub parent_slot_id: u8,
    /// Downstream port on parent Hub (`0` if attached directly to root hub).
    pub parent_port: u8,
    /// Negotiated link speed.
    pub speed: UsbSpeedAbi,
    /// Bound class driver role.
    pub role: UsbDeviceRole,
    /// `bcdUSB` from Device Descriptor (e.g. `0x0200`, `0x0300`).
    pub usb_bcd: u16,
    /// USB `idVendor`.
    pub vendor_id: u16,
    /// USB `idProduct`.
    pub product_id: u16,
    /// Device Descriptor `bDeviceClass`.
    pub device_class: u8,
    /// Device Descriptor `bDeviceSubclass`.
    pub device_subclass: u8,
    /// Device Descriptor `bDeviceProtocol`.
    pub device_protocol: u8,
    /// Primary bound Interface `bInterfaceClass`.
    pub interface_class: u8,
    /// Primary bound Interface `bInterfaceSubclass`.
    pub interface_subclass: u8,
    /// Primary bound Interface `bInterfaceProtocol`.
    pub interface_protocol: u8,
    /// `bNumConfigurations` from Device Descriptor.
    pub num_configurations: u8,
    /// Active `bConfigurationValue`.
    pub config_value: u8,
    /// Number of configured non-EP0 endpoints.
    pub endpoint_count: u8,
    /// Downstream port count when `role == UsbDeviceRole::Hub` (`0` otherwise).
    pub hub_ports: u8,
    /// Logical block size in bytes when `role == UsbDeviceRole::MassStorageBot`.
    pub bot_block_size: u32,
    /// Total logical blocks when `role == UsbDeviceRole::MassStorageBot`.
    pub bot_total_blocks: u64,
    /// Byte length of [`Self::manufacturer`] (`<= MAX_MANUFACTURER_LEN`).
    pub manufacturer_len: u8,
    /// Byte length of [`Self::product`] (`<= MAX_PRODUCT_LEN`).
    pub product_len: u8,
    /// Sanitized printable ASCII manufacturer string.
    pub manufacturer: [u8; MAX_MANUFACTURER_LEN],
    /// Sanitized printable ASCII product string.
    pub product: [u8; MAX_PRODUCT_LEN],
}

impl UsbInventoryDevice {
    /// Zeroed placeholder device slot.
    pub const ZERO: Self = Self {
        slot_id: 0,
        root_port: 0,
        parent_slot_id: 0,
        parent_port: 0,
        speed: UsbSpeedAbi::Unknown,
        role: UsbDeviceRole::Generic,
        usb_bcd: 0,
        vendor_id: 0,
        product_id: 0,
        device_class: 0,
        device_subclass: 0,
        device_protocol: 0,
        interface_class: 0,
        interface_subclass: 0,
        interface_protocol: 0,
        num_configurations: 0,
        config_value: 0,
        endpoint_count: 0,
        hub_ports: 0,
        bot_block_size: 0,
        bot_total_blocks: 0,
        manufacturer_len: 0,
        product_len: 0,
        manufacturer: [0; MAX_MANUFACTURER_LEN],
        product: [0; MAX_PRODUCT_LEN],
    };

    /// Borrow the manufacturer ASCII string slice.
    pub fn manufacturer_str(&self) -> &str {
        let len = usize::from(self.manufacturer_len).min(MAX_MANUFACTURER_LEN);
        core::str::from_utf8(&self.manufacturer[..len]).unwrap_or("")
    }

    /// Borrow the product ASCII string slice.
    pub fn product_str(&self) -> &str {
        let len = usize::from(self.product_len).min(MAX_PRODUCT_LEN);
        core::str::from_utf8(&self.product[..len]).unwrap_or("")
    }
}

/// Inspect a `HEADER_BYTES` prefix and return the declared total byte length.
pub fn declared_size(header: &[u8]) -> Result<usize, UsbInventoryError> {
    if header.len() < HEADER_BYTES {
        return Err(UsbInventoryError::BufferTooSmall);
    }
    if header[0..4] != MAGIC {
        return Err(UsbInventoryError::BadMagic);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(UsbInventoryError::UnsupportedVersion);
    }
    let hdr_bytes = u16::from_le_bytes([header[6], header[7]]) as usize;
    if hdr_bytes != HEADER_BYTES {
        return Err(UsbInventoryError::InvalidLayout);
    }
    let total = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let count = usize::from(header[36]);
    if count > MAX_DEVICES {
        return Err(UsbInventoryError::InvalidLayout);
    }
    let expected = HEADER_BYTES + count * DEVICE_BYTES;
    if total != expected || total > MAX_BYTES {
        return Err(UsbInventoryError::InvalidLayout);
    }
    Ok(total)
}

/// Encode `header` and `devices[..header.device_count]` into `out`.
pub fn encode(
    header: &UsbInventoryHeader,
    devices: &[UsbInventoryDevice],
    out: &mut [u8],
) -> Result<usize, UsbInventoryError> {
    let count = usize::from(header.device_count);
    if count > MAX_DEVICES || devices.len() < count {
        return Err(UsbInventoryError::InvalidLayout);
    }
    if (header.flags & !USB_FLAGS_V1) != 0 {
        return Err(UsbInventoryError::InvalidField);
    }
    let total = HEADER_BYTES + count * DEVICE_BYTES;
    if out.len() < total {
        return Err(UsbInventoryError::BufferTooSmall);
    }
    out[..total].fill(0);
    out[0..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    out[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    // 12..16: checksum filled at end
    out[16..24].copy_from_slice(&header.generation.to_le_bytes());
    out[24..28].copy_from_slice(&header.controller_bdf_packed.to_le_bytes());
    out[28..30].copy_from_slice(&header.controller_vendor_id.to_le_bytes());
    out[30..32].copy_from_slice(&header.controller_device_id.to_le_bytes());
    out[32..34].copy_from_slice(&header.hci_version.to_le_bytes());
    out[34] = header.max_slots;
    out[35] = header.max_ports;
    out[36] = header.device_count;
    out[37] = header.flags;
    // 38..40 reserved zero
    out[40..48].copy_from_slice(&header.completed_trbs.to_le_bytes());
    out[48..56].copy_from_slice(&header.hid_events.to_le_bytes());
    out[56..64].copy_from_slice(&header.bot_blocks_io.to_le_bytes());

    let mut cursor = HEADER_BYTES;
    for dev in devices.iter().take(count) {
        if usize::from(dev.manufacturer_len) > MAX_MANUFACTURER_LEN
            || usize::from(dev.product_len) > MAX_PRODUCT_LEN
        {
            return Err(UsbInventoryError::InvalidField);
        }
        let rec = &mut out[cursor..cursor + DEVICE_BYTES];
        rec[0] = dev.slot_id;
        rec[1] = dev.root_port;
        rec[2] = dev.parent_slot_id;
        rec[3] = dev.parent_port;
        rec[4] = dev.speed as u8;
        rec[5] = dev.role as u8;
        rec[6..8].copy_from_slice(&dev.usb_bcd.to_le_bytes());
        rec[8..10].copy_from_slice(&dev.vendor_id.to_le_bytes());
        rec[10..12].copy_from_slice(&dev.product_id.to_le_bytes());
        rec[12] = dev.device_class;
        rec[13] = dev.device_subclass;
        rec[14] = dev.device_protocol;
        rec[15] = dev.interface_class;
        rec[16] = dev.interface_subclass;
        rec[17] = dev.interface_protocol;
        rec[18] = dev.num_configurations;
        rec[19] = dev.config_value;
        rec[20] = dev.endpoint_count;
        rec[21] = dev.hub_ports;
        rec[22] = dev.manufacturer_len;
        rec[23] = dev.product_len;
        rec[24..28].copy_from_slice(&dev.bot_block_size.to_le_bytes());
        // 28..32 reserved zero
        rec[32..40].copy_from_slice(&dev.bot_total_blocks.to_le_bytes());
        // 40..48 reserved zero
        rec[48..80].copy_from_slice(&dev.manufacturer);
        rec[80..128].copy_from_slice(&dev.product);
        cursor += DEVICE_BYTES;
    }

    let csum = compute_checksum(&out[..total]);
    out[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&csum.to_le_bytes());
    Ok(total)
}

/// Validate checksum/layout of `bytes` and decode the [`UsbInventoryHeader`].
pub fn validate_and_decode_header(bytes: &[u8]) -> Result<UsbInventoryHeader, UsbInventoryError> {
    let total = declared_size(bytes)?;
    if bytes.len() < total {
        return Err(UsbInventoryError::BufferTooSmall);
    }
    let slice = &bytes[..total];
    if slice[38..40] != [0, 0] {
        return Err(UsbInventoryError::InvalidLayout);
    }
    let stored = u32::from_le_bytes([
        slice[CHECKSUM_OFFSET],
        slice[CHECKSUM_OFFSET + 1],
        slice[CHECKSUM_OFFSET + 2],
        slice[CHECKSUM_OFFSET + 3],
    ]);
    if stored != compute_checksum(slice) {
        return Err(UsbInventoryError::BadChecksum);
    }
    let flags = slice[37];
    if (flags & !USB_FLAGS_V1) != 0 {
        return Err(UsbInventoryError::InvalidField);
    }
    let hdr = UsbInventoryHeader {
        generation: read_u64_le(slice, 16),
        controller_bdf_packed: read_u32_le(slice, 24),
        controller_vendor_id: u16::from_le_bytes([slice[28], slice[29]]),
        controller_device_id: u16::from_le_bytes([slice[30], slice[31]]),
        hci_version: u16::from_le_bytes([slice[32], slice[33]]),
        max_slots: slice[34],
        max_ports: slice[35],
        device_count: slice[36],
        flags,
        completed_trbs: read_u64_le(slice, 40),
        hid_events: read_u64_le(slice, 48),
        bot_blocks_io: read_u64_le(slice, 56),
    };
    // Pre-validate every device slot so callers can iterate `0..device_count` infallibly.
    for idx in 0..usize::from(hdr.device_count) {
        let _ = decode_device(slice, idx)?;
    }
    Ok(hdr)
}

/// Decode device record `index` from a validated `HUSB` byte slice.
pub fn decode_device(bytes: &[u8], index: usize) -> Result<UsbInventoryDevice, UsbInventoryError> {
    let total = declared_size(bytes)?;
    let count = usize::from(bytes[36]);
    if bytes.len() < total || index >= count {
        return Err(UsbInventoryError::InvalidLayout);
    }
    let off = HEADER_BYTES + index * DEVICE_BYTES;
    let rec = &bytes[off..off + DEVICE_BYTES];
    if rec[28..32] != [0; 4] || rec[40..48] != [0; 8] {
        return Err(UsbInventoryError::InvalidLayout);
    }
    let speed = UsbSpeedAbi::from_raw(rec[4]).ok_or(UsbInventoryError::InvalidField)?;
    let role = UsbDeviceRole::from_raw(rec[5]).ok_or(UsbInventoryError::InvalidField)?;
    let mfg_len = rec[22];
    let prod_len = rec[23];
    if usize::from(mfg_len) > MAX_MANUFACTURER_LEN || usize::from(prod_len) > MAX_PRODUCT_LEN {
        return Err(UsbInventoryError::InvalidField);
    }
    let mut manufacturer = [0u8; MAX_MANUFACTURER_LEN];
    manufacturer.copy_from_slice(&rec[48..80]);
    let mut product = [0u8; MAX_PRODUCT_LEN];
    product.copy_from_slice(&rec[80..128]);
    if core::str::from_utf8(&manufacturer[..usize::from(mfg_len)]).is_err()
        || core::str::from_utf8(&product[..usize::from(prod_len)]).is_err()
    {
        return Err(UsbInventoryError::InvalidField);
    }
    Ok(UsbInventoryDevice {
        slot_id: rec[0],
        root_port: rec[1],
        parent_slot_id: rec[2],
        parent_port: rec[3],
        speed,
        role,
        usb_bcd: u16::from_le_bytes([rec[6], rec[7]]),
        vendor_id: u16::from_le_bytes([rec[8], rec[9]]),
        product_id: u16::from_le_bytes([rec[10], rec[11]]),
        device_class: rec[12],
        device_subclass: rec[13],
        device_protocol: rec[14],
        interface_class: rec[15],
        interface_subclass: rec[16],
        interface_protocol: rec[17],
        num_configurations: rec[18],
        config_value: rec[19],
        endpoint_count: rec[20],
        hub_ports: rec[21],
        bot_block_size: read_u32_le(rec, 24),
        bot_total_blocks: read_u64_le(rec, 32),
        manufacturer_len: mfg_len,
        product_len: prod_len,
        manufacturer,
        product,
    })
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn compute_checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (idx, &b) in bytes.iter().enumerate() {
        if !(CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4).contains(&idx) {
            sum = sum.wrapping_add(u32::from(b));
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn husb_roundtrip_and_checksum_tamper_rejection() {
        let mut kbd = UsbInventoryDevice::ZERO;
        kbd.slot_id = 2;
        kbd.root_port = 1;
        kbd.parent_slot_id = 1;
        kbd.parent_port = 1;
        kbd.speed = UsbSpeedAbi::High;
        kbd.role = UsbDeviceRole::HidKeyboard;
        kbd.usb_bcd = 0x0200;
        kbd.vendor_id = 0x0627;
        kbd.product_id = 0x0001;
        kbd.interface_class = 0x03;
        kbd.interface_subclass = 0x01;
        kbd.interface_protocol = 0x01;
        kbd.num_configurations = 1;
        kbd.config_value = 1;
        kbd.endpoint_count = 1;
        let mfg = b"QEMU";
        kbd.manufacturer[..mfg.len()].copy_from_slice(mfg);
        kbd.manufacturer_len = mfg.len() as u8;
        let prod = b"QEMU USB Keyboard";
        kbd.product[..prod.len()].copy_from_slice(prod);
        kbd.product_len = prod.len() as u8;

        let hdr = UsbInventoryHeader {
            generation: 7,
            controller_bdf_packed: 0x0000_0018,
            controller_vendor_id: 0x1b36,
            controller_device_id: 0x000d,
            hci_version: 0x0100,
            max_slots: 64,
            max_ports: 8,
            device_count: 1,
            flags: USB_FLAG_IOMMU_ISOLATED | USB_FLAG_MSI_ACTIVE | USB_FLAG_BIOS_HANDOFF_DONE,
            completed_trbs: 42,
            hid_events: 5,
            bot_blocks_io: 0,
        };

        let mut buf = [0u8; MAX_BYTES];
        let enc_res = encode(&hdr, &[kbd], &mut buf);
        assert!(enc_res.is_ok());
        let len = enc_res.unwrap_or(0);
        assert_eq!(len, HEADER_BYTES + DEVICE_BYTES);
        let dec_hdr_res = validate_and_decode_header(&buf[..len]);
        assert_eq!(dec_hdr_res, Ok(hdr));
        let dec_dev_res = decode_device(&buf[..len], 0);
        assert_eq!(dec_dev_res, Ok(kbd));
        let dec_dev = dec_dev_res.unwrap_or(UsbInventoryDevice::ZERO);
        assert_eq!(dec_dev.manufacturer_str(), "QEMU");
        assert_eq!(dec_dev.product_str(), "QEMU USB Keyboard");

        buf[len - 1] ^= 0xFF;
        assert_eq!(
            validate_and_decode_header(&buf[..len]),
            Err(UsbInventoryError::BadChecksum)
        );
    }
}
