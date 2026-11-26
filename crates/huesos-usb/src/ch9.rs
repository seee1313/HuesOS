//! USB 2.0 / 3.x Chapter 9 Setup packets, standard descriptors, and UTF-16LE
//! string sanitizer.

use crate::xhci::XhciEndpointType;

/// Standard descriptor type: Device (`1`).
pub const DESC_DEVICE: u8 = 0x01;
/// Standard descriptor type: Configuration (`2`).
pub const DESC_CONFIGURATION: u8 = 0x02;
/// Standard descriptor type: String (`3`).
pub const DESC_STRING: u8 = 0x03;
/// Standard descriptor type: Interface (`4`).
pub const DESC_INTERFACE: u8 = 0x04;
/// Standard descriptor type: Endpoint (`5`).
pub const DESC_ENDPOINT: u8 = 0x05;
/// Class descriptor type: USB 2.0 Hub (`0x29`).
pub const DESC_HUB: u8 = 0x29;
/// Class descriptor type: SuperSpeed USB 3.0 Hub (`0x2A`).
pub const DESC_SS_HUB: u8 = 0x2A;
/// Standard descriptor type: SuperSpeed Endpoint Companion (`0x30`).
pub const DESC_SS_EP_COMPANION: u8 = 0x30;

/// USB interface class: Human Interface Device (`0x03`).
pub const USB_CLASS_HID: u8 = 0x03;
/// USB interface class: Mass Storage (`0x08`).
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
/// USB interface class: Hub (`0x09`).
pub const USB_CLASS_HUB: u8 = 0x09;

/// HID Boot Interface subclass (`0x01`).
pub const HID_SUBCLASS_BOOT: u8 = 0x01;
/// HID protocol: Keyboard (`0x01`).
pub const HID_PROTO_KEYBOARD: u8 = 0x01;
/// HID protocol: Mouse (`0x02`).
pub const HID_PROTO_MOUSE: u8 = 0x02;

/// Mass Storage subclass: SCSI Transparent Command Set (`0x06`).
pub const MSC_SUBCLASS_SCSI: u8 = 0x06;
/// Mass Storage protocol: Bulk-Only Transport (`BBB`, `0x50`).
pub const MSC_PROTO_BULK_ONLY: u8 = 0x50;

/// 8-byte USB Control `Setup` packet (`IDT = 1` immediate payload for xHCI).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupPacket {
    /// Request characteristics (`direction | type | recipient`).
    pub bm_request_type: u8,
    /// Specific request code (`bRequest`).
    pub b_request: u8,
    /// Request-specific parameter (`wValue`).
    pub w_value: u16,
    /// Interface/endpoint/port selector (`wIndex`).
    pub w_index: u16,
    /// Data stage byte count (`wLength`).
    pub w_length: u16,
}

impl SetupPacket {
    /// Pack the 8-byte Setup packet into a little-endian `u64` for `Trb::xfer_setup`.
    pub const fn to_le_u64(self) -> u64 {
        let v = self.w_value.to_le_bytes();
        let i = self.w_index.to_le_bytes();
        let l = self.w_length.to_le_bytes();
        u64::from_le_bytes([
            self.bm_request_type,
            self.b_request,
            v[0],
            v[1],
            i[0],
            i[1],
            l[0],
            l[1],
        ])
    }

    /// Standard `GET_DESCRIPTOR` (`0x80`, `0x06`).
    pub const fn get_descriptor(desc_type: u8, desc_index: u8, lang_id: u16, len: u16) -> Self {
        Self {
            bm_request_type: 0x80,
            b_request: 0x06,
            w_value: ((desc_type as u16) << 8) | (desc_index as u16),
            w_index: lang_id,
            w_length: len,
        }
    }

    /// Standard `SET_CONFIGURATION` (`0x00`, `0x09`).
    pub const fn set_configuration(config_value: u8) -> Self {
        Self {
            bm_request_type: 0x00,
            b_request: 0x09,
            w_value: config_value as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    /// Standard `CLEAR_FEATURE(ENDPOINT_HALT)` (`0x02`, `0x01`, `wValue = 0`).
    pub const fn clear_endpoint_halt(ep_address: u8) -> Self {
        Self {
            bm_request_type: 0x02,
            b_request: 0x01,
            w_value: 0,
            w_index: ep_address as u16,
            w_length: 0,
        }
    }

    /// HID class `SET_PROTOCOL` (`0` = Boot Protocol, `1` = Report Protocol).
    pub const fn hid_set_protocol(interface_num: u8, report_protocol: bool) -> Self {
        Self {
            bm_request_type: 0x21,
            b_request: 0x0B,
            w_value: if report_protocol { 1 } else { 0 },
            w_index: interface_num as u16,
            w_length: 0,
        }
    }

    /// HID class `SET_IDLE` (`duration_4ms = 0` reports only on state change).
    pub const fn hid_set_idle(interface_num: u8, duration_4ms: u8, report_id: u8) -> Self {
        Self {
            bm_request_type: 0x21,
            b_request: 0x0A,
            w_value: ((duration_4ms as u16) << 8) | (report_id as u16),
            w_index: interface_num as u16,
            w_length: 0,
        }
    }

    /// Hub class `GET_DESCRIPTOR` (`0xA0`, `0x06`, `0x29` for USB2, `0x2A` for USB3).
    pub const fn hub_get_descriptor(is_superspeed: bool, len: u16) -> Self {
        let dtype = if is_superspeed { DESC_SS_HUB } else { DESC_HUB };
        Self {
            bm_request_type: 0xA0,
            b_request: 0x06,
            w_value: (dtype as u16) << 8,
            w_index: 0,
            w_length: len,
        }
    }

    /// Hub class `SET_PORT_FEATURE` (`0x23`, `0x03`).
    pub const fn hub_set_port_feature(feature: u16, port: u8) -> Self {
        Self {
            bm_request_type: 0x23,
            b_request: 0x03,
            w_value: feature,
            w_index: port as u16,
            w_length: 0,
        }
    }

    /// Hub class `CLEAR_PORT_FEATURE` (`0x23`, `0x01`).
    pub const fn hub_clear_port_feature(feature: u16, port: u8) -> Self {
        Self {
            bm_request_type: 0x23,
            b_request: 0x01,
            w_value: feature,
            w_index: port as u16,
            w_length: 0,
        }
    }

    /// Hub class `GET_PORT_STATUS` (`0xA3`, `0x00`, 4 bytes).
    pub const fn hub_get_port_status(port: u8) -> Self {
        Self {
            bm_request_type: 0xA3,
            b_request: 0x00,
            w_value: 0,
            w_index: port as u16,
            w_length: 4,
        }
    }

    /// Hub class `SET_HUB_DEPTH` (`0x20`, `0x0C`, SuperSpeed hubs).
    pub const fn ss_hub_set_depth(depth: u16) -> Self {
        Self {
            bm_request_type: 0x20,
            b_request: 0x0C,
            w_value: depth,
            w_index: 0,
            w_length: 0,
        }
    }

    /// Mass Storage Bulk-Only `GET_MAX_LUN` (`0xA1`, `0xFE`, 1 byte).
    pub const fn msc_get_max_lun(interface_num: u8) -> Self {
        Self {
            bm_request_type: 0xA1,
            b_request: 0xFE,
            w_value: 0,
            w_index: interface_num as u16,
            w_length: 1,
        }
    }

    /// Mass Storage Bulk-Only Reset (`0x21`, `0xFF`).
    pub const fn msc_bulk_only_reset(interface_num: u8) -> Self {
        Self {
            bm_request_type: 0x21,
            b_request: 0xFF,
            w_value: 0,
            w_index: interface_num as u16,
            w_length: 0,
        }
    }
}

/// Decoded 18-byte USB Device Descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor {
    /// USB specification BCD (`0x0200`, `0x0300`, etc.).
    pub usb_bcd: u16,
    /// `bDeviceClass`.
    pub device_class: u8,
    /// `bDeviceSubClass`.
    pub device_subclass: u8,
    /// `bDeviceProtocol`.
    pub device_protocol: u8,
    /// `bMaxPacketSize0` (raw byte: for USB 3.x `9` means `2^9 = 512`).
    pub max_packet_size0_raw: u8,
    /// `idVendor`.
    pub vendor_id: u16,
    /// `idProduct`.
    pub product_id: u16,
    /// `bcdDevice`.
    pub device_bcd: u16,
    /// Manufacturer string index (`iManufacturer`).
    pub manufacturer_str_idx: u8,
    /// Product string index (`iProduct`).
    pub product_str_idx: u8,
    /// Serial number string index (`iSerialNumber`).
    pub serial_str_idx: u8,
    /// `bNumConfigurations`.
    pub num_configurations: u8,
}

impl DeviceDescriptor {
    /// Parse an 18-byte Device Descriptor (or 8-byte prefix via [`Self::ep0_mps_from_prefix`]).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 18 || bytes[0] < 18 || bytes[1] != DESC_DEVICE {
            return None;
        }
        Some(Self {
            usb_bcd: u16::from_le_bytes([bytes[2], bytes[3]]),
            device_class: bytes[4],
            device_subclass: bytes[5],
            device_protocol: bytes[6],
            max_packet_size0_raw: bytes[7],
            vendor_id: u16::from_le_bytes([bytes[8], bytes[9]]),
            product_id: u16::from_le_bytes([bytes[10], bytes[11]]),
            device_bcd: u16::from_le_bytes([bytes[12], bytes[13]]),
            manufacturer_str_idx: bytes[14],
            product_str_idx: bytes[15],
            serial_str_idx: bytes[16],
            num_configurations: bytes[17],
        })
    }

    /// Compute actual EP0 Max Packet Size in bytes (`2^bMaxPacketSize0` for USB 3.x).
    pub const fn ep0_max_packet_size(&self) -> u16 {
        if self.usb_bcd >= 0x0300
            && self.max_packet_size0_raw >= 9
            && self.max_packet_size0_raw <= 15
        {
            1u16 << self.max_packet_size0_raw
        } else {
            match self.max_packet_size0_raw {
                8 | 16 | 32 | 64 => self.max_packet_size0_raw as u16,
                _ => 64,
            }
        }
    }
}

/// Decoded 9-byte USB Configuration Descriptor header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationDescriptor {
    /// Total length of configuration + subordinate descriptors (`wTotalLength`).
    pub total_length: u16,
    /// `bNumInterfaces`.
    pub num_interfaces: u8,
    /// `bConfigurationValue` passed to `SET_CONFIGURATION`.
    pub configuration_value: u8,
    /// `bmAttributes`.
    pub attributes: u8,
}

impl ConfigurationDescriptor {
    /// Parse the 9-byte Configuration Descriptor header.
    pub fn parse_header(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 || bytes[0] < 9 || bytes[1] != DESC_CONFIGURATION {
            return None;
        }
        let total = u16::from_le_bytes([bytes[2], bytes[3]]);
        if total < 9 {
            return None;
        }
        Some(Self {
            total_length: total,
            num_interfaces: bytes[4],
            configuration_value: bytes[5],
            attributes: bytes[7],
        })
    }
}

/// Decoded 9-byte USB Interface Descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceDescriptor {
    /// `bInterfaceNumber`.
    pub interface_number: u8,
    /// `bAlternateSetting`.
    pub alternate_setting: u8,
    /// `bNumEndpoints`.
    pub num_endpoints: u8,
    /// `bInterfaceClass`.
    pub interface_class: u8,
    /// `bInterfaceSubClass`.
    pub interface_subclass: u8,
    /// `bInterfaceProtocol`.
    pub interface_protocol: u8,
}

/// Decoded 7-byte USB Endpoint Descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointDescriptor {
    /// Raw `bEndpointAddress` (`bit 7 = IN`, `bits 3:0 = ep_num`).
    pub endpoint_address: u8,
    /// `bmAttributes` (`bits 1:0`: `0`=Ctrl, `1`=Isoch, `2`=Bulk, `3`=Intr).
    pub attributes: u8,
    /// `wMaxPacketSize` (`bits 10:0` base packet size).
    pub max_packet_size: u16,
    /// `bInterval`.
    pub interval: u8,
}

impl EndpointDescriptor {
    /// True if this is an `IN` (device-to-host) endpoint (`bit 7`).
    pub const fn is_in(&self) -> bool {
        (self.endpoint_address & 0x80) != 0
    }

    /// Endpoint number (`1..=15`).
    pub const fn ep_number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    /// Compute xHCI Device Context Index (`DCI`, `2..=31`) for non-EP0 endpoints.
    pub const fn xhci_dci(&self) -> Option<u8> {
        let num = self.ep_number();
        if num == 0 || num > 15 {
            return None;
        }
        Some(num * 2 + (self.is_in() as u8))
    }

    /// Map transfer attributes + direction to [`XhciEndpointType`] (Bulk & Interrupt).
    pub const fn xhci_ep_type(&self) -> Option<XhciEndpointType> {
        match (self.attributes & 0x03, self.is_in()) {
            (2, false) => Some(XhciEndpointType::BulkOut),
            (2, true) => Some(XhciEndpointType::BulkIn),
            (3, false) => Some(XhciEndpointType::InterruptOut),
            (3, true) => Some(XhciEndpointType::InterruptIn),
            _ => None,
        }
    }

    /// Base packet size (`wMaxPacketSize & 0x07FF`).
    pub const fn base_packet_size(&self) -> u16 {
        self.max_packet_size & 0x07FF
    }
}

/// Parsed item yielded while walking a full Configuration Descriptor blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedDescriptor {
    /// Standard Interface Descriptor.
    Interface(InterfaceDescriptor),
    /// Standard Endpoint Descriptor.
    Endpoint(EndpointDescriptor),
    /// SuperSpeed Endpoint Companion (`bMaxBurst`).
    SsCompanion {
        /// `bMaxBurst` (`0..=15`).
        max_burst: u8,
    },
}

/// Safe bounded iterator over descriptors inside a Configuration Descriptor buffer.
pub struct DescriptorIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DescriptorIter<'a> {
    /// Create an iterator over `config_blob` (may start at offset 0 of Configuration Descriptor).
    pub const fn new(config_blob: &'a [u8]) -> Self {
        Self {
            bytes: config_blob,
            cursor: 0,
        }
    }
}

impl Iterator for DescriptorIter<'_> {
    type Item = ParsedDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor + 2 <= self.bytes.len() {
            let len = usize::from(self.bytes[self.cursor]);
            let dtype = self.bytes[self.cursor + 1];
            if len < 2 || self.cursor + len > self.bytes.len() {
                self.cursor = self.bytes.len();
                return None;
            }
            let slice = &self.bytes[self.cursor..self.cursor + len];
            self.cursor += len;
            match dtype {
                DESC_INTERFACE if len >= 9 => {
                    return Some(ParsedDescriptor::Interface(InterfaceDescriptor {
                        interface_number: slice[2],
                        alternate_setting: slice[3],
                        num_endpoints: slice[4],
                        interface_class: slice[5],
                        interface_subclass: slice[6],
                        interface_protocol: slice[7],
                    }));
                }
                DESC_ENDPOINT if len >= 7 => {
                    return Some(ParsedDescriptor::Endpoint(EndpointDescriptor {
                        endpoint_address: slice[2],
                        attributes: slice[3],
                        max_packet_size: u16::from_le_bytes([slice[4], slice[5]]),
                        interval: slice[6],
                    }));
                }
                DESC_SS_EP_COMPANION if len >= 6 => {
                    return Some(ParsedDescriptor::SsCompanion {
                        max_burst: slice[2].min(15),
                    });
                }
                _ => {}
            }
        }
        None
    }
}

/// Sanitize a UTF-16LE USB String Descriptor into printable ASCII inside `out`,
/// returning the number of bytes written.
pub fn decode_usb_string_ascii(raw_desc: &[u8], out: &mut [u8]) -> usize {
    if raw_desc.len() < 2 || raw_desc[1] != DESC_STRING {
        return 0;
    }
    let declared = usize::from(raw_desc[0]).min(raw_desc.len());
    if declared < 4 {
        return 0;
    }
    let mut written = 0usize;
    let mut off = 2usize;
    while off + 2 <= declared && written < out.len() {
        let code = u16::from_le_bytes([raw_desc[off], raw_desc[off + 1]]);
        off += 2;
        if code == 0 {
            break;
        }
        out[written] = if (0x20..=0x7E).contains(&code) {
            code as u8
        } else {
            b'?'
        };
        written += 1;
    }
    // Trim trailing spaces so `lsusb` output stays crisp.
    while written > 0 && out[written - 1] == b' ' {
        written -= 1;
    }
    written
}
