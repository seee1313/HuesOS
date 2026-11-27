//! Bluetooth Core 5.x Host Controller Interface (`HCI`) wire codecs, EIR parser,
//! Secure Simple Pairing (`SSP` Just-Works), and ACL fragmentation/credit tracking.

use alloc::vec::Vec;
use core::fmt;

/// H4 / USB HCI packet indicator: Command.
pub const H4_CMD: u8 = 0x01;
/// H4 / USB HCI packet indicator: ACL Data.
pub const H4_ACL: u8 = 0x02;
/// H4 / USB HCI packet indicator: Synchronous (SCO) Data.
pub const H4_SCO: u8 = 0x03;
/// H4 / USB HCI packet indicator: Event.
pub const H4_EVT: u8 = 0x04;

// ---- HCI Command Opcodes (`(OGF << 10) | OCF`) ----
/// `HCI_Inquiry` (`OGF 0x01, OCF 0x0001`).
pub const OP_INQUIRY: u16 = 0x0401;
/// `HCI_Inquiry_Cancel` (`OGF 0x01, OCF 0x0002`).
pub const OP_INQUIRY_CANCEL: u16 = 0x0402;
/// `HCI_Create_Connection` (`OGF 0x01, OCF 0x0005`).
pub const OP_CREATE_CONN: u16 = 0x0405;
/// `HCI_Disconnect` (`OGF 0x01, OCF 0x0006`).
pub const OP_DISCONNECT: u16 = 0x0406;
/// `HCI_Accept_Connection_Request` (`OGF 0x01, OCF 0x0009`).
pub const OP_ACCEPT_CONN_REQ: u16 = 0x0409;
/// `HCI_Link_Key_Request_Reply` (`OGF 0x01, OCF 0x000B`).
pub const OP_LINK_KEY_REPLY: u16 = 0x040B;
/// `HCI_Link_Key_Request_Negative_Reply` (`OGF 0x01, OCF 0x000C`).
pub const OP_LINK_KEY_NEG_REPLY: u16 = 0x040C;
/// `HCI_PIN_Code_Request_Reply` (`OGF 0x01, OCF 0x000D`).
pub const OP_PIN_CODE_REPLY: u16 = 0x040D;
/// `HCI_Authentication_Requested` (`OGF 0x01, OCF 0x0011`).
pub const OP_AUTH_REQUESTED: u16 = 0x0411;
/// `HCI_Set_Connection_Encryption` (`OGF 0x01, OCF 0x0013`).
pub const OP_SET_CONN_ENCRYPTION: u16 = 0x0413;
/// `HCI_Remote_Name_Request` (`OGF 0x01, OCF 0x0019`).
pub const OP_REMOTE_NAME_REQ: u16 = 0x0419;
/// `HCI_IO_Capability_Request_Reply` (`OGF 0x01, OCF 0x002B`).
pub const OP_IO_CAP_REPLY: u16 = 0x042B;
/// `HCI_User_Confirmation_Request_Reply` (`OGF 0x01, OCF 0x002C`).
pub const OP_USER_CONFIRM_REPLY: u16 = 0x042C;

/// `HCI_Write_Link_Policy_Settings` (`OGF 0x02, OCF 0x000D`).
pub const OP_WRITE_LINK_POLICY: u16 = 0x080D;
/// `HCI_Write_Default_Link_Policy_Settings` (`OGF 0x02, OCF 0x000F`).
pub const OP_WRITE_DEF_LINK_POLICY: u16 = 0x080F;

/// `HCI_Set_Event_Mask` (`OGF 0x03, OCF 0x0001`).
pub const OP_SET_EVENT_MASK: u16 = 0x0C01;
/// `HCI_Reset` (`OGF 0x03, OCF 0x0003`).
pub const OP_RESET: u16 = 0x0C03;
/// `HCI_Write_Local_Name` (`OGF 0x03, OCF 0x0013`).
pub const OP_WRITE_LOCAL_NAME: u16 = 0x0C13;
/// `HCI_Write_Page_Timeout` (`OGF 0x03, OCF 0x0018`).
pub const OP_WRITE_PAGE_TIMEOUT: u16 = 0x0C18;
/// `HCI_Write_Scan_Enable` (`OGF 0x03, OCF 0x001A`).
pub const OP_WRITE_SCAN_ENABLE: u16 = 0x0C1A;
/// `HCI_Write_Class_Of_Device` (`OGF 0x03, OCF 0x0024`).
pub const OP_WRITE_CLASS_OF_DEV: u16 = 0x0C24;
/// `HCI_Write_Inquiry_Mode` (`OGF 0x03, OCF 0x0045`).
pub const OP_WRITE_INQUIRY_MODE: u16 = 0x0C45;
/// `HCI_Write_Simple_Pairing_Mode` (`OGF 0x03, OCF 0x0056`).
pub const OP_WRITE_SIMPLE_PAIRING_MODE: u16 = 0x0C56;

/// `HCI_Read_Local_Version_Information` (`OGF 0x04, OCF 0x0001`).
pub const OP_READ_LOCAL_VERSION: u16 = 0x1001;
/// `HCI_Read_Buffer_Size` (`OGF 0x04, OCF 0x0005`).
pub const OP_READ_BUFFER_SIZE: u16 = 0x1005;
/// `HCI_Read_BD_ADDR` (`OGF 0x04, OCF 0x0009`).
pub const OP_READ_BD_ADDR: u16 = 0x1009;

// ---- HCI Event Codes ----
/// Inquiry Complete (`0x01`).
pub const EVT_INQUIRY_COMPLETE: u8 = 0x01;
/// Inquiry Result (`0x02`).
pub const EVT_INQUIRY_RESULT: u8 = 0x02;
/// Connection Complete (`0x03`).
pub const EVT_CONN_COMPLETE: u8 = 0x03;
/// Connection Request (`0x04`).
pub const EVT_CONN_REQUEST: u8 = 0x04;
/// Disconnection Complete (`0x05`).
pub const EVT_DISCONN_COMPLETE: u8 = 0x05;
/// Authentication Complete (`0x06`).
pub const EVT_AUTH_COMPLETE: u8 = 0x06;
/// Remote Name Request Complete (`0x07`).
pub const EVT_REMOTE_NAME_COMPLETE: u8 = 0x07;
/// Encryption Change (`0x08`).
pub const EVT_ENCRYPTION_CHANGE: u8 = 0x08;
/// Command Complete (`0x0E`).
pub const EVT_CMD_COMPLETE: u8 = 0x0E;
/// Command Status (`0x0F`).
pub const EVT_CMD_STATUS: u8 = 0x0F;
/// Number Of Completed Packets (`0x13`).
pub const EVT_NUM_COMPLETED_PKTS: u8 = 0x13;
/// PIN Code Request (`0x16`).
pub const EVT_PIN_CODE_REQ: u8 = 0x16;
/// Link Key Request (`0x17`).
pub const EVT_LINK_KEY_REQ: u8 = 0x17;
/// Link Key Notification (`0x18`).
pub const EVT_LINK_KEY_NOTIFY: u8 = 0x18;
/// Inquiry Result with RSSI (`0x22`).
pub const EVT_INQUIRY_RESULT_RSSI: u8 = 0x22;
/// Extended Inquiry Result (`0x2F`).
pub const EVT_EXTENDED_INQUIRY_RESULT: u8 = 0x2F;
/// IO Capability Request (`0x31`).
pub const EVT_IO_CAP_REQ: u8 = 0x31;
/// IO Capability Response (`0x32`).
pub const EVT_IO_CAP_RSP: u8 = 0x32;
/// User Confirmation Request (`0x33`).
pub const EVT_USER_CONFIRM_REQ: u8 = 0x33;
/// Simple Pairing Complete (`0x36`).
pub const EVT_SIMPLE_PAIRING_COMPLETE: u8 = 0x36;

/// ACL Packet Boundary flag: First non-automatically-flushable packet (Host -> Controller).
pub const ACL_PB_FIRST_NON_FLUSH: u8 = 0x00;
/// ACL Packet Boundary flag: Continuing fragment.
pub const ACL_PB_CONTINUING: u8 = 0x01;
/// ACL Packet Boundary flag: First automatically flushable packet (Host <-> Controller).
pub const ACL_PB_FIRST_AUTO_FLUSH: u8 = 0x02;

/// Class of Device value advertising a Desktop/Laptop Audio/Capturing Source (`0x2C010C`).
pub const LOCAL_COD_COMPUTER_AUDIO_SOURCE: [u8; 3] = [0x0C, 0x01, 0x2C];

/// 48-bit Bluetooth Device Address stored in wire little-endian byte order (`[0]` = LSB,
/// `[5]` = OUI MSB), formatted in standard big-endian colon notation `AA:BB:CC:DD:EE:FF`.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    /// All-zero unspecified address.
    pub const ZERO: Self = Self([0; 6]);

    /// Construct from big-endian display order `[b0, b1, b2, b3, b4, b5]` (`b0:b1:b2:b3:b4:b5`).
    pub const fn from_be_bytes(be: [u8; 6]) -> Self {
        Self([be[5], be[4], be[3], be[2], be[1], be[0]])
    }

    /// Return bytes in big-endian display order (`AA:BB:CC:DD:EE:FF`).
    pub const fn to_be_bytes(self) -> [u8; 6] {
        [
            self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0],
        ]
    }

    /// True if all 6 octets are zero.
    pub const fn is_zero(self) -> bool {
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
    }

    /// Parse `AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF`.
    pub fn parse_str(text: &str) -> Option<Self> {
        let trimmed = text.trim();
        let sep = if trimmed.contains('-') { '-' } else { ':' };
        let mut be = [0u8; 6];
        let mut idx = 0usize;
        for part in trimmed.split(sep) {
            if idx >= 6 || part.len() != 2 {
                return None;
            }
            be[idx] = u8::from_str_radix(part, 16).ok()?;
            idx += 1;
        }
        if idx != 6 {
            return None;
        }
        Some(Self::from_be_bytes(be))
    }

    /// Format into an 17-byte ASCII buffer `AA:BB:CC:DD:EE:FF`.
    pub fn format_ascii(self, out: &mut [u8; 17]) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let be = self.to_be_bytes();
        for (i, &b) in be.iter().enumerate() {
            out[i * 3] = HEX[usize::from(b >> 4)];
            out[i * 3 + 1] = HEX[usize::from(b & 0x0F)];
            if i < 5 {
                out[i * 3 + 2] = b':';
            }
        }
    }
}

impl fmt::Debug for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let be = self.to_be_bytes();
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            be[0], be[1], be[2], be[3], be[4], be[5]
        )
    }
}

/// 24-bit Bluetooth Class of Device (`CoD`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClassOfDevice(pub [u8; 3]);

impl ClassOfDevice {
    /// Raw 24-bit value.
    pub const fn raw_u24(self) -> u32 {
        (self.0[0] as u32) | ((self.0[1] as u32) << 8) | ((self.0[2] as u32) << 16)
    }

    /// Major device class (`bits [12:8]`). `0x04` = Audio/Video.
    pub const fn major_device_class(self) -> u8 {
        self.0[1] & 0x1F
    }

    /// True if Major Service Rendering/Audio bits or Audio/Video Major Device (`0x04`) are set.
    pub const fn is_audio_sink_candidate(self) -> bool {
        let service_audio = (self.0[2] & 0x24) != 0; // Audio (bit 21) or Rendering (bit 18)
        let major_av = self.major_device_class() == 0x04;
        service_audio || major_av
    }

    /// Human-readable device category label.
    pub const fn role_label(self) -> &'static str {
        match self.major_device_class() {
            0x01 => "computer",
            0x02 => "phone",
            0x04 => {
                let minor = (self.0[0] >> 2) & 0x3F;
                match minor {
                    1 => "headset",
                    2 => "handsfree",
                    5 => "loudspeaker",
                    6 => "headphones",
                    7 => "portable-audio",
                    10 => "hifi-audio",
                    _ => "audio-video",
                }
            }
            0x05 => "peripheral",
            _ if self.is_audio_sink_candidate() => "audio-device",
            _ => "bt-device",
        }
    }
}

/// 128-bit Bluetooth Classic Link Key persisted after SSP / PIN pairing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkKey {
    /// Raw 16-byte link key.
    pub bytes: [u8; 16],
    /// Key type reported by `Link_Key_Notification` (`0x04` = Unauthenticated P-192,
    /// `0x05` = Authenticated P-192, `0x07` = Unauthenticated P-256, etc.).
    pub key_type: u8,
}

/// Encode an HCI command packet (without the H4 `0x01` byte — matching USB EP0 Control class
/// payload format `[opcode_lo, opcode_hi, param_len, params...]`).
pub fn encode_cmd(opcode: u16, params: &[u8], out: &mut [u8]) -> Option<usize> {
    if params.len() > 255 || out.len() < 3 + params.len() {
        return None;
    }
    let op = opcode.to_le_bytes();
    out[0] = op[0];
    out[1] = op[1];
    out[2] = params.len() as u8;
    out[3..3 + params.len()].copy_from_slice(params);
    Some(3 + params.len())
}

/// Build `HCI_Reset (0x0C03)`.
pub fn cmd_reset(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_RESET, &[], out)
}

/// Build `HCI_Read_Local_Version_Information (0x1001)`.
pub fn cmd_read_local_version(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_READ_LOCAL_VERSION, &[], out)
}

/// Build `HCI_Read_BD_ADDR (0x1009)`.
pub fn cmd_read_bd_addr(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_READ_BD_ADDR, &[], out)
}

/// Build `HCI_Read_Buffer_Size (0x1005)`.
pub fn cmd_read_buffer_size(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_READ_BUFFER_SIZE, &[], out)
}

/// Build `HCI_Set_Event_Mask (0x0C01)` enabling Extended Inquiry & Simple Pairing events.
pub fn cmd_set_event_mask_ssp(out: &mut [u8]) -> Option<usize> {
    // Enable standard events + Extended Inquiry Result (bit 46) + SSP events (bits 48..55)
    let mask: u64 = 0x3FFF_FFFF_FFFF_FFFF;
    encode_cmd(OP_SET_EVENT_MASK, &mask.to_le_bytes(), out)
}

/// Build `HCI_Write_Simple_Pairing_Mode (0x0C56)`.
pub fn cmd_write_simple_pairing_mode(enable: bool, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_SIMPLE_PAIRING_MODE, &[u8::from(enable)], out)
}

/// Build `HCI_Write_Inquiry_Mode (0x0C45)` (`mode = 2` -> Extended Inquiry Result with RSSI+EIR).
pub fn cmd_write_inquiry_mode(mode: u8, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_INQUIRY_MODE, &[mode], out)
}

/// Build `HCI_Write_Class_Of_Device (0x0C24)`.
pub fn cmd_write_class_of_device(cod: [u8; 3], out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_CLASS_OF_DEV, &cod, out)
}

/// Build `HCI_Write_Scan_Enable (0x0C1A)` (`0x00` none, `0x01` inquiry, `0x02` page, `0x03` both).
pub fn cmd_write_scan_enable(mode: u8, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_SCAN_ENABLE, &[mode], out)
}

/// Build `HCI_Write_Page_Timeout (0x0C18)` in `0.625 ms` baseband slots (`0x2000` = ~5.12 s).
pub fn cmd_write_page_timeout(slots: u16, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_PAGE_TIMEOUT, &slots.to_le_bytes(), out)
}

/// Build `HCI_Write_Default_Link_Policy_Settings (0x080F)` (`0x0005` = Role Switch | Sniff).
pub fn cmd_write_default_link_policy(policy: u16, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_WRITE_DEF_LINK_POLICY, &policy.to_le_bytes(), out)
}

/// Build `HCI_Write_Local_Name (0x0C13)` (248-byte NUL-padded UTF-8 payload).
pub fn cmd_write_local_name(name: &str, out: &mut [u8]) -> Option<usize> {
    let mut name_buf = [0u8; 248];
    let take = name.len().min(247);
    name_buf[..take].copy_from_slice(&name.as_bytes()[..take]);
    encode_cmd(OP_WRITE_LOCAL_NAME, &name_buf, out)
}

/// Build `HCI_Inquiry (0x0401)` using GIAC (`0x9E8B33`), duration in `1.28 s` units (`1..=48`).
pub fn cmd_inquiry_giac(duration_units: u8, max_responses: u8, out: &mut [u8]) -> Option<usize> {
    let params = [0x33, 0x8B, 0x9E, duration_units.clamp(1, 30), max_responses];
    encode_cmd(OP_INQUIRY, &params, out)
}

/// Build `HCI_Inquiry_Cancel (0x0402)`.
pub fn cmd_inquiry_cancel(out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_INQUIRY_CANCEL, &[], out)
}

/// Build `HCI_Remote_Name_Request (0x0419)`.
pub fn cmd_remote_name_request(
    addr: BdAddr,
    page_scan_rep_mode: u8,
    clock_offset: u16,
    out: &mut [u8],
) -> Option<usize> {
    let mut params = [0u8; 10];
    params[0..6].copy_from_slice(&addr.0);
    params[6] = page_scan_rep_mode;
    params[7] = 0;
    params[8..10].copy_from_slice(&clock_offset.to_le_bytes());
    encode_cmd(OP_REMOTE_NAME_REQ, &params, out)
}

/// Build `HCI_Create_Connection (0x0405)` with multi-slot ACL packet types (`DM1/DH1/DM3/DH3/DM5/DH5`).
pub fn cmd_create_connection(
    addr: BdAddr,
    page_scan_rep_mode: u8,
    clock_offset: u16,
    allow_role_switch: bool,
    out: &mut [u8],
) -> Option<usize> {
    let mut params = [0u8; 13];
    params[0..6].copy_from_slice(&addr.0);
    // Packet_Type = 0xCC18 (DM1 | DH1 | DM3 | DH3 | DM5 | DH5 + EDR 2-DH3/3-DH5 enabled)
    params[6..8].copy_from_slice(&0xCC18u16.to_le_bytes());
    params[8] = page_scan_rep_mode;
    params[9] = 0;
    params[10..12].copy_from_slice(&clock_offset.to_le_bytes());
    params[12] = u8::from(allow_role_switch);
    encode_cmd(OP_CREATE_CONN, &params, out)
}

/// Build `HCI_Accept_Connection_Request (0x0409)` (`role = 0x00` become central, `0x01` peripheral).
pub fn cmd_accept_connection(addr: BdAddr, role: u8, out: &mut [u8]) -> Option<usize> {
    let mut params = [0u8; 7];
    params[0..6].copy_from_slice(&addr.0);
    params[6] = role;
    encode_cmd(OP_ACCEPT_CONN_REQ, &params, out)
}

/// Build `HCI_Disconnect (0x0406)` (`reason = 0x13` Remote User Terminated Connection).
pub fn cmd_disconnect(conn_handle: u16, reason: u8, out: &mut [u8]) -> Option<usize> {
    let h = conn_handle.to_le_bytes();
    encode_cmd(OP_DISCONNECT, &[h[0], h[1], reason], out)
}

/// Build `HCI_Authentication_Requested (0x0411)`.
pub fn cmd_authentication_requested(conn_handle: u16, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_AUTH_REQUESTED, &conn_handle.to_le_bytes(), out)
}

/// Build `HCI_Set_Connection_Encryption (0x0413)`.
pub fn cmd_set_encryption(conn_handle: u16, enable: bool, out: &mut [u8]) -> Option<usize> {
    let h = conn_handle.to_le_bytes();
    encode_cmd(OP_SET_CONN_ENCRYPTION, &[h[0], h[1], u8::from(enable)], out)
}

/// Build `HCI_Link_Key_Request_Reply (0x040B)`.
pub fn cmd_link_key_reply(addr: BdAddr, key: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let mut params = [0u8; 22];
    params[0..6].copy_from_slice(&addr.0);
    params[6..22].copy_from_slice(key);
    encode_cmd(OP_LINK_KEY_REPLY, &params, out)
}

/// Build `HCI_Link_Key_Request_Negative_Reply (0x040C)` (triggers fresh SSP pairing).
pub fn cmd_link_key_neg_reply(addr: BdAddr, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_LINK_KEY_NEG_REPLY, &addr.0, out)
}

/// Build `HCI_PIN_Code_Request_Reply (0x040D)` (legacy `"0000"` fallback for older headsets).
pub fn cmd_pin_code_reply(addr: BdAddr, pin: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = pin.len().min(16);
    let mut params = [0u8; 23];
    params[0..6].copy_from_slice(&addr.0);
    params[6] = len as u8;
    params[7..7 + len].copy_from_slice(&pin[..len]);
    encode_cmd(OP_PIN_CODE_REPLY, &params, out)
}

/// Build `HCI_IO_Capability_Request_Reply (0x042B)` (`NoInputNoOutput = 0x03`, dedicated/general
/// bonding with MITM disabled so wireless headphones complete Just-Works SSP seamlessly).
pub fn cmd_io_capability_reply_just_works(addr: BdAddr, out: &mut [u8]) -> Option<usize> {
    let mut params = [0u8; 9];
    params[0..6].copy_from_slice(&addr.0);
    params[6] = 0x03; // NoInputNoOutput
    params[7] = 0x00; // OOB auth data not present
    params[8] = 0x02; // Authentication_Requirements = Dedicated/General Bonding, MITM not required
    encode_cmd(OP_IO_CAP_REPLY, &params, out)
}

/// Build `HCI_User_Confirmation_Request_Reply (0x042C)` for SSP Just-Works confirmation.
pub fn cmd_user_confirmation_reply(addr: BdAddr, out: &mut [u8]) -> Option<usize> {
    encode_cmd(OP_USER_CONFIRM_REPLY, &addr.0, out)
}

/// Discovered device entry extracted from Inquiry / RSSI / Extended Inquiry Result (`EIR`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPeer {
    /// Device MAC address.
    pub addr: BdAddr,
    /// Page scan repetition mode (`R0`..`R2`).
    pub page_scan_rep_mode: u8,
    /// Class of Device.
    pub cod: ClassOfDevice,
    /// Clock offset hint for faster `Create_Connection`.
    pub clock_offset: u16,
    /// Measured RSSI in dBm (`0` if unreported).
    pub rssi_dbm: i8,
    /// Sanitized UTF-8/ASCII local name from EIR or Remote Name Request (up to 64 bytes).
    pub name: [u8; 64],
    /// Valid byte length in [`Self::name`].
    pub name_len: u8,
    /// True if EIR advertised `AudioSink` (`0x110B`) or `AdvancedAudioDistribution` (`0x110D`).
    pub advertises_a2dp_sink: bool,
}

impl DiscoveredPeer {
    /// Borrow the peer's decoded UTF-8/ASCII name.
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len)]).unwrap_or("")
    }
}

/// Parse an Extended Inquiry Response (`EIR`, up to 240 bytes) for local name and A2DP UUID16s.
pub fn parse_eir_data(eir: &[u8], out_name: &mut [u8; 64]) -> (u8, bool) {
    let mut pos = 0usize;
    let mut name_len = 0u8;
    let mut has_a2dp_sink = false;
    while pos < eir.len() {
        let field_len = usize::from(eir[pos]);
        if field_len == 0 || pos + 1 + field_len > eir.len() {
            break;
        }
        let ad_type = eir[pos + 1];
        let payload = &eir[pos + 2..pos + 1 + field_len];
        match ad_type {
            // Shortened (0x08) or Complete (0x09) Local Name
            0x08 | 0x09 => {
                if ad_type == 0x09 || name_len == 0 {
                    name_len = sanitize_bt_name(payload, out_name);
                }
            }
            // Incomplete (0x02) or Complete (0x03) list of 16-bit Service Class UUIDs
            0x02 | 0x03 => {
                let mut u_off = 0usize;
                while u_off + 2 <= payload.len() {
                    let uuid16 = u16::from_le_bytes([payload[u_off], payload[u_off + 1]]);
                    if uuid16 == 0x110B || uuid16 == 0x110D || uuid16 == 0x111E {
                        has_a2dp_sink = true;
                    }
                    u_off += 2;
                }
            }
            _ => {}
        }
        pos += 1 + field_len;
    }
    (name_len, has_a2dp_sink)
}

/// Copy printable UTF-8/ASCII characters into a 64-byte name buffer, stopping at NUL.
pub fn sanitize_bt_name(raw: &[u8], out: &mut [u8; 64]) -> u8 {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let slice = &raw[..end];
    let mut w = 0usize;
    for &b in slice {
        if w >= out.len() {
            break;
        }
        if (0x20..=0x7E).contains(&b) {
            out[w] = b;
            w += 1;
        }
    }
    w as u8
}

/// Parsed Local Version Information returned by `OP_READ_LOCAL_VERSION`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalVersionInfo {
    /// HCI version code (`0x06` = 4.0, `0x08` = 4.2, `0x09` = 5.0, `0x0B` = 5.2).
    pub hci_ver: u8,
    /// Controller HCI revision (`0x000C` on `RTL8821CE`).
    pub hci_rev: u16,
    /// LMP version code.
    pub lmp_ver: u8,
    /// Manufacturer ID (`0x005D` = Realtek Semiconductor).
    pub manufacturer: u16,
    /// LMP subversion (`0x8821` on unpatched `RTL8821CE`, fw version after patch).
    pub lmp_subver: u16,
}

/// Parsed HCI Event high-level representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedHciEvent<'a> {
    /// `Command_Complete` (`0x0E`).
    CommandComplete {
        /// Number of command packets the host may send.
        num_hci_cmd_pkts: u8,
        /// Completed opcode.
        opcode: u16,
        /// Status (`0x00` = Success).
        status: u8,
        /// Remaining return parameters after status.
        return_params: &'a [u8],
    },
    /// `Command_Status` (`0x0F`).
    CommandStatus {
        /// Status (`0x00` = Pending/OK).
        status: u8,
        /// Number of command packets the host may send.
        num_hci_cmd_pkts: u8,
        /// Opcode.
        opcode: u16,
    },
    /// `Inquiry_Complete` (`0x01`).
    InquiryComplete {
        /// Status (`0x00` = Success).
        status: u8,
    },
    /// Discovered peer from `0x02`, `0x22`, or `0x2F` (`EIR`).
    PeerDiscovered(DiscoveredPeer),
    /// `Remote_Name_Request_Complete` (`0x07`).
    RemoteNameComplete {
        /// Status.
        status: u8,
        /// Peer address.
        addr: BdAddr,
        /// Sanitized name.
        name: [u8; 64],
        /// Name length.
        name_len: u8,
    },
    /// `Connection_Request` (`0x04`).
    ConnectionRequest {
        /// Peer address.
        addr: BdAddr,
        /// Class of Device.
        cod: ClassOfDevice,
        /// Link type (`0x01` = ACL, `0x00` = SCO, `0x02` = eSCO).
        link_type: u8,
    },
    /// `Connection_Complete` (`0x03`).
    ConnectionComplete {
        /// Status (`0x00` = Connected).
        status: u8,
        /// Assigned 12-bit `Connection_Handle`.
        conn_handle: u16,
        /// Peer address.
        addr: BdAddr,
        /// Link type (`0x01` = ACL).
        link_type: u8,
        /// Encryption enabled flag.
        encryption_enabled: u8,
    },
    /// `Disconnection_Complete` (`0x05`).
    DisconnectionComplete {
        /// Status.
        status: u8,
        /// Disconnected `Connection_Handle`.
        conn_handle: u16,
        /// Reason code.
        reason: u8,
    },
    /// `Authentication_Complete` (`0x06`).
    AuthenticationComplete {
        /// Status (`0x00` = Authenticated).
        status: u8,
        /// `Connection_Handle`.
        conn_handle: u16,
    },
    /// `Encryption_Change` (`0x08`).
    EncryptionChange {
        /// Status.
        status: u8,
        /// `Connection_Handle`.
        conn_handle: u16,
        /// Encryption enable (`0x01` = Link-level encryption ON).
        encryption_enabled: u8,
    },
    /// `Number_Of_Completed_Packets` (`0x13`) — returns `(conn_handle, completed_count)` pairs.
    NumberOfCompletedPackets(&'a [u8]),
    /// `Link_Key_Request` (`0x17`).
    LinkKeyRequest {
        /// Peer address.
        addr: BdAddr,
    },
    /// `Link_Key_Notification` (`0x18`) — newly generated pairing key to persist!
    LinkKeyNotification {
        /// Peer address.
        addr: BdAddr,
        /// Newly derived 128-bit link key + key type.
        key: LinkKey,
    },
    /// `PIN_Code_Request` (`0x16`).
    PinCodeRequest {
        /// Peer address.
        addr: BdAddr,
    },
    /// `IO_Capability_Request` (`0x31`).
    IoCapabilityRequest {
        /// Peer address.
        addr: BdAddr,
    },
    /// `User_Confirmation_Request` (`0x33`).
    UserConfirmationRequest {
        /// Peer address.
        addr: BdAddr,
        /// 6-digit passkey value (`0..=999999`).
        numeric_value: u32,
    },
    /// `Simple_Pairing_Complete` (`0x36`).
    SimplePairingComplete {
        /// Status (`0x00` = Paired).
        status: u8,
        /// Peer address.
        addr: BdAddr,
    },
    /// Unhandled or vendor event.
    Other {
        /// Raw event code.
        event_code: u8,
        /// Event payload.
        params: &'a [u8],
    },
}

/// Decode a raw HCI event packet (`[event_code, param_len, params...]`, without H4 `0x04`).
pub fn decode_event(pkt: &[u8]) -> Option<DecodedHciEvent<'_>> {
    if pkt.len() < 2 {
        return None;
    }
    let code = pkt[0];
    let plen = usize::from(pkt[1]);
    if pkt.len() < 2 + plen {
        return None;
    }
    let p = &pkt[2..2 + plen];
    match code {
        EVT_CMD_COMPLETE if p.len() >= 3 => {
            let num_hci_cmd_pkts = p[0];
            let opcode = u16::from_le_bytes([p[1], p[2]]);
            let (status, return_params) = if p.len() >= 4 {
                (p[3], &p[4..])
            } else {
                (0, &[][..])
            };
            Some(DecodedHciEvent::CommandComplete {
                num_hci_cmd_pkts,
                opcode,
                status,
                return_params,
            })
        }
        EVT_CMD_STATUS if p.len() >= 4 => Some(DecodedHciEvent::CommandStatus {
            status: p[0],
            num_hci_cmd_pkts: p[1],
            opcode: u16::from_le_bytes([p[2], p[3]]),
        }),
        EVT_INQUIRY_COMPLETE if !p.is_empty() => {
            Some(DecodedHciEvent::InquiryComplete { status: p[0] })
        }
        EVT_INQUIRY_RESULT if p.len() >= 1 + 14 && p[0] >= 1 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[1..7]);
            let psrm = p[7];
            let cod = ClassOfDevice([p[10], p[11], p[12]]);
            let clk = u16::from_le_bytes([p[13], p[14]]);
            Some(DecodedHciEvent::PeerDiscovered(DiscoveredPeer {
                addr: BdAddr(addr),
                page_scan_rep_mode: psrm,
                cod,
                clock_offset: clk,
                rssi_dbm: 0,
                name: [0; 64],
                name_len: 0,
                advertises_a2dp_sink: cod.is_audio_sink_candidate(),
            }))
        }
        EVT_INQUIRY_RESULT_RSSI if p.len() >= 1 + 14 && p[0] >= 1 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[1..7]);
            let psrm = p[7];
            let cod = ClassOfDevice([p[9], p[10], p[11]]);
            let clk = u16::from_le_bytes([p[12], p[13]]);
            let rssi = p[14] as i8;
            Some(DecodedHciEvent::PeerDiscovered(DiscoveredPeer {
                addr: BdAddr(addr),
                page_scan_rep_mode: psrm,
                cod,
                clock_offset: clk,
                rssi_dbm: rssi,
                name: [0; 64],
                name_len: 0,
                advertises_a2dp_sink: cod.is_audio_sink_candidate(),
            }))
        }
        EVT_EXTENDED_INQUIRY_RESULT if p.len() >= 15 && p[0] >= 1 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[1..7]);
            let psrm = p[7];
            let cod = ClassOfDevice([p[9], p[10], p[11]]);
            let clk = u16::from_le_bytes([p[12], p[13]]);
            let rssi = p[14] as i8;
            let mut name = [0u8; 64];
            let (name_len, eir_a2dp) = parse_eir_data(&p[15..], &mut name);
            Some(DecodedHciEvent::PeerDiscovered(DiscoveredPeer {
                addr: BdAddr(addr),
                page_scan_rep_mode: psrm,
                cod,
                clock_offset: clk,
                rssi_dbm: rssi,
                name,
                name_len,
                advertises_a2dp_sink: eir_a2dp || cod.is_audio_sink_candidate(),
            }))
        }
        EVT_REMOTE_NAME_COMPLETE if p.len() >= 7 => {
            let status = p[0];
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[1..7]);
            let mut name = [0u8; 64];
            let name_len = sanitize_bt_name(&p[7..], &mut name);
            Some(DecodedHciEvent::RemoteNameComplete {
                status,
                addr: BdAddr(addr),
                name,
                name_len,
            })
        }
        EVT_CONN_REQUEST if p.len() >= 10 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            let cod = ClassOfDevice([p[6], p[7], p[8]]);
            Some(DecodedHciEvent::ConnectionRequest {
                addr: BdAddr(addr),
                cod,
                link_type: p[9],
            })
        }
        EVT_CONN_COMPLETE if p.len() >= 11 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[3..9]);
            Some(DecodedHciEvent::ConnectionComplete {
                status: p[0],
                conn_handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
                addr: BdAddr(addr),
                link_type: p[9],
                encryption_enabled: p[10],
            })
        }
        EVT_DISCONN_COMPLETE if p.len() >= 4 => Some(DecodedHciEvent::DisconnectionComplete {
            status: p[0],
            conn_handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            reason: p[3],
        }),
        EVT_AUTH_COMPLETE if p.len() >= 3 => Some(DecodedHciEvent::AuthenticationComplete {
            status: p[0],
            conn_handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
        }),
        EVT_ENCRYPTION_CHANGE if p.len() >= 4 => Some(DecodedHciEvent::EncryptionChange {
            status: p[0],
            conn_handle: u16::from_le_bytes([p[1], p[2]]) & 0x0FFF,
            encryption_enabled: p[3],
        }),
        EVT_NUM_COMPLETED_PKTS if !p.is_empty() => {
            Some(DecodedHciEvent::NumberOfCompletedPackets(p))
        }
        EVT_LINK_KEY_REQ if p.len() >= 6 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            Some(DecodedHciEvent::LinkKeyRequest { addr: BdAddr(addr) })
        }
        EVT_LINK_KEY_NOTIFY if p.len() >= 23 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            let mut key_bytes = [0u8; 16];
            key_bytes.copy_from_slice(&p[6..22]);
            Some(DecodedHciEvent::LinkKeyNotification {
                addr: BdAddr(addr),
                key: LinkKey {
                    bytes: key_bytes,
                    key_type: p[22],
                },
            })
        }
        EVT_PIN_CODE_REQ if p.len() >= 6 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            Some(DecodedHciEvent::PinCodeRequest { addr: BdAddr(addr) })
        }
        EVT_IO_CAP_REQ if p.len() >= 6 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            Some(DecodedHciEvent::IoCapabilityRequest { addr: BdAddr(addr) })
        }
        EVT_USER_CONFIRM_REQ if p.len() >= 10 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[0..6]);
            let numeric_value = u32::from_le_bytes([p[6], p[7], p[8], p[9]]);
            Some(DecodedHciEvent::UserConfirmationRequest {
                addr: BdAddr(addr),
                numeric_value,
            })
        }
        EVT_SIMPLE_PAIRING_COMPLETE if p.len() >= 7 => {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&p[1..7]);
            Some(DecodedHciEvent::SimplePairingComplete {
                status: p[0],
                addr: BdAddr(addr),
            })
        }
        _ => Some(DecodedHciEvent::Other {
            event_code: code,
            params: p,
        }),
    }
}

/// Decode return parameters of `OP_READ_LOCAL_VERSION`.
pub fn parse_local_version_return(return_params: &[u8]) -> Option<LocalVersionInfo> {
    if return_params.len() < 8 {
        return None;
    }
    Some(LocalVersionInfo {
        hci_ver: return_params[0],
        hci_rev: u16::from_le_bytes([return_params[1], return_params[2]]),
        lmp_ver: return_params[3],
        manufacturer: u16::from_le_bytes([return_params[4], return_params[5]]),
        lmp_subver: u16::from_le_bytes([return_params[6], return_params[7]]),
    })
}

/// Decode return parameters of `OP_READ_BUFFER_SIZE`: `(acl_mtu, total_acl_pkts)`.
pub fn parse_buffer_size_return(return_params: &[u8]) -> Option<(u16, u16)> {
    if return_params.len() < 7 {
        return None;
    }
    let acl_mtu = u16::from_le_bytes([return_params[0], return_params[1]]);
    let total_acl = u16::from_le_bytes([return_params[3], return_params[4]]);
    Some((acl_mtu, total_acl))
}

/// Controller ACL buffer flow-control tracker (`HCI_Read_Buffer_Size` + `0x13` completions).
#[derive(Clone, Copy, Debug)]
pub struct AclCreditTracker {
    /// Max ACL payload bytes per HCI fragment (`RTL8821CE` typically reports `1021` or `1024`).
    pub max_acl_len: u16,
    /// Total ACL buffers in the Bluetooth controller RAM (`RTL8821CE` typically `6`..`8`).
    pub total_credits: u16,
    /// Currently unacknowledged ACL fragments in flight in the controller.
    pub in_flight: u16,
}

impl Default for AclCreditTracker {
    fn default() -> Self {
        Self {
            max_acl_len: 1021,
            total_credits: 8,
            in_flight: 0,
        }
    }
}

impl AclCreditTracker {
    /// Configure from `HCI_Read_Buffer_Size` return values.
    pub fn configure(&mut self, acl_mtu: u16, total_pkts: u16) {
        if acl_mtu >= 27 {
            self.max_acl_len = acl_mtu;
        }
        if total_pkts >= 1 {
            self.total_credits = total_pkts;
        }
    }

    /// Available controller ACL packet slots right now.
    pub const fn available_credits(&self) -> u16 {
        self.total_credits.saturating_sub(self.in_flight)
    }

    /// Congestion ratio in percent (`0..=100`) used for Adaptive SBC Bitpool control.
    pub const fn congestion_percent(&self) -> u8 {
        if self.total_credits == 0 {
            return 100;
        }
        let pct = (self.in_flight as u32 * 100) / (self.total_credits as u32);
        if pct > 100 {
            100
        } else {
            pct as u8
        }
    }

    /// Consume `n` credits when queueing ACL fragments to USB Bulk OUT.
    pub fn take_credits(&mut self, n: u16) -> bool {
        if self.available_credits() < n {
            return false;
        }
        self.in_flight = self.in_flight.saturating_add(n);
        true
    }

    /// Reclaim credits from `EVT_NUM_COMPLETED_PKTS` (`0x13`) payload.
    pub fn on_completed_packets(&mut self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let handles = usize::from(payload[0]);
        for i in 0..handles {
            let off = 1 + i * 4;
            if off + 4 > payload.len() {
                break;
            }
            let completed = u16::from_le_bytes([payload[off + 2], payload[off + 3]]);
            self.in_flight = self.in_flight.saturating_sub(completed);
        }
    }

    /// Reset in-flight counter when a link disconnects or HCI resets.
    pub fn reset_in_flight(&mut self) {
        self.in_flight = 0;
    }
}

/// Segment an L2CAP frame (`[len_lo, len_hi, cid_lo, cid_hi, payload...]`) into HCI ACL packets
/// (`[handle_pb_lo, handle_pb_hi, acl_len_lo, acl_len_hi, chunk...]`) of at most `max_acl_len`.
pub fn segment_l2cap_to_acl(conn_handle: u16, l2cap_pdu: &[u8], max_acl_len: u16) -> Vec<Vec<u8>> {
    let chunk_cap = usize::from(max_acl_len.max(27));
    let mut out = Vec::new();
    if l2cap_pdu.is_empty() {
        return out;
    }
    let mut offset = 0usize;
    let mut first = true;
    while offset < l2cap_pdu.len() {
        let take = (l2cap_pdu.len() - offset).min(chunk_cap);
        let pb = if first {
            ACL_PB_FIRST_AUTO_FLUSH
        } else {
            ACL_PB_CONTINUING
        };
        first = false;
        let hdr_handle = (conn_handle & 0x0FFF) | (u16::from(pb) << 12);
        let mut pkt = Vec::with_capacity(4 + take);
        pkt.extend_from_slice(&hdr_handle.to_le_bytes());
        pkt.extend_from_slice(&(take as u16).to_le_bytes());
        pkt.extend_from_slice(&l2cap_pdu[offset..offset + take]);
        out.push(pkt);
        offset += take;
    }
    out
}

/// Per-connection reassembler turning incoming HCI ACL fragments into complete L2CAP PDUs.
#[derive(Clone, Debug, Default)]
pub struct AclReassembler {
    conn_handle: u16,
    expected_l2cap_total: usize,
    buf: Vec<u8>,
}

impl AclReassembler {
    /// Push a raw HCI ACL packet (`[handle_lo, handle_hi, len_lo, len_hi, data...]`).
    /// Yields `(conn_handle, cid, payload)` once a complete L2CAP PDU has arrived.
    pub fn push_acl(&mut self, acl_pkt: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
        if acl_pkt.len() < 4 {
            return None;
        }
        let raw_h = u16::from_le_bytes([acl_pkt[0], acl_pkt[1]]);
        let handle = raw_h & 0x0FFF;
        let pb = ((raw_h >> 12) & 0x03) as u8;
        let dlen = usize::from(u16::from_le_bytes([acl_pkt[2], acl_pkt[3]]));
        if acl_pkt.len() < 4 + dlen {
            return None;
        }
        let frag = &acl_pkt[4..4 + dlen];

        if pb == ACL_PB_FIRST_NON_FLUSH || pb == ACL_PB_FIRST_AUTO_FLUSH {
            self.buf.clear();
            self.conn_handle = handle;
            if frag.len() < 4 {
                self.expected_l2cap_total = 0;
                return None;
            }
            let l2_len = usize::from(u16::from_le_bytes([frag[0], frag[1]]));
            if l2_len > 16384 {
                self.expected_l2cap_total = 0;
                return None;
            }
            self.expected_l2cap_total = 4 + l2_len;
            self.buf.extend_from_slice(frag);
        } else if pb == ACL_PB_CONTINUING {
            if self.expected_l2cap_total == 0 || handle != self.conn_handle {
                return None;
            }
            let remain = self.expected_l2cap_total.saturating_sub(self.buf.len());
            let take = frag.len().min(remain);
            self.buf.extend_from_slice(&frag[..take]);
        } else {
            return None;
        }

        if self.expected_l2cap_total >= 4 && self.buf.len() >= self.expected_l2cap_total {
            let cid = u16::from_le_bytes([self.buf[2], self.buf[3]]);
            let payload = self.buf[4..self.expected_l2cap_total].to_vec();
            self.buf.clear();
            self.expected_l2cap_total = 0;
            return Some((handle, cid, payload));
        }
        None
    }
}
