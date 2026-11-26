//! USB 2.0 (`0x29`) & SuperSpeed USB 3.0 (`0x2A`) Hub class descriptors,
//! port feature selectors, status decoders, and xHCI Route String helpers.

use crate::ch9::{DESC_HUB, DESC_SS_HUB};
use huesos_abi::usb::UsbSpeedAbi;

/// Hub Port Feature: `PORT_RESET` (`4`).
pub const HUB_FEAT_PORT_RESET: u16 = 4;
/// Hub Port Feature: `PORT_POWER` (`8`, USB 2.0 / 3.0).
pub const HUB_FEAT_PORT_POWER: u16 = 8;
/// Hub Port Feature: `C_PORT_CONNECTION` (`16`).
pub const HUB_FEAT_C_PORT_CONNECTION: u16 = 16;
/// Hub Port Feature: `C_PORT_ENABLE` (`17`).
pub const HUB_FEAT_C_PORT_ENABLE: u16 = 17;
/// Hub Port Feature: `C_PORT_RESET` (`20`).
pub const HUB_FEAT_C_PORT_RESET: u16 = 20;
/// Hub Port Feature: `C_BH_PORT_RESET` (`29`, SuperSpeed warm reset change).
pub const HUB_FEAT_C_BH_PORT_RESET: u16 = 29;

/// Parsed USB 2.0 / 3.0 Hub Class Descriptor summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubDescriptor {
    /// True if parsed from a SuperSpeed Hub descriptor (`0x2A`).
    pub is_superspeed: bool,
    /// Number of downstream ports (`1..=15` supported by xHCI route nibble).
    pub num_ports: u8,
    /// Power-on to power-good settling interval in `2 ms` units (`bPwrOn2PwrGood`).
    pub power_good_2ms: u8,
}

impl HubDescriptor {
    /// Parse a USB 2.0 (`0x29`) or SuperSpeed (`0x2A`) Hub Descriptor.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 7 || bytes[0] < 7 {
            return None;
        }
        let is_ss = match bytes[1] {
            DESC_HUB => false,
            DESC_SS_HUB => true,
            _ => return None,
        };
        let ports = bytes[2];
        if ports == 0 || ports > 15 {
            return None;
        }
        Some(Self {
            is_superspeed: is_ss,
            num_ports: ports,
            power_good_2ms: bytes[5],
        })
    }
}

/// Decoded 4-byte `GET_PORT_STATUS` response from a USB 2.0 or 3.0 Hub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubPortStatus {
    /// Raw `wPortStatus` (`u16`).
    pub status: u16,
    /// Raw `wPortChange` (`u16`).
    pub change: u16,
    /// Device currently attached (`bit 0`).
    pub connected: bool,
    /// Port enabled (`bit 1`).
    pub enabled: bool,
    /// Port currently resetting (`bit 4`).
    pub resetting: bool,
    /// Downstream device speed.
    pub speed: UsbSpeedAbi,
}

impl HubPortStatus {
    /// Decode 4-byte `GET_PORT_STATUS` payload for a USB 2.0 or SuperSpeed Hub.
    pub const fn decode(raw: [u8; 4], hub_is_superspeed: bool) -> Self {
        let status = u16::from_le_bytes([raw[0], raw[1]]);
        let change = u16::from_le_bytes([raw[2], raw[3]]);
        let connected = (status & (1 << 0)) != 0;
        let enabled = (status & (1 << 1)) != 0;
        let resetting = (status & (1 << 4)) != 0;
        let speed = if !connected {
            UsbSpeedAbi::Unknown
        } else if hub_is_superspeed {
            UsbSpeedAbi::Super
        } else if (status & (1 << 9)) != 0 {
            UsbSpeedAbi::Low
        } else if (status & (1 << 10)) != 0 {
            UsbSpeedAbi::High
        } else {
            UsbSpeedAbi::Full
        };
        Self {
            status,
            change,
            connected,
            enabled,
            resetting,
            speed,
        }
    }
}

/// Append a 1-based downstream `hub_port` (`1..=15`) onto `parent_route` (`0` at root hub).
///
/// Per xHCI §8.9, up to 5 hub tiers fit into the 20-bit Route String (4 bits per tier).
pub const fn append_route_port(parent_route: u32, hub_port: u8) -> Option<u32> {
    if hub_port == 0 {
        return None;
    }
    let nibble = if hub_port > 15 { 15u32 } else { hub_port as u32 };
    let mut tier = 0u32;
    while tier < 5 {
        let shift = tier * 4;
        if ((parent_route >> shift) & 0xF) == 0 {
            return Some(parent_route | (nibble << shift));
        }
        tier += 1;
    }
    None
}
