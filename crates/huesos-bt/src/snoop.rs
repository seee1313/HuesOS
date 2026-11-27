//! Standard Wireshark-compatible `btsnoop` Version 1 (`Datalink = 1002 = H4`)
//! bounded ring-buffer packet capture backing `/net/btl/snoop`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::hci::{H4_ACL, H4_CMD, H4_EVT};

/// 16-byte `btsnoop` v1 file header (`"btsnoop\0"`, version `1`, datalink `1002` H4 UART).
pub const BTSNOOP_FILE_HEADER: [u8; 16] = [
    b'b', b't', b's', b'n', b'o', b'o', b'p', 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03,
    0xEA,
];

/// Epoch delta between `0000-01-01 00:00:00` (`btsnoop` base) and `2026-01-01 00:00:00` in us.
const BTSNOOP_BASE_EPOCH_US: u64 = 0x00E0_3AB4_4A67_6000 + (56 * 365 * 86_400 * 1_000_000);

/// Packet direction recorded in `btsnoop` flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnoopDir {
    /// Host -> Controller (`flags bit 0 = 0`).
    HostToController,
    /// Controller -> Host (`flags bit 0 = 1`).
    ControllerToHost,
}

/// Bounded ring-buffer of `btsnoop` records.
pub struct BtSnoopLog {
    records: VecDeque<Vec<u8>>,
    total_record_bytes: usize,
    max_record_bytes: usize,
    dropped_packets: u64,
}

impl Default for BtSnoopLog {
    fn default() -> Self {
        Self::new(64 * 1024)
    }
}

impl BtSnoopLog {
    /// Create a bounded `btsnoop` capture ring holding up to `max_record_bytes` of records.
    pub fn new(max_record_bytes: usize) -> Self {
        Self {
            records: VecDeque::new(),
            total_record_bytes: 0,
            max_record_bytes: max_record_bytes.max(4096),
            dropped_packets: 0,
        }
    }

    /// Number of captured packets currently retained in the ring.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if no packets have been captured yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of older records evicted due to ring capacity.
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets
    }

    /// Record one HCI Command, Event, or ACL packet (`payload` without H4 indicator byte).
    pub fn record(&mut self, h4_type: u8, dir: SnoopDir, monotonic_us: u64, payload: &[u8]) {
        // Truncate giant ACL payloads at 256 bytes in snoop to retain hundreds of signaling frames.
        let orig_len = (1 + payload.len()) as u32;
        let incl_data_len = payload.len().min(256);
        let incl_len = (1 + incl_data_len) as u32;

        let mut flags: u32 = match dir {
            SnoopDir::HostToController => 0,
            SnoopDir::ControllerToHost => 1,
        };
        if h4_type == H4_CMD || h4_type == H4_EVT {
            flags |= 2; // Command/Event flag bit
        }
        let _ = H4_ACL;

        let ts_us = BTSNOOP_BASE_EPOCH_US.wrapping_add(monotonic_us);
        let mut rec = Vec::with_capacity(24 + 1 + incl_data_len);
        rec.extend_from_slice(&orig_len.to_be_bytes());
        rec.extend_from_slice(&incl_len.to_be_bytes());
        rec.extend_from_slice(&flags.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes()); // cumulative drops
        rec.extend_from_slice(&ts_us.to_be_bytes());
        rec.push(h4_type);
        rec.extend_from_slice(&payload[..incl_data_len]);

        while self.total_record_bytes + rec.len() > self.max_record_bytes {
            if let Some(old) = self.records.pop_front() {
                self.total_record_bytes = self.total_record_bytes.saturating_sub(old.len());
                self.dropped_packets = self.dropped_packets.saturating_add(1);
            } else {
                break;
            }
        }
        self.total_record_bytes += rec.len();
        self.records.push_back(rec);
    }

    /// Materialize a complete, valid `btsnoop` binary file (`16-byte header + records`).
    pub fn export_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BTSNOOP_FILE_HEADER.len() + self.total_record_bytes);
        out.extend_from_slice(&BTSNOOP_FILE_HEADER);
        for rec in &self.records {
            out.extend_from_slice(rec);
        }
        out
    }
}
