//! `/services/net.elf` — isolated capability-enforced network stack, VirtIO-Net
//! PCI (`1af4:1000` / `1af4:1041` Modern 1.0 MMIO + Legacy 0.9.5 I/O) driver,
//! and multi-interface (`lo` + `virtio0` + `wlan0`) metric router (`HNET`).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use huesos_abi::net::{
    self, encode_ping_reply, iface_id, IfaceSnapshot, NetOp, NetStatus, NetStatusSnapshot,
    PingResult as AbiPingResult, MAX_IFACES,
};
use huesos_abi::vmar_flags;
use huesos_net::tcp::TcpState;
use huesos_net::{Ipv4Addr, MacAddr, NetError, NetStack, SocketAddrV4};
use libcanvas::resource::IoPort;
use libcanvas::{println, Channel, ErrorCode, Handle, Vmo};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const DMA_MAP_VA: u64 = 0x0000_7200_0000_0000;
const VIRTIO_BAR_VA_BASE: u64 = 0x0000_7210_0000_0000;
const VIRTIO_BAR_VA_STRIDE: u64 = 0x0000_0010_0000_0000;

const VIRTIO_LEGACY_HDR_LEN: usize = 10;
const VIRTIO_MODERN_HDR_LEN: usize = 12;
const PKT_BUF_STRIDE: usize = 2048;
const RX_SLOTS: usize = 64;
const TX_SLOTS: usize = 64;

// Runtime `uplink:wlan0` <-> `uplink:net` wire opcodes
const UPLINK_OP_STATE: u8 = 0x01;
const UPLINK_OP_ETH_FRAME: u8 = 0x02;

// Legacy VirtIO 0.9.5 PCI I/O register offsets (MSI-X disabled)
const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_ISR: u16 = 0x13;
const VIRTIO_PCI_MAC0: u16 = 0x14;

// Modern VirtIO 1.0 `virtio_pci_common_cfg` offsets
const COMMON_DFSELECT: usize = 0x00;
const COMMON_DF: usize = 0x04;
const COMMON_GFSELECT: usize = 0x08;
const COMMON_GF: usize = 0x0C;
const COMMON_STATUS: usize = 0x14;
const COMMON_Q_SELECT: usize = 0x16;
const COMMON_Q_SIZE: usize = 0x18;
const COMMON_Q_ENABLE: usize = 0x1C;
const COMMON_Q_NOTIFY_OFF: usize = 0x1E;
const COMMON_Q_DESCLO: usize = 0x20;
const COMMON_Q_DESCHI: usize = 0x24;
const COMMON_Q_AVAILLO: usize = 0x28;
const COMMON_Q_AVAILHI: usize = 0x2C;
const COMMON_Q_USEDLO: usize = 0x30;
const COMMON_Q_USEDHI: usize = 0x34;

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VIRTIO_F_VERSION_1_HI: u32 = 1 << 0; // bit 32

const VRING_DESC_F_WRITE: u16 = 2;

#[derive(Clone, Copy)]
struct MappedWin {
    base: usize,
    len: usize,
}

impl MappedWin {
    fn read8(&self, off: usize) -> u8 {
        if off < self.len {
            // SAFETY: `off < self.len` within mapped MMIO/DMA VMAR region.
            unsafe { read_volatile((self.base + off) as *const u8) }
        } else {
            0
        }
    }
    fn read16(&self, off: usize) -> u16 {
        if off.saturating_add(2) <= self.len {
            // SAFETY: `off + 2 <= self.len` within mapped MMIO/DMA VMAR region.
            unsafe { read_volatile((self.base + off) as *const u16) }
        } else {
            0
        }
    }
    fn read32(&self, off: usize) -> u32 {
        if off.saturating_add(4) <= self.len {
            // SAFETY: `off + 4 <= self.len` within mapped MMIO/DMA VMAR region.
            unsafe { read_volatile((self.base + off) as *const u32) }
        } else {
            0
        }
    }
    fn write8(&self, off: usize, v: u8) {
        if off < self.len {
            // SAFETY: `off < self.len` within mapped MMIO/DMA VMAR region.
            unsafe { write_volatile((self.base + off) as *mut u8, v) }
        }
    }
    fn write16(&self, off: usize, v: u16) {
        if off.saturating_add(2) <= self.len {
            // SAFETY: `off + 2 <= self.len` within mapped MMIO/DMA VMAR region.
            unsafe { write_volatile((self.base + off) as *mut u16, v) }
        }
    }
    fn write32(&self, off: usize, v: u32) {
        if off.saturating_add(4) <= self.len {
            // SAFETY: `off + 4 <= self.len` within mapped MMIO/DMA VMAR region.
            unsafe { write_volatile((self.base + off) as *mut u32, v) }
        }
    }
    fn write64(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off.saturating_add(4), (v >> 32) as u32);
    }
    fn copy_out(&self, off: usize, dst: &mut [u8]) {
        if off.saturating_add(dst.len()) <= self.len {
            // SAFETY: `[off .. off + dst.len())` validated within mapped DMA region.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.base + off) as *const u8,
                    dst.as_mut_ptr(),
                    dst.len(),
                );
            }
        }
    }
    fn copy_in(&self, off: usize, src: &[u8], zero_len: usize) {
        let z_ok = zero_len > 0 && off.saturating_add(zero_len) <= self.len;
        let s_ok = !src.is_empty() && off.saturating_add(src.len()) <= self.len;
        if z_ok || s_ok {
            // SAFETY: Both `zero_len` and `src.len()` bounds checked against `self.len` above.
            unsafe {
                if z_ok {
                    core::ptr::write_bytes((self.base + off) as *mut u8, 0, zero_len);
                }
                if s_ok {
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        (self.base + off) as *mut u8,
                        src.len(),
                    );
                }
            }
        }
    }
    fn write_desc(&self, desc_off: usize, slot: usize, addr: u64, len: u32, flags: u16) {
        let base = desc_off + slot * 16;
        self.write64(base, addr);
        self.write32(base + 8, len);
        self.write16(base + 12, flags);
        self.write16(base + 14, 0);
    }
}

struct VirtioQueue {
    q_idx: u16,
    q_size: u16,
    desc_off: usize,
    avail_off: usize,
    used_off: usize,
    notify_win: MappedWin,
    notify_off: usize,
    last_used_idx: u16,
}

#[derive(Clone, Copy)]
struct Vt10CapInfo {
    common_bar: u8,
    notify_bar: u8,
    isr_bar: u8,
    dev_bar: u8,
    has_dev: bool,
    common_off: u32,
    common_len: u32,
    notify_off: u32,
    notify_len: u32,
    notify_mult: u32,
    isr_off: u32,
    isr_len: u32,
    dev_off: u32,
    dev_len: u32,
    bdf_packed: u32,
}

impl Vt10CapInfo {
    fn decode(raw: &[u8; 48]) -> Option<Self> {
        if &raw[0..4] != b"VT10" {
            return None;
        }
        let rd32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        Some(Self {
            common_bar: raw[4],
            notify_bar: raw[5],
            isr_bar: raw[6],
            dev_bar: raw[7] & 0x7F,
            has_dev: raw[7] != 0xFF,
            common_off: rd32(8),
            common_len: rd32(12),
            notify_off: rd32(16),
            notify_len: rd32(20),
            notify_mult: rd32(24),
            isr_off: rd32(28),
            isr_len: rd32(32),
            dev_off: rd32(36),
            dev_len: rd32(40),
            bdf_packed: rd32(44),
        })
    }
}

enum VirtioTransport {
    ModernMmio {
        isr_win: MappedWin,
        isr_off: usize,
        bdf_packed: u32,
    },
    LegacyIo {
        ioport: IoPort,
        base_port: u16,
    },
}

struct VirtioNetNic {
    transport: VirtioTransport,
    dma: MappedWin,
    hdr_len: usize,
    mac: MacAddr,
    rxq: VirtioQueue,
    txq: VirtioQueue,
    rx_buf_off: usize,
    tx_buf_off: usize,
    tx_buf_pa: u64,
    tx_cursor: u16,
}

const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

const fn vring_bytes(qsz: usize) -> (usize, usize, usize) {
    let desc_off = 0usize;
    let avail_off = 16 * qsz;
    let used_off = align_up(avail_off + 6 + 2 * qsz, 4096);
    let total = align_up(used_off + 6 + 8 * qsz, 4096);
    (avail_off - desc_off, used_off, total)
}

impl VirtioNetNic {
    fn try_init_modern(
        vt10: &Vt10CapInfo,
        mapped_bars: &[Option<MappedWin>; 6],
        dma: MappedWin,
        dma_pa: u64,
    ) -> Option<Self> {
        if dma.len < 512 * 1024 {
            return None;
        }
        let resolve_region = |bar: u8, off: u32, min_len: usize| -> Option<(MappedWin, usize)> {
            let win = (*mapped_bars.get(usize::from(bar))?)?;
            let o = off as usize;
            if o.checked_add(min_len)? <= win.len {
                Some((win, o))
            } else {
                None
            }
        };

        if (vt10.common_len as usize) < 0x38 || (vt10.isr_len as usize) < 1 {
            return None;
        }
        let (common_win, common_off) = resolve_region(vt10.common_bar, vt10.common_off, 0x38)?;
        let (isr_win, isr_off) = resolve_region(vt10.isr_bar, vt10.isr_off, 1)?;
        let notify_win = (*mapped_bars.get(usize::from(vt10.notify_bar))?)?;
        if (vt10.notify_off as usize).saturating_add(2) > notify_win.len {
            return None;
        }

        // 1. Reset device -> poll until status == 0 -> ACK -> DRIVER
        common_win.write8(common_off + COMMON_STATUS, 0);
        for _ in 0..10_000 {
            if common_win.read8(common_off + COMMON_STATUS) == 0 {
                break;
            }
        }
        common_win.write8(common_off + COMMON_STATUS, VIRTIO_STATUS_ACK);
        common_win.write8(
            common_off + COMMON_STATUS,
            VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER,
        );

        // 2. Negotiate VIRTIO_F_VERSION_1 + VIRTIO_NET_F_MAC + VIRTIO_NET_F_STATUS
        common_win.write32(common_off + COMMON_DFSELECT, 0);
        let host_lo = common_win.read32(common_off + COMMON_DF);
        common_win.write32(common_off + COMMON_DFSELECT, 1);
        let host_hi = common_win.read32(common_off + COMMON_DF);
        if (host_hi & VIRTIO_F_VERSION_1_HI) == 0 {
            return None;
        }
        let guest_lo = host_lo & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        let guest_hi = VIRTIO_F_VERSION_1_HI;
        common_win.write32(common_off + COMMON_GFSELECT, 0);
        common_win.write32(common_off + COMMON_GF, guest_lo);
        common_win.write32(common_off + COMMON_GFSELECT, 1);
        common_win.write32(common_off + COMMON_GF, guest_hi);

        let st_feat = VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK;
        common_win.write8(common_off + COMMON_STATUS, st_feat);
        if (common_win.read8(common_off + COMMON_STATUS) & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return None;
        }

        let mut mac_bytes = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        if vt10.has_dev && vt10.dev_len >= 6 {
            if let Some((dev_win, dev_off)) = resolve_region(vt10.dev_bar, vt10.dev_off, 6) {
                for (i, slot) in mac_bytes.iter_mut().enumerate() {
                    *slot = dev_win.read8(dev_off + i);
                }
            }
        }

        // 3. Configure RX queue (0) and TX queue (1)
        let mut dma_cursor = 0usize;
        let setup_modern_q = |q_idx: u16, cursor: &mut usize| -> Option<VirtioQueue> {
            common_win.write16(common_off + COMMON_Q_SELECT, q_idx);
            let qsz = common_win.read16(common_off + COMMON_Q_SIZE);
            let q_noff = common_win.read16(common_off + COMMON_Q_NOTIFY_OFF);
            if qsz == 0 || qsz > 1024 {
                return None;
            }
            let notify_rel = (vt10.notify_off as usize)
                .checked_add((usize::from(q_noff)).checked_mul(vt10.notify_mult as usize)?)?;
            if notify_rel.checked_add(2)? > notify_win.len
                || (notify_rel - (vt10.notify_off as usize)) + 2 > (vt10.notify_len as usize).max(2)
            {
                return None;
            }

            let (_avail_rel, used_rel, total_bytes) = vring_bytes(usize::from(qsz));
            let ring_off = align_up(*cursor, 4096);
            if ring_off + total_bytes > dma.len {
                return None;
            }
            let desc_pa = dma_pa + (ring_off as u64);
            let avail_pa = desc_pa + (16 * usize::from(qsz)) as u64;
            let used_pa = desc_pa + (used_rel as u64);

            dma.copy_in(ring_off, &[], total_bytes);
            fence(Ordering::SeqCst);
            common_win.write32(common_off + COMMON_Q_DESCLO, desc_pa as u32);
            common_win.write32(common_off + COMMON_Q_DESCHI, (desc_pa >> 32) as u32);
            common_win.write32(common_off + COMMON_Q_AVAILLO, avail_pa as u32);
            common_win.write32(common_off + COMMON_Q_AVAILHI, (avail_pa >> 32) as u32);
            common_win.write32(common_off + COMMON_Q_USEDLO, used_pa as u32);
            common_win.write32(common_off + COMMON_Q_USEDHI, (used_pa >> 32) as u32);
            common_win.write16(common_off + COMMON_Q_ENABLE, 1);

            *cursor = ring_off + total_bytes;
            Some(VirtioQueue {
                q_idx,
                q_size: qsz,
                desc_off: ring_off,
                avail_off: ring_off + 16 * usize::from(qsz),
                used_off: ring_off + used_rel,
                notify_win,
                notify_off: notify_rel,
                last_used_idx: 0,
            })
        };

        let rxq = setup_modern_q(0, &mut dma_cursor)?;
        let txq = setup_modern_q(1, &mut dma_cursor)?;

        let rx_buf_off = align_up(dma_cursor, 4096);
        let tx_buf_off = rx_buf_off + RX_SLOTS * PKT_BUF_STRIDE;
        if tx_buf_off + TX_SLOTS * PKT_BUF_STRIDE > dma.len {
            return None;
        }
        let rx_buf_pa = dma_pa + (rx_buf_off as u64);
        let tx_buf_pa = dma_pa + (tx_buf_off as u64);

        let rx_active = RX_SLOTS.min(usize::from(rxq.q_size));
        for i in 0..rx_active {
            dma.write_desc(
                rxq.desc_off,
                i,
                rx_buf_pa + ((i * PKT_BUF_STRIDE) as u64),
                PKT_BUF_STRIDE as u32,
                VRING_DESC_F_WRITE,
            );
            dma.write16(rxq.avail_off + 4 + i * 2, i as u16);
        }
        fence(Ordering::SeqCst);
        dma.write16(rxq.avail_off + 2, rx_active as u16);
        fence(Ordering::SeqCst);
        common_win.write8(
            common_off + COMMON_STATUS,
            VIRTIO_STATUS_ACK
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
        fence(Ordering::SeqCst);
        rxq.notify_win.write16(rxq.notify_off, rxq.q_idx);

        Some(Self {
            transport: VirtioTransport::ModernMmio {
                isr_win,
                isr_off,
                bdf_packed: vt10.bdf_packed,
            },
            dma,
            hdr_len: VIRTIO_MODERN_HDR_LEN,
            mac: MacAddr(mac_bytes),
            rxq,
            txq,
            rx_buf_off,
            tx_buf_off,
            tx_buf_pa,
            tx_cursor: 0,
        })
    }

    fn try_init_legacy(
        ioport: IoPort,
        base_port: u16,
        dma: MappedWin,
        dma_pa: u64,
    ) -> Option<Self> {
        if dma.len < 512 * 1024 {
            return None;
        }
        ioport.write_u8(base_port + VIRTIO_PCI_STATUS, 0).ok()?;
        ioport
            .write_u8(base_port + VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACK)
            .ok()?;
        ioport
            .write_u8(
                base_port + VIRTIO_PCI_STATUS,
                VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER,
            )
            .ok()?;

        let host_feat = ioport.read_u32(base_port + VIRTIO_PCI_HOST_FEATURES).ok()?;
        let guest_feat = host_feat & VIRTIO_NET_F_MAC;
        ioport
            .write_u32(base_port + VIRTIO_PCI_GUEST_FEATURES, guest_feat)
            .ok()?;

        let mut mac_bytes = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        if (host_feat & VIRTIO_NET_F_MAC) != 0 {
            for (i, slot) in mac_bytes.iter_mut().enumerate() {
                if let Ok(b) = ioport.read_u8(base_port + VIRTIO_PCI_MAC0 + (i as u16)) {
                    *slot = b;
                }
            }
        }

        let mut dma_cursor = 0usize;
        let setup_queue = |q_idx: u16, cursor: &mut usize| -> Option<VirtioQueue> {
            ioport
                .write_u16(base_port + VIRTIO_PCI_QUEUE_SEL, q_idx)
                .ok()?;
            let qsz = ioport.read_u16(base_port + VIRTIO_PCI_QUEUE_NUM).ok()?;
            if qsz == 0 || qsz > 1024 {
                return None;
            }
            let (_avail_rel, used_rel, total_bytes) = vring_bytes(usize::from(qsz));
            let ring_off = align_up(*cursor, 4096);
            if ring_off + total_bytes > dma.len {
                return None;
            }
            let ring_pa = dma_pa + (ring_off as u64);
            dma.copy_in(ring_off, &[], total_bytes);
            fence(Ordering::SeqCst);
            ioport
                .write_u32(base_port + VIRTIO_PCI_QUEUE_PFN, (ring_pa >> 12) as u32)
                .ok()?;
            *cursor = ring_off + total_bytes;
            Some(VirtioQueue {
                q_idx,
                q_size: qsz,
                desc_off: ring_off,
                avail_off: ring_off + 16 * usize::from(qsz),
                used_off: ring_off + used_rel,
                notify_win: MappedWin { base: 0, len: 0 },
                notify_off: 0,
                last_used_idx: 0,
            })
        };

        let rxq = setup_queue(0, &mut dma_cursor)?;
        let txq = setup_queue(1, &mut dma_cursor)?;

        let rx_buf_off = align_up(dma_cursor, 4096);
        let tx_buf_off = rx_buf_off + RX_SLOTS * PKT_BUF_STRIDE;
        if tx_buf_off + TX_SLOTS * PKT_BUF_STRIDE > dma.len {
            return None;
        }
        let rx_buf_pa = dma_pa + (rx_buf_off as u64);
        let tx_buf_pa = dma_pa + (tx_buf_off as u64);

        let rx_active = RX_SLOTS.min(usize::from(rxq.q_size));
        for i in 0..rx_active {
            dma.write_desc(
                rxq.desc_off,
                i,
                rx_buf_pa + ((i * PKT_BUF_STRIDE) as u64),
                PKT_BUF_STRIDE as u32,
                VRING_DESC_F_WRITE,
            );
            dma.write16(rxq.avail_off + 4 + i * 2, i as u16);
        }
        fence(Ordering::SeqCst);
        dma.write16(rxq.avail_off + 2, rx_active as u16);
        fence(Ordering::SeqCst);

        ioport
            .write_u8(
                base_port + VIRTIO_PCI_STATUS,
                VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
            )
            .ok()?;
        let _ = ioport.write_u16(base_port + VIRTIO_PCI_QUEUE_NOTIFY, rxq.q_idx);

        Some(Self {
            transport: VirtioTransport::LegacyIo { ioport, base_port },
            dma,
            hdr_len: VIRTIO_LEGACY_HDR_LEN,
            mac: MacAddr(mac_bytes),
            rxq,
            txq,
            rx_buf_off,
            tx_buf_off,
            tx_buf_pa,
            tx_cursor: 0,
        })
    }

    fn ack_isr(&self) {
        match &self.transport {
            VirtioTransport::ModernMmio {
                isr_win, isr_off, ..
            } => {
                let _ = isr_win.read8(*isr_off);
            }
            VirtioTransport::LegacyIo { ioport, base_port } => {
                let _ = ioport.read_u8(*base_port + VIRTIO_PCI_ISR);
            }
        }
    }

    fn notify_queue(&self, q: &VirtioQueue) {
        match &self.transport {
            VirtioTransport::ModernMmio { .. } => {
                q.notify_win.write16(q.notify_off, q.q_idx);
            }
            VirtioTransport::LegacyIo { ioport, base_port } => {
                let _ = ioport.write_u16(*base_port + VIRTIO_PCI_QUEUE_NOTIFY, q.q_idx);
            }
        }
    }

    fn poll_rx(&mut self, stack: &mut NetStack, now_ms: u64, tx_out: &mut VecDeque<Vec<u8>>) {
        self.ack_isr();
        fence(Ordering::SeqCst);
        let used_idx = self.dma.read16(self.rxq.used_off + 2);
        let mut recycled = false;

        while self.rxq.last_used_idx != used_idx {
            let ring_slot = usize::from(self.rxq.last_used_idx % self.rxq.q_size);
            let elem_off = self.rxq.used_off + 4 + ring_slot * 8;
            let desc_id = self.dma.read32(elem_off) as usize;
            let byte_len = self.dma.read32(elem_off + 4) as usize;
            self.rxq.last_used_idx = self.rxq.last_used_idx.wrapping_add(1);

            if desc_id < RX_SLOTS && byte_len > self.hdr_len && byte_len <= PKT_BUF_STRIDE {
                let frame_len = byte_len - self.hdr_len;
                let mut frame = alloc::vec![0u8; frame_len];
                let src_off = self.rx_buf_off + desc_id * PKT_BUF_STRIDE + self.hdr_len;
                self.dma.copy_out(src_off, &mut frame);
                stack.ingest_frame(now_ms, &frame, tx_out);
            }

            if desc_id < RX_SLOTS {
                let avail_idx = self.dma.read16(self.rxq.avail_off + 2);
                let a_slot = usize::from(avail_idx % self.rxq.q_size);
                self.dma
                    .write16(self.rxq.avail_off + 4 + a_slot * 2, desc_id as u16);
                fence(Ordering::SeqCst);
                self.dma
                    .write16(self.rxq.avail_off + 2, avail_idx.wrapping_add(1));
                recycled = true;
            }
        }
        if recycled {
            fence(Ordering::SeqCst);
            self.notify_queue(&self.rxq);
        }
    }

    fn flush_tx(&mut self, tx_out: &mut VecDeque<Vec<u8>>) {
        let mut notified = false;
        while let Some(frame) = tx_out.pop_front() {
            if frame.len() + self.hdr_len > PKT_BUF_STRIDE {
                continue;
            }
            let tx_cap = (TX_SLOTS as u16).min(self.txq.q_size);
            let slot = usize::from(self.tx_cursor % tx_cap);
            self.tx_cursor = self.tx_cursor.wrapping_add(1);

            let dst_off = self.tx_buf_off + slot * PKT_BUF_STRIDE;
            let dst_pa = self.tx_buf_pa + ((slot * PKT_BUF_STRIDE) as u64);
            let total_len = self.hdr_len + frame.len();

            self.dma.copy_in(dst_off, &[], self.hdr_len);
            self.dma.copy_in(dst_off + self.hdr_len, &frame, 0);
            self.dma
                .write_desc(self.txq.desc_off, slot, dst_pa, total_len as u32, 0);

            let avail_idx = self.dma.read16(self.txq.avail_off + 2);
            let a_slot = usize::from(avail_idx % self.txq.q_size);
            self.dma
                .write16(self.txq.avail_off + 4 + a_slot * 2, slot as u16);
            fence(Ordering::SeqCst);
            self.dma
                .write16(self.txq.avail_off + 2, avail_idx.wrapping_add(1));
            notified = true;
        }
        if notified {
            fence(Ordering::SeqCst);
            self.notify_queue(&self.txq);
        }
    }
}

struct NetClientConn {
    ch: Channel,
    read_only: bool,
}

struct PendingPingWait {
    iface: u8,
    client_idx: usize,
    target_ip: [u8; 4],
    ident: u16,
    seq: u16,
    deadline_ms: u64,
}

struct PendingDnsWait {
    iface: u8,
    client_idx: usize,
    txid: u16,
    deadline_ms: u64,
}

struct PendingTcpConnect {
    iface: u8,
    client_idx: usize,
    sock_id: u32,
    deadline_ms: u64,
}

struct ActiveTcpBridge {
    iface: u8,
    sock_id: u32,
    data_ch: Channel,
}

struct ActiveUdpBridge {
    iface: u8,
    sock_id: u32,
    ch: Channel,
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(trimmed, 16).ok()
}

fn rdtsc_ms(boot_tsc: u64) -> u64 {
    let cur: u64;
    // SAFETY: `rdtsc` is unprivileged on x86_64.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        cur = ((hi as u64) << 32) | (lo as u64);
    }
    cur.saturating_sub(boot_tsc) / 2_000_000
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let p = prefix.min(32);
    if p == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from_u32(!0u32 << (32 - p))
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    mask.to_u32().leading_ones() as u8
}

fn in_same_subnet(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    !a.is_unspecified()
        && !mask.is_unspecified()
        && (a.to_u32() & mask.to_u32()) == (b.to_u32() & mask.to_u32())
}

/// Select the outgoing interface (`iface_id::VIRTIO0` metric 100 vs `iface_id::WLAN0` metric 600).
fn select_route_iface(
    dst: Option<Ipv4Addr>,
    eth_present: bool,
    eth: &NetStack,
    wlan_present: bool,
    wlan: &NetStack,
) -> u8 {
    let eth_ready = eth_present && eth.cfg.link_up && !eth.cfg.ip.is_unspecified();
    let wlan_ready = wlan_present && wlan.cfg.link_up && !wlan.cfg.ip.is_unspecified();

    if let Some(ip) = dst {
        // Direct on-link subnet match wins regardless of default-gateway metric
        if eth_ready && in_same_subnet(eth.cfg.ip, ip, eth.cfg.subnet_mask) {
            return iface_id::VIRTIO0;
        }
        if wlan_ready && in_same_subnet(wlan.cfg.ip, ip, wlan.cfg.subnet_mask) {
            return iface_id::WLAN0;
        }
    }

    // Default gateway metric: wired Ethernet (100) beats Wi-Fi (600)
    if eth_ready {
        iface_id::VIRTIO0
    } else if wlan_ready {
        iface_id::WLAN0
    } else if eth_present && eth.cfg.link_up {
        iface_id::VIRTIO0
    } else if wlan_present && wlan.cfg.link_up {
        iface_id::WLAN0
    } else if eth_present {
        iface_id::VIRTIO0
    } else if wlan_present {
        iface_id::WLAN0
    } else {
        iface_id::LO
    }
}

fn flush_wlan_tx(wlan_ch: Option<&Channel>, tx_wlan: &mut VecDeque<Vec<u8>>) {
    let Some(ch) = wlan_ch else {
        tx_wlan.clear();
        return;
    };
    while let Some(frame) = tx_wlan.pop_front() {
        let mut pkt = alloc::vec![0u8; 1 + frame.len()];
        pkt[0] = UPLINK_OP_ETH_FRAME;
        pkt[1..].copy_from_slice(&frame);
        let _ = ch.write(&pkt);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: called once before any allocations.
    if unsafe { !HEAP.init() } {
        libcanvas::process::exit(-10);
    }
    let boot_tsc = {
        let lo: u32;
        let hi: u32;
        // SAFETY: `rdtsc` is unprivileged.
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        }
        ((hi as u64) << 32) | (lo as u64)
    };

    let bootstrap = libcanvas::channel::bootstrap();
    let mut dma_res: Option<(Handle, u64, u64)> = None;
    let mut ioport_res: Option<(Handle, u16, u16)> = None;
    let mut mmio_bars: [Option<(Handle, u64)>; 6] = [const { None }; 6];
    let mut vt10_info: Option<Vt10CapInfo> = None;
    let mut wlan_uplink_ch: Option<Channel> = None;

    // Drain manifest/PCI resources until `resource:transfer-complete`
    let mut label_buf = [0u8; 128];
    for _ in 0..256 {
        match bootstrap.read_optional_handle_timeout(&mut label_buf, 100) {
            Ok((n, handle_opt)) => {
                let msg = core::str::from_utf8(&label_buf[..n]).unwrap_or("");
                if msg == "resource:transfer-complete" {
                    break;
                }
                if msg == "uplink:wlan0" {
                    if let Some(h) = handle_opt {
                        wlan_uplink_ch = Some(Channel::from_handle(h));
                    }
                } else if let Some(rest) = msg.strip_prefix("resource:net-service:") {
                    let mut parts = rest.split(':');
                    let kind = parts.next().unwrap_or("");
                    let base = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let len = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let tag_tail = parts.next().unwrap_or("");
                    if let Some(h) = handle_opt {
                        if kind == "dma" && dma_res.is_none() {
                            dma_res = Some((h, base, len));
                        } else if kind == "ioport" && len >= 0x20 && ioport_res.is_none() {
                            ioport_res = Some((h, base as u16, len as u16));
                        } else if kind == "mmio" && len > 0 {
                            if let Some(bar_s) = tag_tail.strip_prefix("bar") {
                                if let Ok(bidx) = bar_s.parse::<usize>() {
                                    if bidx < 6 && mmio_bars[bidx].is_none() {
                                        mmio_bars[bidx] = Some((h, len));
                                    }
                                }
                            }
                        } else if kind == "virtio1" && vt10_info.is_none() {
                            let vmo = Vmo::from_handle(h);
                            let mut raw = [0u8; 48];
                            if vmo.read(0, &mut raw) == Ok(48) {
                                vt10_info = Vt10CapInfo::decode(&raw);
                            }
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => break,
        }
    }

    let mut mapped_dma: Option<(MappedWin, u64)> = None;
    if let Some((dma_h, dma_pa, dma_len)) = dma_res.as_ref() {
        let map_len = (*dma_len).min(4 * 1024 * 1024) & !0xFFF;
        if map_len >= 512 * 1024
            && libcanvas::resource::map_self(
                dma_h,
                0,
                DMA_MAP_VA,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
        {
            mapped_dma = Some((
                MappedWin {
                    base: DMA_MAP_VA as usize,
                    len: map_len as usize,
                },
                *dma_pa,
            ));
        }
    }

    let mut mapped_bars: [Option<MappedWin>; 6] = [None; 6];
    for (idx, slot) in mmio_bars.iter().enumerate() {
        if let Some((bar_h, bar_len)) = slot {
            let map_len = (*bar_len + 0xFFF) & !0xFFF;
            let va = VIRTIO_BAR_VA_BASE + (idx as u64) * VIRTIO_BAR_VA_STRIDE;
            if libcanvas::resource::map_self(
                bar_h,
                0,
                va,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
            {
                mapped_bars[idx] = Some(MappedWin {
                    base: va as usize,
                    len: map_len as usize,
                });
            }
        }
    }

    let mut nic: Option<VirtioNetNic> = None;
    if let Some((dma_win, dma_pa)) = mapped_dma {
        if let Some(vt10) = vt10_info.as_ref() {
            nic = VirtioNetNic::try_init_modern(vt10, &mapped_bars, dma_win, dma_pa);
        }
        if nic.is_none() {
            if let Some((io_h, port_base, _port_len)) = ioport_res {
                nic = VirtioNetNic::try_init_legacy(
                    IoPort::from_handle(io_h),
                    port_base,
                    dma_win,
                    dma_pa,
                );
            }
        }
    }

    let eth_mac = nic
        .as_ref()
        .map(|n| n.mac)
        .unwrap_or(MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
    let mut eth_stack = NetStack::new(eth_mac);
    let mut tx_eth_out: VecDeque<Vec<u8>> = VecDeque::with_capacity(32);

    let mut wlan_present = false;
    let mut wlan_stack = NetStack::new(MacAddr::ZERO);
    wlan_stack.cfg.link_up = false;
    let mut tx_wlan_out: VecDeque<Vec<u8>> = VecDeque::with_capacity(32);

    if let Some(n) = nic.as_mut() {
        match &n.transport {
            VirtioTransport::ModernMmio { bdf_packed, .. } => println!(
                "[net-service] virtio-net 1.0 modern MMIO online bdf={:#06x} mac={}",
                bdf_packed, n.mac
            ),
            VirtioTransport::LegacyIo { base_port, .. } => println!(
                "[net-service] virtio-net legacy I/O online io={:#x} mac={}",
                base_port, n.mac
            ),
        }
        eth_stack.cfg.link_up = true;
        eth_stack.start_dhcp(0, &mut tx_eth_out);
        n.flush_tx(&mut tx_eth_out);
    } else {
        println!("[net-service] started without virtio-net NIC (lo + wlan0 uplink ready)");
        eth_stack.cfg.link_up = false;
    }

    let _ = bootstrap.write(b"service:net:ready");

    let mut clients: Vec<Option<NetClientConn>> = Vec::with_capacity(32);
    let mut pending_pings: Vec<PendingPingWait> = Vec::new();
    let mut pending_dns: Vec<PendingDnsWait> = Vec::new();
    let mut pending_tcp: Vec<PendingTcpConnect> = Vec::new();
    let mut active_tcp: Vec<ActiveTcpBridge> = Vec::new();
    let mut active_udp: Vec<ActiveUdpBridge> = Vec::new();
    let mut last_timer_ms = 0u64;

    loop {
        let now_ms = rdtsc_ms(boot_tsc);

        // 1. Poll DriverManager bootstrap for newly attached client / wlan0 uplink channels
        for _ in 0..8 {
            let mut bmsg = [0u8; 64];
            match bootstrap.read_optional_handle(&mut bmsg) {
                Ok((n, Some(h))) => {
                    let tag = &bmsg[..n];
                    let ro = tag == b"net-client:ro";
                    if tag == b"net-client" || ro {
                        let conn = NetClientConn {
                            ch: Channel::from_handle(h),
                            read_only: ro,
                        };
                        if let Some(slot) = clients.iter_mut().find(|s| s.is_none()) {
                            *slot = Some(conn);
                        } else if clients.len() < 32 {
                            clients.push(Some(conn));
                        }
                    } else if tag == b"uplink:wlan0" {
                        wlan_uplink_ch = Some(Channel::from_handle(h));
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 2a. Poll VirtIO-Net RX
        if let Some(n) = nic.as_mut() {
            n.poll_rx(&mut eth_stack, now_ms, &mut tx_eth_out);
            n.flush_tx(&mut tx_eth_out);
            if eth_stack.cfg.ip.is_unspecified() && now_ms > 4_000 {
                eth_stack.configure_static(
                    Ipv4Addr::new(10, 0, 2, 15),
                    Ipv4Addr::new(255, 255, 255, 0),
                    Ipv4Addr::new(10, 0, 2, 2),
                    Ipv4Addr::new(10, 0, 2, 3),
                );
                eth_stack.cfg.dhcp_bound = true;
            }
        }

        // 2b. Poll `wlan0` runtime uplink channel from `wlan-service`
        if let Some(wch) = wlan_uplink_ch.as_ref() {
            let mut wbuf = [0u8; 2048];
            for _ in 0..16 {
                match wch.read_into(&mut wbuf) {
                    Ok(n) if n >= 19 && wbuf[0] == UPLINK_OP_STATE => {
                        wlan_present = wbuf[1] != 0;
                        let link_up = wbuf[2] != 0;
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&wbuf[3..9]);
                        let start_dhcp = wbuf[9] != 0;
                        let static_ip = Ipv4Addr([wbuf[10], wbuf[11], wbuf[12], wbuf[13]]);
                        let pfx = wbuf[14];
                        let static_gw = Ipv4Addr([wbuf[15], wbuf[16], wbuf[17], wbuf[18]]);

                        wlan_stack.cfg.mac = MacAddr(mac);
                        wlan_stack.cfg.link_up = link_up;
                        if !link_up {
                            wlan_stack.cfg.ip = Ipv4Addr::UNSPECIFIED;
                            wlan_stack.cfg.gateway = Ipv4Addr::UNSPECIFIED;
                            wlan_stack.cfg.dhcp_bound = false;
                        } else if !static_ip.is_unspecified() {
                            wlan_stack.configure_static(
                                static_ip,
                                prefix_to_mask(pfx),
                                static_gw,
                                static_gw,
                            );
                        } else if start_dhcp {
                            wlan_stack.start_dhcp(now_ms, &mut tx_wlan_out);
                        }
                    }
                    Ok(n) if n > 15 && wbuf[0] == UPLINK_OP_ETH_FRAME => {
                        wlan_stack.ingest_frame(now_ms, &wbuf[1..n], &mut tx_wlan_out);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);

        if now_ms.saturating_sub(last_timer_ms) >= 50 {
            last_timer_ms = now_ms;
            if nic.is_some() {
                eth_stack.poll_timers(now_ms, &mut tx_eth_out);
                if let Some(n) = nic.as_mut() {
                    n.flush_tx(&mut tx_eth_out);
                }
            }
            if wlan_stack.cfg.link_up {
                wlan_stack.poll_timers(now_ms, &mut tx_wlan_out);
                flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
            }
        }

        // 3. Service HNET control requests from clients
        let mut req_buf = [0u8; 512];
        #[allow(clippy::needless_range_loop)]
        for idx in 0..clients.len() {
            let mut drop_client = false;
            let mut ro_flag = false;
            let mut got_len = 0usize;
            if let Some(c) = clients[idx].as_ref() {
                ro_flag = c.read_only;
                match c.ch.read_into(&mut req_buf) {
                    Ok(n) => got_len = n,
                    Err(ErrorCode::ShouldWait) => {}
                    Err(_) => drop_client = true,
                }
            }
            if drop_client {
                clients[idx] = None;
                continue;
            }
            if got_len == 0 {
                continue;
            }
            let Some((op, payload)) = net::parse_request(&req_buf[..got_len]) else {
                if let Some(c) = clients[idx].as_ref() {
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::Status, NetStatus::InvalidRequest);
                    let _ = c.ch.write(&rep);
                }
                continue;
            };
            if ro_flag && op.requires_write() {
                if let Some(c) = clients[idx].as_ref() {
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, op, NetStatus::AccessDenied);
                    let _ = c.ch.write(&rep);
                }
                continue;
            }

            match op {
                NetOp::Status => {
                    let active_up = select_route_iface(
                        None,
                        nic.is_some(),
                        &eth_stack,
                        wlan_present,
                        &wlan_stack,
                    );
                    let active_dns = if active_up == iface_id::WLAN0
                        && !wlan_stack.cfg.dns_server.is_unspecified()
                    {
                        wlan_stack.cfg.dns_server.0
                    } else if !eth_stack.cfg.dns_server.is_unspecified() {
                        eth_stack.cfg.dns_server.0
                    } else {
                        wlan_stack.cfg.dns_server.0
                    };

                    let mut snap = NetStatusSnapshot {
                        dns_server: active_dns,
                        active_uplink: active_up,
                        active_tcp_sockets: active_tcp.len().min(255) as u8,
                        active_udp_sockets: active_udp.len().min(255) as u8,
                        free_packet_buffers: (RX_SLOTS + TX_SLOTS) as u16,
                        total_packet_buffers: (RX_SLOTS + TX_SLOTS) as u16,
                        ifaces: [IfaceSnapshot::default(); MAX_IFACES],
                    };
                    snap.ifaces[0].name[..2].copy_from_slice(b"lo");
                    snap.ifaces[0].present = true;
                    snap.ifaces[0].link_up = true;
                    snap.ifaces[0].prefix_len = 8;
                    snap.ifaces[0].ipv4 = [127, 0, 0, 1];

                    snap.ifaces[1].name[..7].copy_from_slice(b"virtio0");
                    snap.ifaces[1].present = nic.is_some();
                    snap.ifaces[1].link_up = nic.is_some() && eth_stack.cfg.link_up;
                    snap.ifaces[1].dhcp_enabled = eth_stack.cfg.dhcp_bound;
                    snap.ifaces[1].prefix_len = mask_to_prefix(eth_stack.cfg.subnet_mask);
                    snap.ifaces[1].mac = eth_stack.cfg.mac.0;
                    snap.ifaces[1].ipv4 = eth_stack.cfg.ip.0;
                    snap.ifaces[1].gateway = eth_stack.cfg.gateway.0;
                    snap.ifaces[1].rx_packets = eth_stack.stats.rx_packets;
                    snap.ifaces[1].tx_packets = eth_stack.stats.tx_packets;
                    snap.ifaces[1].rx_bytes = eth_stack.stats.rx_bytes;
                    snap.ifaces[1].tx_bytes = eth_stack.stats.tx_bytes;

                    snap.ifaces[2].name[..5].copy_from_slice(b"wlan0");
                    snap.ifaces[2].present = wlan_present;
                    snap.ifaces[2].link_up = wlan_present && wlan_stack.cfg.link_up;
                    snap.ifaces[2].dhcp_enabled = wlan_stack.cfg.dhcp_bound;
                    snap.ifaces[2].prefix_len = mask_to_prefix(wlan_stack.cfg.subnet_mask);
                    snap.ifaces[2].mac = wlan_stack.cfg.mac.0;
                    snap.ifaces[2].ipv4 = wlan_stack.cfg.ip.0;
                    snap.ifaces[2].gateway = wlan_stack.cfg.gateway.0;
                    snap.ifaces[2].rx_packets = wlan_stack.stats.rx_packets;
                    snap.ifaces[2].tx_packets = wlan_stack.stats.tx_packets;
                    snap.ifaces[2].rx_bytes = wlan_stack.stats.rx_bytes;
                    snap.ifaces[2].tx_bytes = wlan_stack.stats.tx_bytes;

                    let mut out = [0u8; 256];
                    if let (Some(n), Some(c)) = (snap.encode_reply(&mut out), clients[idx].as_ref())
                    {
                        let _ = c.ch.write(&out[..n]);
                    }
                }
                NetOp::Ping => {
                    if payload.len() < 14 {
                        if let Some(c) = clients[idx].as_ref() {
                            let rep = encode_ping_reply(
                                NetStatus::InvalidRequest,
                                &AbiPingResult::default(),
                            );
                            let _ = c.ch.write(&rep);
                        }
                        continue;
                    }
                    let dst = Ipv4Addr([payload[0], payload[1], payload[2], payload[3]]);
                    let ident = u16::from_le_bytes([payload[4], payload[5]]);
                    let seq = u16::from_le_bytes([payload[6], payload[7]]);
                    let timeout_ms =
                        u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                    let plen = u16::from_le_bytes([payload[12], payload[13]]) as usize;

                    let route_if = select_route_iface(
                        Some(dst),
                        nic.is_some(),
                        &eth_stack,
                        wlan_present,
                        &wlan_stack,
                    );
                    let send_ok = if route_if == iface_id::WLAN0 && !dst.is_loopback() {
                        let ok = wlan_stack
                            .ping_send(now_ms, dst, ident, seq, plen, &mut tx_wlan_out)
                            .is_ok();
                        flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
                        ok
                    } else {
                        let ok = eth_stack
                            .ping_send(now_ms, dst, ident, seq, plen, &mut tx_eth_out)
                            .is_ok();
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_eth_out);
                        }
                        ok
                    };

                    if send_ok {
                        pending_pings.push(PendingPingWait {
                            iface: if route_if == iface_id::WLAN0 && !dst.is_loopback() {
                                iface_id::WLAN0
                            } else {
                                iface_id::VIRTIO0
                            },
                            client_idx: idx,
                            target_ip: dst.0,
                            ident,
                            seq,
                            deadline_ms: now_ms + u64::from(timeout_ms.clamp(100, 10_000)),
                        });
                    } else if let Some(c) = clients[idx].as_ref() {
                        let stack_up = (nic.is_some()
                            && eth_stack.cfg.link_up
                            && !eth_stack.cfg.ip.is_unspecified())
                            || (wlan_present
                                && wlan_stack.cfg.link_up
                                && !wlan_stack.cfg.ip.is_unspecified());
                        let st = if stack_up {
                            NetStatus::Unreachable
                        } else {
                            NetStatus::NetworkDown
                        };
                        let rep = encode_ping_reply(st, &AbiPingResult::default());
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::ResolveDns => {
                    if payload.len() < 2 {
                        continue;
                    }
                    let hlen = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
                    if payload.len() < 2 + hlen {
                        continue;
                    }
                    let host = core::str::from_utf8(&payload[2..2 + hlen]).unwrap_or("");
                    let route_if = select_route_iface(
                        None,
                        nic.is_some(),
                        &eth_stack,
                        wlan_present,
                        &wlan_stack,
                    );
                    let dns_res = if route_if == iface_id::WLAN0 {
                        let r = wlan_stack.dns_start(now_ms, host, &mut tx_wlan_out);
                        flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
                        r
                    } else {
                        let r = eth_stack.dns_start(now_ms, host, &mut tx_eth_out);
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_eth_out);
                        }
                        r
                    };

                    match dns_res {
                        Ok(Ok(ip)) => {
                            let mut rep = [0u8; 16];
                            net::write_header(&mut rep, NetOp::ResolveDns, NetStatus::Ok);
                            rep[8..12].copy_from_slice(&ip.0);
                            rep[12..16].copy_from_slice(&300u32.to_le_bytes());
                            if let Some(c) = clients[idx].as_ref() {
                                let _ = c.ch.write(&rep);
                            }
                        }
                        Ok(Err(txid)) => {
                            pending_dns.push(PendingDnsWait {
                                iface: if route_if == iface_id::WLAN0 {
                                    iface_id::WLAN0
                                } else {
                                    iface_id::VIRTIO0
                                },
                                client_idx: idx,
                                txid,
                                deadline_ms: now_ms + 3_000,
                            });
                        }
                        Err(_) => {
                            let stack_up = (nic.is_some()
                                && eth_stack.cfg.link_up
                                && !eth_stack.cfg.ip.is_unspecified())
                                || (wlan_present
                                    && wlan_stack.cfg.link_up
                                    && !wlan_stack.cfg.ip.is_unspecified());
                            let st = if stack_up {
                                NetStatus::Unreachable
                            } else {
                                NetStatus::NetworkDown
                            };
                            let mut rep = [0u8; 16];
                            net::write_header(&mut rep, NetOp::ResolveDns, st);
                            if let Some(c) = clients[idx].as_ref() {
                                let _ = c.ch.write(&rep);
                            }
                        }
                    }
                }
                NetOp::OpenTcp => {
                    if payload.len() < 10 {
                        continue;
                    }
                    let dst = Ipv4Addr([payload[0], payload[1], payload[2], payload[3]]);
                    let port = u16::from_le_bytes([payload[4], payload[5]]);
                    let timeout_ms =
                        u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]);
                    let route_if = select_route_iface(
                        Some(dst),
                        nic.is_some(),
                        &eth_stack,
                        wlan_present,
                        &wlan_stack,
                    );
                    let use_wlan = route_if == iface_id::WLAN0 && !dst.is_loopback();
                    let conn_res = if use_wlan {
                        let r = wlan_stack.tcp_connect(
                            now_ms,
                            SocketAddrV4 { ip: dst, port },
                            &mut tx_wlan_out,
                        );
                        flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
                        r
                    } else {
                        let r = eth_stack.tcp_connect(
                            now_ms,
                            SocketAddrV4 { ip: dst, port },
                            &mut tx_eth_out,
                        );
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_eth_out);
                        }
                        r
                    };

                    match conn_res {
                        Ok(sock_id) => {
                            pending_tcp.push(PendingTcpConnect {
                                iface: if use_wlan {
                                    iface_id::WLAN0
                                } else {
                                    iface_id::VIRTIO0
                                },
                                client_idx: idx,
                                sock_id,
                                deadline_ms: now_ms + u64::from(timeout_ms.clamp(200, 15_000)),
                            });
                        }
                        Err(_) => {
                            let stack_up = dst.is_loopback()
                                || (nic.is_some()
                                    && eth_stack.cfg.link_up
                                    && !eth_stack.cfg.ip.is_unspecified())
                                || (wlan_present
                                    && wlan_stack.cfg.link_up
                                    && !wlan_stack.cfg.ip.is_unspecified());
                            let st = if stack_up {
                                NetStatus::Unreachable
                            } else {
                                NetStatus::NetworkDown
                            };
                            let mut rep = [0u8; 8];
                            net::write_header(&mut rep, NetOp::OpenTcp, st);
                            if let Some(c) = clients[idx].as_ref() {
                                let _ = c.ch.write(&rep);
                            }
                        }
                    }
                }
                NetOp::OpenUdp => {
                    let req_port = if payload.len() >= 2 {
                        u16::from_le_bytes([payload[0], payload[1]])
                    } else {
                        0
                    };
                    let route_if = select_route_iface(
                        None,
                        nic.is_some(),
                        &eth_stack,
                        wlan_present,
                        &wlan_stack,
                    );
                    let use_wlan = route_if == iface_id::WLAN0;
                    let bind_res = if use_wlan {
                        wlan_stack.udp_bind(req_port)
                    } else {
                        eth_stack.udp_bind(req_port)
                    };
                    match (bind_res, Channel::pair()) {
                        (Ok((sock_id, bound_port)), Ok((srv_ch, cli_ch))) => {
                            let mut rep = [0u8; 10];
                            net::write_header(&mut rep, NetOp::OpenUdp, NetStatus::Ok);
                            rep[8..10].copy_from_slice(&bound_port.to_le_bytes());
                            if let Some(c) = clients[idx].as_ref() {
                                if c.ch.write_handle(&rep, cli_ch.into_handle()).is_ok() {
                                    active_udp.push(ActiveUdpBridge {
                                        iface: if use_wlan {
                                            iface_id::WLAN0
                                        } else {
                                            iface_id::VIRTIO0
                                        },
                                        sock_id,
                                        ch: srv_ch,
                                    });
                                } else if use_wlan {
                                    wlan_stack.udp_close(sock_id);
                                } else {
                                    eth_stack.udp_close(sock_id);
                                }
                            }
                        }
                        _ => {
                            let mut rep = [0u8; 10];
                            net::write_header(&mut rep, NetOp::OpenUdp, NetStatus::Busy);
                            if let Some(c) = clients[idx].as_ref() {
                                let _ = c.ch.write(&rep);
                            }
                        }
                    }
                }
                NetOp::SetDhcp => {
                    let target_if = payload.first().copied().unwrap_or(iface_id::VIRTIO0);
                    let enable = payload.get(1).copied().unwrap_or(1) != 0;
                    if target_if == iface_id::WLAN0 {
                        if enable {
                            wlan_stack.start_dhcp(now_ms, &mut tx_wlan_out);
                            flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
                        } else {
                            wlan_stack.cfg.dhcp_bound = false;
                        }
                    } else if enable {
                        eth_stack.start_dhcp(now_ms, &mut tx_eth_out);
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_eth_out);
                        }
                    } else {
                        eth_stack.cfg.dhcp_bound = false;
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::SetDhcp, NetStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::SetStaticIp => {
                    if payload.len() >= 10 {
                        let target_if = payload[0];
                        let prefix = payload[1];
                        let ip = Ipv4Addr([payload[2], payload[3], payload[4], payload[5]]);
                        let gw = Ipv4Addr([payload[6], payload[7], payload[8], payload[9]]);
                        if target_if == iface_id::WLAN0 {
                            let dns = if wlan_stack.cfg.dns_server.is_unspecified() {
                                gw
                            } else {
                                wlan_stack.cfg.dns_server
                            };
                            wlan_stack.configure_static(ip, prefix_to_mask(prefix), gw, dns);
                        } else {
                            let dns = if eth_stack.cfg.dns_server.is_unspecified() {
                                gw
                            } else {
                                eth_stack.cfg.dns_server
                            };
                            eth_stack.configure_static(ip, prefix_to_mask(prefix), gw, dns);
                        }
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::SetStaticIp, NetStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::SetDns => {
                    if payload.len() >= 4 {
                        let dns = Ipv4Addr([payload[0], payload[1], payload[2], payload[3]]);
                        eth_stack.cfg.dns_server = dns;
                        wlan_stack.cfg.dns_server = dns;
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::SetDns, NetStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::QueryArp => {
                    let mut rep = [0u8; 9];
                    net::write_header(&mut rep, NetOp::QueryArp, NetStatus::Ok);
                    rep[8] = 0;
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
            }
        }

        // 4. Complete pending Ping / DNS / TCP-Connect waits across both stacks
        let mut p_idx = 0usize;
        while p_idx < pending_pings.len() {
            let pw = &pending_pings[p_idx];
            let done_opt = if pw.iface == iface_id::WLAN0 {
                wlan_stack.ping_poll(pw.ident, pw.seq)
            } else {
                eth_stack.ping_poll(pw.ident, pw.seq)
            };
            if let Some(done) = done_opt {
                let res = AbiPingResult {
                    responder_ipv4: pw.target_ip,
                    seq: done.seq,
                    payload_bytes: done.reply_bytes,
                    ttl: done.ttl,
                    rtt_us: done.rtt_us.unwrap_or(100),
                };
                if let Some(Some(c)) = clients.get(pw.client_idx) {
                    let _ = c.ch.write(&encode_ping_reply(NetStatus::Ok, &res));
                }
                let _ = pending_pings.swap_remove(p_idx);
            } else if now_ms >= pw.deadline_ms {
                if let Some(Some(c)) = clients.get(pw.client_idx) {
                    let _ = c.ch.write(&encode_ping_reply(
                        NetStatus::TimedOut,
                        &AbiPingResult::default(),
                    ));
                }
                let _ = pending_pings.swap_remove(p_idx);
            } else {
                p_idx += 1;
            }
        }

        let mut d_idx = 0usize;
        while d_idx < pending_dns.len() {
            let dw = &pending_dns[d_idx];
            let res_opt = if dw.iface == iface_id::WLAN0 {
                wlan_stack.dns_poll(dw.txid)
            } else {
                eth_stack.dns_poll(dw.txid)
            };
            if let Some(res) = res_opt {
                let mut rep = [0u8; 16];
                match res {
                    Ok(ip) => {
                        net::write_header(&mut rep, NetOp::ResolveDns, NetStatus::Ok);
                        rep[8..12].copy_from_slice(&ip.0);
                        rep[12..16].copy_from_slice(&300u32.to_le_bytes());
                    }
                    Err(_) => {
                        net::write_header(&mut rep, NetOp::ResolveDns, NetStatus::NameNotFound);
                    }
                }
                if let Some(Some(c)) = clients.get(dw.client_idx) {
                    let _ = c.ch.write(&rep);
                }
                let _ = pending_dns.swap_remove(d_idx);
            } else if now_ms >= dw.deadline_ms {
                let mut rep = [0u8; 16];
                net::write_header(&mut rep, NetOp::ResolveDns, NetStatus::TimedOut);
                if let Some(Some(c)) = clients.get(dw.client_idx) {
                    let _ = c.ch.write(&rep);
                }
                let _ = pending_dns.swap_remove(d_idx);
            } else {
                d_idx += 1;
            }
        }

        let mut c_idx = 0usize;
        while c_idx < pending_tcp.len() {
            let cw = &pending_tcp[c_idx];
            let st_opt = if cw.iface == iface_id::WLAN0 {
                wlan_stack.tcp_state(cw.sock_id)
            } else {
                eth_stack.tcp_state(cw.sock_id)
            };
            match st_opt {
                Some((TcpState::Established | TcpState::CloseWait, false)) => {
                    if let Ok((srv_ch, cli_ch)) = Channel::pair() {
                        let mut rep = [0u8; 8];
                        net::write_header(&mut rep, NetOp::OpenTcp, NetStatus::Ok);
                        if let Some(Some(c)) = clients.get(cw.client_idx) {
                            if c.ch.write_handle(&rep, cli_ch.into_handle()).is_ok() {
                                active_tcp.push(ActiveTcpBridge {
                                    iface: cw.iface,
                                    sock_id: cw.sock_id,
                                    data_ch: srv_ch,
                                });
                            } else if cw.iface == iface_id::WLAN0 {
                                wlan_stack.tcp_close(now_ms, cw.sock_id, &mut tx_wlan_out);
                            } else {
                                eth_stack.tcp_close(now_ms, cw.sock_id, &mut tx_eth_out);
                            }
                        }
                    }
                    let _ = pending_tcp.swap_remove(c_idx);
                }
                Some((_, true)) | None => {
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::OpenTcp, NetStatus::ConnectionRefused);
                    if let Some(Some(c)) = clients.get(cw.client_idx) {
                        let _ = c.ch.write(&rep);
                    }
                    let _ = pending_tcp.swap_remove(c_idx);
                }
                _ if now_ms >= cw.deadline_ms => {
                    if cw.iface == iface_id::WLAN0 {
                        wlan_stack.tcp_close(now_ms, cw.sock_id, &mut tx_wlan_out);
                    } else {
                        eth_stack.tcp_close(now_ms, cw.sock_id, &mut tx_eth_out);
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::OpenTcp, NetStatus::TimedOut);
                    if let Some(Some(c)) = clients.get(cw.client_idx) {
                        let _ = c.ch.write(&rep);
                    }
                    let _ = pending_tcp.swap_remove(c_idx);
                }
                _ => c_idx += 1,
            }
        }

        // 5. Pump active TCP & UDP data channels across both stacks
        let mut t_idx = 0usize;
        let mut sbuf = [0u8; 1460];
        while t_idx < active_tcp.len() {
            let sock_id = active_tcp[t_idx].sock_id;
            let is_wlan = active_tcp[t_idx].iface == iface_id::WLAN0;
            let mut close_bridge = false;

            match active_tcp[t_idx].data_ch.read_into(&mut sbuf) {
                Ok(n) if n > 0 => {
                    if is_wlan {
                        let _ = wlan_stack.tcp_send(now_ms, sock_id, &sbuf[..n], &mut tx_wlan_out);
                    } else {
                        let _ = eth_stack.tcp_send(now_ms, sock_id, &sbuf[..n], &mut tx_eth_out);
                    }
                }
                Ok(_) | Err(ErrorCode::ShouldWait) => {}
                Err(ErrorCode::PeerClosed) | Err(_) => {
                    if is_wlan {
                        wlan_stack.tcp_close(now_ms, sock_id, &mut tx_wlan_out);
                    } else {
                        eth_stack.tcp_close(now_ms, sock_id, &mut tx_eth_out);
                    }
                    close_bridge = true;
                }
            }

            if !close_bridge {
                let recv_res = if is_wlan {
                    wlan_stack.tcp_recv(sock_id, &mut sbuf)
                } else {
                    eth_stack.tcp_recv(sock_id, &mut sbuf)
                };
                match recv_res {
                    Ok(0) => {
                        close_bridge = true;
                    }
                    Ok(n) => {
                        if active_tcp[t_idx].data_ch.write(&sbuf[..n]).is_err() {
                            if is_wlan {
                                wlan_stack.tcp_close(now_ms, sock_id, &mut tx_wlan_out);
                            } else {
                                eth_stack.tcp_close(now_ms, sock_id, &mut tx_eth_out);
                            }
                            close_bridge = true;
                        }
                    }
                    Err(NetError::WouldBlock) => {}
                    Err(_) => {
                        close_bridge = true;
                    }
                }
            }

            if close_bridge {
                let _ = active_tcp.swap_remove(t_idx);
            } else {
                t_idx += 1;
            }
        }

        let mut u_idx = 0usize;
        let mut ubuf = [0u8; 1500];
        while u_idx < active_udp.len() {
            let sock_id = active_udp[u_idx].sock_id;
            let is_wlan = active_udp[u_idx].iface == iface_id::WLAN0;
            let mut close_udp = false;
            match active_udp[u_idx].ch.read_into(&mut ubuf) {
                Ok(n) if n >= 6 => {
                    let dst = SocketAddrV4 {
                        ip: Ipv4Addr([ubuf[0], ubuf[1], ubuf[2], ubuf[3]]),
                        port: u16::from_le_bytes([ubuf[4], ubuf[5]]),
                    };
                    if is_wlan {
                        let _ = wlan_stack.udp_send_to(
                            now_ms,
                            sock_id,
                            dst,
                            &ubuf[6..n],
                            &mut tx_wlan_out,
                        );
                    } else {
                        let _ = eth_stack.udp_send_to(
                            now_ms,
                            sock_id,
                            dst,
                            &ubuf[6..n],
                            &mut tx_eth_out,
                        );
                    }
                }
                Ok(_) | Err(ErrorCode::ShouldWait) => {}
                Err(_) => {
                    if is_wlan {
                        wlan_stack.udp_close(sock_id);
                    } else {
                        eth_stack.udp_close(sock_id);
                    }
                    close_udp = true;
                }
            }
            if !close_udp {
                let dgram_res = if is_wlan {
                    wlan_stack.udp_recv_from(sock_id)
                } else {
                    eth_stack.udp_recv_from(sock_id)
                };
                if let Ok(dgram) = dgram_res {
                    let mut msg = alloc::vec![0u8; 6 + dgram.data.len()];
                    msg[0..4].copy_from_slice(&dgram.src.ip.0);
                    msg[4..6].copy_from_slice(&dgram.src.port.to_le_bytes());
                    msg[6..].copy_from_slice(&dgram.data);
                    let _ = active_udp[u_idx].ch.write(&msg);
                }
            }
            if close_udp {
                let _ = active_udp.swap_remove(u_idx);
            } else {
                u_idx += 1;
            }
        }

        if let Some(n) = nic.as_mut() {
            n.flush_tx(&mut tx_eth_out);
        }
        flush_wlan_tx(wlan_uplink_ch.as_ref(), &mut tx_wlan_out);
        libcanvas::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::debug::write_str("[net-service] PANIC\n");
    libcanvas::process::exit(-99);
}
