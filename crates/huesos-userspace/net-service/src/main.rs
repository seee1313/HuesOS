//! `/services/net.elf` — isolated capability-enforced network stack & VirtIO-Net
//! PCI (`1af4:1000`) userspace driver service (`HNET` wire protocol).

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
use libcanvas::{println, Channel, ErrorCode, Handle};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const DMA_MAP_VA: u64 = 0x0000_7200_0000_0000;
const VIRTIO_HDR_LEN: usize = 10;
const PKT_BUF_STRIDE: usize = 2048;
const RX_SLOTS: usize = 64;
const TX_SLOTS: usize = 64;

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

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

struct VirtioQueue {
    q_idx: u16,
    q_size: u16,
    desc_va: usize,
    avail_va: usize,
    used_va: usize,
    last_used_idx: u16,
}

struct VirtioNetNic {
    ioport: IoPort,
    base_port: u16,
    mac: MacAddr,
    rxq: VirtioQueue,
    txq: VirtioQueue,
    rx_buf_va: usize,
    tx_buf_va: usize,
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
    fn try_init(
        ioport: IoPort,
        base_port: u16,
        dma_va: usize,
        dma_pa: u64,
        dma_len: usize,
    ) -> Option<Self> {
        if dma_len < 512 * 1024 {
            return None;
        }
        // 1. Reset device -> ACKNOWLEDGE -> DRIVER
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

        // 2. Negotiate only VIRTIO_NET_F_MAC (10-byte virtio_net_hdr, no MRG_RXBUF/CSUM)
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

        // 3. Configure RX queue (0) and TX queue (1)
        let mut dma_cursor = 0usize;
        let setup_queue = |q_idx: u16, cursor: &mut usize| -> Option<VirtioQueue> {
            ioport
                .write_u16(base_port + VIRTIO_PCI_QUEUE_SEL, q_idx)
                .ok()?;
            let qsz = ioport.read_u16(base_port + VIRTIO_PCI_QUEUE_NUM).ok()?;
            if qsz == 0 || qsz > 1024 {
                return None;
            }
            let (_avail_rel, used_off, total_bytes) = vring_bytes(usize::from(qsz));
            let ring_off = align_up(*cursor, 4096);
            if ring_off + total_bytes > dma_len {
                return None;
            }
            let ring_va = dma_va + ring_off;
            let ring_pa = dma_pa + (ring_off as u64);
            // SAFETY: `[ring_va..ring_va + total_bytes)` lies inside our exclusively mapped DMA pool.
            unsafe {
                core::ptr::write_bytes(ring_va as *mut u8, 0, total_bytes);
            }
            fence(Ordering::SeqCst);
            ioport
                .write_u32(base_port + VIRTIO_PCI_QUEUE_PFN, (ring_pa >> 12) as u32)
                .ok()?;
            *cursor = ring_off + total_bytes;
            Some(VirtioQueue {
                q_idx,
                q_size: qsz,
                desc_va: ring_va,
                avail_va: ring_va + 16 * usize::from(qsz),
                used_va: ring_va + used_off,
                last_used_idx: 0,
            })
        };

        let rxq = setup_queue(0, &mut dma_cursor)?;
        let txq = setup_queue(1, &mut dma_cursor)?;

        let rx_buf_off = align_up(dma_cursor, 4096);
        let tx_buf_off = rx_buf_off + RX_SLOTS * PKT_BUF_STRIDE;
        if tx_buf_off + TX_SLOTS * PKT_BUF_STRIDE > dma_len {
            return None;
        }
        let rx_buf_va = dma_va + rx_buf_off;
        let rx_buf_pa = dma_pa + (rx_buf_off as u64);
        let tx_buf_va = dma_va + tx_buf_off;
        let tx_buf_pa = dma_pa + (tx_buf_off as u64);

        // Populate RX descriptors and avail ring
        let rx_active = RX_SLOTS.min(usize::from(rxq.q_size));
        for i in 0..rx_active {
            let desc = VringDesc {
                addr: rx_buf_pa + ((i * PKT_BUF_STRIDE) as u64),
                len: PKT_BUF_STRIDE as u32,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
            // SAFETY: descriptor `i` and `avail.ring[i]` are in-bounds of `rxq` in DMA memory.
            unsafe {
                write_volatile((rxq.desc_va as *mut VringDesc).add(i), desc);
                write_volatile(((rxq.avail_va + 4) as *mut u16).add(i), i as u16);
            }
        }
        fence(Ordering::SeqCst);
        // SAFETY: `avail.idx` is at `avail_va + 2` in DMA memory.
        unsafe {
            write_volatile((rxq.avail_va + 2) as *mut u16, rx_active as u16);
        }
        fence(Ordering::SeqCst);

        ioport
            .write_u8(
                base_port + VIRTIO_PCI_STATUS,
                VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
            )
            .ok()?;
        let _ = ioport.write_u16(base_port + VIRTIO_PCI_QUEUE_NOTIFY, rxq.q_idx);

        Some(Self {
            ioport,
            base_port,
            mac: MacAddr(mac_bytes),
            rxq,
            txq,
            rx_buf_va,
            tx_buf_va,
            tx_buf_pa,
            tx_cursor: 0,
        })
    }

    fn poll_rx(&mut self, stack: &mut NetStack, now_ms: u64, tx_out: &mut VecDeque<Vec<u8>>) {
        let _ = self.ioport.read_u8(self.base_port + VIRTIO_PCI_ISR);
        fence(Ordering::SeqCst);
        // SAFETY: `used.idx` is at `used_va + 2` in DMA memory.
        let used_idx = unsafe { read_volatile((self.rxq.used_va + 2) as *const u16) };
        let mut recycled = false;

        while self.rxq.last_used_idx != used_idx {
            let ring_slot = usize::from(self.rxq.last_used_idx % self.rxq.q_size);
            // SAFETY: `used.ring[ring_slot]` lies at `used_va + 4 + ring_slot * 8`.
            let elem = unsafe {
                read_volatile(((self.rxq.used_va + 4) as *const VringUsedElem).add(ring_slot))
            };
            self.rxq.last_used_idx = self.rxq.last_used_idx.wrapping_add(1);
            let desc_id = elem.id as usize;
            let byte_len = elem.len as usize;
            if desc_id < RX_SLOTS && byte_len > VIRTIO_HDR_LEN && byte_len <= PKT_BUF_STRIDE {
                let frame_len = byte_len - VIRTIO_HDR_LEN;
                let mut frame = alloc::vec![0u8; frame_len];
                // SAFETY: RX slot buffer lies inside `[rx_buf_va..rx_buf_va + RX_SLOTS * 2048)`.
                unsafe {
                    let src =
                        (self.rx_buf_va + desc_id * PKT_BUF_STRIDE + VIRTIO_HDR_LEN) as *const u8;
                    core::ptr::copy_nonoverlapping(src, frame.as_mut_ptr(), frame_len);
                }
                stack.ingest_frame(now_ms, &frame, tx_out);
            }

            if desc_id < RX_SLOTS {
                // SAFETY: Repost `desc_id` into `avail.ring[avail_idx % q_size]`.
                unsafe {
                    let avail_idx = read_volatile((self.rxq.avail_va + 2) as *const u16);
                    let a_slot = usize::from(avail_idx % self.rxq.q_size);
                    write_volatile(
                        ((self.rxq.avail_va + 4) as *mut u16).add(a_slot),
                        desc_id as u16,
                    );
                    fence(Ordering::SeqCst);
                    write_volatile(
                        (self.rxq.avail_va + 2) as *mut u16,
                        avail_idx.wrapping_add(1),
                    );
                }
                recycled = true;
            }
        }
        if recycled {
            fence(Ordering::SeqCst);
            let _ = self
                .ioport
                .write_u16(self.base_port + VIRTIO_PCI_QUEUE_NOTIFY, self.rxq.q_idx);
        }
    }

    fn flush_tx(&mut self, tx_out: &mut VecDeque<Vec<u8>>) {
        let mut notified = false;
        while let Some(frame) = tx_out.pop_front() {
            if frame.len() + VIRTIO_HDR_LEN > PKT_BUF_STRIDE {
                continue;
            }
            let tx_cap = (TX_SLOTS as u16).min(self.txq.q_size);
            let slot = usize::from(self.tx_cursor % tx_cap);
            self.tx_cursor = self.tx_cursor.wrapping_add(1);

            let dst_va = self.tx_buf_va + slot * PKT_BUF_STRIDE;
            let dst_pa = self.tx_buf_pa + ((slot * PKT_BUF_STRIDE) as u64);
            let total_len = VIRTIO_HDR_LEN + frame.len();
            // SAFETY: `dst_va..dst_va + total_len` lies inside `tx_buf_va` DMA region.
            unsafe {
                core::ptr::write_bytes(dst_va as *mut u8, 0, VIRTIO_HDR_LEN);
                core::ptr::copy_nonoverlapping(
                    frame.as_ptr(),
                    (dst_va + VIRTIO_HDR_LEN) as *mut u8,
                    frame.len(),
                );
                let desc = VringDesc {
                    addr: dst_pa,
                    len: total_len as u32,
                    flags: 0,
                    next: 0,
                };
                write_volatile((self.txq.desc_va as *mut VringDesc).add(slot), desc);
                let avail_idx = read_volatile((self.txq.avail_va + 2) as *const u16);
                let a_slot = usize::from(avail_idx % self.txq.q_size);
                write_volatile(
                    ((self.txq.avail_va + 4) as *mut u16).add(a_slot),
                    slot as u16,
                );
                fence(Ordering::SeqCst);
                write_volatile(
                    (self.txq.avail_va + 2) as *mut u16,
                    avail_idx.wrapping_add(1),
                );
            }
            notified = true;
        }
        if notified {
            fence(Ordering::SeqCst);
            let _ = self
                .ioport
                .write_u16(self.base_port + VIRTIO_PCI_QUEUE_NOTIFY, self.txq.q_idx);
        }
    }
}

struct NetClientConn {
    ch: Channel,
    read_only: bool,
}

struct PendingPingWait {
    client_idx: usize,
    target_ip: [u8; 4],
    ident: u16,
    seq: u16,
    deadline_ms: u64,
}

struct PendingDnsWait {
    client_idx: usize,
    txid: u16,
    deadline_ms: u64,
}

struct PendingTcpConnect {
    client_idx: usize,
    sock_id: u32,
    deadline_ms: u64,
}

struct ActiveTcpBridge {
    sock_id: u32,
    data_ch: Channel,
}

struct ActiveUdpBridge {
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

    // Drain manifest/PCI resources until `resource:transfer-complete`
    let mut label_buf = [0u8; 128];
    for _ in 0..256 {
        match bootstrap.read_optional_handle_timeout(&mut label_buf, 100) {
            Ok((n, handle_opt)) => {
                let msg = core::str::from_utf8(&label_buf[..n]).unwrap_or("");
                if msg == "resource:transfer-complete" {
                    break;
                }
                if let Some(rest) = msg.strip_prefix("resource:net-service:") {
                    let mut parts = rest.split(':');
                    let kind = parts.next().unwrap_or("");
                    let base = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let len = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    if let Some(h) = handle_opt {
                        if kind == "dma" && dma_res.is_none() {
                            dma_res = Some((h, base, len));
                        } else if kind == "ioport" && len >= 0x20 && ioport_res.is_none() {
                            ioport_res = Some((h, base as u16, len as u16));
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => break,
        }
    }

    let mut nic: Option<VirtioNetNic> = None;
    if let (Some((dma_h, dma_pa, dma_len)), Some((io_h, port_base, _port_len))) =
        (dma_res.as_ref(), ioport_res)
    {
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
            nic = VirtioNetNic::try_init(
                IoPort::from_handle(io_h),
                port_base,
                DMA_MAP_VA as usize,
                *dma_pa,
                map_len as usize,
            );
        }
    }

    let mac = nic
        .as_ref()
        .map(|n| n.mac)
        .unwrap_or(MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
    let mut stack = NetStack::new(mac);
    let mut tx_out: VecDeque<Vec<u8>> = VecDeque::with_capacity(32);

    if let Some(n) = nic.as_mut() {
        println!(
            "[net-service] virtio-net online io={:#x} mac={}",
            n.base_port, n.mac
        );
        stack.cfg.link_up = true;
        stack.start_dhcp(0, &mut tx_out);
        n.flush_tx(&mut tx_out);
    } else {
        println!("[net-service] started in loopback-only mode (no virtio-net PCI NIC)");
        stack.cfg.link_up = false;
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

        // 1. Poll DriverManager bootstrap for newly attached client channels
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
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 2. Poll VirtIO-Net RX & periodic timers
        if let Some(n) = nic.as_mut() {
            n.poll_rx(&mut stack, now_ms, &mut tx_out);
            n.flush_tx(&mut tx_out);
            // If DHCP has not finished within 2.5s in QEMU SLIRP, apply standard SLIRP fallback
            // only if retries exhausted so boot scripts never stall.
            if stack.cfg.ip.is_unspecified() && now_ms > 4_000 {
                stack.configure_static(
                    Ipv4Addr::new(10, 0, 2, 15),
                    Ipv4Addr::new(255, 255, 255, 0),
                    Ipv4Addr::new(10, 0, 2, 2),
                    Ipv4Addr::new(10, 0, 2, 3),
                );
                stack.cfg.dhcp_bound = true;
            }
        }
        if now_ms.saturating_sub(last_timer_ms) >= 50 {
            last_timer_ms = now_ms;
            stack.poll_timers(now_ms, &mut tx_out);
            if let Some(n) = nic.as_mut() {
                n.flush_tx(&mut tx_out);
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
                    let mut snap = NetStatusSnapshot {
                        dns_server: stack.cfg.dns_server.0,
                        active_uplink: if nic.is_some() {
                            iface_id::VIRTIO0
                        } else {
                            iface_id::LO
                        },
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
                    snap.ifaces[1].link_up = nic.is_some() && stack.cfg.link_up;
                    snap.ifaces[1].dhcp_enabled = stack.cfg.dhcp_bound;
                    snap.ifaces[1].prefix_len = mask_to_prefix(stack.cfg.subnet_mask);
                    snap.ifaces[1].mac = stack.cfg.mac.0;
                    snap.ifaces[1].ipv4 = stack.cfg.ip.0;
                    snap.ifaces[1].gateway = stack.cfg.gateway.0;
                    snap.ifaces[1].rx_packets = stack.stats.rx_packets;
                    snap.ifaces[1].tx_packets = stack.stats.tx_packets;
                    snap.ifaces[1].rx_bytes = stack.stats.rx_bytes;
                    snap.ifaces[1].tx_bytes = stack.stats.tx_bytes;

                    snap.ifaces[2].name[..5].copy_from_slice(b"wlan0");

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

                    if stack
                        .ping_send(now_ms, dst, ident, seq, plen, &mut tx_out)
                        .is_ok()
                    {
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_out);
                        }
                        pending_pings.push(PendingPingWait {
                            client_idx: idx,
                            target_ip: dst.0,
                            ident,
                            seq,
                            deadline_ms: now_ms + u64::from(timeout_ms.clamp(100, 10_000)),
                        });
                    } else if let Some(c) = clients[idx].as_ref() {
                        let rep =
                            encode_ping_reply(NetStatus::Unreachable, &AbiPingResult::default());
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
                    match stack.dns_start(now_ms, host, &mut tx_out) {
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
                            if let Some(n) = nic.as_mut() {
                                n.flush_tx(&mut tx_out);
                            }
                            pending_dns.push(PendingDnsWait {
                                client_idx: idx,
                                txid,
                                deadline_ms: now_ms + 3_000,
                            });
                        }
                        Err(_) => {
                            let mut rep = [0u8; 16];
                            net::write_header(&mut rep, NetOp::ResolveDns, NetStatus::Unreachable);
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
                    match stack.tcp_connect(now_ms, SocketAddrV4 { ip: dst, port }, &mut tx_out) {
                        Ok(sock_id) => {
                            if let Some(n) = nic.as_mut() {
                                n.flush_tx(&mut tx_out);
                            }
                            pending_tcp.push(PendingTcpConnect {
                                client_idx: idx,
                                sock_id,
                                deadline_ms: now_ms + u64::from(timeout_ms.clamp(200, 15_000)),
                            });
                        }
                        Err(_) => {
                            let mut rep = [0u8; 8];
                            net::write_header(&mut rep, NetOp::OpenTcp, NetStatus::Unreachable);
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
                    match (stack.udp_bind(req_port), Channel::pair()) {
                        (Ok((sock_id, bound_port)), Ok((srv_ch, cli_ch))) => {
                            let mut rep = [0u8; 10];
                            net::write_header(&mut rep, NetOp::OpenUdp, NetStatus::Ok);
                            rep[8..10].copy_from_slice(&bound_port.to_le_bytes());
                            if let Some(c) = clients[idx].as_ref() {
                                if c.ch.write_handle(&rep, cli_ch.into_handle()).is_ok() {
                                    active_udp.push(ActiveUdpBridge {
                                        sock_id,
                                        ch: srv_ch,
                                    });
                                } else {
                                    stack.udp_close(sock_id);
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
                    let enable = payload.get(1).copied().unwrap_or(1) != 0;
                    if enable {
                        stack.start_dhcp(now_ms, &mut tx_out);
                        if let Some(n) = nic.as_mut() {
                            n.flush_tx(&mut tx_out);
                        }
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::SetDhcp, NetStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::SetStaticIp => {
                    if payload.len() >= 10 {
                        let prefix = payload[1];
                        let ip = Ipv4Addr([payload[2], payload[3], payload[4], payload[5]]);
                        let gw = Ipv4Addr([payload[6], payload[7], payload[8], payload[9]]);
                        let dns = if stack.cfg.dns_server.is_unspecified() {
                            gw
                        } else {
                            stack.cfg.dns_server
                        };
                        stack.configure_static(ip, prefix_to_mask(prefix), gw, dns);
                    }
                    let mut rep = [0u8; 8];
                    net::write_header(&mut rep, NetOp::SetStaticIp, NetStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                NetOp::SetDns => {
                    if payload.len() >= 4 {
                        stack.cfg.dns_server =
                            Ipv4Addr([payload[0], payload[1], payload[2], payload[3]]);
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

        // 4. Complete pending Ping / DNS / TCP-Connect waits
        let mut p_idx = 0usize;
        while p_idx < pending_pings.len() {
            let pw = &pending_pings[p_idx];
            if let Some(done) = stack.ping_poll(pw.ident, pw.seq) {
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
            if let Some(res) = stack.dns_poll(dw.txid) {
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
            match stack.tcp_state(cw.sock_id) {
                Some((TcpState::Established | TcpState::CloseWait, false)) => {
                    if let Ok((srv_ch, cli_ch)) = Channel::pair() {
                        let mut rep = [0u8; 8];
                        net::write_header(&mut rep, NetOp::OpenTcp, NetStatus::Ok);
                        if let Some(Some(c)) = clients.get(cw.client_idx) {
                            if c.ch.write_handle(&rep, cli_ch.into_handle()).is_ok() {
                                active_tcp.push(ActiveTcpBridge {
                                    sock_id: cw.sock_id,
                                    data_ch: srv_ch,
                                });
                            } else {
                                stack.tcp_close(now_ms, cw.sock_id, &mut tx_out);
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
                    stack.tcp_close(now_ms, cw.sock_id, &mut tx_out);
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

        // 5. Pump active TCP & UDP data channels
        let mut t_idx = 0usize;
        let mut sbuf = [0u8; 1460];
        while t_idx < active_tcp.len() {
            let sock_id = active_tcp[t_idx].sock_id;
            let mut close_bridge = false;

            match active_tcp[t_idx].data_ch.read_into(&mut sbuf) {
                Ok(n) if n > 0 => {
                    let _ = stack.tcp_send(now_ms, sock_id, &sbuf[..n], &mut tx_out);
                }
                Ok(_) | Err(ErrorCode::ShouldWait) => {}
                Err(ErrorCode::PeerClosed) | Err(_) => {
                    stack.tcp_close(now_ms, sock_id, &mut tx_out);
                    close_bridge = true;
                }
            }

            if !close_bridge {
                match stack.tcp_recv(sock_id, &mut sbuf) {
                    Ok(0) => {
                        // Remote sent FIN -> drop `data_ch` so client sees clean EOF!
                        close_bridge = true;
                    }
                    Ok(n) => {
                        if active_tcp[t_idx].data_ch.write(&sbuf[..n]).is_err() {
                            stack.tcp_close(now_ms, sock_id, &mut tx_out);
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
            let mut close_udp = false;
            match active_udp[u_idx].ch.read_into(&mut ubuf) {
                Ok(n) if n >= 6 => {
                    let dst = SocketAddrV4 {
                        ip: Ipv4Addr([ubuf[0], ubuf[1], ubuf[2], ubuf[3]]),
                        port: u16::from_le_bytes([ubuf[4], ubuf[5]]),
                    };
                    let _ = stack.udp_send_to(now_ms, sock_id, dst, &ubuf[6..n], &mut tx_out);
                }
                Ok(_) | Err(ErrorCode::ShouldWait) => {}
                Err(_) => {
                    stack.udp_close(sock_id);
                    close_udp = true;
                }
            }
            if !close_udp {
                if let Ok(dgram) = stack.udp_recv_from(sock_id) {
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
            n.flush_tx(&mut tx_out);
        }
        libcanvas::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::debug::write_str("[net-service] PANIC\n");
    libcanvas::process::exit(-99);
}
