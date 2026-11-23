//! RFC 793 / RFC 6298 TCP state machine with bounded 16 KiB RX/TX ring buffers
//! and exponential-backoff retransmission.

use alloc::collections::VecDeque;

use crate::wire::{TcpSegment, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use crate::{Ipv4Addr, NetError, SocketAddrV4};

pub const TCP_RING_CAP: usize = 16 * 1024;
pub const TCP_DEFAULT_MSS: u16 = 1460;
const INITIAL_RTO_MS: u64 = 250;
const MAX_RETRIES: u8 = 6;

/// TCP connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

/// Outbound TCP segment descriptor emitted by a `TcpSocket`.
#[derive(Clone, Debug)]
pub struct OutboundTcp {
    pub local_port: u16,
    pub remote: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload_len: usize,
    pub payload: [u8; 1460],
}

impl OutboundTcp {
    pub fn control(
        local_port: u16,
        remote: SocketAddrV4,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
    ) -> Self {
        Self {
            local_port,
            remote,
            seq,
            ack,
            flags,
            window,
            mss,
            payload_len: 0,
            payload: [0u8; 1460],
        }
    }
}

/// One TCP socket entry.
pub struct TcpSocket {
    pub id: u32,
    pub state: TcpState,
    pub local_port: u16,
    pub remote: SocketAddrV4,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub remote_wnd: u16,
    pub peer_mss: u16,
    pub rx_buf: VecDeque<u8>,
    pub tx_buf: VecDeque<u8>,
    pub fin_queued: bool,
    pub fin_sent: bool,
    pub reset_error: bool,
    pub rto_ms: u64,
    pub last_tx_ms: u64,
    pub retries: u8,
    pub timewait_until_ms: u64,
}

impl TcpSocket {
    pub fn new_connect(
        id: u32,
        local_port: u16,
        remote: SocketAddrV4,
        iss: u32,
        now_ms: u64,
    ) -> (Self, OutboundTcp) {
        let sock = Self {
            id,
            state: TcpState::SynSent,
            local_port,
            remote,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: 0,
            remote_wnd: TCP_RING_CAP as u16,
            peer_mss: TCP_DEFAULT_MSS,
            rx_buf: VecDeque::with_capacity(4096),
            tx_buf: VecDeque::with_capacity(4096),
            fin_queued: false,
            fin_sent: false,
            reset_error: false,
            rto_ms: INITIAL_RTO_MS,
            last_tx_ms: now_ms,
            retries: 0,
            timewait_until_ms: 0,
        };
        let syn = OutboundTcp::control(
            local_port,
            remote,
            iss,
            0,
            TCP_SYN,
            TCP_RING_CAP as u16,
            Some(TCP_DEFAULT_MSS),
        );
        (sock, syn)
    }

    pub fn new_listen(id: u32, local_port: u16) -> Self {
        Self {
            id,
            state: TcpState::Listen,
            local_port,
            remote: SocketAddrV4 {
                ip: Ipv4Addr::UNSPECIFIED,
                port: 0,
            },
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            remote_wnd: TCP_RING_CAP as u16,
            peer_mss: TCP_DEFAULT_MSS,
            rx_buf: VecDeque::with_capacity(4096),
            tx_buf: VecDeque::with_capacity(4096),
            fin_queued: false,
            fin_sent: false,
            reset_error: false,
            rto_ms: INITIAL_RTO_MS,
            last_tx_ms: 0,
            retries: 0,
            timewait_until_ms: 0,
        }
    }

    pub fn rx_window(&self) -> u16 {
        TCP_RING_CAP.saturating_sub(self.rx_buf.len()).min(65535) as u16
    }

    pub fn enqueue_send(&mut self, data: &[u8]) -> Result<usize, NetError> {
        if self.reset_error {
            return Err(NetError::ConnectionReset);
        }
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(NetError::InvalidState);
        }
        let free = TCP_RING_CAP.saturating_sub(self.tx_buf.len());
        if free == 0 && !data.is_empty() {
            return Err(NetError::WouldBlock);
        }
        let take = data.len().min(free);
        for &b in &data[..take] {
            self.tx_buf.push_back(b);
        }
        Ok(take)
    }

    pub fn dequeue_recv(&mut self, out: &mut [u8]) -> Result<usize, NetError> {
        if !self.rx_buf.is_empty() {
            let take = out.len().min(self.rx_buf.len());
            for slot in out.iter_mut().take(take) {
                *slot = self.rx_buf.pop_front().unwrap_or(0);
            }
            return Ok(take);
        }
        if self.reset_error {
            return Err(NetError::ConnectionReset);
        }
        if matches!(
            self.state,
            TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait | TcpState::Closed
        ) {
            return Ok(0); // Clean EOF
        }
        Err(NetError::WouldBlock)
    }

    pub fn initiate_close(&mut self) {
        match self.state {
            TcpState::SynSent | TcpState::Listen => {
                self.state = TcpState::Closed;
            }
            TcpState::Established => {
                self.fin_queued = true;
                self.state = TcpState::FinWait1;
            }
            TcpState::CloseWait => {
                self.fin_queued = true;
                self.state = TcpState::LastAck;
            }
            _ => {}
        }
    }

    /// Flush any unsent bytes in `tx_buf` (or a queued `FIN`) within the peer window.
    pub fn flush_unsent(&mut self, now_ms: u64, out: &mut VecDeque<OutboundTcp>) {
        if !matches!(
            self.state,
            TcpState::Established | TcpState::CloseWait | TcpState::FinWait1 | TcpState::LastAck
        ) {
            return;
        }
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        let fin_in_flight = usize::from(self.fin_sent);
        let data_in_flight = in_flight.saturating_sub(fin_in_flight);

        while data_in_flight < self.tx_buf.len() {
            let cur_in_flight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let cur_data_in_flight = cur_in_flight.saturating_sub(usize::from(self.fin_sent));
            if cur_data_in_flight >= self.tx_buf.len() {
                break;
            }
            let wnd_avail =
                usize::from(self.remote_wnd.max(536)).saturating_sub(cur_data_in_flight);
            if wnd_avail == 0 {
                break;
            }
            let unsent = self.tx_buf.len() - cur_data_in_flight;
            let seg_len = unsent
                .min(wnd_avail)
                .min(usize::from(self.peer_mss.min(1460)));
            if seg_len == 0 {
                break;
            }
            let mut seg = OutboundTcp::control(
                self.local_port,
                self.remote,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_ACK | TCP_PSH,
                self.rx_window(),
                None,
            );
            for i in 0..seg_len {
                seg.payload[i] = self.tx_buf[cur_data_in_flight + i];
            }
            seg.payload_len = seg_len;
            self.snd_nxt = self.snd_nxt.wrapping_add(seg_len as u32);
            if self.fin_queued
                && !self.fin_sent
                && (cur_data_in_flight + seg_len == self.tx_buf.len())
            {
                seg.flags |= TCP_FIN;
                self.fin_sent = true;
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
            }
            self.last_tx_ms = now_ms;
            out.push_back(seg);
        }

        if self.fin_queued && !self.fin_sent && self.tx_buf.is_empty() {
            let seg = OutboundTcp::control(
                self.local_port,
                self.remote,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_FIN | TCP_ACK,
                self.rx_window(),
                None,
            );
            self.fin_sent = true;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.last_tx_ms = now_ms;
            out.push_back(seg);
        }
    }

    /// Handle an incoming TCP segment destined to this socket.
    pub fn on_segment(
        &mut self,
        src_ip: Ipv4Addr,
        seg: &TcpSegment<'_>,
        iss_seed: u32,
        now_ms: u64,
        out: &mut VecDeque<OutboundTcp>,
    ) {
        if (seg.flags & TCP_RST) != 0 {
            self.reset_error = true;
            self.state = TcpState::Closed;
            return;
        }
        if let Some(m) = seg.mss {
            self.peer_mss = m.clamp(536, 1460);
        }
        self.remote_wnd = seg.window;

        match self.state {
            TcpState::Closed => {}
            TcpState::Listen => {
                if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
                    self.remote = SocketAddrV4 {
                        ip: src_ip,
                        port: seg.src_port,
                    };
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.snd_una = iss_seed;
                    self.snd_nxt = iss_seed.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    self.last_tx_ms = now_ms;
                    out.push_back(OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        iss_seed,
                        self.rcv_nxt,
                        TCP_SYN | TCP_ACK,
                        self.rx_window(),
                        Some(TCP_DEFAULT_MSS),
                    ));
                }
            }
            TcpState::SynSent => {
                if (seg.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
                    && seg.ack == self.snd_nxt
                {
                    self.snd_una = seg.ack;
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.state = TcpState::Established;
                    self.retries = 0;
                    self.rto_ms = INITIAL_RTO_MS;
                    out.push_back(OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        self.snd_nxt,
                        self.rcv_nxt,
                        TCP_ACK,
                        self.rx_window(),
                        None,
                    ));
                    self.flush_unsent(now_ms, out);
                } else if (seg.flags & TCP_SYN) != 0 && (seg.flags & TCP_ACK) == 0 {
                    // Simultaneous open
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    out.push_back(OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        self.snd_una,
                        self.rcv_nxt,
                        TCP_SYN | TCP_ACK,
                        self.rx_window(),
                        Some(TCP_DEFAULT_MSS),
                    ));
                }
            }
            TcpState::SynReceived => {
                if (seg.flags & TCP_ACK) != 0 && seg.ack == self.snd_nxt {
                    self.snd_una = seg.ack;
                    self.state = TcpState::Established;
                    self.retries = 0;
                    self.rto_ms = INITIAL_RTO_MS;
                }
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::LastAck
            | TcpState::TimeWait => {
                if (seg.flags & TCP_ACK) != 0 {
                    let acked = seg.ack.wrapping_sub(self.snd_una);
                    let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
                    if acked > 0 && acked <= in_flight {
                        let data_acked = (acked as usize).min(self.tx_buf.len());
                        for _ in 0..data_acked {
                            let _ = self.tx_buf.pop_front();
                        }
                        self.snd_una = seg.ack;
                        self.retries = 0;
                        self.rto_ms = INITIAL_RTO_MS;

                        if self.snd_una == self.snd_nxt && self.fin_sent {
                            if self.state == TcpState::FinWait1 {
                                self.state = TcpState::FinWait2;
                            } else if self.state == TcpState::LastAck {
                                self.state = TcpState::Closed;
                                return;
                            }
                        }
                    }
                }

                let mut send_ack = false;
                if !seg.payload.is_empty() {
                    if seg.seq == self.rcv_nxt {
                        let free = TCP_RING_CAP.saturating_sub(self.rx_buf.len());
                        let take = seg.payload.len().min(free);
                        for &b in &seg.payload[..take] {
                            self.rx_buf.push_back(b);
                        }
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                    }
                    send_ack = true;
                }

                if (seg.flags & TCP_FIN) != 0
                    && seg.seq.wrapping_add(seg.payload.len() as u32) == self.rcv_nxt
                {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    send_ack = true;
                    match self.state {
                        TcpState::Established => self.state = TcpState::CloseWait,
                        TcpState::FinWait1 => {
                            if self.snd_una == self.snd_nxt {
                                self.state = TcpState::TimeWait;
                                self.timewait_until_ms = now_ms + 1_000;
                            } else {
                                self.state = TcpState::CloseWait;
                            }
                        }
                        TcpState::FinWait2 => {
                            self.state = TcpState::TimeWait;
                            self.timewait_until_ms = now_ms + 1_000;
                        }
                        _ => {}
                    }
                }

                if send_ack {
                    out.push_back(OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        self.snd_nxt,
                        self.rcv_nxt,
                        TCP_ACK,
                        self.rx_window(),
                        None,
                    ));
                }
                self.flush_unsent(now_ms, out);
            }
        }
    }

    /// Periodic retransmit & `TIME_WAIT` timer tick.
    pub fn on_timer(&mut self, now_ms: u64, out: &mut VecDeque<OutboundTcp>) {
        if self.state == TcpState::TimeWait && now_ms >= self.timewait_until_ms {
            self.state = TcpState::Closed;
            return;
        }
        if self.snd_una == self.snd_nxt {
            return;
        }
        if now_ms.saturating_sub(self.last_tx_ms) < self.rto_ms {
            return;
        }
        if self.retries >= MAX_RETRIES {
            self.reset_error = true;
            self.state = TcpState::Closed;
            return;
        }
        self.retries += 1;
        self.rto_ms = (self.rto_ms * 2).min(4_000);
        self.last_tx_ms = now_ms;

        match self.state {
            TcpState::SynSent => {
                out.push_back(OutboundTcp::control(
                    self.local_port,
                    self.remote,
                    self.snd_una,
                    0,
                    TCP_SYN,
                    self.rx_window(),
                    Some(TCP_DEFAULT_MSS),
                ));
            }
            TcpState::SynReceived => {
                out.push_back(OutboundTcp::control(
                    self.local_port,
                    self.remote,
                    self.snd_una,
                    self.rcv_nxt,
                    TCP_SYN | TCP_ACK,
                    self.rx_window(),
                    Some(TCP_DEFAULT_MSS),
                ));
            }
            TcpState::Established
            | TcpState::CloseWait
            | TcpState::FinWait1
            | TcpState::LastAck => {
                if !self.tx_buf.is_empty() {
                    let seg_len = self.tx_buf.len().min(usize::from(self.peer_mss.min(1460)));
                    let mut seg = OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        self.snd_una,
                        self.rcv_nxt,
                        TCP_ACK | TCP_PSH,
                        self.rx_window(),
                        None,
                    );
                    for i in 0..seg_len {
                        seg.payload[i] = self.tx_buf[i];
                    }
                    seg.payload_len = seg_len;
                    out.push_back(seg);
                } else if self.fin_sent {
                    out.push_back(OutboundTcp::control(
                        self.local_port,
                        self.remote,
                        self.snd_una,
                        self.rcv_nxt,
                        TCP_FIN | TCP_ACK,
                        self.rx_window(),
                        None,
                    ));
                }
            }
            _ => {}
        }
    }
}
