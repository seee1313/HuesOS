//! Plan 9 synthetic VFS namespaces for `/net/btl/*` and `/dev/audio/*`.
//!
//! Every file operation checks the caller's process capability mask (`BTL_*` or
//! `AUDIO_*`) and speaks to `btl-service` / `audio-service` through the granted
//! `CapKind::{BtlService, AudioService}` channels. Standard file tools (`ls`,
//! `cat`, `hexdump`, shell redirects) work seamlessly on both subtrees.

#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::collapsible_if,
    clippy::collapsible_match
)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use huesos_abi::audio::AudioRouteMode;
use huesos_abi::auxv::caps_mask;

use crate::audio::{self, AudioStream};
use crate::error::{Error, ErrorKind, Result};
use crate::fs::{Entry, EntryKind, Metadata};
use crate::net;
use crate::os::huesos::caps_mask as current_caps_mask;

/// True when `normalized` belongs to `/net`, `/net/btl/*`, or `/dev/audio/*`.
pub fn is_synth_path(normalized: &str) -> bool {
    normalized == "/net"
        || normalized == "/net/btl"
        || normalized.starts_with("/net/btl/")
        || normalized == "/dev/audio"
        || normalized.starts_with("/dev/audio/")
}

fn require_btl_ro() -> Result<()> {
    if (current_caps_mask() & caps_mask::BTL_RO) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

fn require_audio_ro() -> Result<()> {
    if (current_caps_mask() & caps_mask::AUDIO_RO) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

fn dir_meta() -> Metadata {
    Metadata {
        object_id: 0,
        len: 0,
        kind: EntryKind::Dir,
        mode: 0o755,
        modified_unix_ns: 0,
    }
}

fn file_meta(len: u64, mode: u32) -> Metadata {
    Metadata {
        object_id: 0,
        len,
        kind: EntryKind::File,
        mode,
        modified_unix_ns: 0,
    }
}

/// Stat a synthetic `/net/*` or `/dev/audio/*` path.
pub fn metadata(normalized: &str) -> Result<Metadata> {
    match normalized {
        "/net" => Ok(dir_meta()),
        "/net/btl" => {
            require_btl_ro()?;
            Ok(dir_meta())
        }
        "/net/btl/ctl" => {
            require_btl_ro()?;
            Ok(file_meta(render_btl_status()?.len() as u64, 0o660))
        }
        "/net/btl/status" => {
            require_btl_ro()?;
            Ok(file_meta(render_btl_status()?.len() as u64, 0o444))
        }
        "/net/btl/peers" => {
            require_btl_ro()?;
            Ok(file_meta(render_btl_peers()?.len() as u64, 0o444))
        }
        "/net/btl/keys" => {
            require_btl_ro()?;
            Ok(file_meta(render_btl_keys()?.len() as u64, 0o440))
        }
        "/net/btl/snoop" => {
            require_btl_ro()?;
            let st = net::btl_status()?;
            Ok(file_meta(u64::from(st.snoop_bytes), 0o440))
        }
        "/net/btl/clone" => {
            require_btl_ro()?;
            Ok(file_meta(2, 0o660))
        }
        "/dev/audio" => {
            require_audio_ro()?;
            Ok(dir_meta())
        }
        "/dev/audio/ctl" => {
            require_audio_ro()?;
            Ok(file_meta(render_audio_status()?.len() as u64, 0o660))
        }
        "/dev/audio/status" => {
            require_audio_ro()?;
            Ok(file_meta(render_audio_status()?.len() as u64, 0o444))
        }
        "/dev/audio/pcm" => {
            require_audio_ro()?;
            Ok(file_meta(0, 0o220))
        }
        _ => Err(Error::new(ErrorKind::NotFound)),
    }
}

/// List a synthetic directory (`/net`, `/net/btl`, or `/dev/audio`).
pub fn list(normalized: &str) -> Result<Vec<Entry>> {
    match normalized {
        "/net" => {
            let mask = current_caps_mask();
            let mut entries = Vec::new();
            if (mask & caps_mask::NET_RO) != 0 {
                entries.push(Entry {
                    name: String::from("ip"),
                    kind: EntryKind::Dir,
                    size: None,
                });
            }
            if (mask & caps_mask::WLAN_RO) != 0 {
                entries.push(Entry {
                    name: String::from("wlan"),
                    kind: EntryKind::Dir,
                    size: None,
                });
            }
            if (mask & caps_mask::BTL_RO) != 0 {
                entries.push(Entry {
                    name: String::from("btl"),
                    kind: EntryKind::Dir,
                    size: None,
                });
            }
            Ok(entries)
        }
        "/net/btl" => {
            require_btl_ro()?;
            let snoop_len = net::btl_status().map(|s| u64::from(s.snoop_bytes)).ok();
            Ok(alloc::vec![
                Entry {
                    name: String::from("ctl"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("status"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("peers"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("keys"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("snoop"),
                    kind: EntryKind::File,
                    size: snoop_len,
                },
                Entry {
                    name: String::from("clone"),
                    kind: EntryKind::File,
                    size: Some(2),
                },
            ])
        }
        "/dev/audio" => {
            require_audio_ro()?;
            Ok(alloc::vec![
                Entry {
                    name: String::from("ctl"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("status"),
                    kind: EntryKind::File,
                    size: None,
                },
                Entry {
                    name: String::from("pcm"),
                    kind: EntryKind::File,
                    size: Some(0),
                },
            ])
        }
        _ => Err(Error::new(ErrorKind::NotFound)),
    }
}

fn render_btl_status() -> Result<Vec<u8>> {
    let st = net::btl_status()?;
    let coex_name = match st.coex_profile {
        0 => "idle",
        1 => "inquiry-scan",
        2 => "a2dp-streaming",
        3 => "page-connect",
        _ => "unknown",
    };
    let mut out = String::with_capacity(384);
    let _ = writeln!(out, "transport={}", st.transport.as_str());
    let _ = writeln!(out, "powered={}", st.powered);
    let _ = writeln!(out, "firmware_loaded={}", st.firmware_loaded);
    let _ = writeln!(out, "fw_version=0x{:08x}", st.fw_version);
    let _ = writeln!(out, "usb_id={:04x}:{:04x}", st.usb_vid, st.usb_pid);
    let _ = writeln!(out, "bd_addr={}", net::format_bd_addr(&st.local_bd_addr));
    let _ = writeln!(
        out,
        "acl_credits={}/{} (mtu={})",
        st.acl_max_slots.saturating_sub(st.acl_in_flight),
        st.acl_max_slots,
        st.acl_mtu
    );
    let _ = writeln!(out, "coex_profile={} ({})", st.coex_profile, coex_name);
    let _ = writeln!(out, "peers={}", st.peer_count);
    let _ = writeln!(out, "saved_keys={}", st.saved_keys);
    let _ = writeln!(out, "open_l2cap_channels={}", st.open_l2cap_channels);
    let _ = writeln!(out, "tx_packets={}", st.tx_packets);
    let _ = writeln!(out, "rx_packets={}", st.rx_packets);
    let _ = writeln!(out, "snoop_bytes={}", st.snoop_bytes);
    Ok(out.into_bytes())
}

fn render_btl_peers() -> Result<Vec<u8>> {
    let peers = net::btl_list_peers()?;
    let mut out = String::with_capacity(256);
    let _ = writeln!(out, "bd_addr\trssi_dbm\tpaired\tconnected\ta2dp_sink\tname");
    for peer in &peers {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            net::format_bd_addr(&peer.bd_addr),
            peer.rssi_dbm,
            peer.is_paired(),
            peer.is_connected(),
            peer.is_audio_sink(),
            peer.name_str()
        );
    }
    Ok(out.into_bytes())
}

fn render_btl_keys() -> Result<Vec<u8>> {
    let keys = net::btl_list_keys()?;
    let mut out = String::with_capacity(192);
    let _ = writeln!(out, "bd_addr\tkey_type\tsha256_fp");
    for key in &keys {
        let _ = writeln!(
            out,
            "{}\t0x{:02x}\t{:02x}{:02x}{:02x}{:02x}",
            net::format_bd_addr(&key.bd_addr),
            key.key_type,
            key.key_fingerprint[0],
            key.key_fingerprint[1],
            key.key_fingerprint[2],
            key.key_fingerprint[3]
        );
    }
    Ok(out.into_bytes())
}

fn render_audio_status() -> Result<Vec<u8>> {
    let st = audio::status()?;
    let active_sink = match st.active_sinks_mask {
        0 => "none",
        1 => "virtio-snd",
        2 => "btl-a2dp",
        3 => "mirror(virtio-snd+btl-a2dp)",
        _ => "unknown",
    };
    let mut out = String::with_capacity(384);
    let _ = writeln!(out, "route_mode={}", st.route_mode.as_str());
    let _ = writeln!(out, "active_sink={}", active_sink);
    let _ = writeln!(out, "volume_pct={}", st.master_volume_pct);
    let _ = writeln!(out, "muted={}", st.muted);
    let _ = writeln!(out, "mix_sample_rate={}", st.mix_sample_rate);
    let _ = writeln!(out, "active_streams={}", st.active_streams);
    let _ = writeln!(out, "virtio_online={}", st.virtio_online);
    let _ = writeln!(out, "virtio_periods={}", st.virtio_periods);
    let _ = writeln!(out, "btl_streaming={}", st.btl_streaming);
    let _ = writeln!(
        out,
        "btl_peer={} ({})",
        net::format_bd_addr(&st.btl_peer_addr),
        st.btl_peer_name_str()
    );
    let _ = writeln!(
        out,
        "sbc_bitpool={} ({} kbps)",
        st.btl_sbc_bitpool, st.btl_bitrate_kbps
    );
    let _ = writeln!(out, "avrcp_events={}", st.avrcp_events);
    let _ = writeln!(out, "mixed_frames={}", st.mixed_frames);
    let _ = writeln!(out, "btl_rtp_packets={}", st.btl_rtp_packets);
    let _ = writeln!(out, "underruns={}", st.underruns);
    Ok(out.into_bytes())
}

fn execute_btl_ctl_line(line: &str) -> Result<()> {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Ok(());
    };
    match cmd {
        "power" => match parts.next().unwrap_or("") {
            "off" | "0" => net::btl_set_power(0),
            "on" | "1" => net::btl_set_power(1),
            "virtual" | "airbuds" | "2" => net::btl_set_power(2),
            _ => Err(Error::new(ErrorKind::InvalidInput)),
        },
        "scan" => net::btl_scan().map(|_| ()),
        "pair" => {
            let addr = parts
                .next()
                .and_then(net::parse_bd_addr)
                .ok_or(Error::new(ErrorKind::InvalidInput))?;
            net::btl_pair(addr)
        }
        "unpair" | "delete-key" => {
            let addr = parts
                .next()
                .and_then(net::parse_bd_addr)
                .ok_or(Error::new(ErrorKind::InvalidInput))?;
            net::btl_delete_key(addr)
        }
        "connect" => {
            let addr = parts
                .next()
                .and_then(net::parse_bd_addr)
                .ok_or(Error::new(ErrorKind::InvalidInput))?;
            net::btl_connect_acl(addr).map(|_| ())
        }
        "disconnect" => {
            let addr = parts
                .next()
                .and_then(net::parse_bd_addr)
                .ok_or(Error::new(ErrorKind::InvalidInput))?;
            net::btl_disconnect_acl(addr)
        }
        "coex" => {
            let profile = match parts.next().unwrap_or("") {
                "idle" | "0" => 0,
                "scan" | "1" => 1,
                "a2dp" | "2" => 2,
                "page" | "3" => 3,
                _ => return Err(Error::new(ErrorKind::InvalidInput)),
            };
            net::btl_set_coex_hint(profile)
        }
        _ => Err(Error::new(ErrorKind::InvalidInput)),
    }
}

fn execute_audio_ctl_line(line: &str) -> Result<()> {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Ok(());
    };
    match cmd {
        "volume" | "vol" => {
            let vol = parts
                .next()
                .and_then(|s| s.parse::<u8>().ok())
                .ok_or(Error::new(ErrorKind::InvalidInput))?;
            let muted = audio::status().map(|s| s.muted).unwrap_or(false);
            audio::set_volume(vol.min(100), muted)
        }
        "mute" => {
            let vol = audio::status().map(|s| s.master_volume_pct).unwrap_or(80);
            audio::set_volume(vol, true)
        }
        "unmute" => {
            let vol = audio::status().map(|s| s.master_volume_pct).unwrap_or(80);
            audio::set_volume(vol, false)
        }
        "route" => {
            let mode = match parts.next().unwrap_or("") {
                "auto" => AudioRouteMode::Auto,
                "virtio" | "snd" => AudioRouteMode::VirtioOnly,
                "btl" | "bt" | "a2dp" => AudioRouteMode::BtlOnly,
                "mirror" | "both" => AudioRouteMode::Mirror,
                _ => return Err(Error::new(ErrorKind::InvalidInput)),
            };
            audio::set_route_mode(mode)
        }
        "bt-connect" => {
            let addr = match parts.next() {
                Some(raw) => {
                    Some(net::parse_bd_addr(raw).ok_or(Error::new(ErrorKind::InvalidInput))?)
                }
                None => None,
            };
            audio::connect_btl_sink(addr)
        }
        "bt-disconnect" => audio::disconnect_btl_sink(),
        "tone" => {
            let freq = parts
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(440);
            let ms = parts
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200);
            audio::play_test_tone(freq, ms)
        }
        _ => Err(Error::new(ErrorKind::InvalidInput)),
    }
}

/// Backing state for an open synthetic file under `/net/btl/*` or `/dev/audio/*`.
pub enum SynthFile {
    Snapshot(Vec<u8>),
    BtlCtl(Vec<u8>),
    AudioCtl(Vec<u8>),
    AudioPcm { stream: Option<AudioStream> },
}

/// Open a synthetic file under `/net/btl/*` or `/dev/audio/*`.
pub fn open_file(normalized: &str) -> Result<SynthFile> {
    match normalized {
        "/net" | "/net/btl" | "/dev/audio" => Err(Error::new(ErrorKind::InvalidInput)),
        "/net/btl/status" => Ok(SynthFile::Snapshot(render_btl_status()?)),
        "/net/btl/peers" => Ok(SynthFile::Snapshot(render_btl_peers()?)),
        "/net/btl/keys" => Ok(SynthFile::Snapshot(render_btl_keys()?)),
        "/net/btl/snoop" => Ok(SynthFile::Snapshot(net::btl_read_snoop()?)),
        "/net/btl/clone" => {
            require_btl_ro()?;
            let st = net::btl_status()?;
            Ok(SynthFile::Snapshot(
                format!("{}\n", st.open_l2cap_channels).into_bytes(),
            ))
        }
        "/net/btl/ctl" => Ok(SynthFile::BtlCtl(render_btl_status()?)),
        "/dev/audio/status" => Ok(SynthFile::Snapshot(render_audio_status()?)),
        "/dev/audio/ctl" => Ok(SynthFile::AudioCtl(render_audio_status()?)),
        "/dev/audio/pcm" => {
            require_audio_ro()?;
            Ok(SynthFile::AudioPcm { stream: None })
        }
        _ => Err(Error::new(ErrorKind::NotFound)),
    }
}

impl SynthFile {
    /// Current readable byte length.
    pub fn size(&self) -> u64 {
        match self {
            Self::Snapshot(buf) | Self::BtlCtl(buf) | Self::AudioCtl(buf) => buf.len() as u64,
            Self::AudioPcm { .. } => 0,
        }
    }

    /// Read at `position` into `dst`.
    pub fn read_at(&self, position: u64, dst: &mut [u8]) -> Result<usize> {
        let src = match self {
            Self::Snapshot(buf) | Self::BtlCtl(buf) | Self::AudioCtl(buf) => buf.as_slice(),
            Self::AudioPcm { .. } => return Ok(0),
        };
        let pos = usize::try_from(position).unwrap_or(src.len());
        if pos >= src.len() {
            return Ok(0);
        }
        let n = dst.len().min(src.len() - pos);
        dst[..n].copy_from_slice(&src[pos..pos + n]);
        Ok(n)
    }

    /// Write `src` into a control or PCM synthetic file.
    pub fn write(&mut self, src: &[u8]) -> Result<usize> {
        match self {
            Self::Snapshot(_) => Err(Error::capability()),
            Self::BtlCtl(_) => {
                let text =
                    core::str::from_utf8(src).map_err(|_| Error::new(ErrorKind::InvalidInput))?;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        execute_btl_ctl_line(trimmed)?;
                    }
                }
                Ok(src.len())
            }
            Self::AudioCtl(_) => {
                let text =
                    core::str::from_utf8(src).map_err(|_| Error::new(ErrorKind::InvalidInput))?;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        execute_audio_ctl_line(trimmed)?;
                    }
                }
                Ok(src.len())
            }
            Self::AudioPcm { stream } => {
                if stream.is_none() {
                    *stream = Some(audio::open_stream(48_000, 2)?);
                }
                let Some(s) = stream.as_mut() else {
                    return Err(Error::new(ErrorKind::Io));
                };
                s.write_pcm_bytes(src)
            }
        }
    }

    /// Truncate/reset a writable synthetic file (`File::create` compatibility).
    pub fn truncate(&mut self) -> Result<()> {
        match self {
            Self::Snapshot(_) => Err(Error::capability()),
            Self::BtlCtl(_) | Self::AudioCtl(_) | Self::AudioPcm { .. } => Ok(()),
        }
    }

    /// Flush/drain queued state.
    pub fn fsync(&self) -> Result<()> {
        if let Self::AudioPcm { stream: Some(s) } = self {
            s.drain(250);
        }
        Ok(())
    }
}
