//! `/bin/audioctl.elf` — HuesOS Audio Mixer, `VirtIO-Sound` PCIe, and
//! `/net/btl` Bluetooth A2DP / AVRCP Control CLI.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;

use huesos_abi::audio::AudioRouteMode;
use huesos_coreutils as cu;
use huesos_std::audio;
use huesos_std::net;

cu::coreutil_entry!(run);

fn print_usage() {
    cu::outln(
        "usage: audioctl [status|volume <0..100>|mute|unmute|route <auto|virtio|btl|mirror>|bt-connect [addr]|bt-disconnect|tone [hz] [ms]]",
    );
}

fn cmd_status() -> i32 {
    match audio::status() {
        Ok(st) => {
            let sink_label = match st.active_sinks_mask {
                0 => "none",
                1 => "virtio-snd",
                2 => "btl-a2dp",
                3 => "mirror(virtio-snd+btl-a2dp)",
                _ => "unknown",
            };
            cu::outln(&format!(
                "audio0: route={} active_sink={} volume={}% muted={} rate={}Hz streams={}",
                st.route_mode.as_str(),
                sink_label,
                st.master_volume_pct,
                st.muted,
                st.mix_sample_rate,
                st.active_streams,
            ));
            cu::outln(&format!(
                "  virtio_snd: online={} periods={}",
                st.virtio_online, st.virtio_periods,
            ));
            cu::outln(&format!(
                "  btl_a2dp: streaming={} peer={} ({}) sbc_bitpool={} bitrate={}kbps avrcp_events={}",
                st.btl_streaming,
                net::format_bd_addr(&st.btl_peer_addr),
                st.btl_peer_name_str(),
                st.btl_sbc_bitpool,
                st.btl_bitrate_kbps,
                st.avrcp_events,
            ));
            cu::outln(&format!(
                "  telemetry: mixed_frames={} btl_rtp_packets={} underruns={}",
                st.mixed_frames, st.btl_rtp_packets, st.underruns,
            ));
            0
        }
        Err(e) => {
            cu::errln(&format!("audioctl: status failed: {e}"));
            1
        }
    }
}

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return cmd_status();
    };

    match sub {
        "--help" | "-h" | "help" => {
            print_usage();
            0
        }
        "status" => cmd_status(),
        "volume" | "vol" => {
            let Some(vol) = args.get(1).and_then(|s| s.parse::<u8>().ok()) else {
                cu::errln("audioctl: usage: audioctl volume <0..100>");
                return 1;
            };
            let muted = audio::status().map(|s| s.muted).unwrap_or(false);
            match audio::set_volume(vol.min(100), muted) {
                Ok(()) => {
                    cu::outln(&format!("audioctl: volume={}%", vol.min(100)));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: volume failed: {e}"));
                    1
                }
            }
        }
        "mute" => {
            let vol = audio::status().map(|s| s.master_volume_pct).unwrap_or(80);
            match audio::set_volume(vol, true) {
                Ok(()) => {
                    cu::outln("audioctl: muted=true");
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: mute failed: {e}"));
                    1
                }
            }
        }
        "unmute" => {
            let vol = audio::status().map(|s| s.master_volume_pct).unwrap_or(80);
            match audio::set_volume(vol, false) {
                Ok(()) => {
                    cu::outln("audioctl: muted=false");
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: unmute failed: {e}"));
                    1
                }
            }
        }
        "route" => {
            let mode = match args.get(1).map(|s| s.as_str()) {
                Some("auto") => AudioRouteMode::Auto,
                Some("virtio" | "snd") => AudioRouteMode::VirtioOnly,
                Some("btl" | "bt" | "a2dp") => AudioRouteMode::BtlOnly,
                Some("mirror" | "both") => AudioRouteMode::Mirror,
                _ => {
                    cu::errln("audioctl: usage: audioctl route <auto|virtio|btl|mirror>");
                    return 1;
                }
            };
            match audio::set_route_mode(mode) {
                Ok(()) => {
                    cu::outln(&format!("audioctl: route={}", mode.as_str()));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: route failed: {e}"));
                    1
                }
            }
        }
        "bt-connect" => {
            let addr = match args.get(1) {
                Some(raw) => match net::parse_bd_addr(raw) {
                    Some(a) => Some(a),
                    None => {
                        cu::errln("audioctl: invalid BD_ADDR (expected AA:BB:CC:DD:EE:FF)");
                        return 1;
                    }
                },
                None => None,
            };
            match audio::connect_btl_sink(addr) {
                Ok(()) => {
                    if let Ok(st) = audio::status() {
                        cu::outln(&format!(
                            "audioctl: connected A2DP+AVRCP sink {} ({}) bitpool={} ({} kbps)",
                            net::format_bd_addr(&st.btl_peer_addr),
                            st.btl_peer_name_str(),
                            st.btl_sbc_bitpool,
                            st.btl_bitrate_kbps,
                        ));
                    } else {
                        cu::outln("audioctl: connected Bluetooth A2DP sink");
                    }
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: bt-connect failed: {e}"));
                    1
                }
            }
        }
        "bt-disconnect" => match audio::disconnect_btl_sink() {
            Ok(()) => {
                cu::outln("audioctl: Bluetooth A2DP sink disconnected");
                0
            }
            Err(e) => {
                cu::errln(&format!("audioctl: bt-disconnect failed: {e}"));
                1
            }
        },
        "tone" => {
            let freq = args
                .get(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(440);
            let ms = args
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200);
            match audio::play_test_tone(freq, ms) {
                Ok(()) => {
                    cu::outln(&format!("audioctl: playing {freq}Hz test tone for {ms}ms"));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("audioctl: tone failed: {e}"));
                    1
                }
            }
        }
        other => {
            cu::errln(&format!("audioctl: unknown command '{other}'"));
            print_usage();
            1
        }
    }
}
