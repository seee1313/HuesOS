//! `#![no_std]` `#![forbid(unsafe_code)]` Bluetooth Classic protocol stack
//! (`HCI`, Realtek `btrtl` `RTL8821CE` firmware patcher, `SSP` Just-Works pairing,
//! `L2CAP` multiplexer, `SDP` server/client, Wireshark `btsnoop` capture, and
//! deterministic virtual A2DP headphones) powering `/net/btl`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod btrtl;
pub mod hci;
pub mod l2cap;
pub mod sdp;
pub mod snoop;
pub mod virtual_bt;

#[cfg(test)]
mod tests {
    use super::btrtl::{
        is_rtl8821ce_usb_id, parse_and_assemble_rtl8821c, OP_RTL_DOWNLOAD, PROJECT_ID_8821C,
        REALTEK_USB_VID, RTL_DOWNLOAD_CHUNK_DATA,
    };
    use super::hci::{
        cmd_create_connection, cmd_inquiry_giac, decode_event, segment_l2cap_to_acl,
        AclCreditTracker, AclReassembler, BdAddr, DecodedHciEvent, H4_CMD, H4_EVT,
    };
    use super::l2cap::{wrap_l2cap_pdu, L2capEngine, L2capEvent, PSM_AVDTP, PSM_SDP};
    use super::sdp::{
        build_query_audio_sink_req, handle_sdp_request, parse_audio_sink_response,
        SDP_SVC_SEARCH_ATTR_REQ, UUID_AUDIO_SOURCE,
    };
    use super::snoop::{BtSnoopLog, SnoopDir, BTSNOOP_FILE_HEADER};
    use super::virtual_bt::{VirtualBtMedium, VIRTUAL_HEADSET_ADDR, VIRTUAL_HEADSET_NAME};
    use alloc::vec::Vec;

    #[test]
    fn bd_addr_roundtrip_and_display_order() {
        let Some(parsed) = BdAddr::parse_str("52:54:00:B7:A2:D9") else {
            assert!(false);
            return;
        };
        assert_eq!(parsed, VIRTUAL_HEADSET_ADDR);
        // Wire order is reversed LSB-first
        assert_eq!(parsed.0, [0xD9, 0xA2, 0xB7, 0x00, 0x54, 0x52]);
        let mut text = [0u8; 17];
        parsed.format_ascii(&mut text);
        assert_eq!(&text, b"52:54:00:B7:A2:D9");
    }

    #[test]
    fn real_rtl8821ce_firmware_parses_both_revisions_and_chunks_cleanly() {
        assert!(is_rtl8821ce_usb_id(REALTEK_USB_VID, 0xC821));
        assert!(is_rtl8821ce_usb_id(REALTEK_USB_VID, 0xB00A));
        let fw = include_bytes!("../../../third_party/firmware/rtl_bt/rtl8821c_fw.bin");
        let cfg = include_bytes!("../../../third_party/firmware/rtl_bt/rtl8821c_config.bin");

        // Revision A-cut (`rom_version = 0` -> `chip_id = 1`)
        let Ok(assembled_a) = parse_and_assemble_rtl8821c(fw, Some(cfg), 0) else {
            assert!(false);
            return;
        };
        assert_eq!(assembled_a.project_id, PROJECT_ID_8821C);
        assert_eq!(assembled_a.chip_id, 1);
        assert_eq!(assembled_a.payload.len(), 15472 + cfg.len());

        // Revision B-cut (`rom_version = 1` -> `chip_id = 2`)
        let Ok(assembled_b) = parse_and_assemble_rtl8821c(fw, Some(cfg), 1) else {
            assert!(false);
            return;
        };
        assert_eq!(assembled_b.chip_id, 2);
        assert_eq!(assembled_b.payload.len(), 21668 + cfg.len());
        let frags = assembled_b.fragment_count();
        assert_eq!(
            frags,
            assembled_b.payload.len().div_ceil(RTL_DOWNLOAD_CHUNK_DATA)
        );

        let mut cmd_buf = [0u8; 260];
        let Some(first_len) = assembled_b.encode_download_cmd(0, &mut cmd_buf) else {
            assert!(false);
            return;
        };
        assert_eq!(first_len, 3 + 1 + RTL_DOWNLOAD_CHUNK_DATA);
        assert_eq!(
            u16::from_le_bytes([cmd_buf[0], cmd_buf[1]]),
            OP_RTL_DOWNLOAD
        );
        assert_eq!(cmd_buf[3], 0x00);

        let Some(last_len) = assembled_b.encode_download_cmd(frags - 1, &mut cmd_buf) else {
            assert!(false);
            return;
        };
        assert!(last_len >= 4);
        // Final fragment must carry end-of-patch bit 7 (`0x80`).
        assert_ne!(cmd_buf[3] & 0x80, 0);
    }

    #[test]
    fn acl_segmentation_reassembly_and_credit_tracking() {
        let mut payload = Vec::new();
        for i in 0..700u16 {
            payload.push((i & 0xFF) as u8);
        }
        let l2_pdu = wrap_l2cap_pdu(0x0044, &payload);
        let acl_frags = segment_l2cap_to_acl(0x0041, &l2_pdu, 250);
        assert_eq!(acl_frags.len(), 3);

        let mut credits = AclCreditTracker::default();
        credits.configure(250, 6);
        assert!(credits.take_credits(acl_frags.len() as u16));
        assert_eq!(credits.congestion_percent(), 50);
        credits.on_completed_packets(&[1, 0x41, 0x00, 0x03, 0x00]);
        assert_eq!(credits.available_credits(), 6);

        let mut reasm = AclReassembler::default();
        assert!(reasm.push_acl(&acl_frags[0]).is_none());
        assert!(reasm.push_acl(&acl_frags[1]).is_none());
        let Some((handle, cid, out)) = reasm.push_acl(&acl_frags[2]) else {
            assert!(false);
            return;
        };
        assert_eq!(handle, 0x0041);
        assert_eq!(cid, 0x0044);
        assert_eq!(out, payload);
    }

    #[test]
    fn l2cap_two_engines_handshake_and_sdp_query() {
        let addr_a = BdAddr::from_be_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let addr_b = VIRTUAL_HEADSET_ADDR;
        let mut a = L2capEngine::new();
        let mut b = L2capEngine::new();
        b.register_psm(PSM_AVDTP);

        let cid_a = a.connect(1, addr_b, PSM_SDP);
        for _ in 0..6 {
            for pdu in a.drain_outbound() {
                let cid = u16::from_le_bytes([pdu.pdu[2], pdu.pdu[3]]);
                b.on_reassembled_pdu(1, addr_a, cid, &pdu.pdu[4..]);
            }
            for pdu in b.drain_outbound() {
                let cid = u16::from_le_bytes([pdu.pdu[2], pdu.pdu[3]]);
                a.on_reassembled_pdu(1, addr_b, cid, &pdu.pdu[4..]);
            }
        }
        let events_a = a.drain_events();
        assert!(events_a
            .iter()
            .any(|e| matches!(e, L2capEvent::ChannelOpened { local_cid, psm: PSM_SDP, .. } if *local_cid == cid_a)));

        // Query local SDP server for AudioSource (`0x110A`)
        let req = [
            SDP_SVC_SEARCH_ATTR_REQ,
            0x00,
            0x01,
            0x00,
            0x0D,
            0x35,
            0x03,
            0x19,
            (UUID_AUDIO_SOURCE >> 8) as u8,
            (UUID_AUDIO_SOURCE & 0xFF) as u8,
            0x02,
            0x00,
            0x35,
            0x05,
            0x0A,
            0x00,
            0x00,
            0xFF,
            0xFF,
            0x00,
        ];
        let Some(rsp) = handle_sdp_request(&req) else {
            assert!(false);
            return;
        };
        assert_eq!(rsp[0], 0x07);
        assert!(rsp.windows(3).any(|w| w == [0x19, 0x11, 0x0A]));
    }

    #[test]
    fn virtual_headset_completes_inquiry_ssp_and_sdp_sink_discovery() {
        let mut medium = VirtualBtMedium::new();
        let mut snoop = BtSnoopLog::new(8192);
        let mut cmd = [0u8; 32];

        let Some(n) = cmd_inquiry_giac(4, 8, &mut cmd) else {
            assert!(false);
            return;
        };
        snoop.record(H4_CMD, SnoopDir::HostToController, 100, &cmd[..n]);
        medium.submit_hci_cmd(&cmd[..n]);

        let mut found_headset = false;
        while let Some(evt) = medium.pop_hci_event() {
            snoop.record(H4_EVT, SnoopDir::ControllerToHost, 200, &evt);
            if let Some(DecodedHciEvent::PeerDiscovered(peer)) = decode_event(&evt) {
                if peer.addr == VIRTUAL_HEADSET_ADDR {
                    assert_eq!(peer.name_str(), VIRTUAL_HEADSET_NAME);
                    assert!(peer.advertises_a2dp_sink);
                    found_headset = true;
                }
            }
        }
        assert!(found_headset);
        let snoop_bytes = snoop.export_bytes();
        assert_eq!(&snoop_bytes[..16], &BTSNOOP_FILE_HEADER);

        // Connect ACL + open SDP + query `AudioSink (0x110B)`
        let Some(cn) = cmd_create_connection(VIRTUAL_HEADSET_ADDR, 1, 0, true, &mut cmd) else {
            assert!(false);
            return;
        };
        medium.submit_hci_cmd(&cmd[..cn]);
        let _ = medium.pop_hci_event(); // CmdStatus
        let Some(cc_evt) = medium.pop_hci_event() else {
            assert!(false);
            return;
        };
        let Some(DecodedHciEvent::ConnectionComplete {
            status: 0,
            conn_handle,
            ..
        }) = decode_event(&cc_evt)
        else {
            assert!(false);
            return;
        };

        let mut host_l2 = L2capEngine::new();
        let mut host_reasm = AclReassembler::default();
        let sdp_cid = host_l2.connect(conn_handle, VIRTUAL_HEADSET_ADDR, PSM_SDP);
        for _ in 0..6 {
            for out in host_l2.drain_outbound() {
                for frag in segment_l2cap_to_acl(out.conn_handle, &out.pdu, 1021) {
                    medium.submit_hci_acl(&frag);
                }
            }
            while let Some(acl_in) = medium.pop_hci_acl() {
                if let Some((h, cid, p)) = host_reasm.push_acl(&acl_in) {
                    host_l2.on_reassembled_pdu(h, VIRTUAL_HEADSET_ADDR, cid, &p);
                }
            }
        }
        let q = build_query_audio_sink_req(0x0042);
        assert!(host_l2.send_data(sdp_cid, &q));
        for out in host_l2.drain_outbound() {
            for frag in segment_l2cap_to_acl(out.conn_handle, &out.pdu, 1021) {
                medium.submit_hci_acl(&frag);
            }
        }
        while let Some(acl_in) = medium.pop_hci_acl() {
            if let Some((h, cid, p)) = host_reasm.push_acl(&acl_in) {
                host_l2.on_reassembled_pdu(h, VIRTUAL_HEADSET_ADDR, cid, &p);
            }
        }
        let mut sdp_sink_ok = false;
        for ev in host_l2.drain_events() {
            if let L2capEvent::DataReceived { payload, .. } = ev {
                if parse_audio_sink_response(&payload) {
                    sdp_sink_ok = true;
                }
            }
        }
        assert!(sdp_sink_ok);
    }
}
