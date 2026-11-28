//! `#![no_std]` `#![forbid(unsafe_code)]` Bluetooth Classic protocol stack
//! (`HCI`, Realtek `btrtl` `RTL8821CE` firmware patcher, `SSP` Just-Works pairing,
//! `L2CAP` multiplexer, `SDP` server/client, Wireshark `btsnoop` capture, and
//! deterministic virtual A2DP headphones) powering `/net/btl`.

#![no_std]
#![forbid(unsafe_code)]
#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_contains,
    clippy::identity_op,
    clippy::erasing_op,
    clippy::large_enum_variant,
    clippy::type_complexity,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::collapsible_match,
    clippy::vec_init_then_push,
    clippy::int_plus_one,
    clippy::single_match,
    clippy::manual_div_ceil
)]

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
        cmd_drop_firmware, cmd_read_rom_version, cmd_vendor_read_reg16, is_rtl8821ce_usb_id,
        matches_rtl8821c_rom, parse_and_assemble_rtl8821c, parse_and_assemble_rtl8821c_with_key,
        AssembledRtlFirmware, HCI_REV_8821C, HCI_VER_8821C, LMP_SUBVER_8821C, OP_RTL_DOWNLOAD,
        OP_RTL_DROP_FIRMWARE, OP_RTL_READ_REG16, OP_RTL_READ_ROM_VERSION, PROJECT_ID_8821C,
        REALTEK_USB_VID, RTL_DOWNLOAD_CHUNK_DATA, RTL_REG_CHIP_SUBVER, RTL_REG_SEC_PROJ,
    };
    use super::hci::{
        cmd_create_connection, cmd_inquiry_giac, decode_event, segment_l2cap_to_acl,
        AclCreditTracker, AclReassembler, BdAddr, BtUsbAclReassembler, BtUsbEvtReassembler,
        DecodedHciEvent, EVT_INQUIRY_RESULT_RSSI, H4_CMD, H4_EVT,
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
        assert!(matches_rtl8821c_rom(
            LMP_SUBVER_8821C,
            HCI_REV_8821C,
            HCI_VER_8821C
        ));
        assert_eq!(OP_RTL_READ_ROM_VERSION, 0xFC6D);
        assert_eq!(OP_RTL_READ_REG16, 0xFC61);
        assert_eq!(OP_RTL_DROP_FIRMWARE, 0xFC66);

        let mut vcmd = [0u8; 16];
        assert_eq!(cmd_read_rom_version(&mut vcmd), Some(3));
        assert_eq!(&vcmd[..3], &[0x6D, 0xFC, 0x00]);
        assert_eq!(cmd_drop_firmware(&mut vcmd), Some(3));
        assert_eq!(&vcmd[..3], &[0x66, 0xFC, 0x00]);
        assert_eq!(
            cmd_vendor_read_reg16(&RTL_REG_CHIP_SUBVER, &mut vcmd),
            Some(8)
        );
        assert_eq!(
            &vcmd[..8],
            &[0x61, 0xFC, 0x05, 0x10, 0x38, 0x04, 0x28, 0x80]
        );
        assert_eq!(cmd_vendor_read_reg16(&RTL_REG_SEC_PROJ, &mut vcmd), Some(8));
        assert_eq!(
            &vcmd[..8],
            &[0x61, 0xFC, 0x05, 0x10, 0xA4, 0xAD, 0x00, 0xB0]
        );

        let fw = include_bytes!("../../../third_party/firmware/rtl_bt/rtl8821c_fw.bin");
        let cfg = include_bytes!("../../../third_party/firmware/rtl_bt/rtl8821c_config.bin");

        // Revision A-cut (`rom_version = 0` -> `chip_id = 1`)
        let Ok(assembled_a) = parse_and_assemble_rtl8821c(fw, Some(cfg), 0) else {
            assert!(false);
            return;
        };
        assert_eq!(assembled_a.project_id, PROJECT_ID_8821C);
        assert_eq!(assembled_a.chip_id, 1);
        assert_eq!(assembled_a.fw_version, 0x826C_A99E);
        assert_eq!(assembled_a.payload.len(), 15472 + cfg.len());

        // Revision B-cut (`rom_version = 1` -> `chip_id = 2`, `key_id = 0`)
        let Ok(assembled_b) = parse_and_assemble_rtl8821c(fw, Some(cfg), 1) else {
            assert!(false);
            return;
        };
        assert_eq!(assembled_b.chip_id, 2);
        assert_eq!(assembled_b.payload.len(), 21668 + cfg.len());

        // When `key_id != 0`, Linux `btrtl_initialize` skips appending `rtl8821c_config.bin`.
        let Ok(assembled_b_sec) = parse_and_assemble_rtl8821c_with_key(fw, Some(cfg), 1, 1) else {
            assert!(false);
            return;
        };
        assert_eq!(assembled_b_sec.payload.len(), 21668);

        let frags = assembled_b.fragment_count();
        assert_eq!(
            frags,
            assembled_b.payload.len() / RTL_DOWNLOAD_CHUNK_DATA + 1
        );
        assert_eq!(frags, 87);

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
        assert_eq!(
            last_len,
            4 + (assembled_b.payload.len() % RTL_DOWNLOAD_CHUNK_DATA)
        );
        // Final fragment must carry end-of-patch bit 7 (`0x80`).
        assert_eq!(cmd_buf[3], 86 | 0x80);

        // Verify Linux `rtl_download_firmware` edge cases: exact multiple of 252 + `0x7F -> 1` wrap.
        let mut big = Vec::new();
        big.resize(130 * RTL_DOWNLOAD_CHUNK_DATA, 0x5Au8);
        let synth = AssembledRtlFirmware {
            fw_version: 1,
            project_id: PROJECT_ID_8821C,
            chip_id: 2,
            payload: big,
        };
        assert_eq!(synth.fragment_count(), 131);
        assert_eq!(synth.fragment_index_byte(0x7F), Some(0x7F));
        assert_eq!(synth.fragment_index_byte(0x80), Some(0x01));
        assert_eq!(synth.fragment_index_byte(0x81), Some(0x02));
        assert_eq!(synth.fragment_index_byte(130), Some(0x03 | 0x80));
        let Some(zero_tail_len) = synth.encode_download_cmd(130, &mut cmd_buf) else {
            assert!(false);
            return;
        };
        assert_eq!(zero_tail_len, 4);
    }

    #[test]
    fn epatch_v2_and_btusb_stream_reassemblers_work_end_to_end() {
        // Synthetic EPATCH v2 (`RTBTCore`) with out-of-order subsection priorities + tail TLV
        let mut fw_v2 = Vec::new();
        fw_v2.extend_from_slice(b"RTBTCore");
        fw_v2.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        fw_v2.extend_from_slice(&[0u8; 4]);
        fw_v2.extend_from_slice(&1u32.to_le_bytes()); // num_sections = 1
                                                      // Section: opcode = 1 (`RTL_PATCH_SNIPPETS`), two subsecs for eco=2 (`rom_version=1`)
        let mut sec = Vec::new();
        sec.extend_from_slice(&2u16.to_le_bytes());
        sec.extend_from_slice(&[0u8; 2]);
        // Subsec A: eco=2, prio=2, key_id=0, len=3, data=[0xCC, 0xDD, 0xEE]
        sec.extend_from_slice(&[2, 2, 0, 0]);
        sec.extend_from_slice(&3u32.to_le_bytes());
        sec.extend_from_slice(&[0xCC, 0xDD, 0xEE]);
        // Subsec B: eco=2, prio=1, key_id=0, len=2, data=[0xAA, 0xBB]
        sec.extend_from_slice(&[2, 1, 0, 0]);
        sec.extend_from_slice(&2u32.to_le_bytes());
        sec.extend_from_slice(&[0xAA, 0xBB]);

        fw_v2.extend_from_slice(&1u32.to_le_bytes()); // opcode = SNIPPETS
        fw_v2.extend_from_slice(&(sec.len() as u32).to_le_bytes());
        fw_v2.extend_from_slice(&sec);
        // Extension tail: [0x00, 0x00, 0xFF, PROJECT_ID_8821C, 0x01, 0x00, 0x51, 0x04, 0xFD, 0x77]
        fw_v2.extend_from_slice(&[
            0x00,
            0x00,
            0xFF,
            PROJECT_ID_8821C,
            0x01,
            0x00,
            0x51,
            0x04,
            0xFD,
            0x77,
        ]);

        let Ok(parsed_v2) = parse_and_assemble_rtl8821c_with_key(&fw_v2, None, 1, 0) else {
            assert!(false);
            return;
        };
        assert_eq!(parsed_v2.fw_version, 0x1122_3344);
        assert_eq!(parsed_v2.payload, alloc::vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        // USB Interrupt IN fragmented + coalesced event reassembly
        let mut evt_rx = BtUsbEvtReassembler::default();
        // Split a 7-byte CommandComplete across two 4-byte + 3-byte chunks, followed by a coalesced pair
        assert!(evt_rx.push_chunk(&[0x0E, 0x05, 0x01, 0x6D]).is_empty());
        let done = evt_rx.push_chunk(&[0xFC, 0x00, 0x01]);
        assert_eq!(done.len(), 1);
        assert_eq!(
            done[0],
            alloc::vec![0x0E, 0x05, 0x01, 0x6D, 0xFC, 0x00, 0x01]
        );

        let coalesced = evt_rx.push_chunk(&[
            0x0F, 0x04, 0x00, 0x01, 0x01, 0x04, // CommandStatus
            0x01, 0x01, 0x00, // InquiryComplete
        ]);
        assert_eq!(coalesced.len(), 2);

        // USB Bulk IN fragmented ACL reassembly
        let mut acl_rx = BtUsbAclReassembler::default();
        assert!(acl_rx.push_chunk(&[0x41, 0x20, 0x03]).is_empty());
        let acl_done = acl_rx.push_chunk(&[0x00, 0x11, 0x22, 0x33]);
        assert_eq!(acl_done.len(), 1);
        assert_eq!(
            acl_done[0],
            alloc::vec![0x41, 0x20, 0x03, 0x00, 0x11, 0x22, 0x33]
        );

        // Columnar 2-response `EVT_INQUIRY_RESULT_RSSI` (`0x22`)
        let mut multi = Vec::new();
        multi.push(EVT_INQUIRY_RESULT_RSSI);
        multi.push(1 + 2 * 14);
        multi.push(2); // num_responses = 2
        multi.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // BD_ADDR[0]
        multi.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // BD_ADDR[1]
        multi.extend_from_slice(&[0x01, 0x02]); // PSRM[0..2]
        multi.extend_from_slice(&[0x00, 0x00]); // Reserved[0..2]
        multi.extend_from_slice(&[0x18, 0x04, 0x24, 0x00, 0x00, 0x00]); // CoD[0], CoD[1]
        multi.extend_from_slice(&[0x34, 0x12, 0x00, 0x00]); // ClockOffset[0..2]
        multi.extend_from_slice(&[(-47i8) as u8, (-70i8) as u8]); // RSSI[0..2]
        let Some(DecodedHciEvent::PeerDiscovered(peer)) = decode_event(&multi) else {
            assert!(false);
            return;
        };
        assert_eq!(peer.addr, BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(peer.page_scan_rep_mode, 0x01);
        assert!(peer.advertises_a2dp_sink);
        assert_eq!(peer.clock_offset, 0x1234);
        assert_eq!(peer.rssi_dbm, -47);
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

    #[test]
    fn l2cap_handles_config_pending_and_mtu_fallback() {
        let mut l2 = L2capEngine::new();
        let cid = l2.connect(0x0040, VIRTUAL_HEADSET_ADDR, PSM_AVDTP);
        let tx0 = l2.drain_outbound();
        assert_eq!(tx0.len(), 1);

        // Peer replies ConnRsp Pending (`result = 0x0001`), then ConnRsp Success (`remote_cid = 0x0055`)
        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[
                0x03, 0x01, 0x08, 0x00, 0x55, 0x00, 0x40, 0x00, 0x01, 0x00, 0x02, 0x00,
            ],
        );
        assert!(l2.drain_outbound().is_empty());

        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[
                0x03, 0x01, 0x08, 0x00, 0x55, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        let cfg_tx = l2.drain_outbound();
        assert_eq!(cfg_tx.len(), 1); // Initial ConfigReq (MTU 896)

        // Peer replies ConfigRsp Pending (`result = 0x0004`), then Unacceptable Params (`0x0001`, MTU 672)
        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[0x05, 0x02, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, 0x04, 0x00],
        );
        assert!(l2.drain_events().is_empty());

        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[
                0x05, 0x02, 0x0A, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0xA0, 0x02,
            ],
        );
        let retry_tx = l2.drain_outbound();
        assert_eq!(retry_tx.len(), 1); // Retried ConfigReq with MTU 672 (`0x02A0`)
        assert_eq!(&retry_tx[0].pdu[14..16], &672u16.to_le_bytes());

        // Peer accepts retried ConfigReq and sends its own ConfigReq (MTU 895)
        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[0x05, 0x03, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        l2.on_reassembled_pdu(
            0x0040,
            VIRTUAL_HEADSET_ADDR,
            CID_SIGNALING,
            &[
                0x04, 0x09, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x02, 0x7F, 0x03,
            ],
        );
        assert!(l2.is_open(cid));
        assert_eq!(l2.remote_mtu(cid), 895);
    }
}
