//! Bluetooth Service Discovery Protocol (`SDP`, `PSM 0x0001`) server and client.
//!
//! Exports local service records for `A2DP Audio Source (0x110A)`,
//! `AVRCP Controller (0x110E)`, and `AVRCP Target (0x110C)` so real wireless
//! headphones recognize HuesOS as a stereo music source, and builds client
//! queries for `A2DP Audio Sink (0x110B)`.

use alloc::vec::Vec;

// ---- SDP PDU IDs ----
/// Error Response (`0x01`).
pub const SDP_ERROR_RSP: u8 = 0x01;
/// Service Search Request (`0x02`).
pub const SDP_SVC_SEARCH_REQ: u8 = 0x02;
/// Service Search Response (`0x03`).
pub const SDP_SVC_SEARCH_RSP: u8 = 0x03;
/// Service Attribute Request (`0x04`).
pub const SDP_SVC_ATTR_REQ: u8 = 0x04;
/// Service Attribute Response (`0x05`).
pub const SDP_SVC_ATTR_RSP: u8 = 0x05;
/// Service Search Attribute Request (`0x06`).
pub const SDP_SVC_SEARCH_ATTR_REQ: u8 = 0x06;
/// Service Search Attribute Response (`0x07`).
pub const SDP_SVC_SEARCH_ATTR_RSP: u8 = 0x07;

// ---- UUID16 Constants ----
/// L2CAP Protocol UUID (`0x0100`).
pub const UUID_L2CAP: u16 = 0x0100;
/// AVCTP Protocol UUID (`0x0017`).
pub const UUID_AVCTP: u16 = 0x0017;
/// AVDTP Protocol UUID (`0x0019`).
pub const UUID_AVDTP: u16 = 0x0019;
/// Public Browse Group (`0x1002`).
pub const UUID_PUBLIC_BROWSE_ROOT: u16 = 0x1002;
/// A2DP Audio Source Service Class (`0x110A`).
pub const UUID_AUDIO_SOURCE: u16 = 0x110A;
/// A2DP Audio Sink Service Class (`0x110B`).
pub const UUID_AUDIO_SINK: u16 = 0x110B;
/// AVRCP Remote Control Target (`0x110C`).
pub const UUID_AV_REMOTE_TARGET: u16 = 0x110C;
/// Advanced Audio Distribution Profile (`0x110D`).
pub const UUID_ADV_AUDIO_DIST: u16 = 0x110D;
/// AVRCP Remote Control (`0x110E`).
pub const UUID_AV_REMOTE: u16 = 0x110E;
/// AVRCP Remote Control Controller (`0x110F`).
pub const UUID_AV_REMOTE_CONTROLLER: u16 = 0x110F;

const RECORD_HANDLE_A2DP_SOURCE: u32 = 0x0001_0001;
const RECORD_HANDLE_AVRCP_TARGET: u32 = 0x0001_0002;
const RECORD_HANDLE_AVRCP_CTRL: u32 = 0x0001_0003;

fn push_de_uint16(out: &mut Vec<u8>, v: u16) {
    out.push(0x09); // uint16
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_de_uint32(out: &mut Vec<u8>, v: u32) {
    out.push(0x0A); // uint32
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_de_uuid16(out: &mut Vec<u8>, uuid: u16) {
    out.push(0x19); // uuid16
    out.extend_from_slice(&uuid.to_be_bytes());
}

fn push_de_seq(out: &mut Vec<u8>, inner: &[u8]) {
    if inner.len() <= 255 {
        out.push(0x35); // sequence uint8 length
        out.push(inner.len() as u8);
    } else {
        out.push(0x36); // sequence uint16 length
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(inner);
}

fn build_a2dp_source_attr_list() -> Vec<u8> {
    let mut list = Vec::new();
    // Attr 0x0000: ServiceRecordHandle
    push_de_uint16(&mut list, 0x0000);
    push_de_uint32(&mut list, RECORD_HANDLE_A2DP_SOURCE);

    // Attr 0x0001: ServiceClassIDList = [AudioSource(0x110A)]
    push_de_uint16(&mut list, 0x0001);
    let mut sc = Vec::new();
    push_de_uuid16(&mut sc, UUID_AUDIO_SOURCE);
    push_de_seq(&mut list, &sc);

    // Attr 0x0004: ProtocolDescriptorList = [ [L2CAP(0x0100), PSM=0x0019], [AVDTP(0x0019), v1.3(0x0103)] ]
    push_de_uint16(&mut list, 0x0004);
    let mut l2 = Vec::new();
    push_de_uuid16(&mut l2, UUID_L2CAP);
    push_de_uint16(&mut l2, 0x0019);
    let mut av = Vec::new();
    push_de_uuid16(&mut av, UUID_AVDTP);
    push_de_uint16(&mut av, 0x0103);
    let mut pdl = Vec::new();
    push_de_seq(&mut pdl, &l2);
    push_de_seq(&mut pdl, &av);
    push_de_seq(&mut list, &pdl);

    // Attr 0x0005: BrowseGroupList = [PublicBrowseRoot(0x1002)]
    push_de_uint16(&mut list, 0x0005);
    let mut bg = Vec::new();
    push_de_uuid16(&mut bg, UUID_PUBLIC_BROWSE_ROOT);
    push_de_seq(&mut list, &bg);

    // Attr 0x0009: BluetoothProfileDescriptorList = [ [AdvancedAudioDistribution(0x110D), v1.3(0x0103)] ]
    push_de_uint16(&mut list, 0x0009);
    let mut prof = Vec::new();
    push_de_uuid16(&mut prof, UUID_ADV_AUDIO_DIST);
    push_de_uint16(&mut prof, 0x0103);
    let mut prof_outer = Vec::new();
    push_de_seq(&mut prof_outer, &prof);
    push_de_seq(&mut list, &prof_outer);

    // Attr 0x0311: SupportedFeatures = 0x0001 (Player)
    push_de_uint16(&mut list, 0x0311);
    push_de_uint16(&mut list, 0x0001);

    let mut wrapped = Vec::new();
    push_de_seq(&mut wrapped, &list);
    wrapped
}

fn build_avrcp_record_attr_list(handle: u32, is_target: bool) -> Vec<u8> {
    let mut list = Vec::new();
    push_de_uint16(&mut list, 0x0000);
    push_de_uint32(&mut list, handle);

    push_de_uint16(&mut list, 0x0001);
    let mut sc = Vec::new();
    if is_target {
        push_de_uuid16(&mut sc, UUID_AV_REMOTE_TARGET);
    } else {
        push_de_uuid16(&mut sc, UUID_AV_REMOTE);
        push_de_uuid16(&mut sc, UUID_AV_REMOTE_CONTROLLER);
    }
    push_de_seq(&mut list, &sc);

    push_de_uint16(&mut list, 0x0004);
    let mut l2 = Vec::new();
    push_de_uuid16(&mut l2, UUID_L2CAP);
    push_de_uint16(&mut l2, 0x0017);
    let mut av = Vec::new();
    push_de_uuid16(&mut av, UUID_AVCTP);
    push_de_uint16(&mut av, 0x0104);
    let mut pdl = Vec::new();
    push_de_seq(&mut pdl, &l2);
    push_de_seq(&mut pdl, &av);
    push_de_seq(&mut list, &pdl);

    push_de_uint16(&mut list, 0x0005);
    let mut bg = Vec::new();
    push_de_uuid16(&mut bg, UUID_PUBLIC_BROWSE_ROOT);
    push_de_seq(&mut list, &bg);

    push_de_uint16(&mut list, 0x0009);
    let mut prof = Vec::new();
    push_de_uuid16(&mut prof, UUID_AV_REMOTE);
    push_de_uint16(&mut prof, 0x0106);
    let mut prof_outer = Vec::new();
    push_de_seq(&mut prof_outer, &prof);
    push_de_seq(&mut list, &prof_outer);

    // SupportedFeatures: Category 1 (Player/Recorder = 0x0001) | Category 2 (Monitor/Amp = 0x0002)
    push_de_uint16(&mut list, 0x0311);
    push_de_uint16(&mut list, if is_target { 0x0001 } else { 0x0002 });

    let mut wrapped = Vec::new();
    push_de_seq(&mut wrapped, &list);
    wrapped
}

struct LocalSdpRecord {
    handle: u32,
    uuids: &'static [u16],
    encoded_attrs: Vec<u8>,
}

fn local_records() -> [LocalSdpRecord; 3] {
    [
        LocalSdpRecord {
            handle: RECORD_HANDLE_A2DP_SOURCE,
            uuids: &[
                UUID_L2CAP,
                UUID_AVDTP,
                UUID_PUBLIC_BROWSE_ROOT,
                UUID_AUDIO_SOURCE,
                UUID_ADV_AUDIO_DIST,
            ],
            encoded_attrs: build_a2dp_source_attr_list(),
        },
        LocalSdpRecord {
            handle: RECORD_HANDLE_AVRCP_TARGET,
            uuids: &[
                UUID_L2CAP,
                UUID_AVCTP,
                UUID_PUBLIC_BROWSE_ROOT,
                UUID_AV_REMOTE_TARGET,
                UUID_AV_REMOTE,
            ],
            encoded_attrs: build_avrcp_record_attr_list(RECORD_HANDLE_AVRCP_TARGET, true),
        },
        LocalSdpRecord {
            handle: RECORD_HANDLE_AVRCP_CTRL,
            uuids: &[
                UUID_L2CAP,
                UUID_AVCTP,
                UUID_PUBLIC_BROWSE_ROOT,
                UUID_AV_REMOTE,
                UUID_AV_REMOTE_CONTROLLER,
            ],
            encoded_attrs: build_avrcp_record_attr_list(RECORD_HANDLE_AVRCP_CTRL, false),
        },
    ]
}

/// Extract all UUID16 values (including Bluetooth Base UUID128 `0000xxxx-0000-1000-8000-00805F9B34FB`)
/// from a Data Element Sequence at the start of `buf`, returning `(uuids, bytes_consumed)`.
pub fn parse_uuid_sequence(buf: &[u8]) -> Option<(Vec<u16>, usize)> {
    if buf.is_empty() {
        return None;
    }
    let (seq_len, hdr_len) = match buf[0] {
        0x35 if buf.len() >= 2 => (usize::from(buf[1]), 2usize),
        0x36 if buf.len() >= 3 => (usize::from(u16::from_be_bytes([buf[1], buf[2]])), 3usize),
        _ => return None,
    };
    if buf.len() < hdr_len + seq_len {
        return None;
    }
    let mut uuids = Vec::new();
    let body = &buf[hdr_len..hdr_len + seq_len];
    let mut pos = 0usize;
    while pos < body.len() {
        match body[pos] {
            0x19 if pos + 3 <= body.len() => {
                uuids.push(u16::from_be_bytes([body[pos + 1], body[pos + 2]]));
                pos += 3;
            }
            0x1A if pos + 5 <= body.len() => {
                // uuid32 -> low 16 bits when high 16 == 0
                if body[pos + 1] == 0 && body[pos + 2] == 0 {
                    uuids.push(u16::from_be_bytes([body[pos + 3], body[pos + 4]]));
                }
                pos += 5;
            }
            0x1C if pos + 17 <= body.len() => {
                // uuid128 -> extract bytes [2..4]
                uuids.push(u16::from_be_bytes([body[pos + 3], body[pos + 4]]));
                pos += 17;
            }
            _ => break,
        }
    }
    Some((uuids, hdr_len + seq_len))
}

fn build_sdp_pdu(pdu_id: u8, tid: u16, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + params.len());
    out.push(pdu_id);
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&(params.len() as u16).to_be_bytes());
    out.extend_from_slice(params);
    out
}

/// Handle an incoming SDP request PDU on `PSM 0x0001` and produce the response PDU.
pub fn handle_sdp_request(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 5 {
        return None;
    }
    let pdu_id = req[0];
    let tid = u16::from_be_bytes([req[1], req[2]]);
    let plen = usize::from(u16::from_be_bytes([req[3], req[4]]));
    if req.len() < 5 + plen {
        return None;
    }
    let p = &req[5..5 + plen];
    let records = local_records();

    match pdu_id {
        SDP_SVC_SEARCH_REQ => {
            let Some((search_uuids, used)) = parse_uuid_sequence(p) else {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes()));
            };
            if p.len() < used + 3 {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes()));
            }
            let max_cnt = usize::from(u16::from_be_bytes([p[used], p[used + 1]]));
            let mut matched = Vec::new();
            for rec in &records {
                if search_uuids.iter().all(|u| rec.uuids.contains(u)) && matched.len() < max_cnt {
                    matched.push(rec.handle);
                }
            }
            let mut rsp = Vec::new();
            rsp.extend_from_slice(&(matched.len() as u16).to_be_bytes());
            rsp.extend_from_slice(&(matched.len() as u16).to_be_bytes());
            for h in matched {
                rsp.extend_from_slice(&h.to_be_bytes());
            }
            rsp.push(0x00); // ContinuationState = 0
            Some(build_sdp_pdu(SDP_SVC_SEARCH_RSP, tid, &rsp))
        }
        SDP_SVC_ATTR_REQ => {
            if p.len() < 7 {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes()));
            }
            let handle = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
            let max_bytes = usize::from(u16::from_be_bytes([p[4], p[5]])).max(7);
            let Some(rec) = records.iter().find(|r| r.handle == handle) else {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0002u16.to_be_bytes()));
            };
            let cont_offset = parse_continuation_offset(p);
            Some(fragment_attr_response(
                SDP_SVC_ATTR_RSP,
                tid,
                &rec.encoded_attrs,
                max_bytes,
                cont_offset,
            ))
        }
        SDP_SVC_SEARCH_ATTR_REQ => {
            let Some((search_uuids, used)) = parse_uuid_sequence(p) else {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes()));
            };
            if p.len() < used + 3 {
                return Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes()));
            }
            let max_bytes = usize::from(u16::from_be_bytes([p[used], p[used + 1]])).max(7);
            let mut inner = Vec::new();
            for rec in &records {
                if search_uuids.iter().all(|u| rec.uuids.contains(u)) {
                    inner.extend_from_slice(&rec.encoded_attrs);
                }
            }
            let mut outer = Vec::new();
            push_de_seq(&mut outer, &inner);
            let cont_offset = parse_continuation_offset(p);
            Some(fragment_attr_response(
                SDP_SVC_SEARCH_ATTR_RSP,
                tid,
                &outer,
                max_bytes,
                cont_offset,
            ))
        }
        _ => Some(build_sdp_pdu(SDP_ERROR_RSP, tid, &0x0003u16.to_be_bytes())),
    }
}

fn parse_continuation_offset(params: &[u8]) -> usize {
    // Check if trailing ContinuationState is `[0x02, hi, lo]`.
    if params.len() >= 3 && params[params.len() - 3] == 0x02 {
        usize::from(u16::from_be_bytes([
            params[params.len() - 2],
            params[params.len() - 1],
        ]))
    } else {
        0
    }
}

fn fragment_attr_response(
    rsp_id: u8,
    tid: u16,
    full_blob: &[u8],
    max_attr_bytes: usize,
    offset: usize,
) -> Vec<u8> {
    let safe_off = offset.min(full_blob.len());
    let remain = &full_blob[safe_off..];
    let take = remain.len().min(max_attr_bytes);
    let mut rsp = Vec::with_capacity(2 + take + 3);
    rsp.extend_from_slice(&(take as u16).to_be_bytes());
    rsp.extend_from_slice(&remain[..take]);
    let next_off = safe_off + take;
    if next_off < full_blob.len() {
        rsp.push(0x02);
        rsp.extend_from_slice(&(next_off as u16).to_be_bytes());
    } else {
        rsp.push(0x00);
    }
    build_sdp_pdu(rsp_id, tid, &rsp)
}

/// Build an outbound `SDP_ServiceSearchAttributeRequest` querying `AudioSink (0x110B)`.
pub fn build_query_audio_sink_req(tid: u16) -> Vec<u8> {
    let mut params = Vec::new();
    // ServiceSearchPattern: [UUID16(0x110B)]
    let mut pat = Vec::new();
    push_de_uuid16(&mut pat, UUID_AUDIO_SINK);
    push_de_seq(&mut params, &pat);
    // MaximumAttributeByteCount = 512
    params.extend_from_slice(&512u16.to_be_bytes());
    // AttributeIDList: [ uint32 range 0x0000..0xFFFF ]
    let mut aid = Vec::new();
    aid.push(0x0A); // uint32
    aid.extend_from_slice(&0x0000_FFFFu32.to_be_bytes());
    push_de_seq(&mut params, &aid);
    // ContinuationState = 0
    params.push(0x00);
    build_sdp_pdu(SDP_SVC_SEARCH_ATTR_REQ, tid, &params)
}

/// Inspect an `SDP_ServiceSearchAttributeResponse` and return `true` if `AudioSink (0x110B)`
/// or `AVDTP (0x0019)` is advertised in the returned attribute list.
pub fn parse_audio_sink_response(rsp: &[u8]) -> bool {
    if rsp.len() < 8 || rsp[0] != SDP_SVC_SEARCH_ATTR_RSP {
        return false;
    }
    let body = &rsp[7..];
    // Scan for UUID16 `0x19 0x11 0x0B` (AudioSink) or `0x19 0x00 0x19` (AVDTP).
    body.windows(3)
        .any(|w| w == [0x19, 0x11, 0x0B] || w == [0x19, 0x00, 0x19])
}
