//! Truncation / boundary fuzzing for the cEMI + KNXnet/IP codecs.
//!
//! The core property: a valid frame chopped at EVERY byte boundary must produce
//! an error, never a panic. Plus malformed length fields and wrong service codes.

use std::panic::{AssertUnwindSafe, catch_unwind};

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{CemiFrame, Destination, GroupData, MessageCode};
use bussard_transport::knxnet::{
    self, ServiceType, parse, parse_channel_status, parse_connect_response, parse_routing_busy,
    parse_routing_lost, parse_search_response, parse_tunneling_ack, parse_tunneling_request,
};

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

/// A representative spread of valid cEMI frames covering every APDU/TPCI branch.
fn valid_cemi_frames() -> Vec<Vec<u8>> {
    let mut out = vec![
        // group write small
        CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[1]).encode(),
        // group write large (2-byte)
        CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[0x0C, 0x1A]).encode(),
        // group read
        CemiFrame::group_read(ga("3/0/4"), ia("1.1.1")).encode(),
        // group response
        CemiFrame::group_response_packed(ga("3/0/4"), ia("1.1.1"), &[0x41]).encode(),
        // t_control (single-octet TPDU)
        CemiFrame::t_control(ia("1.1.4"), ia("0.0.255"), 0x80).encode(),
        // t_data_connected (management)
        CemiFrame::t_data_connected(ia("1.1.4"), ia("0.0.255"), 0x40, 0x300, &[]).encode(),
        CemiFrame::t_data_connected(ia("1.1.4"), ia("0.0.255"), 0x44, 0x200, &[3, 1, 0]).encode(),
        // broadcast
        CemiFrame::t_broadcast(ia("0.0.255"), 0x100, &[]).encode(),
    ];
    // frame with additional info
    let mut with_ai: Vec<u8> = vec![0x29, 0x04, 0x03, 0x02, 0xAA, 0xBB];
    with_ai.extend_from_slice(&[0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x81]);
    out.push(with_ai);
    out
}

#[test]
fn cemi_chopped_at_every_boundary_errors_not_panics() {
    for full in valid_cemi_frames() {
        // The full frame decodes.
        assert!(CemiFrame::decode(&full).is_ok(), "full frame should decode");
        // Every strict prefix must be an error (never panic, never Ok — a short
        // frame is always incomplete for these layouts).
        for cut in 0..full.len() {
            let prefix = &full[..cut];
            let r = catch_unwind(AssertUnwindSafe(|| CemiFrame::decode(prefix)));
            assert!(
                r.is_ok(),
                "PANIC decoding cEMI prefix len {cut}: {prefix:?}"
            );
            assert!(
                r.unwrap().is_err(),
                "cEMI prefix len {cut} unexpectedly decoded: {prefix:?}"
            );
        }
    }
}

#[test]
fn cemi_full_frames_roundtrip_byte_for_byte() {
    for full in valid_cemi_frames() {
        let decoded = CemiFrame::decode(&full).expect("decode");
        assert_eq!(decoded.encode(), full, "cEMI roundtrip");
    }
}

#[test]
fn cemi_malformed_additional_info_length_errors() {
    // AI length says 200 but there aren't 200 bytes.
    let hex: &[u8] = &[
        0x29, 200, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x81,
    ];
    let r = catch_unwind(AssertUnwindSafe(|| CemiFrame::decode(hex)));
    assert!(r.is_ok() && r.unwrap().is_err(), "huge AI len must error");
}

#[test]
fn cemi_bad_message_code_errors_for_all_unknown_codes() {
    for code in 0u16..=255 {
        let code = code as u8;
        if matches!(code, 0x11 | 0x2E | 0x29) {
            continue;
        }
        let hex = [
            code, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x00,
        ];
        let r = catch_unwind(AssertUnwindSafe(|| CemiFrame::decode(&hex)));
        assert!(r.is_ok(), "panic for message code {code:#x}");
        assert!(r.unwrap().is_err(), "code {code:#x} should be rejected");
    }
}

#[test]
fn cemi_npdu_length_overrun_errors() {
    // NPDU length claims 5 but only 1 TPDU byte present.
    let hex: &[u8] = &[0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x05, 0x00];
    assert!(CemiFrame::decode(hex).is_err());
}

#[test]
fn cemi_random_bytes_never_panic() {
    // A cheap deterministic PRNG sweep of arbitrary buffers.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..5000 {
        let len = (next() % 24) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        let r = catch_unwind(AssertUnwindSafe(|| CemiFrame::decode(&buf)));
        assert!(r.is_ok(), "cEMI decode panicked on {buf:?}");
    }
}

// ---------------------------------------------------------------------------
// KNXnet/IP header + service bodies.
// ---------------------------------------------------------------------------

/// A spread of valid KNXnet/IP datagrams.
fn valid_knxnet_frames() -> Vec<Vec<u8>> {
    let cemi = CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[1]);
    vec![
        knxnet::routing_indication(&cemi),
        knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x15,
                seq: 3,
            },
            &cemi,
        ),
        knxnet::tunneling_ack(0x15, 3, 0),
        knxnet::connectionstate_response(0x15, 0),
        knxnet::disconnect_response(0x15, 0),
        knxnet::connectionstate_request(0x15, knxnet::Hpai::wildcard()),
        knxnet::search_request(knxnet::Hpai::wildcard()),
    ]
}

#[test]
fn knxnet_chopped_at_every_boundary_errors_not_panics() {
    for full in valid_knxnet_frames() {
        assert!(parse(&full).is_ok(), "full KNXnet frame should parse");
        for cut in 0..full.len() {
            let prefix = &full[..cut];
            let r = catch_unwind(AssertUnwindSafe(|| parse(prefix)));
            assert!(r.is_ok(), "PANIC parsing KNXnet prefix len {cut}");
            // A truncated header/body should error.
            assert!(
                r.unwrap().is_err(),
                "KNXnet prefix len {cut} unexpectedly parsed: {prefix:?}"
            );
        }
    }
}

#[test]
fn knxnet_bad_header_bytes_rejected() {
    // Wrong header size / version.
    assert!(parse(&[0x07, 0x10, 0x02, 0x05, 0x00, 0x06]).is_err());
    assert!(parse(&[0x06, 0x11, 0x02, 0x05, 0x00, 0x06]).is_err());
    // total length larger than buffer.
    assert!(parse(&[0x06, 0x10, 0x05, 0x30, 0xFF, 0xFF]).is_err());
    // total length smaller than header.
    assert!(parse(&[0x06, 0x10, 0x05, 0x30, 0x00, 0x03]).is_err());
}

#[test]
fn knxnet_unknown_service_types_rejected() {
    // Sweep all u16 service codes; the known ones parse-header-ok, unknown error.
    let known: &[u16] = &[
        0x0201, 0x0202, 0x0205, 0x0206, 0x0207, 0x0208, 0x0209, 0x020A, 0x0420, 0x0421, 0x0530,
        0x0531, 0x0532,
    ];
    for svc in 0u16..=0x0600 {
        let hdr = [0x06, 0x10, (svc >> 8) as u8, (svc & 0xff) as u8, 0x00, 0x06];
        let r = catch_unwind(AssertUnwindSafe(|| parse(&hdr)));
        assert!(r.is_ok(), "panic on service {svc:#x}");
        let parsed = r.unwrap();
        if known.contains(&svc) {
            assert!(parsed.is_ok(), "known service {svc:#x} should parse header");
        } else {
            assert!(parsed.is_err(), "unknown service {svc:#x} should error");
        }
    }
}

#[test]
fn knxnet_service_body_parsers_never_panic_on_junk() {
    // Feed each body parser truncations of a plausible-but-short body.
    let bodies: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x15, 0x00],
        vec![0x04, 0x15, 0x00, 0x00],
        vec![0xFF; 8],
        vec![0x08, 0x01, 1, 2, 3, 4, 0, 0],
    ];
    for body in &bodies {
        for cut in 0..=body.len() {
            let b = &body[..cut];
            for f in [
                (|b: &[u8]| {
                    let _ = parse_channel_status(b);
                }) as fn(&[u8]),
                |b| {
                    let _ = parse_connect_response(b);
                },
                |b| {
                    let _ = parse_tunneling_request(b);
                },
                |b| {
                    let _ = parse_tunneling_ack(b);
                },
                |b| {
                    let _ = parse_routing_busy(b);
                },
                |b| {
                    let _ = parse_routing_lost(b);
                },
                |b| {
                    let _ = parse_search_response(b);
                },
            ] {
                let r = catch_unwind(AssertUnwindSafe(|| f(b)));
                assert!(r.is_ok(), "body parser panicked on {b:?}");
            }
        }
    }
}

#[test]
fn knxnet_search_response_short_device_info_does_not_panic() {
    // A device-info DIB shorter than 52 bytes must be skipped, not indexed.
    let mut body = Vec::new();
    // control HPAI
    body.extend_from_slice(&[0x08, 0x01, 192, 168, 1, 20, 0x0E, 0x57]);
    // DIB len 10, type 1 (device info), only 8 body bytes (< 52).
    body.extend_from_slice(&[10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
    let r = catch_unwind(AssertUnwindSafe(|| parse_search_response(&body)));
    assert!(r.is_ok(), "short device-info DIB must not panic");
    let info = r.unwrap().expect("parses");
    // Too short to read the IA, so it stays None.
    assert!(info.individual_address.is_none());
}

#[test]
fn knxnet_full_service_frames_roundtrip() {
    // Round-trip the parseable service frames.
    let cemi = CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[1]);
    let ri = knxnet::routing_indication(&cemi);
    let parsed = parse(&ri).unwrap();
    assert_eq!(parsed.service, ServiceType::RoutingIndication);
    let back = knxnet::parse_routing_indication(parsed.body).unwrap();
    assert_eq!(back, cemi);
}

// ---------------------------------------------------------------------------
// GroupData::bytes() invariants and small/large classification.
// ---------------------------------------------------------------------------

#[test]
fn group_data_small_masks_to_six_bits() {
    // A Small value only exposes its low 6 bits.
    assert_eq!(GroupData::Small(0xFF).bytes(), vec![0x3F]);
    assert_eq!(GroupData::Small(0x00).bytes(), vec![0x00]);
    assert_eq!(GroupData::Large(vec![1, 2, 3]).bytes(), vec![1, 2, 3]);
}

#[test]
fn cemi_destination_type_follows_control2_group_bit() {
    // group_write targets a group; t_control targets an individual.
    let g = CemiFrame::group_write_packed(ga("1/2/3"), ia("1.1.1"), &[1]);
    assert!(matches!(g.destination, Destination::Group(_)));
    assert_eq!(g.message_code, MessageCode::LDataReq);

    let i = CemiFrame::t_control(ia("1.1.4"), ia("0.0.255"), 0x80);
    assert!(matches!(i.destination, Destination::Individual(_)));
}
