//! The sim started from a recorded download (`knx_sim::replay`, bussard
//! issues #469 and #478): the ETS DA.tp flash, wrapped as a capture of
//! tunnelling requests (with a retransmission and the gateway's
//! confirmations), replays to the same device state as the requests delivered
//! one by one.

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::RecordingSink;
use knx_sim::device::{Device, LoadState};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::replay::{ReplayError, replay, requests_from_capture};
use knx_sim::wire::knxnetip::service;
use knx_sim::wire::{CemiLData, ConnectionHeader, IndividualAddress, KnxnetIpFrame, MessageCode};

const FIXTURE: &str = include_str!("fixtures/ets_da_tp_flash_requests.txt");

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn requests() -> Result<Vec<CemiLData>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for line in FIXTURE.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let src = u16::from_str_radix(parts.next().ok_or("src")?, 16)?;
        let dst = u16::from_str_radix(parts.next().ok_or("dst")?, 16)?;
        let hex = parts.next().ok_or("tpdu")?;
        let tpdu = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        out.push(CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress(src),
            dest: dst,
            tpdu,
        });
    }
    Ok(out)
}

/// A classic pcap (raw IPv4, as the sim records) of one tunnel carrying
/// `requests`, each followed by the gateway's confirmation, the first one
/// retransmitted once.
fn capture(requests: &[CemiLData]) -> Vec<u8> {
    let mut datagrams = vec![KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0; 20])];
    for (n, r) in requests.iter().enumerate() {
        let frame = |cemi: &CemiLData| {
            let mut body = ConnectionHeader {
                channel: 7,
                seq: n as u8,
                status: 0,
            }
            .to_bytes()
            .to_vec();
            body.extend_from_slice(&cemi.encode());
            KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body)
        };
        datagrams.push(frame(r));
        if n == 0 {
            datagrams.push(frame(r));
        }
        datagrams.push(frame(&CemiLData {
            message_code: MessageCode::LDataCon,
            ..r.clone()
        }));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    for v in [0u32, 0, 65535, 101] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for d in datagrams {
        let udp_len = 8 + d.len();
        let total = 20 + udp_len;
        let mut pkt = vec![0x45, 0];
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]);
        pkt.extend_from_slice(&[0xc0, 0x00, 0x0e, 0x58]);
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&d);
        for v in [0u32, 0, pkt.len() as u32, pkt.len() as u32] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&pkt);
    }
    out
}

#[test]
fn test_requests_from_capture_da_tp_flash_round_trips() -> TestResult {
    let want = requests()?;
    let got = requests_from_capture(&capture(&want))?;
    assert_eq!(got, want);
    Ok(())
}

#[test]
fn test_replay_da_tp_flash_matches_direct_delivery() -> TestResult {
    let Some(bytes) = knx_sim::testfixtures::da_tp_knxprod() else {
        eprintln!("SKIP: DA.tp fixture not present; place it in tests/fixtures/");
        return Ok(());
    };
    let pd = read_knxprod_bytes(&bytes, Some("M-00FA_A-2500-10-51CB"))?;
    let ia = IndividualAddress::new(1, 1, 2);
    let bus_with = || -> Bus {
        let sink = Arc::new(RecordingSink::new());
        let mut bus = Bus::new(sink.clone());
        bus.add_device(Device::from_product(ia, &pd, LoadState::Unloaded, sink));
        bus
    };
    // The same requests delivered one by one, as the calibration tests do.
    let mut direct = bus_with();
    for r in requests()? {
        let _ = direct.deliver_from_tool(&r);
    }
    let mut replayed = bus_with();
    let reqs = requests_from_capture(&capture(&requests()?))?;
    assert_eq!(replay(&mut replayed, &reqs, 0x1000), reqs.len());
    let (a, b) = (
        direct.device(ia).ok_or("device")?,
        replayed.device(ia).ok_or("device")?,
    );
    for lsm in 1..=4u8 {
        assert_eq!(a.load_state(lsm), b.load_state(lsm), "LSM {lsm}");
    }
    // The download's tables and parameters landed, byte for byte.
    for (addr, len) in [
        (0x6000u32, 256usize),
        (0x8000, 64),
        (0xA000, 64),
        (0xC000, 64),
    ] {
        assert_eq!(
            a.memory().read(addr, len),
            b.memory().read(addr, len),
            "0x{addr:04X}"
        );
    }
    assert!(b.memory().written_len() > 0);
    Ok(())
}

#[test]
fn test_replay_files_missing_capture_is_an_error() {
    let mut bus = Bus::new(Arc::new(RecordingSink::new()));
    let err = knx_sim::replay::replay_files(&mut bus, &["/nonexistent/x.pcap"], 0x1000);
    assert!(matches!(err, Err(ReplayError::Io { .. })));
}
