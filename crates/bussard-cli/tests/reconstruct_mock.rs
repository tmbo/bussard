//! End-to-end tests of `bussard reconstruct` against an in-process mock KNX
//! device (same mock-gateway pattern as `scan_mock.rs`).
//!
//! The scripted System B device serves object discovery and `PID_TABLE`
//! property arrays; the built `bussard` binary runs as a subprocess with
//! `--gateway 127.0.0.1:PORT --json` and the diff against a written model is
//! asserted: matching pairs, a pair only on the device, and a pair only in the
//! model. A second test checks the friendly refusal for a non-System-B mask.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x22;

/// A scripted System B device with PID_TABLE-served tables.
#[derive(Clone)]
struct TableDevice {
    address: IndividualAddress,
    mask: u16,
    object_types: Vec<u16>,
    props: HashMap<(u8, u8), Vec<Vec<u8>>>,
}

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn assoc_elem(tsap: u16, asap: u16) -> Vec<u8> {
    let mut v = tsap.to_be_bytes().to_vec();
    v.extend_from_slice(&asap.to_be_bytes());
    v
}

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

async fn push(gw: &UdpSocket, peer: SocketAddr, gw_seq: &mut u8, cemi: &CemiFrame) {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    gw.send_to(&knxnet::tunneling_request(hdr, cemi), peer)
        .await
        .unwrap();
    *gw_seq = gw_seq.wrapping_add(1);
}

fn property_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

fn device_response(dev: &TableDevice, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (req_apci, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    match req_apci {
        // Strict, like a real device: the descriptor type lives in the low 6
        // APCI bits and the request carries no payload octet.
        apci::A_DEVICE_DESCRIPTOR_READ if data.is_empty() => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let empty = || property_response(pv.object_index, pv.property_id, 0, pv.start, &[]);
            if pv.property_id == PID_OBJECT_TYPE {
                let resp = match dev.object_types.get(usize::from(pv.object_index)) {
                    Some(ot) => {
                        property_response(pv.object_index, pv.property_id, 1, pv.start, &be16(*ot))
                    }
                    None => empty(),
                };
                return Some((apci::A_PROPERTY_VALUE_RESPONSE, resp));
            }
            let Some(elems) = dev.props.get(&(pv.object_index, pv.property_id)) else {
                return Some((apci::A_PROPERTY_VALUE_RESPONSE, empty()));
            };
            let resp = if pv.start == 0 {
                property_response(
                    pv.object_index,
                    pv.property_id,
                    1,
                    0,
                    &be16(elems.len() as u16),
                )
            } else {
                let start = usize::from(pv.start);
                if start > elems.len() {
                    empty()
                } else {
                    let want = usize::from(pv.count).min(elems.len() - start + 1);
                    let bytes: Vec<u8> = elems[start - 1..start - 1 + want]
                        .iter()
                        .flatten()
                        .copied()
                        .collect();
                    property_response(
                        pv.object_index,
                        pv.property_id,
                        want as u8,
                        pv.start,
                        &bytes,
                    )
                }
            };
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => None,
    }
}

/// Runs the mock gateway until the client disconnects or it goes idle.
async fn run_gateway(gw: UdpSocket, device: TableDevice) {
    let mut gw_seq = 0u8;
    let mut dev_seq = 0u8;
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(30), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, &gw),
                );
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::ConnectionstateRequest => {
                gw.send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await
                    .unwrap();
            }
            ServiceType::DisconnectRequest => {
                gw.send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await
                    .unwrap();
                return;
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                gw.send_to(
                    &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                    from,
                )
                .await
                .unwrap();

                let cemi = &tr.cemi;
                let dest = match cemi.destination {
                    Destination::Individual(ia) => ia,
                    Destination::Group(_) => continue,
                };
                if dest != device.address {
                    continue;
                }
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => dev_seq = 0,
                    TpciKind::NumberedData(client_seq) => {
                        let ack =
                            CemiFrame::t_control(tool, device.address, tpci::t_ack(client_seq));
                        push(&gw, from, &mut gw_seq, &ack).await;
                        if let Some((rapci, rdata)) = device_response(&device, cemi) {
                            let resp = CemiFrame::t_data_connected(
                                tool,
                                device.address,
                                tpci::ndt(dev_seq),
                                rapci,
                                &rdata,
                            );
                            push(&gw, from, &mut gw_seq, &resp).await;
                            dev_seq = (dev_seq + 1) & 0x0f;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// The scripted device:
/// - GAs: 1/2/0, 1/2/1, 1/2/2
/// - associations: (1, 20), (2, 21), (3, 21) — the ASAP is the com-object
///   number → object 20: {1/2/0}; object 21: {1/2/1, 1/2/2}
fn scripted_device(addr: &str, mask: u16) -> TableDevice {
    let mut props = HashMap::new();
    props.insert(
        (1u8, PID_TABLE),
        vec![
            be16(ga("1/2/0").raw()),
            be16(ga("1/2/1").raw()),
            be16(ga("1/2/2").raw()),
        ],
    );
    props.insert(
        (2u8, PID_TABLE),
        vec![assoc_elem(1, 20), assoc_elem(2, 21), assoc_elem(3, 21)],
    );
    props.insert((3u8, PID_TABLE), (0..22).map(|_| be16(0x079C)).collect());
    TableDevice {
        address: addr.parse().unwrap(),
        mask,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        props,
    }
}

/// The model: object 20 matches; object 21 has one matching GA and one the
/// device does not have; object 99 exists only in the model.
fn write_model(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n    - 5/5/5\n  - object: 99\n    send: 4/4/4\n",
    )
    .unwrap();
}

fn run_reconstruct(port: u16, model_dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "reconstruct",
        "1.1.4",
        "--dir",
        model_dir.to_str().unwrap(),
        "--gateway",
    ];
    let gw = format!("127.0.0.1:{port}");
    args.push(&gw);
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard reconstruct")
}

#[test]
fn reconstruct_reports_inventory_and_diff() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });
    let handle = rt.spawn(run_gateway(gw, scripted_device("1.1.4", 0x07B0)));

    let tmp = std::env::temp_dir().join(format!("bussard-reconstruct-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = run_reconstruct(port, &model_dir, &["--json"]);
    rt.block_on(async { handle.abort() });
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "reconstruct should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--json must emit valid JSON: {e}\n{stdout}"));

    assert_eq!(json["address"], "1.1.4");
    assert_eq!(json["mask"], "07B0");
    assert_eq!(json["system_type"], "System B");
    assert_eq!(
        json["addresses"],
        serde_json::json!(["1/2/0", "1/2/1", "1/2/2"])
    );
    assert_eq!(json["associations"].as_array().unwrap().len(), 3);
    assert_eq!(json["objects"]["20"], serde_json::json!(["1/2/0"]));
    assert_eq!(json["objects"]["21"], serde_json::json!(["1/2/1", "1/2/2"]));
    assert!(
        json["table_source"]["addresses"]
            .as_str()
            .unwrap()
            .contains("property"),
        "address table should be read via the property path: {stdout}"
    );

    // The diff: matches (20 → 1/2/0, 21 → 1/2/1); on device only (21 → 1/2/2);
    // in model only (21 → 5/5/5, 99 → 4/4/4).
    let diff = &json["diff"];
    assert_eq!(
        diff["matches"],
        serde_json::json!([
            {"object": 20, "ga": "1/2/0"},
            {"object": 21, "ga": "1/2/1"},
        ])
    );
    assert_eq!(
        diff["on_device_not_in_model"],
        serde_json::json!([{"object": 21, "ga": "1/2/2"}])
    );
    assert_eq!(
        diff["in_model_not_on_device"],
        serde_json::json!([
            {"object": 21, "ga": "5/5/5"},
            {"object": 99, "ga": "4/4/4"},
        ])
    );
    assert!(
        diff["note"].as_str().unwrap().contains("send/listen"),
        "the direction limitation must be noted: {stdout}"
    );
}

#[test]
fn reconstruct_refuses_non_system_b_masks() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });
    // A System 7 device: reconstruct must refuse it with a friendly message.
    let handle = rt.spawn(run_gateway(gw, scripted_device("1.1.4", 0x0705)));

    let tmp = std::env::temp_dir().join(format!(
        "bussard-reconstruct-mask-test-{}",
        std::process::id()
    ));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = run_reconstruct(port, &model_dir, &[]);
    rt.block_on(async { handle.abort() });
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !output.status.success(),
        "a non-System-B mask must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0705") && stderr.contains("System B"),
        "the refusal must name the mask and the supported system: {stderr}"
    );
}
