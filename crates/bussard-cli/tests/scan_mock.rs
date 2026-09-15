//! End-to-end test of `bussard scan` against an in-process mock KNX line.
//!
//! A mock KNXnet/IP gateway task answers the management protocol for three
//! present devices among otherwise-absent addresses on line `1.1`. The built
//! `bussard` binary is run as a subprocess with `--gateway 127.0.0.1:PORT
//! --json`, and its JSON output is asserted for device content and the model
//! cross-reference (one device present on the bus but missing from the model,
//! one model device that did not respond).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x21;

struct Device {
    address: IndividualAddress,
    mask: u16,
    manufacturer: u16,
    serial: Vec<u8>,
    order: Vec<u8>,
}

fn device(addr: &str, mask: u16, manufacturer: u16, order: &[u8]) -> Device {
    Device {
        address: addr.parse().unwrap(),
        mask,
        manufacturer,
        serial: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        order: order.to_vec(),
    }
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

fn device_response(dev: &Device, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (apci, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    match apci {
        apci::A_DEVICE_DESCRIPTOR_READ => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => dev.manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => dev.serial.clone(),
                apci::PID_ORDER_INFO => dev.order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0 } else { 1 };
            let mut resp = vec![
                pv.object_index,
                pv.property_id,
                (count << 4) | ((pv.start >> 8) as u8 & 0x0f),
                (pv.start & 0xff) as u8,
            ];
            resp.extend_from_slice(&value);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => None,
    }
}

async fn handle(
    gw: &UdpSocket,
    peer: SocketAddr,
    devices: &[Device],
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_seq: &mut HashMap<u16, u8>,
) {
    let dest = match cemi.destination {
        Destination::Individual(ia) => ia,
        Destination::Group(_) => return,
    };
    let Some(dev) = devices.iter().find(|d| d.address == dest) else {
        return; // absent address
    };
    let tool = cemi.source;
    match tpci::classify(cemi.tpci_octet()) {
        TpciKind::Connect => {
            dev_seq.insert(dev.address.raw(), 0);
        }
        TpciKind::Disconnect => {
            dev_seq.remove(&dev.address.raw());
        }
        TpciKind::NumberedData(client_seq) => {
            // ACK the request.
            let ack = CemiFrame::t_control(tool, dev.address, tpci::t_ack(client_seq));
            push(gw, peer, gw_seq, &ack).await;
            // Answer.
            if let Some((rapci, rdata)) = device_response(dev, cemi) {
                let seq = *dev_seq.get(&dev.address.raw()).unwrap_or(&0);
                let resp =
                    CemiFrame::t_data_connected(tool, dev.address, tpci::ndt(seq), rapci, &rdata);
                push(gw, peer, gw_seq, &resp).await;
                dev_seq.insert(dev.address.raw(), (seq + 1) & 0x0f);
            }
        }
        _ => {}
    }
}

/// Runs the mock gateway until the client disconnects or it goes idle.
async fn run_gateway(gw: UdpSocket, devices: Vec<Device>) {
    let mut gw_seq = 0u8;
    let mut dev_seq: HashMap<u16, u8> = HashMap::new();
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
                handle(&gw, from, &devices, &tr.cemi, &mut gw_seq, &mut dev_seq).await;
            }
            _ => {}
        }
    }
}

fn write_model(dir: &std::path::Path) {
    std::fs::create_dir_all(dir.join("devices")).unwrap();
    // Model knows 1.1.4 and 1.1.6; 1.1.6 will NOT respond (missing from bus),
    // and 1.1.7 responds but is NOT in the model. Kept in a tight device-number
    // cluster so the test can restrict the sweep to `--from 1 --to 8`.
    std::fs::write(
        dir.join("devices").join("1.1.4-jal.yaml"),
        "address: 1.1.4\nname: Rollladen Wohnzimmer\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("devices").join("1.1.6-dimmer.yaml"),
        "address: 1.1.6\nname: Dimmer Flur\n",
    )
    .unwrap();
}

#[test]
fn scan_reports_devices_and_model_delta() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Bind the mock gateway and learn its port before spawning.
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });

    // Three present devices among absent addresses, all inside 1..=8 so the
    // sweep can be restricted to a handful of addresses.
    let devices = vec![
        device("1.1.4", 0x07B0, 0x0083, b"MDT-JAL0410"), // MDT, System B, known
        device("1.1.7", 0x0705, 0x0004, b"2118REGHE"),   // Jung, System 7, not in model
        device("1.1.8", 0x0012, 0x0002, b"6197/15"),     // ABB, System 1, not in model
    ];

    let handle = rt.spawn(run_gateway(gw, devices));

    let tmp = std::env::temp_dir().join(format!("bussard-scan-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "scan",
            "1.1",
            "--from",
            "1",
            "--to",
            "8",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
            "--json",
        ])
        // Keep the few absent-address probes fast; combined with the 1..=8 range
        // restriction the whole mock sweep finishes in well under a second.
        .env("BUSSARD_SCAN_DISCOVERY_MS", "40")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard scan");

    rt.block_on(async { handle.abort() });
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "scan should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json must emit valid JSON: {e}\n{stdout}"));

    let found = json["found"].as_array().expect("found array");
    assert_eq!(found.len(), 3, "three devices should respond: {stdout}");

    // Find 1.1.4 and check its decoded fields.
    let d4 = found
        .iter()
        .find(|d| d["address"] == "1.1.4")
        .expect("1.1.4 present");
    assert_eq!(d4["mask"], "07B0");
    assert_eq!(d4["system_type"], "System B");
    assert_eq!(d4["manufacturer"], "MDT");
    assert_eq!(d4["order"], "MDT-JAL0410");
    assert_eq!(d4["model_status"], "known");

    // 1.1.7 responds but is not in the model.
    let d7 = found
        .iter()
        .find(|d| d["address"] == "1.1.7")
        .expect("1.1.7 present");
    assert_eq!(d7["manufacturer"], "Jung");
    assert_eq!(d7["system_type"], "System 7");
    assert_eq!(d7["model_status"], "not_in_model");

    // 1.1.8 → ABB, System 1.
    let d8 = found
        .iter()
        .find(|d| d["address"] == "1.1.8")
        .expect("1.1.8 present");
    assert_eq!(d8["manufacturer"], "ABB");
    assert_eq!(d8["system_type"], "System 1");

    // Cross-reference deltas.
    let not_in_model: Vec<&str> = json["not_in_model"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(not_in_model.contains(&"1.1.7"));
    assert!(not_in_model.contains(&"1.1.8"));

    let missing: Vec<&str> = json["missing_from_bus"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_str().unwrap())
        .collect();
    assert_eq!(missing, vec!["1.1.6"], "1.1.6 is in the model but silent");
}
