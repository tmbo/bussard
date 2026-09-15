//! End-to-end test of `bussard assign` against an in-process mock KNX gateway.
//!
//! A mock KNXnet/IP gateway task answers the broadcast + connected management
//! protocol for a single device that starts in programming mode at the factory
//! address 15.15.255. The built `bussard` binary is run as a subprocess with an
//! **explicit** target address (so its non-TTY confirmation gate passes), and
//! the test asserts it exits 0, prints the old → new line, and writes a stub
//! device file into the model directory.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x22;

#[derive(Clone)]
struct DeviceState {
    address: IndividualAddress,
    programming: bool,
    mask: u16,
    manufacturer: u16,
    serial: [u8; 6],
    order: Vec<u8>,
}

type Shared = Arc<Mutex<Vec<DeviceState>>>;

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

async fn handle(
    gw: &UdpSocket,
    peer: SocketAddr,
    devices: &Shared,
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_seq: &mut HashMap<u16, u8>,
) {
    let tool = cemi.source;
    match &cemi.destination {
        Destination::Group(_) => {
            let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
                (Tpci::DataGroup, Apdu::Other { apci, data }) => (*apci, data.clone()),
                _ => return,
            };
            match apci_val {
                apci::A_INDIVIDUAL_ADDRESS_READ => {
                    let responders: Vec<IndividualAddress> = {
                        let devs = devices.lock().unwrap();
                        devs.iter()
                            .filter(|d| d.programming)
                            .map(|d| d.address)
                            .collect()
                    };
                    for addr in responders {
                        let resp =
                            CemiFrame::t_broadcast(addr, apci::A_INDIVIDUAL_ADDRESS_RESPONSE, &[]);
                        push(gw, peer, gw_seq, &resp).await;
                    }
                }
                apci::A_INDIVIDUAL_ADDRESS_WRITE if data.len() >= 2 => {
                    let new_addr =
                        IndividualAddress::from_raw(u16::from_be_bytes([data[0], data[1]]));
                    let mut devs = devices.lock().unwrap();
                    for d in devs.iter_mut() {
                        if d.programming {
                            d.address = new_addr;
                            d.programming = false;
                        }
                    }
                }
                _ => {}
            }
        }
        Destination::Individual(dest) => {
            let dest = *dest;
            let dev = {
                let devs = devices.lock().unwrap();
                devs.iter().find(|d| d.address == dest).cloned()
            };
            let Some(dev) = dev else {
                return; // absent address
            };
            match tpci::classify(cemi.tpci_octet()) {
                TpciKind::Connect => {
                    dev_seq.insert(dev.address.raw(), 0);
                }
                TpciKind::Disconnect => {
                    dev_seq.remove(&dev.address.raw());
                }
                TpciKind::NumberedData(client_seq) => {
                    let ack = CemiFrame::t_control(tool, dev.address, tpci::t_ack(client_seq));
                    push(gw, peer, gw_seq, &ack).await;
                    if let Some((rapci, rdata)) = device_response(&dev, cemi) {
                        let seq = *dev_seq.get(&dev.address.raw()).unwrap_or(&0);
                        let resp = CemiFrame::t_data_connected(
                            tool,
                            dev.address,
                            tpci::ndt(seq),
                            rapci,
                            &rdata,
                        );
                        push(gw, peer, gw_seq, &resp).await;
                        dev_seq.insert(dev.address.raw(), (seq + 1) & 0x0f);
                    }
                }
                _ => {}
            }
        }
    }
}

fn device_response(dev: &DeviceState, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    match apci_val {
        apci::A_DEVICE_DESCRIPTOR_READ => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => dev.manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => dev.serial.to_vec(),
                apci::PID_ORDER_INFO => dev.order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0u8 } else { 1 };
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

async fn run_gateway(gw: UdpSocket, devices: Shared) {
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
    // One existing device on line 1.1 so the model has a dominant line and the
    // explicit 1.1.7 sits on a known line.
    std::fs::write(
        dir.join("devices").join("1.1.4-jal.yaml"),
        "address: 1.1.4\nname: Rollladen Wohnzimmer\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n",
    )
    .unwrap();
}

#[test]
fn assign_writes_address_and_stub_file() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });

    // A factory device in programming mode at 15.15.255.
    let shared: Shared = Arc::new(Mutex::new(vec![DeviceState {
        address: "15.15.255".parse().unwrap(),
        programming: true,
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: b"MDT-JAL0410".to_vec(),
    }]));
    let handle = rt.spawn(run_gateway(gw, shared));

    let tmp = std::env::temp_dir().join(format!("bussard-assign-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        // Shrink both the poll budgets and the per-poll collection window: the
        // programming-mode device answers instantly, so a 200ms window is ample
        // and avoids the default 1500ms wait.
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null()) // non-TTY: explicit address must be accepted
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard assign");

    rt.block_on(async { handle.abort() });

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    // Read the stub file before cleanup.
    let stub = model_dir
        .join("devices")
        .join("1.1.7-new-device-assign.yaml");
    let stub_body = std::fs::read_to_string(&stub).ok();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "assign should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("assigned 15.15.255 → 1.1.7"),
        "expected old→new line; stdout:\n{stdout}"
    );

    let body = stub_body.expect("stub device file should exist");
    assert!(body.contains("address: 1.1.7"), "stub body:\n{body}");
    assert!(body.contains("New device (assign)"), "stub body:\n{body}");
    // The product block reflects the verified read-back (MDT / order / mask).
    assert!(body.contains("MDT"), "stub body:\n{body}");
    assert!(body.contains("MDT-JAL0410"), "stub body:\n{body}");
}

#[test]
fn assign_refuses_implicit_address_without_tty() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });
    let shared: Shared = Arc::new(Mutex::new(vec![DeviceState {
        address: "15.15.255".parse().unwrap(),
        programming: true,
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: b"MDT-JAL0410".to_vec(),
    }]));
    let handle = rt.spawn(run_gateway(gw, shared));

    let tmp = std::env::temp_dir().join(format!("bussard-assign-tty-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    // No explicit address → implicit allocation. Piped stdin (non-TTY) must be
    // refused for safety.
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        // The device is in programming mode and answers instantly; a short
        // collection window keeps the safety-refusal path fast.
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard assign");

    rt.block_on(async { handle.abort() });
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !output.status.success(),
        "implicit allocation without a TTY must fail; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refusing to assign") || stderr.contains("without a terminal"),
        "expected a safety refusal; stderr:\n{stderr}"
    );
}
