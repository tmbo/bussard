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
    /// When true, the device keeps answering the programming-mode broadcast even
    /// after it takes its new address — modelling a KNX Virtual device (which
    /// does not clear programming mode) or a stuck programming button.
    stay_in_programming: bool,
    /// Set true once the tool writes `PID_PROGMODE = 0` on the device object,
    /// so the test can assert bussard clears programming mode explicitly (as ETS
    /// does) after the assignment.
    progmode_write_seen: bool,
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
                            // A conformant device leaves programming mode here;
                            // a KNX-Virtual-style device keeps answering.
                            d.programming = d.stay_in_programming;
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
                    // A property-value WRITE mutates device state (e.g. clearing
                    // programming mode via PID_PROGMODE = 0) and is echoed back as a
                    // confirming A_PropertyValue_Response. Handle it with mutable
                    // access to the shared device before the read-only responder.
                    let write_response = handle_property_write(devices, dest, cemi);
                    if let Some((rapci, rdata)) =
                        write_response.or_else(|| device_response(&dev, cemi))
                    {
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
        // Authorize (issue #52 finding #1): grant full access (level 0).
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
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

/// Handles an `A_PropertyValue_Write` against the shared device state, echoing the
/// stored value back in an `A_PropertyValue_Response` (the KNX confirm form).
/// Returns `None` for any non-write telegram so the caller falls through to the
/// read-only responder. Records a `PID_PROGMODE = 0` write on the device object so
/// the test can assert bussard cleared programming mode, as ETS does.
fn handle_property_write(
    devices: &Shared,
    dest: IndividualAddress,
    cemi: &CemiFrame,
) -> Option<(u16, Vec<u8>)> {
    let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    if apci_val != apci::A_PROPERTY_VALUE_WRITE || data.len() < 4 {
        return None;
    }
    // De-mirrored A_PropertyValue_Write header: [obj_index, pid, (count<<4)|start_hi, start_lo, value…].
    let object_index = data[0];
    let property_id = data[1];
    let count = (data[2] >> 4) & 0x0f;
    let start = (((data[2] & 0x0f) as u16) << 8) | data[3] as u16;
    let value = data[4..].to_vec();

    if object_index == apci::DEVICE_OBJECT_INDEX
        && property_id == apci::PID_PROGMODE
        && value.first() == Some(&0x00)
    {
        let mut devs = devices.lock().unwrap();
        for d in devs.iter_mut() {
            if d.address == dest {
                d.progmode_write_seen = true;
                // The device clears programming mode when told to (unless it is
                // modelling a stuck one that ignores the write).
                if !d.stay_in_programming {
                    d.programming = false;
                }
            }
        }
    }
    // Echo the stored value back as the confirming response.
    let mut resp = vec![
        object_index,
        property_id,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(&value);
    Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
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
        stay_in_programming: false,
        progmode_write_seen: false,
    }]));
    let handle = rt.spawn(run_gateway(gw, shared));

    let tmp = std::env::temp_dir().join(format!("bussard-assign-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
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
    // The device cleared programming mode, so no persistence warning.
    assert!(
        !stderr.contains("still in programming mode"),
        "a device that cleared programming mode must NOT warn; stderr:\n{stderr}"
    );

    let body = stub_body.expect("stub device file should exist");
    assert!(body.contains("address: 1.1.7"), "stub body:\n{body}");
    assert!(body.contains("New device (assign)"), "stub body:\n{body}");
    // The product block reflects the verified read-back (MDT / order / mask).
    assert!(body.contains("MDT"), "stub body:\n{body}");
    assert!(body.contains("MDT-JAL0410"), "stub body:\n{body}");
}

#[test]
fn assign_clears_programming_mode_like_ets() {
    // After the address write + verify, bussard must explicitly clear programming
    // mode by writing PID_PROGMODE = 0 on the device object (index 0), exactly as
    // ETS does — not merely rely on the device auto-clearing. This asserts the
    // write reached the device AND that assign reports it.
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
        stay_in_programming: false,
        progmode_write_seen: false,
    }]));
    // Keep a handle to the shared state to inspect it after the run.
    let observer = Arc::clone(&shared);
    let handle = rt.spawn(run_gateway(gw, shared));

    let tmp = std::env::temp_dir().join(format!("bussard-assign-clearprog-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard assign");

    rt.block_on(async { handle.abort() });

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let progmode_write_seen = observer.lock().unwrap()[0].progmode_write_seen;
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "assign should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The explicit PID_PROGMODE = 0 write must have reached the device.
    assert!(
        progmode_write_seen,
        "assign must write PID_PROGMODE = 0 to clear programming mode (ETS behaviour); \
         stderr:\n{stderr}"
    );
    // assign reports that it cleared programming mode.
    assert!(
        stderr.contains("cleared programming mode on 1.1.7"),
        "assign should report clearing programming mode; stderr:\n{stderr}"
    );
    // A conformant device that took the explicit clear does NOT trigger the
    // persistence warning.
    assert!(
        !stderr.contains("still in programming mode"),
        "a device that cleared must not warn; stderr:\n{stderr}"
    );
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
        stay_in_programming: false,
        progmode_write_seen: false,
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

#[test]
fn assign_warns_when_device_stays_in_programming_mode() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });

    // A KNX-Virtual-style device: it takes the new address but keeps answering
    // the programming-mode broadcast (never clears programming mode).
    let shared: Shared = Arc::new(Mutex::new(vec![DeviceState {
        address: "15.15.255".parse().unwrap(),
        programming: true,
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: b"MDT-JAL0410".to_vec(),
        stay_in_programming: true,
        progmode_write_seen: false,
    }]));
    let handle = rt.spawn(run_gateway(gw, shared));

    let tmp = std::env::temp_dir().join(format!("bussard-assign-progmode-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard assign");

    rt.block_on(async { handle.abort() });

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    // The assignment still succeeds — the warning is advisory, not fatal.
    assert!(
        success,
        "assign should still exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("assigned 15.15.255 → 1.1.7"),
        "expected old→new line; stdout:\n{stdout}"
    );
    // The persistence warning must fire, naming the address and the KNX Virtual
    // guidance.
    assert!(
        stderr.contains("1.1.7 is still in programming mode"),
        "expected a programming-mode persistence warning; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("KNX Virtual"),
        "warning should point at the KNX Virtual GUI toggle; stderr:\n{stderr}"
    );
}
