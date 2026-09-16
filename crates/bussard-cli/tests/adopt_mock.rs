//! End-to-end tests of `bussard adopt` against an in-process mock KNX gateway.
//!
//! `adopt` is a wizard, so its non-interactive shape is gated: it runs only when
//! BOTH a `--product` file and the documented `BUSSARD_ADOPT_ADDRESS` env hook
//! are supplied (the env var stands in for the address the wizard would prompt
//! for). These tests assemble a tiny fabricated `.knxprod` in a temp dir — the
//! same technique `bussard-prod`'s own tests use — and drive the built binary as
//! a subprocess against a mock gateway hosting one device in programming mode.
//!
//! Cases:
//!   * happy path — device adopted, rich device file with a com-object table;
//!   * order-number mismatch — device reports an order the product doesn't list,
//!     so a loud warning prints but the run still succeeds;
//!   * no-device timeout — nothing in programming mode → clean failure;
//!   * product-less stub path — no `--product` and a non-TTY → refused (the
//!     wizard needs inputs), documenting the gate.

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

// ---------------------------------------------------------------------------
// A tiny fabricated .knxprod (fixture XML — no vendor data committed).
// ---------------------------------------------------------------------------

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-0083">
    <Hardware>
      <Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

// Two com-objects: one transmit-capable (a button, #0) and one write-only
// (#1). `adopt` should list the transmit-capable one first.
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
  <ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster BE 04001" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-0" Number="0" Text="Taste 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" ReadFlag="Disabled" WriteFlag="Disabled" />
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-1" Number="1" Text="LED 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-1_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-1" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn build_knxprod(path: &std::path::Path) {
    // A `.knxprod` is a plain ZIP. To keep this test free of a `zip` dev-dep
    // (file-set discipline — only adopt_*.rs is ours to add), we emit a
    // store-mode (uncompressed, method 0) ZIP by hand. Store mode needs only a
    // CRC-32 per entry, so the writer below is a few dozen lines.
    let entries: &[(&str, &[u8])] = &[
        ("knx_master.xml", b"<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML.as_bytes()),
        ("M-0083/M-0083_A-1234-11-ABCD-O000A.xml", APP_XML.as_bytes()),
    ];
    let bytes = zip_store(entries);
    std::fs::write(path, bytes).unwrap();
}

/// Emits a minimal store-mode (method 0) ZIP archive for the given entries.
fn zip_store(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        offsets.push(offset);
        let crc = crc32(data);
        let name_bytes = name.as_bytes();

        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // signature
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: store
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
    }

    // Central directory.
    let cd_start = out.len() as u32;
    for ((name, data), offset) in entries.iter().zip(&offsets) {
        let crc = crc32(data);
        let name_bytes = name.as_bytes();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // signature
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: store
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory record.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // signature
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries on disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// A standard CRC-32 (IEEE 802.3, reflected) over `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Mock gateway (a trimmed copy of tests/assign_mock.rs — same protocol shape).
// ---------------------------------------------------------------------------

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
                return;
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

// ---------------------------------------------------------------------------
// Test harness helpers.
// ---------------------------------------------------------------------------

fn write_model(dir: &std::path::Path) {
    std::fs::create_dir_all(dir.join("devices")).unwrap();
    // One existing device on line 1.1 so the explicit 1.1.7 sits on a known line.
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

/// Spawns the gateway and returns (runtime, port, join-handle, shared-devices).
fn spawn_gateway(devices: Shared) -> (tokio::runtime::Runtime, u16, tokio::task::JoinHandle<()>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });
    let handle = rt.spawn(run_gateway(gw, devices));
    (rt, port, handle)
}

fn factory_device(order: &[u8]) -> DeviceState {
    DeviceState {
        address: "15.15.255".parse().unwrap(),
        programming: true,
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: order.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn adopt_happy_path_writes_rich_device_file() {
    let shared: Shared = Arc::new(Mutex::new(vec![factory_device(b"MDT-BE-04001.02")]));
    let (rt, port, gw_handle) = spawn_gateway(shared);

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-happy-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--product",
            knxprod.to_str().unwrap(),
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard adopt");

    rt.block_on(async { gw_handle.abort() });
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    let device_file = model_dir.join("devices").join("1.1.7-taster-be-04001.yaml");
    let body = std::fs::read_to_string(&device_file).ok();
    let vendor_cached = knxprod_cached(&model_dir);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "adopt should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("adopted 15.15.255 → 1.1.7"),
        "expected the adopted line; stdout:\n{stdout}"
    );
    // No order-number mismatch warning on the happy path.
    assert!(
        !stderr.contains("WARNING:"),
        "no mismatch warning expected; stderr:\n{stderr}"
    );
    // A ready-to-paste links snippet is printed (model itself untouched).
    assert!(
        stdout.contains("links.yaml (under `links:`)"),
        "expected a links.yaml snippet; stdout:\n{stdout}"
    );
    assert!(
        !model_dir.join("links.yaml").exists(),
        "adopt must not create links.yaml — it prints a snippet only"
    );
    // Flash pointer surfaces for a product-backed adoption.
    assert!(
        stdout.contains("bussard flash 1.1.7"),
        "expected a flash pointer; stdout:\n{stdout}"
    );

    // The rich device file: address, product identity, and a com-object table.
    let body = body.expect("device file should exist");
    assert!(body.contains("address: 1.1.7"), "device body:\n{body}");
    assert!(body.contains("Taster BE 04001"), "device body:\n{body}");
    assert!(body.contains("MDT-BE-04001.02"), "device body:\n{body}");
    assert!(
        body.contains("M-0083_A-1234-11-ABCD-O000A"),
        "expected application_ref; device body:\n{body}"
    );
    assert!(body.contains("com_objects:"), "device body:\n{body}");
    // The two com-objects with their DPTs.
    assert!(
        body.contains("1.001"),
        "expected a DPT; device body:\n{body}"
    );
    // The vendor .knxprod is cached under vendor/.
    assert!(
        vendor_cached,
        "expected the vendor file cached under vendor/"
    );
}

#[test]
fn adopt_warns_on_order_number_mismatch() {
    // The device reports a totally different order number than the product lists.
    let shared: Shared = Arc::new(Mutex::new(vec![factory_device(b"JUNG-4093TSM")]));
    let (rt, port, gw_handle) = spawn_gateway(shared);

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-mismatch-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--product",
            knxprod.to_str().unwrap(),
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard adopt");

    rt.block_on(async { gw_handle.abort() });
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    // A mismatch is a loud warning, not a failure.
    assert!(
        success,
        "mismatch must not fail the run; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("WARNING") && stderr.contains("JUNG-4093TSM"),
        "expected a loud order-number mismatch warning; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("adopted 15.15.255 → 1.1.7"),
        "still adopts; stdout:\n{stdout}"
    );
}

#[test]
fn adopt_times_out_with_no_device() {
    // No device in programming mode → clean failure after the (shortened) budget.
    let shared: Shared = Arc::new(Mutex::new(vec![]));
    let (rt, port, gw_handle) = spawn_gateway(shared);

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-timeout-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--product",
            knxprod.to_str().unwrap(),
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "300")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard adopt");

    rt.block_on(async { gw_handle.abort() });
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let device_written = model_dir
        .join("devices")
        .join("1.1.7-taster-be-04001.yaml")
        .exists();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !success,
        "no device in programming mode must fail; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("no device entered programming mode"),
        "expected the timeout guidance; stderr:\n{stderr}"
    );
    assert!(
        !device_written,
        "no device file should be written on timeout"
    );
}

#[test]
fn adopt_refuses_product_less_non_tty() {
    // No --product and a non-TTY: the wizard needs inputs, so it must refuse.
    let tmp = std::env::temp_dir().join(format!("bussard-adopt-refuse-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir);

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--dir",
            model_dir.to_str().unwrap(),
            "--gateway",
            "127.0.0.1:1", // never contacted — the gate fails first
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard adopt");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !success,
        "product-less non-TTY adopt must be refused; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("interactive wizard") && stderr.contains("BUSSARD_ADOPT_ADDRESS"),
        "expected the wizard-needs-inputs refusal; stderr:\n{stderr}"
    );
}

/// Whether the vendor `.knxprod` was cached under `<dir>/vendor/`.
fn knxprod_cached(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir.join("vendor"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().ends_with(".knxprod"))
}
