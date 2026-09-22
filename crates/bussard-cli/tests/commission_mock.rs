//! End-to-end tests of `bussard commission` against an in-process mock KNX
//! gateway (issue #100).
//!
//! One physical device sits on the bench at the factory address `15.15.255`
//! with its programming button pressed. The model says which products belong at
//! which addresses on line `1.1`, and `commission` must refuse to address the
//! bench device wherever the order numbers disagree — a hard stop for that
//! device only, with the run continuing to the next one.
//!
//! The mock is the `assign` gateway extended with an order-number-carrying
//! device: it answers the programming-mode broadcast, the descriptor and the
//! device-object property reads, takes `A_IndividualAddress_Write`, and honours
//! the `PID_PROGMODE = 0` clear. Addresses no device holds stay silent, which is
//! how `commission`'s presence pre-pass decides a model device is not yet
//! assigned.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x66;

/// The single device on the bench.
#[derive(Clone)]
struct DeviceState {
    address: IndividualAddress,
    programming: bool,
    mask: u16,
    manufacturer: u16,
    serial: [u8; 6],
    /// What the device reports for `PID_ORDER_INFO` — the field the hard stop
    /// compares against the model.
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

fn connect_response_body(channel: u8, port: u16) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

async fn push(gw: &UdpSocket, peer: SocketAddr, gw_seq: &mut u8, cemi: &CemiFrame) -> bool {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    if gw
        .send_to(&knxnet::tunneling_request(hdr, cemi), peer)
        .await
        .is_err()
    {
        return false;
    }
    *gw_seq = gw_seq.wrapping_add(1);
    true
}

/// Answers the read-only device-object properties and the descriptor.
fn device_response(dev: &DeviceState, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    match apci_val {
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

/// Handles `A_PropertyValue_Write`, echoing the stored value back. A
/// `PID_PROGMODE = 0` write clears programming mode, as a conformant device does.
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
    let object_index = data[0];
    let property_id = data[1];
    let count = (data[2] >> 4) & 0x0f;
    let start = (((data[2] & 0x0f) as u16) << 8) | data[3] as u16;
    let value = data[4..].to_vec();

    if object_index == apci::DEVICE_OBJECT_INDEX
        && property_id == apci::PID_PROGMODE
        && value.first() == Some(&0x00)
    {
        if let Ok(mut devs) = devices.lock() {
            for d in devs.iter_mut() {
                if d.address == dest {
                    d.programming = false;
                }
            }
        }
    }
    let mut resp = vec![
        object_index,
        property_id,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(&value);
    Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
}

async fn handle(
    gw: &UdpSocket,
    peer: SocketAddr,
    devices: &Shared,
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_seq: &mut HashMap<u16, u8>,
) -> bool {
    let tool = cemi.source;
    match &cemi.destination {
        Destination::Group(_) => {
            let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
                (Tpci::DataGroup, Apdu::Other { apci, data }) => (*apci, data.clone()),
                _ => return true,
            };
            match apci_val {
                apci::A_INDIVIDUAL_ADDRESS_READ => {
                    let responders: Vec<IndividualAddress> = {
                        let Ok(devs) = devices.lock() else {
                            return false;
                        };
                        devs.iter()
                            .filter(|d| d.programming)
                            .map(|d| d.address)
                            .collect()
                    };
                    for addr in responders {
                        let resp =
                            CemiFrame::t_broadcast(addr, apci::A_INDIVIDUAL_ADDRESS_RESPONSE, &[]);
                        if !push(gw, peer, gw_seq, &resp).await {
                            return false;
                        }
                    }
                }
                apci::A_INDIVIDUAL_ADDRESS_WRITE if data.len() >= 2 => {
                    let new_addr =
                        IndividualAddress::from_raw(u16::from_be_bytes([data[0], data[1]]));
                    let Ok(mut devs) = devices.lock() else {
                        return false;
                    };
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
                let Ok(devs) = devices.lock() else {
                    return false;
                };
                devs.iter().find(|d| d.address == dest).cloned()
            };
            let Some(dev) = dev else {
                return true; // absent address: silence
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
                    if !push(gw, peer, gw_seq, &ack).await {
                        return false;
                    }
                    let write_response = handle_property_write(devices, dest, cemi);
                    if let Some((rapci, rdata)) =
                        write_response.or_else(|| device_response(&dev, cemi))
                    {
                        let seq = dev_seq.get(&dev.address.raw()).copied().unwrap_or(0);
                        let resp = CemiFrame::t_data_connected(
                            tool,
                            dev.address,
                            tpci::ndt(seq),
                            rapci,
                            &rdata,
                        );
                        if !push(gw, peer, gw_seq, &resp).await {
                            return false;
                        }
                        dev_seq.insert(dev.address.raw(), (seq + 1) & 0x0f);
                    }
                }
                _ => {}
            }
        }
    }
    true
}

async fn run_gateway(gw: UdpSocket, devices: Shared) {
    let Ok(local) = gw.local_addr() else {
        return;
    };
    let port = local.port();
    let mut gw_seq = 0u8;
    let mut dev_seq: HashMap<u16, u8> = HashMap::new();
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(60), gw.recv_from(&mut buf)).await {
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
                    &connect_response_body(CHANNEL, port),
                );
                if gw.send_to(&resp, from).await.is_err() {
                    return;
                }
            }
            ServiceType::ConnectionstateRequest => {
                if gw
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ServiceType::DisconnectRequest => {
                // Keep serving: `commission` opens one tunnel per device.
                if gw
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                if gw
                    .send_to(
                        &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                        from,
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                if !handle(&gw, from, &devices, &tr.cemi, &mut gw_seq, &mut dev_seq).await {
                    return;
                }
            }
            _ => {}
        }
    }
}

/// The bench device: in programming mode at the factory address, reporting
/// `order` for `PID_ORDER_INFO`.
fn bench_device(order: &str) -> anyhow::Result<DeviceState> {
    Ok(DeviceState {
        address: "15.15.255".parse()?,
        programming: true,
        mask: 0x07B0,
        manufacturer: 0x0083, // MDT
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: order.as_bytes().to_vec(),
    })
}

/// Writes a model device file with a product block and a location.
fn write_device(dir: &Path, address: &str, name: &str, order: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join(format!("{address}.yaml")),
        format!(
            "address: {address}\nname: {name}\nlocation:\n  floor: Ground floor\n  room: Living room\nproduct:\n  manufacturer: MDT\n  order_number: {order}\n"
        ),
    )?;
    Ok(())
}

/// A unique temporary directory for one test.
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bussard-commission-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// Spawns the mock bench, returning its port and the gateway task handle.
fn spawn_bench(
    rt: &tokio::runtime::Runtime,
    order: &str,
) -> anyhow::Result<(u16, Shared, tokio::task::JoinHandle<()>)> {
    let (sock, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let port = sock.local_addr()?.port();
        anyhow::Ok((sock, port))
    })?;
    let shared: Shared = Arc::new(Mutex::new(vec![bench_device(order)?]));
    let handle = rt.spawn(run_gateway(sock, Arc::clone(&shared)));
    Ok((port, shared, handle))
}

/// Runs the built `bussard` binary against the mock bench.
fn run_commission(port: u16, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let gw = format!("127.0.0.1:{port}");
    let mut all: Vec<&str> = args.to_vec();
    all.push("--gateway");
    all.push(&gw);
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&all)
        // Shrink the programming-mode poll budgets and the presence pre-pass:
        // the mock answers instantly.
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_SCAN_DISCOVERY_MS", "150")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// Finds one device row in a `--json` summary.
fn row<'a>(json: &'a serde_json::Value, address: &str) -> anyhow::Result<&'a serde_json::Value> {
    json["devices"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no devices array in {json}"))?
        .iter()
        .find(|d| d["address"] == address)
        .ok_or_else(|| anyhow::anyhow!("no row for {address} in {json}"))
}

#[test]
fn test_commission_assigns_and_writes_the_label_row() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (port, shared, task) = spawn_bench(&rt, "JAL-0810.03")?;

    let tmp = tmp_dir("happy");
    let model_dir = tmp.join("knx");
    write_device(&model_dir, "1.1.7", "Blind actuator", "JAL-0810.03")?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();
    let labels = tmp.join("labels.csv");
    let labels_arg = labels
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();

    let output = run_commission(
        port,
        &[
            "commission",
            "--line",
            "1.1",
            "--yes",
            "--dir",
            &model_arg,
            "--labels",
            &labels_arg,
        ],
    )?;
    task.abort();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let csv = std::fs::read_to_string(&labels).ok();
    let assigned = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("the mock device state was poisoned"))?[0]
        .address;
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "commission should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        assigned,
        "1.1.7".parse::<IndividualAddress>()?,
        "the bench device must have taken its model address"
    );
    assert!(
        stdout.contains("1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room"),
        "the label line must be printed verbatim; stdout:\n{stdout}"
    );
    // The prompt named the device and its order number.
    assert!(
        stderr.contains("press the programming button on Blind actuator (JAL-0810.03)"),
        "the prompt must name the product; stderr:\n{stderr}"
    );

    let csv = csv.ok_or_else(|| anyhow::anyhow!("the labels CSV should have been written"))?;
    assert!(
        csv.starts_with("address;name;order_number;floor;room\n"),
        "the CSV must carry its header; got:\n{csv}"
    );
    assert!(
        csv.contains("1.1.7;Blind actuator;JAL-0810.03;Ground floor;Living room"),
        "the CSV row must carry every column; got:\n{csv}"
    );
    Ok(())
}

#[test]
fn test_commission_hard_stops_on_an_order_number_mismatch() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    // The bench device is the SECOND model device's product, not the first's.
    let (port, shared, task) = spawn_bench(&rt, "AKK-0216.03")?;

    let tmp = tmp_dir("mismatch");
    let model_dir = tmp.join("knx");
    write_device(&model_dir, "1.1.7", "Blind actuator", "JAL-0810.03")?;
    write_device(&model_dir, "1.1.8", "Switch actuator", "AKK-0216.03")?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();

    let output = run_commission(
        port,
        &[
            "commission",
            "--line",
            "1.1",
            "--yes",
            "--json",
            "--dir",
            &model_arg,
        ],
    )?;
    task.abort();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let assigned = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("the mock device state was poisoned"))?[0]
        .address;
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !success,
        "a device that hard-stopped must make the run exit non-zero; stdout:\n{stdout}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| anyhow::anyhow!("--json must emit valid JSON: {e}\n{stdout}\n{stderr}"))?;

    // The mismatch is a hard stop for that device, naming both order numbers.
    let stopped = row(&json, "1.1.7")?;
    assert_eq!(stopped["status"], "failed");
    let detail = stopped["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("AKK-0216.03") && detail.contains("JAL-0810.03"),
        "the refusal must name what was read and what was expected: {detail}"
    );
    assert!(
        detail.contains("nothing was written"),
        "the refusal must say nothing was written: {detail}"
    );

    // The run continued: the next device matched and was commissioned.
    let ok = row(&json, "1.1.8")?;
    assert_eq!(ok["status"], "commissioned");
    assert_eq!(
        ok["label"],
        "1.1.8  Switch actuator  MDT AKK-0216.03  Ground floor / Living room"
    );
    assert_eq!(
        assigned,
        "1.1.8".parse::<IndividualAddress>()?,
        "only the matching address may have been written"
    );
    assert_eq!(json["failed"], 1);
    assert_eq!(json["commissioned"], 1);
    Ok(())
}
