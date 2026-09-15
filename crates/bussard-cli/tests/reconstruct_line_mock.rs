//! End-to-end tests of `bussard reconstruct --line` against an in-process mock
//! gateway hosting a small line: two System B devices with readable tables, one
//! non-System-B device (recorded as a stub), and absent addresses in between.
//!
//! The built `bussard` binary runs as a subprocess with
//! `--line 1.1 --out <fresh> --gateway 127.0.0.1:PORT`, a short discovery
//! timeout (via `BUSSARD_SCAN_DISCOVERY_MS`) to keep the sweep fast, and the
//! synthesized model is asserted: it loads via `Model::load`, validates without
//! ERRORS, and contains the expected GAs and links. A second test asserts line
//! mode refuses a non-empty `--out`; a third checks the `--json` summary shape.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_model::{GroupAddress, IndividualAddress, Model, Severity, validate};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x22;

/// A scripted device: System B ones serve object discovery + `PID_TABLE`
/// arrays; a non-System-B one only answers the descriptor.
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

/// Runs a mock gateway hosting a whole line of scripted devices.
async fn run_gateway(gw: UdpSocket, devices: Vec<TableDevice>) {
    let by_addr: HashMap<IndividualAddress, TableDevice> =
        devices.into_iter().map(|d| (d.address, d)).collect();
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
                // Absent address: no device answers (the sweep times out on it).
                let Some(device) = by_addr.get(&dest) else {
                    continue;
                };
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => dev_seq = 0,
                    TpciKind::NumberedData(client_seq) => {
                        let ack =
                            CemiFrame::t_control(tool, device.address, tpci::t_ack(client_seq));
                        push(&gw, from, &mut gw_seq, &ack).await;
                        if let Some((rapci, rdata)) = device_response(device, cemi) {
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

/// A System B device with `PID_TABLE`-served tables.
fn system_b_device(addr: &str, addresses: &[&str], assocs: &[(u16, u16)]) -> TableDevice {
    let mut props = HashMap::new();
    props.insert(
        (1u8, PID_TABLE),
        addresses.iter().map(|a| be16(ga(a).raw())).collect(),
    );
    props.insert(
        (2u8, PID_TABLE),
        assocs.iter().map(|&(t, a)| assoc_elem(t, a)).collect(),
    );
    // A group object table with enough entries to cover the ASAPs.
    let max_asap = assocs.iter().map(|&(_, a)| a).max().unwrap_or(0);
    props.insert(
        (3u8, PID_TABLE),
        (0..max_asap).map(|_| be16(0x079C)).collect(),
    );
    TableDevice {
        address: addr.parse().unwrap(),
        mask: 0x07B0,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        props,
    }
}

/// A non-System-B device: only answers the descriptor (System 7 mask), so
/// reconstruction records it as a stub.
fn non_system_b_device(addr: &str) -> TableDevice {
    TableDevice {
        address: addr.parse().unwrap(),
        mask: 0x0705,
        object_types: vec![],
        props: HashMap::new(),
    }
}

/// The scripted line:
/// - 1.1.4 (System B): GAs 1/2/0..2, assocs (1,20),(2,21),(3,21)
/// - 1.1.5 (System B): GAs 3/1/0..1, assocs (1,10),(2,11)
/// - 1.1.9 (non-B): System 7, recorded as a stub
/// - everything else absent
fn scripted_line() -> Vec<TableDevice> {
    vec![
        system_b_device(
            "1.1.4",
            &["1/2/0", "1/2/1", "1/2/2"],
            &[(1, 20), (2, 21), (3, 21)],
        ),
        system_b_device("1.1.5", &["3/1/0", "3/1/1"], &[(1, 10), (2, 11)]),
        non_system_b_device("1.1.9"),
    ]
}

fn spawn_line(rt: &tokio::runtime::Runtime) -> (u16, tokio::task::JoinHandle<()>) {
    let (gw, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    });
    let handle = rt.spawn(run_gateway(gw, scripted_line()));
    (port, handle)
}

fn run_reconstruct_line(port: u16, out: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let gw = format!("127.0.0.1:{port}");
    let mut args = vec![
        "reconstruct",
        "--line",
        "1.1",
        // Keep the mock sweep quick: only probe 0..=10.
        "--from",
        "0",
        "--to",
        "10",
        "--out",
        out.to_str().unwrap(),
        "--gateway",
        &gw,
    ];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        // Short discovery timeout so absent addresses do not stall the sweep.
        .env("BUSSARD_SCAN_DISCOVERY_MS", "150")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard reconstruct --line")
}

#[test]
fn line_mode_synthesizes_a_valid_model() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (port, handle) = spawn_line(&rt);

    let tmp = std::env::temp_dir().join(format!("bussard-reconstruct-line-{}", std::process::id()));
    let out = tmp.join("fresh");

    let output = run_reconstruct_line(port, &out, &[]);
    rt.block_on(async { handle.abort() });

    assert!(
        output.status.success(),
        "line reconstruct should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The synthesized model loads.
    let model = Model::load(&out).expect("synthesized model must load");

    // groups.yaml has every GA read from both System B devices (5 total).
    for g in ["1/2/0", "1/2/1", "1/2/2", "3/1/0", "3/1/1"] {
        assert!(
            model.groups.groups.contains_key(&ga(g)),
            "GA {g} must be in groups.yaml; have {:?}",
            model.groups.groups.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(model.groups.groups.len(), 5, "exactly the 5 read GAs");
    // Reconstructed GAs carry a placeholder name and no DPT.
    let g = &model.groups.groups[&ga("1/2/0")];
    assert!(
        g.name.contains("reconstructed"),
        "placeholder name: {}",
        g.name
    );
    assert!(g.dpt.is_none(), "reconstructed GAs have no DPT");

    // links.yaml: 1.1.4 → objects 20 (1/2/0) and 21 (1/2/1, 1/2/2), all listen.
    let ia4: IndividualAddress = "1.1.4".parse().unwrap();
    let links4 = &model.links.links[&ia4];
    assert_eq!(links4.len(), 2, "two linked objects on 1.1.4");
    let obj21 = links4.iter().find(|l| l.object == 21).unwrap();
    assert!(obj21.send.is_none(), "direction unknown → no send");
    assert_eq!(
        obj21.listen,
        vec![ga("1/2/1"), ga("1/2/2")],
        "both GAs recorded as listen"
    );

    // 1.1.5 was also read.
    let ia5: IndividualAddress = "1.1.5".parse().unwrap();
    assert_eq!(model.links.links[&ia5].len(), 2, "two objects on 1.1.5");

    // The non-System-B device is a stub: present as a device, no links.
    let ia9: IndividualAddress = "1.1.9".parse().unwrap();
    assert!(
        model.devices.contains_key(&ia9),
        "1.1.9 recorded as a device"
    );
    assert!(
        !model.links.links.contains_key(&ia9),
        "the stub device has no links"
    );
    let dev9 = &model.devices[&ia9].device;
    assert!(dev9.com_objects.is_empty(), "stub has no com_objects");
    assert_eq!(
        dev9.product.as_ref().and_then(|p| p.mask.as_deref()),
        Some("0705"),
        "the stub records its mask"
    );

    // The synthesized files carry the reconstruction banner.
    let groups_txt = std::fs::read_to_string(out.join("groups.yaml")).unwrap();
    assert!(
        groups_txt.contains("RECONSTRUCTED from on-device table read-back"),
        "groups.yaml must carry the reconstruction banner:\n{groups_txt}"
    );
    let links_txt = std::fs::read_to_string(out.join("links.yaml")).unwrap();
    assert!(
        links_txt.contains("send/listen DIRECTION is not recoverable"),
        "links.yaml banner must state the direction limitation"
    );

    // The model validates without ERRORS (warnings — e.g. W011 no-DPT — fine).
    let diags = validate(&model);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "reconstructed model must have no validation ERRORS; got: {errors:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn line_mode_refuses_a_non_empty_out() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (port, handle) = spawn_line(&rt);

    let tmp = std::env::temp_dir().join(format!(
        "bussard-reconstruct-line-nonempty-{}",
        std::process::id()
    ));
    let out = tmp.join("existing");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("groups.yaml"), "groups: {}\n").unwrap();

    let output = run_reconstruct_line(port, &out, &[]);
    rt.block_on(async { handle.abort() });

    assert!(
        !output.status.success(),
        "a non-empty --out must be refused (exit non-zero)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not empty") && stderr.contains("never merges"),
        "the refusal must explain it never merges into an existing model: {stderr}"
    );
    // The existing file is untouched.
    assert_eq!(
        std::fs::read_to_string(out.join("groups.yaml")).unwrap(),
        "groups: {}\n"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn line_mode_json_summary_shape() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (port, handle) = spawn_line(&rt);

    let tmp = std::env::temp_dir().join(format!(
        "bussard-reconstruct-line-json-{}",
        std::process::id()
    ));
    let out = tmp.join("fresh");

    let output = run_reconstruct_line(port, &out, &["--json"]);
    rt.block_on(async { handle.abort() });

    assert!(
        output.status.success(),
        "line reconstruct --json should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--json must emit valid JSON: {e}\n{stdout}"));

    assert_eq!(json["line"], "1.1");
    assert_eq!(json["devices_found"], 3);
    assert_eq!(json["devices_read"], 2);
    assert_eq!(json["devices_skipped"], 1);
    assert_eq!(json["group_addresses"], 5);
    assert_eq!(
        json["links"], 4,
        "2 + 2 links across the two System B devices"
    );

    let details = json["device_details"].as_array().unwrap();
    assert_eq!(details.len(), 3);
    let stub = details.iter().find(|d| d["address"] == "1.1.9").unwrap();
    assert_eq!(stub["status"], "stub");
    assert!(
        stub["skip_reason"]
            .as_str()
            .unwrap()
            .contains("not System B"),
        "the stub reason must be named: {stub}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
