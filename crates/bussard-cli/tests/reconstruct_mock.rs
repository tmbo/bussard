//! End-to-end tests of `bussard reconstruct` against an in-process mock KNX
//! device (the `bussard-testkit` mock gateway, as in `scan_mock.rs`).
//!
//! The scripted System B device serves object discovery and `PID_TABLE`
//! property arrays; the built `bussard` binary runs as a subprocess with
//! `--gateway 127.0.0.1:PORT --json` and the diff against a written model is
//! asserted: matching pairs, a pair only on the device, and a pair only in the
//! model. A second test checks the friendly refusal for a non-System-B mask.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ga, ia};

const CHANNEL: u8 = 0x22;

/// A scripted System B device with PID_TABLE-served tables.
#[derive(Clone)]
struct TableDevice {
    mask: u16,
    object_types: Vec<u16>,
    props: HashMap<(u8, u8), Vec<Vec<u8>>>,
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn assoc_elem(tsap: u16, asap: u16) -> Vec<u8> {
    let mut v = tsap.to_be_bytes().to_vec();
    v.extend_from_slice(&asap.to_be_bytes());
    v
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

fn device_response(dev: &TableDevice, req_apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    match req_apci {
        // Authorize (issue #52 finding #1): ETS presents a key before any
        // configuration access, so bussard authorizes every management connect.
        // Grant full access (level 0) for the free-access key.
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
        // Strict, like a real device: the descriptor type lives in the low 6
        // APCI bits and the request carries no payload octet.
        apci::A_DEVICE_DESCRIPTOR_READ if data.is_empty() => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(data)?;
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

/// The scripted device:
/// - GAs: 1/2/0, 1/2/1, 1/2/2
/// - associations: (1, 20), (2, 21), (3, 21) — the ASAP is the com-object
///   number → object 20: {1/2/0}; object 21: {1/2/1, 1/2/2}
fn scripted_device(addr: &str, mask: u16) -> TestResult<MockDevice> {
    let mut props = HashMap::new();
    props.insert(
        (1u8, PID_TABLE),
        vec![
            be16(ga("1/2/0")?.raw()),
            be16(ga("1/2/1")?.raw()),
            be16(ga("1/2/2")?.raw()),
        ],
    );
    props.insert(
        (2u8, PID_TABLE),
        vec![assoc_elem(1, 20), assoc_elem(2, 21), assoc_elem(3, 21)],
    );
    props.insert((3u8, PID_TABLE), (0..22).map(|_| be16(0x079C)).collect());
    let dev = TableDevice {
        mask,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        props,
    };
    Ok(table_device(ia(addr)?, dev))
}

/// Puts `dev` on the line at `address`: it `T_ACK`s every numbered request and
/// answers what [`device_response`] knows.
fn table_device(address: bussard_model::IndividualAddress, dev: TableDevice) -> MockDevice {
    MockDevice::new(address).with_hook(move |_, apci, data| {
        Some(match device_response(&dev, apci, data) {
            Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
            None => Reaction::Ack,
        })
    })
}

/// Starts the mock gateway on `rt` with `device` on its line.
fn start_gateway(rt: &tokio::runtime::Runtime, device: MockDevice) -> TestResult<MockGateway> {
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .device(device)
            .start(),
    )?)
}

/// The model: object 20 matches; object 21 has one matching GA and one the
/// device does not have; object 99 exists only in the model.
fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n    - 5/5/5\n  - object: 99\n    send: 4/4/4\n",
    )
}

fn run_reconstruct(
    port: u16,
    model_dir: &std::path::Path,
    extra: &[&str],
) -> TestResult<std::process::Output> {
    let mut args = vec![
        "reconstruct",
        "1.1.4",
        "--dir",
        model_dir.to_str().ok_or("temp path is not UTF-8")?,
        "--gateway",
    ];
    let gw = format!("127.0.0.1:{port}");
    args.push(&gw);
    args.extend_from_slice(extra);
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

#[test]
fn reconstruct_reports_inventory_and_diff() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = start_gateway(&rt, scripted_device("1.1.4", 0x07B0)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-reconstruct-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = run_reconstruct(port, &model_dir, &["--json"])?;
    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "reconstruct should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("--json must emit valid JSON: {e}\n{stdout}"))?;

    assert_eq!(json["address"], "1.1.4");
    assert_eq!(json["mask"], "07B0");
    assert_eq!(json["system_type"], "System B");
    assert_eq!(
        json["addresses"],
        serde_json::json!(["1/2/0", "1/2/1", "1/2/2"])
    );
    assert_eq!(
        json["associations"]
            .as_array()
            .ok_or("associations array")?
            .len(),
        3
    );
    assert_eq!(json["objects"]["20"], serde_json::json!(["1/2/0"]));
    assert_eq!(json["objects"]["21"], serde_json::json!(["1/2/1", "1/2/2"]));
    assert!(
        json["table_source"]["addresses"]
            .as_str()
            .ok_or("table_source.addresses string")?
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
        diff["note"]
            .as_str()
            .ok_or("diff.note string")?
            .contains("send/listen"),
        "the direction limitation must be noted: {stdout}"
    );
    Ok(())
}

#[test]
fn reconstruct_refuses_an_unsupported_mask_family() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    // A System 1 (BCU1) device: neither table reader speaks it, so `reconstruct`
    // must refuse it with a friendly message. System 7 (0705/0701) is supported
    // now (issue #91) and is covered by the System 7 mock suites.
    let gw = start_gateway(&rt, scripted_device("1.1.4", 0x0012)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!(
        "bussard-reconstruct-mask-test-{}",
        std::process::id()
    ));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = run_reconstruct(port, &model_dir, &[])?;
    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !output.status.success(),
        "an unsupported mask family must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0012") && stderr.contains("System B") && stderr.contains("System 7"),
        "the refusal must name the mask and the supported families: {stderr}"
    );
    Ok(())
}
