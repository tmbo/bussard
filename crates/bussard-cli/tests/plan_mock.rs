//! End-to-end test of `bussard plan --json` against an in-process mock KNX
//! device (the `bussard-testkit` mock gateway, as in `reconstruct_mock.rs`).
//!
//! `plan` is read-only on the bus, so the mock only needs to serve object
//! discovery and `PID_TABLE` property arrays. The device carries a ghost link
//! (object 59 → a GA the model dropped) and is missing a model link (object 22),
//! so the plan must show one removal and one addition, with the resulting table
//! sizes and the load-op list.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ga, ia};

const CHANNEL: u8 = 0x44;

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
        // Authorize (issue #52 finding #1): grant full access (level 0).
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
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
/// - GAs: 1/2/0, 1/2/1, 4/2/12 (the last used only by the ghost).
/// - associations: (1,20), (2,21), (3,59) — object 59 is the ghost.
fn scripted_device(addr: &str, mask: u16) -> TestResult<MockDevice> {
    let mut props = HashMap::new();
    props.insert(
        (1u8, PID_TABLE),
        vec![
            be16(ga("1/2/0")?.raw()),
            be16(ga("1/2/1")?.raw()),
            be16(ga("4/2/12")?.raw()),
        ],
    );
    props.insert(
        (2u8, PID_TABLE),
        vec![assoc_elem(1, 20), assoc_elem(2, 21), assoc_elem(3, 59)],
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

/// The model: objects 20 (matches), 21 (matches), and 22 (a new addition). The
/// ghost (59 → 4/2/12) is not in the model, so it is a removal.
fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n  - object: 22\n    listen:\n    - 1/2/2\n",
    )
}

fn run_plan(
    port: u16,
    model_dir: &std::path::Path,
    extra: &[&str],
) -> TestResult<std::process::Output> {
    let mut args = vec![
        "plan",
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
fn plan_reports_additions_removals_and_ops() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = start_gateway(&rt, scripted_device("1.1.4", 0x07B0)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-plan-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = run_plan(port, &model_dir, &["--json"])?;
    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "plan should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("--json must emit valid JSON: {e}\n{stdout}"))?;

    assert_eq!(json["address"], "1.1.4");
    assert_eq!(json["mask"], "07B0");
    assert_eq!(json["system_type"], "System B");
    assert_eq!(json["noop"], false);

    // Removal: the ghost object 59 → 4/2/12.
    assert_eq!(
        json["removals"],
        serde_json::json!([{ "object": 59, "ga": "4/2/12" }])
    );
    // Addition: object 22 → 1/2/2.
    assert_eq!(
        json["additions"],
        serde_json::json!([{ "object": 22, "ga": "1/2/2" }])
    );
    // Unchanged: 20 → 1/2/0 and 21 → 1/2/1.
    let unchanged = json["unchanged"].as_array().ok_or("unchanged array")?;
    assert_eq!(unchanged.len(), 2);

    // Table sizes: current 3 addresses / 3 associations; resulting 3 / 3
    // (drop 4/2/12, add 1/2/2 → still 3 GAs; drop assoc 59, add assoc 22 → 3).
    assert_eq!(json["current_address_count"], 3);
    assert_eq!(json["resulting_address_count"], 3);
    assert_eq!(json["current_association_count"], 3);
    assert_eq!(json["resulting_association_count"], 3);

    // The load ops list both tables.
    let steps = json["load_steps"].as_array().ok_or("load_steps array")?;
    assert_eq!(steps.len(), 2);
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().is_some_and(|t| t.contains("address")))
    );
    assert!(
        steps
            .iter()
            .any(|s| s.as_str().is_some_and(|t| t.contains("association")))
    );
    Ok(())
}

#[test]
fn plan_refuses_an_unsupported_mask_family() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    // A System 1 (BCU1) device: neither table reader speaks it, so `plan` must
    // refuse it with a friendly message. System 7 (0705/0701) is supported now
    // (issue #91) and is covered by the System 7 mock suites.
    let gw = start_gateway(&rt, scripted_device("1.1.4", 0x0012)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-plan-mask-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = run_plan(port, &model_dir, &[])?;
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
