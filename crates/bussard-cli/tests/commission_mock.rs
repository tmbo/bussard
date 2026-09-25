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

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, Reaction};

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

/// Answers the read-only device-object properties and the descriptor.
fn device_response(dev: &DeviceState, apci_val: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    match apci_val {
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
        apci::A_DEVICE_DESCRIPTOR_READ => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(data)?;
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
    dev: &mut MockDevice,
    apci_val: u16,
    data: &[u8],
) -> Option<(u16, Vec<u8>)> {
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
        dev.programming = false;
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

/// Puts `state` on a testkit gateway line. The testkit device answers the
/// programming-mode broadcast and takes `A_IndividualAddress_Write`; the hook
/// `T_ACK`s every numbered request and answers property writes, the descriptor
/// and the device-object property reads.
fn gateway_device(state: DeviceState) -> MockDevice {
    MockDevice::new(state.address)
        .with_programming(state.programming)
        .with_hook(move |dev, apci_val, data| {
            let answer = handle_property_write(dev, apci_val, data)
                .or_else(|| device_response(&state, apci_val, data));
            Some(match answer {
                Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
                None => Reaction::Ack,
            })
        })
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

/// Writes a model device file with a product and a location, plus its
/// `bussard.lock` entry (appended, so several devices share one lock).
fn write_device(dir: &Path, address: &str, name: &str, order: &str) -> anyhow::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join(format!("{address}.toml")),
        format!(
            "address = \"{address}\"\nname = \"{name}\"\nproduct = \"{order}\"\n\n\
             [location]\nfloor = \"Ground floor\"\nroom = \"Living room\"\n"
        ),
    )?;
    let lock = dir.join("bussard.lock");
    let fresh = !lock.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lock)?;
    if fresh {
        writeln!(file, "version = 2")?;
    }
    write!(
        file,
        "\n[[device]]\naddress = \"{address}\"\nproduct = \"{order}\"\nmanufacturer = \"MDT\"\n"
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

/// Starts the mock bench gateway.
fn spawn_bench(rt: &tokio::runtime::Runtime, order: &str) -> anyhow::Result<MockGateway> {
    let device = gateway_device(bench_device(order)?);
    // Keep serving: `commission` opens one tunnel per device.
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .device(device)
            .start(),
    )?)
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
    let gw = spawn_bench(&rt, "JAL-0810.03")?;

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
        gw.port(),
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

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let csv = std::fs::read_to_string(&labels).ok();
    let assigned = gw
        .devices()?
        .first()
        .ok_or_else(|| anyhow::anyhow!("the bench device is gone"))?
        .address;
    drop(gw);
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
    let gw = spawn_bench(&rt, "AKK-0216.03")?;

    let tmp = tmp_dir("mismatch");
    let model_dir = tmp.join("knx");
    write_device(&model_dir, "1.1.7", "Blind actuator", "JAL-0810.03")?;
    write_device(&model_dir, "1.1.8", "Switch actuator", "AKK-0216.03")?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();

    let output = run_commission(
        gw.port(),
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

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let assigned = gw
        .devices()?
        .first()
        .ok_or_else(|| anyhow::anyhow!("the bench device is gone"))?
        .address;
    drop(gw);
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
