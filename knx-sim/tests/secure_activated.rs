//! The `activated` KNX Data Secure start state built from a config (bussard
//! issue #1054): the `syn-secure` device of the synthetic catalogue, its tool
//! key and sending sequence taken from the keyring ETS exported in the
//! committed `captures/synthetic/syn-secure/defaults/` capture (a synthetic
//! device under the public catalogue password), its sender table and
//! group-object flags from the config.
//!
//! The device must take management access under the keyring's tool key over
//! `A_SecureData` only, answer with the keyring's sequence, refuse a frame
//! under another key, and hold the tables. The tool side here wraps its
//! requests with the sim's own `DataSecureSession`, as `secure_conformance.rs`
//! does. Ungated: committed files only.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::config::SimConfig;
use knx_sim::secure::{A_SECURE_DATA_APCI, DataSecureSession, Key16, SecAlgorithm};
use knx_sim::wire::{Apdu, CemiLData, IndividualAddress, MessageCode};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The device's individual address in the capture (and its keyring).
const DEV: u16 = 0x1101;
/// A secured sender the config lists in the device's PID 54.
const SENDER: u16 = 0x1114;

/// The repository root (knx-sim is a workspace of its own one level down).
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `syn-secure`'s committed XML zipped with the stub master, as a file in
/// `dir`.
fn syn_secure_knxprod(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let xml = repo().join("tests-support/synthetic-products/syn-secure/xml/M-00FA");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&xml)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        files.push((name, std::fs::read(&path)?));
    }
    files.sort();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (name, data) in files {
        zip.start_file(format!("M-00FA/{name}"), opts)?;
        zip.write_all(&data)?;
    }
    let path = dir.join("syn-secure.knxprod");
    std::fs::write(&path, zip.finish()?.into_inner())?;
    Ok(path)
}

/// The config of the README example: the capture's device, `activated` from
/// the capture's keyring.
fn config(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let knxprod = syn_secure_knxprod(dir)?;
    let keyring = repo().join("captures/synthetic/syn-secure/defaults/project.knxkeys");
    Ok(format!(
        r#"
gateway:
  host: "127.0.0.1"
  port: 0
devices:
  - address: "1.1.1"
    knxprod: "{}"
    application: "M-00FA_A-2900-10-0000"
    initial_state: unloaded
    lsm_access: property
    security:
      status: activated
      keyring:
        file: "{}"
        password: "SyntheticKeyring1!"
      senders:
        - {{ address: "1.1.20", seq: 77 }}
      go_security_flags:
        - {{ object: 1, flags: 3 }}
    properties:
      - {{ object: 0, pid: 11, value: "00fad4730c98" }}
"#,
        knxprod.display(),
        keyring.display()
    ))
}

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Result<Scratch, std::io::Error> {
    let dir = std::env::temp_dir().join(format!("knx-sim-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(Scratch(dir))
}

fn cemi(dst: u16, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress(0),
        dest: dst,
        tpdu,
    }
}

/// `A_DeviceDescriptor_Read` on connection sequence 0, wrapped under `key`;
/// returns the device's replies.
fn secured_descriptor_read(bus: &mut knx_sim::bus::Bus, key: Key16) -> Vec<CemiLData> {
    let mut tool = DataSecureSession::new(key, 1, 0);
    bus.deliver_from_tool(&cemi(DEV, vec![0x80]));
    let head = 0x40;
    let carrier = cemi(DEV, vec![head | 0x03, 0xF1]);
    let (asdu, _) = tool.wrap_outgoing(
        &carrier,
        (head >> 2) & 0x3F,
        SecAlgorithm::AuthEnc,
        &[0x03, 0x00],
    );
    let mut tpdu = carrier.tpdu.clone();
    tpdu.extend_from_slice(&asdu);
    bus.deliver_from_tool(&cemi(DEV, tpdu))
}

/// The tool key the keyring gives 1.1.1.
fn keyring_tool_key(dir: &Path) -> Result<Key16, Box<dyn std::error::Error>> {
    let cfg = SimConfig::from_yaml(&config(dir)?)?;
    let sec = cfg.devices[0]
        .security
        .as_ref()
        .ok_or("no security block")?;
    let (activation, _) = sec.resolve(
        dir,
        IndividualAddress(DEV),
        knx_sim::config::serial_override(&cfg.devices[0].properties),
    )?;
    Ok(activation.tool_key)
}

#[test]
fn test_activated_from_keyring_takes_secured_access_under_its_tool_key() -> TestResult {
    let dir = scratch("activated-keyring")?;
    let cfg = SimConfig::from_yaml(&config(&dir.0)?)?;
    let sink = Arc::new(RecordingSink::new());
    let mut bus = cfg.build_bus(&dir.0, sink.clone())?;
    bus.settle_activated_tables()?;

    let replies = secured_descriptor_read(&mut bus, keyring_tool_key(&dir.0)?);
    let secured: Vec<&CemiLData> = replies
        .iter()
        .filter(|r| Apdu::parse(&r.tpdu).is_some_and(|a| a.apci_raw == A_SECURE_DATA_APCI))
        .collect();
    assert_eq!(secured.len(), 1, "one secured answer: {replies:?}");
    let refused: Vec<String> = sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Telegram { summary, .. } if summary.contains("REJECTED") => Some(summary),
            _ => None,
        })
        .collect();
    assert!(refused.is_empty(), "{refused:#?}");

    let device = bus
        .device(IndividualAddress(DEV))
        .ok_or("the device is missing")?;
    let obj = device.security_object().ok_or("no security object")?;
    assert_eq!(obj.security_mode(), 1);
    assert_eq!(obj.ia_table_sequence(SENDER), Some(77));
    assert_eq!(obj.go_flag(1), Some(0x03));
    // The keyring's group key is for an address the unloaded device does not
    // use: dropped, not an error.
    assert_eq!(obj.group_key_rows(), 0);
    Ok(())
}

#[test]
fn test_activated_from_keyring_refuses_another_key_and_plain_access() -> TestResult {
    let dir = scratch("activated-refuse")?;
    let cfg = SimConfig::from_yaml(&config(&dir.0)?)?;
    let sink = Arc::new(RecordingSink::new());
    let mut bus = cfg.build_bus(&dir.0, sink.clone())?;
    let replies = secured_descriptor_read(&mut bus, Key16::new([0x5A; 16]));
    assert!(
        !replies
            .iter()
            .any(|r| Apdu::parse(&r.tpdu).is_some_and(|a| a.apci_raw == A_SECURE_DATA_APCI)),
        "a frame under another key is answered: {replies:?}"
    );
    // A plain descriptor read on the activated device is refused too.
    bus.deliver_from_tool(&cemi(DEV, vec![0x80]));
    bus.deliver_from_tool(&cemi(DEV, vec![0x43, 0x00]));
    let refused = sink
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::Telegram { summary, .. } if summary.contains("REJECTED")))
        .count();
    assert!(refused >= 1, "the plain read was not refused");
    Ok(())
}

#[test]
fn test_activated_with_a_required_key_and_no_address_table_does_not_start() -> TestResult {
    let dir = scratch("activated-required")?;
    let yaml = config(&dir.0)?.replace(
        "      senders:",
        "      group_keys:\n        - { address: \"1/0/1\", key: \"00112233445566778899aabbccddeeff\" }\n      senders:",
    );
    let cfg = SimConfig::from_yaml(&yaml)?;
    let mut bus = cfg.build_bus(&dir.0, Arc::new(RecordingSink::new()))?;
    let err = bus.settle_activated_tables().err().unwrap_or_default();
    assert!(err.contains("1/0/1") && err.contains("1.1.1"), "{err}");
    Ok(())
}
