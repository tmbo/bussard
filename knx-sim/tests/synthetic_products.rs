//! The synthetic product catalogue (epic #596) loads into knx-sim.
//!
//! `tests-support/synthetic-products/<name>/xml/` holds the committed product
//! XML of each synthetic product. This test zips it with the stub
//! `knx_master.xml` (`<KNX/>`) the catalogue ships and reads it with knx-sim's
//! own reader, so the simulator checks the same files bussard's
//! `bussard-product` test reads, with no shared code: knx-sim depends on no
//! bussard crate.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use knx_sim::prod::{LdCtrl, read_knxprod_bytes};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/` in the repository.
fn catalogue_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests-support/synthetic-products")
}

/// Every product directory (one holding a `product.toml`), sorted.
fn products() -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(catalogue_dir())? {
        let dir = entry?.path();
        if dir.join("product.toml").is_file() {
            out.push(dir);
        }
    }
    out.sort();
    Ok(out)
}

/// The `M-00FA/*.xml` files of a product, as `(entry name, contents)`, sorted.
fn product_xml(product: &Path) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(product.join("xml/M-00FA"))? {
        let p = entry?.path();
        if let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) {
            out.push((format!("M-00FA/{name}"), std::fs::read(&p)?));
        }
    }
    out.sort();
    Ok(out)
}

/// The `.knxprod` of a product: the stub master plus its XML.
fn knxprod(product: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (name, data) in product_xml(product)? {
        zip.start_file(name, opts)?;
        zip.write_all(&data)?;
    }
    Ok(zip.finish()?.into_inner())
}

#[test]
fn test_read_knxprod_bytes_synthetic_catalogue() -> TestResult {
    let products = products()?;
    assert!(
        products.iter().any(|p| p.ends_with("syn-minimal")),
        "the baseline product is missing: {products:?}"
    );
    for product in &products {
        let apps: Vec<String> = product_xml(product)?
            .into_iter()
            .filter(|(name, _)| name.contains("_A-"))
            .map(|(name, _)| name["M-00FA/".len()..].trim_end_matches(".xml").to_string())
            .collect();
        assert_eq!(apps.len(), 1, "{}: {apps:?}", product.display());
        let id = &apps[0];
        let bytes = knxprod(product)?;
        let data = read_knxprod_bytes(&bytes, Some(id))?;
        assert_eq!(&data.application_id, id);
        // M-00FA_A-<number>-<version>-0000: the number and version the id names.
        let number = u32::from_str_radix(&id[9..13], 16)?;
        let version = u32::from_str_radix(&id[14..16], 16)?;
        assert_eq!(data.application_number, number, "{id}");
        assert_eq!(data.application_version, version, "{id}");
    }
    Ok(())
}

#[test]
fn test_read_knxprod_bytes_synthetic_minimal_contents() -> TestResult {
    let bytes = knxprod(&catalogue_dir().join("syn-minimal"))?;
    let data = read_knxprod_bytes(&bytes, Some("M-00FA_A-2700-10-0000"))?;
    assert_eq!(data.mask_version, "MV-07B0");
    assert_eq!(data.segments.len(), 1);
    assert_eq!(data.segments[0].lsm_index, 4);
    assert_eq!(data.segments[0].size, 256);
    let steps: Vec<&LdCtrl> = data.load_procedures.iter().flat_map(|p| &p.steps).collect();
    assert_eq!(
        steps,
        vec![
            &LdCtrl::RelSegment {
                lsm_index: 4,
                size: 256,
                mode: 0,
                fill: 0
            },
            &LdCtrl::WriteRelMem {
                obj_index: 4,
                offset: 0,
                size: 256,
                verify: false
            },
        ]
    );
    Ok(())
}

/// The synthetic identity `tools/ets-sweep/secure.py` (`synthetic_identity`)
/// derives for syn-secure's rendered application id `M-00FA_A-2900-10-0000`:
/// the serial number (manufacturer 00FA, four hash octets) and the FDSK.
/// Synthetic, never a real device's; `capture.py` writes the same pair into
/// the capture's `sim.yaml` (`test_ets_sweep.py` checks that side).
const SYN_SECURE_SERIAL: &str = "00fad4730c98";
const SYN_SECURE_FDSK: &str = "5e2c820a4e1b264302afda130b69c915";

/// syn-secure's rendered application id.
const SYN_SECURE_APP: &str = "M-00FA_A-2900-10-0000";

/// knx-sim's bus with the syn-secure device at 1.1.1 in factory state
/// carrying the synthetic FDSK and serial number, the config the ETS
/// sweep writes into `sim.yaml`. `tag` keeps the temporary directories of
/// tests in one process apart.
fn syn_secure_bus(tag: &str) -> Result<knx_sim::bus::Bus, Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use knx_sim::bus::event::RecordingSink;
    use knx_sim::config::SimConfig;

    let bytes = knxprod(&catalogue_dir().join("syn-secure"))?;
    let dir = std::env::temp_dir().join(format!("knx-sim-syn-secure-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("syn-secure.knxprod"), &bytes)?;
    let yaml = format!(
        "gateway:\n  host: 127.0.0.1\n  port: 3672\n\
         devices:\n- address: 1.1.1\n  knxprod: syn-secure.knxprod\n  application: {SYN_SECURE_APP}\n  \
         initial_state: unloaded\n  security:\n    status: factory\n    tool_key: {SYN_SECURE_FDSK}\n  \
         properties:\n  - object: 0\n    pid: 11\n    value: {SYN_SECURE_SERIAL}\n"
    );
    let built = SimConfig::from_yaml(&yaml)?.build_bus(&dir, Arc::new(RecordingSink::new()));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(built?)
}

/// syn-secure (bussard #604 row 18, #423) is a Data Secure capable 07B0
/// product. knx-sim builds its device in factory state, as ETS meets it before
/// commissioning: security mode off, the FDSK as tool key, the serial number
/// on the device object, and the security object sized by the product's
/// `MaxSecurityGroupKeyTableEntries` and `MaxSecurityIndividualAddressEntries`
/// (4 and 4).
#[test]
fn test_build_bus_synthetic_secure_factory_device() -> TestResult {
    use knx_sim::wire::IndividualAddress;

    let bytes = knxprod(&catalogue_dir().join("syn-secure"))?;
    let data = read_knxprod_bytes(&bytes, Some(SYN_SECURE_APP))?;
    assert_eq!(data.security_capacity.group_key_rows, Some(4));
    assert_eq!(data.security_capacity.ia_rows, Some(4));

    let bus = syn_secure_bus("build")?;
    let address: IndividualAddress = "1.1.1".parse()?;
    let device = bus.device(address).ok_or("no device 1.1.1")?;
    let security = device.security_object().ok_or("no security object")?;
    assert_eq!(
        security.security_mode(),
        0,
        "factory state: security mode off"
    );
    assert_eq!(security.group_key_capacity(), 4);
    assert_eq!(security.ia_capacity(), 4);
    Ok(())
}

/// Decode hex octets, spaces allowed.
fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

/// The CCM `block_0` and `counter_0` of a TP individual telegram (KNX 3/3/7
/// §5.1.3), built here from the bytes so the test checks the device model's
/// Sync code independently of it.
fn nonce_blocks(seq: &[u8], src: u16, dst: u16, tpci: u8, len: u8) -> ([u8; 16], [u8; 16]) {
    let mut b0 = [0u8; 16];
    b0[..6].copy_from_slice(seq);
    b0[6..8].copy_from_slice(&src.to_be_bytes());
    b0[8..10].copy_from_slice(&dst.to_be_bytes());
    b0[12] = (tpci & 0xFC) | 0x03;
    b0[13] = 0xF1;
    b0[15] = len;
    let mut c0 = [0u8; 16];
    c0[..10].copy_from_slice(&b0[..10]);
    c0[14] = 0x01;
    (b0, c0)
}

/// ETS 6.4.1 opens Data Secure tool access to the factory-state syn-secure
/// device with a connectionless S-A_Sync_Req (`T_Data_Individual`, before any
/// `T_Connect`). The frame is the one the sweep captured (sim.log of the #423
/// run, 2026-11-04). It verifies under the synthetic FDSK, and the sim answers
/// it with an unnumbered S-A_Sync_Res (KNX 3/3/7 §5.3.2: either transport
/// service, the answer in the request's communication mode). A secured
/// connectionless A_PropertyValue_Read of the serial number then gets a
/// secured unnumbered answer (§5.5.5).
#[test]
fn test_deliver_from_tool_connectionless_sync_request_from_ets() -> TestResult {
    use knx_sim::secure::{DataSecureSession, Key16, SecAlgorithm, crypto};
    use knx_sim::wire::{Apdu, CemiLData, IndividualAddress, MessageCode};

    const ETS: u16 = 0x11FE; // 1.1.254, the tunnel address in the capture
    const DEV: u16 = 0x1101; // 1.1.1
    let key: [u8; 16] = hex(SYN_SECURE_FDSK)?
        .try_into()
        .map_err(|_| "the FDSK is 16 octets")?;
    let frame = |tpdu: Vec<u8>| CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xBC,
        ctrl2: 0x60,
        source: IndividualAddress(ETS),
        dest: DEV,
        tpdu,
    };
    let captured =
        hex("03 f1 92 00 40 e4 d6 eb 6b 00 00 00 00 00 00 fb 62 28 72 fe 9a 83 e7 ff 2b")?;
    let req = &captured[2..];
    let req_seq = &req[1..7];

    // The captured request verifies under the synthetic FDSK: the key ETS
    // took from the certificate is the sim's tool key.
    let (b0, c0) = nonce_blocks(req_seq, ETS, DEV, captured[0], 6);
    let (challenge, _) = crypto::decrypt_data_ctr(&key, &c0, &req[19..23], &req[13..19]);
    let mut ad = vec![req[0]];
    ad.extend_from_slice(&req[7..13]);
    let mac = crypto::cbc_mac(&key, &ad, &challenge, &b0);
    let (_, expected) = crypto::encrypt_data_ctr(&key, &c0, &mac[..4], &[]);
    assert_eq!(
        &expected[..],
        &req[19..23],
        "the captured Sync_Req verifies"
    );

    let mut bus = syn_secure_bus("sync")?;
    let responses = bus.deliver_from_tool(&frame(captured.clone()));
    let [resp] = responses.as_slice() else {
        return Err(format!("expected one S-A_Sync_Res, got {responses:?}").into());
    };
    assert_eq!(resp.tpdu[0], 0x03, "unnumbered T_Data_Individual, no T_ACK");
    let apdu = Apdu::parse(&resp.tpdu).ok_or("the response parses")?;
    assert_eq!(apdu.apci_raw, 0x3F1);
    let res = &apdu.data;
    assert_eq!(res.len(), 1 + 6 + 12 + 4);
    assert_eq!(res[0], 0x93, "SCF of S-A_Sync_Res, tool key");
    let nonce: Vec<u8> = res[1..7]
        .iter()
        .zip(&challenge)
        .map(|(r, c)| r ^ c)
        .collect();
    let (rb0, rc0) = nonce_blocks(&nonce, DEV, ETS, resp.tpdu[0], 12);
    let (plain, _) = crypto::decrypt_data_ctr(&key, &rc0, &res[19..23], &res[7..19]);
    let rmac = crypto::cbc_mac(&key, &[0x93], &plain, &rb0);
    let (_, expected) = crypto::encrypt_data_ctr(&key, &rc0, &rmac[..4], &[]);
    assert_eq!(&expected[..], &res[19..23], "the Sync_Res MAC verifies");
    assert_eq!(
        &plain[6..],
        req_seq,
        "the device accepts the request's sequence next"
    );

    // A secured connectionless A_PropertyValue_Read of PID 11 (serial number)
    // under the FDSK, with the sequence the Sync agreed.
    let mut seq_be = [0u8; 8];
    seq_be[2..].copy_from_slice(req_seq);
    let mut tool = DataSecureSession::new(Key16::new(key), u64::from_be_bytes(seq_be), 0);
    let (asdu, _) = tool.wrap_outgoing(
        &frame(vec![0x03, 0xF1]),
        0,
        SecAlgorithm::AuthEnc,
        &[0x03, 0xD5, 0x00, 0x0B, 0x10, 0x01],
    );
    let mut tpdu = vec![0x03, 0xF1];
    tpdu.extend_from_slice(&asdu);
    let responses = bus.deliver_from_tool(&frame(tpdu));
    let [resp] = responses.as_slice() else {
        return Err(format!("expected one secured answer, got {responses:?}").into());
    };
    assert_eq!(resp.tpdu[..2], [0x03, 0xF1], "unnumbered A_SecureData");
    // S-A_Data, auth+conf: SCF || seq || enc(APDU) || MAC. Its sequence is the
    // one the Sync_Res announced as the device's next.
    let sec = &resp.tpdu[2..];
    assert_eq!(sec[0], 0x90, "SCF of S-A_Data, tool key, auth+conf");
    assert_eq!(&sec[1..7], &plain[..6], "the announced device sequence");
    let body = &sec[7..sec.len() - 4];
    let wire_mac = &sec[sec.len() - 4..];
    let (db0, dc0) = nonce_blocks(&sec[1..7], DEV, ETS, resp.tpdu[0], body.len() as u8);
    let (inner, _) = crypto::decrypt_data_ctr(&key, &dc0, wire_mac, body);
    let dmac = crypto::cbc_mac(&key, &[sec[0]], &inner, &db0);
    let (_, expected) = crypto::encrypt_data_ctr(&key, &dc0, &dmac[..4], &[]);
    assert_eq!(&expected[..], wire_mac, "the secured answer's MAC verifies");
    let mut serial = vec![0x03, 0xD6, 0x00, 0x0B, 0x10, 0x01];
    serial.extend_from_slice(&hex(SYN_SECURE_SERIAL)?);
    assert_eq!(
        inner, serial,
        "A_PropertyValue_Response with the serial number"
    );
    Ok(())
}

/// The second #423 run (sim.log, 2026-11-04 21:51): after the connectionless
/// Sync and two secured A_DeviceDescriptor_Reads, ETS 6.4.1 reads the current
/// security mode with a secured A_FunctionPropertyExt_State_Read of PID 51,
/// data `00 00`. The sim's old answer `[rc 00][00]` made ETS stop with
/// "Unexpected response length when reading current security mode". The
/// frames are replayed byte for byte; the sim's answers up to the mode read
/// match the capture byte for byte, and the mode read is answered `[rc 00]
/// [ReadServiceID 00][mode 00]` (KNX 3/5/1 §6.3.5.2, Figure 71).
#[test]
fn test_deliver_from_tool_security_mode_read_from_ets() -> TestResult {
    use knx_sim::secure::crypto;
    use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

    const ETS: u16 = 0x11FE;
    const DEV: u16 = 0x1101;
    let key: [u8; 16] = hex(SYN_SECURE_FDSK)?
        .try_into()
        .map_err(|_| "the FDSK is 16 octets")?;
    let frame = |tpdu: Vec<u8>| CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xBC,
        ctrl2: 0x60,
        source: IndividualAddress(ETS),
        dest: DEV,
        tpdu,
    };
    // (request, the sim's answer in the capture)
    let exchanges = [
        (
            "03 f1 92 00 40 e4 ed 9a 91 00 00 00 00 00 00 f3 97 e0 ff c6 32 d3 8d c1 b0",
            "03 f1 93 65 f8 f0 43 d0 75 7a e1 b7 a3 da 23 0c 88 f1 43 98 ff 37 d1 f3 eb",
        ),
        (
            "03 f1 90 00 40 e4 ed 9a ab 33 c9 bf 19 7a 69",
            "03 f1 90 00 00 00 00 00 00 d7 17 6c 87 76 09 71 e3",
        ),
        (
            "03 f1 90 00 40 e4 ed 9a ac 72 5f 59 a6 b3 c2",
            "03 f1 90 00 00 00 00 00 01 c3 bf 51 1b fa 51 f5 fb",
        ),
    ];
    let mut bus = syn_secure_bus("mode")?;
    for (req, captured) in exchanges {
        let responses = bus.deliver_from_tool(&frame(hex(req)?));
        let [resp] = responses.as_slice() else {
            return Err(format!("{req}: expected one answer, got {responses:?}").into());
        };
        assert_eq!(resp.tpdu, hex(captured)?, "answer to {req}");
    }

    let read = hex("03 f1 90 00 40 e4 ed 9a ad c3 29 82 ef 78 ca 3c 69 6c ae f3 ac 28")?;
    // The captured request: A_FunctionPropertyExt_State_Read, object type 17,
    // instance 1, PID 51, data `00 00`.
    let sec = &read[2..];
    let (b0, c0) = nonce_blocks(&sec[1..7], ETS, DEV, read[0], 9);
    let (inner, _) = crypto::decrypt_data_ctr(&key, &c0, &sec[16..20], &sec[7..16]);
    let mac = crypto::cbc_mac(&key, &[sec[0]], &inner, &b0);
    let (_, expected) = crypto::encrypt_data_ctr(&key, &c0, &mac[..4], &[]);
    assert_eq!(&expected[..], &sec[16..20], "the captured request verifies");
    assert_eq!(inner, hex("01 d5 00 11 00 10 33 00 00")?);

    let responses = bus.deliver_from_tool(&frame(read));
    let [resp] = responses.as_slice() else {
        return Err(format!("expected one answer, got {responses:?}").into());
    };
    let sec = &resp.tpdu[2..];
    assert_eq!(
        &sec[..7],
        &[0x90, 0, 0, 0, 0, 0, 2],
        "S-A_Data, device seq 2"
    );
    let body = &sec[7..sec.len() - 4];
    let wire_mac = &sec[sec.len() - 4..];
    let (b0, c0) = nonce_blocks(&sec[1..7], DEV, ETS, resp.tpdu[0], body.len() as u8);
    let (inner, _) = crypto::decrypt_data_ctr(&key, &c0, wire_mac, body);
    let mac = crypto::cbc_mac(&key, &[sec[0]], &inner, &b0);
    let (_, expected) = crypto::encrypt_data_ctr(&key, &c0, &mac[..4], &[]);
    assert_eq!(&expected[..], wire_mac, "the answer verifies");
    assert_eq!(
        inner,
        hex("01 d6 00 11 00 10 33 00 00 00")?,
        "rc 00, ReadServiceID 00, security mode 00 (factory)"
    );
    Ok(())
}
