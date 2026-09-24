//! KNX Data Secure calibration against a real ETS capture (issue #71, #90).
//!
//! Ignored by default: it needs a private capture and keyring that are never
//! committed. Run it with
//!
//! ```text
//! BUSSARD_SECURE_PCAP=<capture.pcapng> \
//! BUSSARD_SECURE_KEYRING=<keys.knxkeys> \
//! BUSSARD_KEYRING_PASSWORD=<password> \
//! BUSSARD_SECURE_DEVICE=<individual address> \
//! cargo test -p bussard-cli --test secure_capture_oracle -- --ignored --nocapture
//! ```
//!
//! It extracts every `A_SecureData` frame to or from the device (KNXnet/IP
//! tunnelling over UDP or TCP), verifies each one with bussard-secure's own
//! codec and the device's keyring tool key, and prints one line per frame:
//! direction, SCF, sequence, verdict and the inner service. It never prints key
//! material and never prints decrypted data octets (a secured write can carry a
//! key); only service names, property headers and lengths.
//!
//! The first run against the secure-1-1-12 capture (2026-09-23) verified 0 of
//! 210 frames. The cause was the CTR stage: the payload keystream starts right
//! after the 4 truncated MAC bytes, not at the second block. With that fixed,
//! and with the Sync layouts decoded from the same capture, every frame
//! verifies.

use std::collections::HashMap;

use bussard_model::IndividualAddress;
use bussard_secure::asdu::{self, Challenge, TpAddressing};
use bussard_secure::{Key16, Scf, SecureService};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One cEMI `L_Data` frame from the capture.
#[derive(Debug, Clone)]
struct Frame {
    /// Position among all decoded cEMI frames.
    idx: usize,
    /// cEMI message code (`0x11` req, `0x2E` con, `0x29` ind).
    mc: u8,
    ctrl2: u8,
    src: u16,
    dst: u16,
    npdu: Vec<u8>,
}

fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

fn u16be(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}

/// The link-layer payloads of every Enhanced Packet Block of a little-endian
/// pcapng file.
fn pcapng_packets(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while let (Some(kind), Some(len)) = (u32le(data, i), u32le(data, i + 4)) {
        let len = len as usize;
        if len < 12 || i + len > data.len() {
            break;
        }
        if kind == 6
            && let Some(cap) = u32le(data, i + 20)
        {
            let start = i + 28;
            if let Some(pkt) = data.get(start..start + cap as usize) {
                out.push(pkt);
            }
        }
        i += len;
    }
    out
}

/// `(flow key, TCP sequence or None for UDP, payload)` of an Ethernet/IPv4 frame.
type Segment = (Vec<u8>, Option<u32>, Vec<u8>);

fn transport_payload(eth: &[u8]) -> Option<Segment> {
    let mut off = 12;
    let mut ethertype = u16be(eth, off)?;
    if ethertype == 0x8100 {
        off += 4;
        ethertype = u16be(eth, off)?;
    }
    if ethertype != 0x0800 {
        return None;
    }
    let ip = eth.get(off + 2..)?;
    let ihl = usize::from(ip.first()? & 0x0F) * 4;
    let total = usize::from(u16be(ip, 2)?).min(ip.len());
    let l4 = ip.get(ihl..total)?;
    let mut flow = ip.get(12..20)?.to_vec();
    flow.extend_from_slice(l4.get(0..4)?);
    match ip.get(9)? {
        17 => Some((flow, None, l4.get(8..)?.to_vec())),
        6 => {
            let seq = u32::from_be_bytes([*l4.get(4)?, *l4.get(5)?, *l4.get(6)?, *l4.get(7)?]);
            let data_off = usize::from(l4.get(12)? >> 4) * 4;
            Some((flow, Some(seq), l4.get(data_off..)?.to_vec()))
        }
        _ => None,
    }
}

/// Splits the capture into KNXnet/IP frames, reassembling TCP streams (ETS 6
/// tunnels over TCP) and skipping TCP retransmissions.
fn knxip_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut streams: HashMap<Vec<u8>, (u32, Vec<u8>)> = HashMap::new();
    for pkt in pcapng_packets(data) {
        let Some((flow, seq, payload)) = transport_payload(pkt) else {
            continue;
        };
        let Some(seq) = seq else {
            out.push(payload);
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        let entry = streams.entry(flow).or_insert((seq, Vec::new()));
        if seq.wrapping_sub(entry.0) > u32::MAX / 2 {
            continue; // a retransmission of bytes already consumed
        }
        entry.0 = seq.wrapping_add(payload.len() as u32);
        entry.1.extend_from_slice(&payload);
        while let Some(len) = u16be(&entry.1, 4).map(usize::from) {
            if len < 6 || entry.1.len() < len {
                break;
            }
            out.push(entry.1.drain(..len).collect());
        }
    }
    out
}

/// The cEMI `L_Data` frames carried in TUNNELING_REQUESTs.
fn cemi_frames(data: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    for k in knxip_frames(data) {
        if k.len() < 10 || k[0] != 0x06 || k[1] != 0x10 || u16be(&k, 2) != Some(0x0420) {
            continue;
        }
        let Some(cemi) = k.get(6 + usize::from(k[6])..) else {
            continue;
        };
        let Some(&mc) = cemi.first() else { continue };
        if !matches!(mc, 0x11 | 0x2E | 0x29) || cemi.len() < 2 {
            continue;
        }
        let off = 2 + usize::from(cemi[1]);
        if cemi.len() < off + 8 {
            continue;
        }
        let n = usize::from(cemi[off + 6]);
        let npdu = cemi[off + 7..(off + 8 + n).min(cemi.len())].to_vec();
        out.push(Frame {
            idx: out.len(),
            mc,
            ctrl2: cemi[off + 1],
            src: u16be(cemi, off + 2).unwrap_or(0),
            dst: u16be(cemi, off + 4).unwrap_or(0),
            npdu,
        });
    }
    out
}

fn apci_of(npdu: &[u8]) -> Option<u16> {
    Some(((u16::from(*npdu.first()?) & 0x03) << 8) | u16::from(*npdu.get(1)?))
}

fn ia_str(raw: u16) -> String {
    format!("{}.{}.{}", raw >> 12, (raw >> 8) & 0x0F, raw & 0xFF)
}

/// A management service name plus a data-free summary of its header.
fn describe_inner(apci: u16, data: &[u8]) -> String {
    let name = match apci {
        0x300 => "A_DeviceDescriptor_Read",
        0x340..=0x37F => "A_DeviceDescriptor_Response",
        0x380 => "A_Restart",
        0x3A1 => "A_Restart_Response",
        0x3D1 => "A_Authorize_Request",
        0x3D2 => "A_Authorize_Response",
        0x3D5 => "A_PropertyValue_Read",
        0x3D6 => "A_PropertyValue_Response",
        0x3D7 => "A_PropertyValue_Write",
        0x3D8 => "A_PropertyDescription_Read",
        0x3D9 => "A_PropertyDescription_Response",
        0x3C7 => "A_FunctionPropertyCommand",
        0x3C8 => "A_FunctionPropertyState_Read",
        0x3C9 => "A_FunctionPropertyState_Response",
        0x1CC => "A_PropertyExtValue_Read",
        0x1CD => "A_PropertyExtValue_Response",
        0x1CE => "A_PropertyExtValue_WriteCon",
        0x1CF => "A_PropertyExtValue_WriteConResponse",
        0x1D0 => "A_PropertyExtValue_WriteUnCon",
        0x1D2 => "A_PropertyExtDescription_Read",
        0x1D3 => "A_PropertyExtDescription_Response",
        0x1D4 => "A_FunctionPropertyExt_Command",
        0x1D5 => "A_FunctionPropertyExt_State_Read",
        0x1D6 => "A_FunctionPropertyExt_State_Response",
        _ if apci & 0x3F0 == 0x200 => "A_Memory_Read",
        _ if apci & 0x3F0 == 0x240 => "A_Memory_Response",
        _ if apci & 0x3F0 == 0x280 => "A_Memory_Write",
        _ if apci & 0x3C0 == 0x380 => "A_Restart (other form)",
        _ => "other",
    };
    let header = match apci {
        // obj, pid
        0x3D5..=0x3D9 | 0x3C7..=0x3C9 if data.len() >= 2 => {
            format!(" obj={} pid={}", data[0], data[1])
        }
        // object type (2), instance (12 bit), pid (12 bit)
        0x1CC..=0x1D6 if data.len() >= 5 => {
            let ot = u16::from_be_bytes([data[0], data[1]]);
            let inst = (u16::from(data[2]) << 4) | u16::from(data[3] >> 4);
            let pid = (u16::from(data[3] & 0x0F) << 8) | u16::from(data[4]);
            format!(" ot={ot} inst={inst} pid={pid}")
        }
        _ => String::new(),
    };
    format!("{name} ({apci:#05x}){header} data_len={}", data.len())
}

#[test]
#[ignore = "needs BUSSARD_SECURE_PCAP, BUSSARD_SECURE_KEYRING, BUSSARD_KEYRING_PASSWORD and BUSSARD_SECURE_DEVICE"]
fn test_every_ets_capture_frame_verifies() -> TestResult {
    let pcap = std::env::var("BUSSARD_SECURE_PCAP")?;
    let keyring = std::env::var("BUSSARD_SECURE_KEYRING")?;
    let password = std::env::var("BUSSARD_KEYRING_PASSWORD")?;
    let device: IndividualAddress = std::env::var("BUSSARD_SECURE_DEVICE")?.parse()?;
    let keys = bussard_project::parse_keyring(&std::fs::read_to_string(keyring)?, &password)?;
    let tool_key: Key16 = keys
        .tool_key(device)
        .ok_or("the keyring has no tool key for the device")?
        .clone();
    let dev = device.raw();

    let frames = cemi_frames(&std::fs::read(pcap)?);
    // One copy per frame: the tool's L_Data.req (ETS fills in the tunnel IA on
    // secured frames) and the device's L_Data.ind; the .con echo repeats the
    // .req and is skipped.
    let relevant: Vec<&Frame> = frames
        .iter()
        .filter(|f| f.mc != 0x2E)
        .filter(|f| f.src == dev || f.dst == dev || (f.dst == 0 && f.ctrl2 & 0x80 != 0))
        .collect();

    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut by_kind: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut challenge: Option<Challenge> = None;
    let mut ets_ops: Vec<String> = Vec::new();

    for f in &relevant {
        let from_device = f.src == dev;
        let dir = if from_device { "dev->ETS" } else { "ETS->dev" };
        let Some(apci) = apci_of(&f.npdu) else {
            // Transport control (T_Connect / T_ACK / T_Disconnect).
            let name = match f.npdu.first() {
                Some(0x80) => Some("T_Connect"),
                Some(0x81) => Some("T_Disconnect"),
                _ => None,
            };
            if let (false, Some(name)) = (from_device, name) {
                ets_ops.push(format!("#{} {name} -> {}", f.idx, ia_str(f.dst)));
            }
            continue;
        };
        if apci != asdu::A_SECURE_DATA {
            if !from_device && f.dst == dev {
                ets_ops.push(format!(
                    "#{} plain {}",
                    f.idx,
                    describe_inner(apci, f.npdu.get(2..).unwrap_or_default())
                ));
            }
            continue;
        }
        let body = &f.npdu[2..];
        let addr = TpAddressing {
            source: f.src,
            destination: f.dst,
            address_type_group: f.ctrl2 & 0x80 != 0,
            extended_frame_format: f.ctrl2 & 0x0F,
            tpci: f.npdu[0],
        };
        let scf = Scf::from_byte(body[0])?;
        let mut seq_bytes = [0u8; 8];
        seq_bytes[2..].copy_from_slice(&body[1..7]);
        let seq_field = u64::from_be_bytes(seq_bytes);
        let (kind, verdict) = match scf.service {
            SecureService::Data => (
                "S-A_Data",
                asdu::decode(&tool_key, body, &addr)
                    .map(|d| describe_inner(d.apci, &d.data))
                    .map_err(|e| e.to_string()),
            ),
            SecureService::SyncReq => (
                "S-A_Sync_Req",
                asdu::decode_sync_req(&tool_key, body, &addr)
                    .map(|(_, req)| {
                        challenge = Some(req.challenge);
                        format!(
                            "seq={} serial={}",
                            req.sequence.value(),
                            if req.serial == [0u8; 6] {
                                "zero"
                            } else {
                                "set"
                            }
                        )
                    })
                    .map_err(|e| e.to_string()),
            ),
            SecureService::SyncRes => (
                "S-A_Sync_Res",
                match &challenge {
                    None => Err("no preceding Sync_Req".to_string()),
                    Some(ch) => asdu::decode_sync_res(&tool_key, body, &addr, ch)
                        .map(|r| {
                            format!(
                                "device_seq={} next_tool_seq={}",
                                r.responder_sequence.value(),
                                r.requester_sequence.value()
                            )
                        })
                        .map_err(|e| e.to_string()),
                },
            ),
        };
        let counts = by_kind.entry(kind).or_default();
        let to = if addr.address_type_group {
            "0/0/0".to_string()
        } else {
            ia_str(f.dst)
        };
        match &verdict {
            Ok(summary) => {
                ok += 1;
                counts.0 += 1;
                println!(
                    "#{:>4} {dir} {}->{to} scf={:#04x} seq_field={seq_field} OK {kind} {summary}",
                    f.idx,
                    ia_str(f.src),
                    body[0]
                );
                if !from_device {
                    ets_ops.push(format!("#{} {kind} {summary}", f.idx));
                }
            }
            Err(err) => {
                failed += 1;
                counts.1 += 1;
                println!(
                    "#{:>4} {dir} {}->{to} scf={:#04x} seq_field={seq_field} FAIL {kind}: {err}",
                    f.idx,
                    ia_str(f.src),
                    body[0]
                );
            }
        }
    }

    println!("\nper service (ok, fail): {by_kind:?}");
    println!("tool key: {ok} verified, {failed} failed");
    println!("\nfirst 30 ETS operations toward {device}:");
    for op in ets_ops.iter().take(30) {
        println!("  {op}");
    }
    assert!(
        ok > 0,
        "the capture holds no A_SecureData frames for {device}"
    );
    assert_eq!(
        failed, 0,
        "{failed} frame(s) did not verify under the tool key"
    );
    Ok(())
}

/// The security-object program bussard builds equals what ETS wrote (issue
/// #156), byte for byte, without printing a key.
///
/// From the decrypted capture it takes ETS's own address, association and
/// group-object tables (the `A_MemoryExtended_Write`s following each object's
/// `PID_TABLE_REFERENCE` read), feeds them with the keyring's group keys to
/// `security_inputs_for` + `build_security_program`, and compares the result
/// with ETS's `PID_GRP_KEY_TABLE` (53), `PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE`
/// (54) and `PID_GO_SECURITY_FLAGS` (61) writes and with the order of the
/// security-object operations. Only lengths, counts and verdicts are printed.
#[test]
#[ignore = "needs BUSSARD_SECURE_PCAP, BUSSARD_SECURE_KEYRING, BUSSARD_KEYRING_PASSWORD and BUSSARD_SECURE_DEVICE"]
fn test_security_object_program_matches_ets() -> TestResult {
    use bussard_mgmt::property_ext::{
        self, PID_GO_SECURITY_FLAGS, PID_GRP_KEY_TABLE, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
        PID_SECURITY_LOAD_STATE_CONTROL,
    };
    use std::collections::BTreeMap;

    let pcap = std::env::var("BUSSARD_SECURE_PCAP")?;
    let keyring = std::env::var("BUSSARD_SECURE_KEYRING")?;
    let password = std::env::var("BUSSARD_KEYRING_PASSWORD")?;
    let device: IndividualAddress = std::env::var("BUSSARD_SECURE_DEVICE")?.parse()?;
    let keys = bussard_project::parse_keyring(&std::fs::read_to_string(keyring)?, &password)?;
    let tool_key: Key16 = keys
        .tool_key(device)
        .ok_or("the keyring has no tool key for the device")?
        .clone();
    let dev = device.raw();

    // The decrypted ETS -> device management APDUs of the LAST download session
    // (the capture also holds the activation session before it).
    let mut inner: Vec<(u16, Vec<u8>)> = Vec::new();
    for f in cemi_frames(&std::fs::read(pcap)?) {
        if f.mc == 0x2E || f.dst != dev || f.src == dev {
            continue;
        }
        if apci_of(&f.npdu) != Some(asdu::A_SECURE_DATA) {
            continue;
        }
        let body = &f.npdu[2..];
        if Scf::from_byte(body[0])?.service != SecureService::Data {
            continue;
        }
        let addr = TpAddressing {
            source: f.src,
            destination: f.dst,
            address_type_group: false,
            extended_frame_format: f.ctrl2 & 0x0F,
            tpci: f.npdu[0],
        };
        if let Ok(d) = asdu::decode(&tool_key, body, &addr) {
            inner.push((d.apci, d.data));
        }
    }

    // Table images: memory writes after `A_PropertyValue_Read obj=N pid=7`.
    let mut images: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut current: Option<u8> = None;
    // Security object operations in order: (pid, start, data).
    let mut sec_ops: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    for (apci, data) in &inner {
        match *apci {
            0x3D5 if data.len() >= 2 && data[1] == 7 => {
                current = Some(data[0]);
                images.insert(data[0], Vec::new());
            }
            0x1FB if data.len() >= 4 => {
                if let Some(obj) = current {
                    images.entry(obj).or_default().extend_from_slice(&data[4..]);
                }
            }
            0x1D4 => {
                let cmd = property_ext::decode_function_property_ext(data).ok_or("fpe")?;
                if cmd.addr.object_type == 17 {
                    sec_ops.push((cmd.addr.property_id, 0, cmd.data));
                }
            }
            0x1CE => {
                let w = property_ext::decode_property_ext_value(data).ok_or("writecon")?;
                if w.addr.object_type == 17 {
                    sec_ops.push((w.addr.property_id, w.start, w.data));
                }
            }
            _ => {}
        }
    }
    // Keep the download session's operations: from the last PID 5 Unload on.
    let unload = sec_ops
        .iter()
        .rposition(|(pid, _, d)| *pid == PID_SECURITY_LOAD_STATE_CONTROL && d.first() == Some(&4))
        .ok_or("no security-object Unload in the capture")?;
    let sec_ops = &sec_ops[unload..];

    let word = |b: &[u8], i: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
    };
    let addr_img = images.get(&1).ok_or("no address table image")?;
    let assoc_img = images.get(&2).ok_or("no association table image")?;
    let go_img = images.get(&3).ok_or("no group-object table image")?;
    let n_addr = usize::from(word(addr_img, 0).ok_or("addr count")?);
    let addresses: Vec<bussard_model::GroupAddress> = (0..n_addr)
        .filter_map(|i| word(addr_img, 2 + 2 * i))
        .map(bussard_model::GroupAddress::from_raw)
        .collect();
    let n_assoc = usize::from(word(assoc_img, 0).ok_or("assoc count")?);
    let associations: Vec<(u16, u16)> = (0..n_assoc)
        .filter_map(|i| Some((word(assoc_img, 2 + 4 * i)?, word(assoc_img, 4 + 4 * i)?)))
        .collect();
    let go_count = word(go_img, 0).ok_or("GO count")?;
    println!(
        "ETS tables: {} address(es), {} association(s), {} group object(s)",
        addresses.len(),
        associations.len(),
        go_count
    );

    let desired = bussard_download::DesiredTables {
        addresses: addresses.clone(),
        associations,
    };
    let inputs = bussard_download::security_inputs_for(None, device, &desired, &keys.group_keys);
    let program = bussard_download::build_security_program(
        device,
        &addresses,
        go_count,
        &inputs.secure_objects,
        &inputs.secure_gas,
        &inputs.group_keys,
    )?;

    let ets_concat = |pid: u16| -> Vec<u8> {
        sec_ops
            .iter()
            .filter(|(p, _, _)| *p == pid)
            .flat_map(|(_, _, d)| d.clone())
            .collect()
    };
    let ets_53 = ets_concat(PID_GRP_KEY_TABLE);
    let ets_54: Vec<(u16, Vec<u8>)> = sec_ops
        .iter()
        .filter(|(p, _, _)| *p == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)
        .map(|(_, s, d)| (*s, d.clone()))
        .collect();
    let ets_61 = ets_concat(PID_GO_SECURITY_FLAGS);
    let ours_53 = program.group_key_table_bytes();
    println!(
        "PID 53: ETS {} octet(s), bussard {} octet(s), equal: {}",
        ets_53.len(),
        ours_53.len(),
        ets_53 == ours_53
    );
    println!(
        "PID 61: ETS {} flag(s), bussard {} flag(s), equal: {}, secured objects {:?}",
        ets_61.len(),
        program.go_flags.len(),
        ets_61 == program.go_flags,
        program.secured_objects()
    );
    println!("PID 54: ETS writes {:?}", ets_54);
    let order: Vec<String> = sec_ops
        .iter()
        .map(|(p, _, d)| match *p {
            PID_SECURITY_LOAD_STATE_CONTROL => {
                format!("PID5:{:02x}", d.first().copied().unwrap_or(0xFF))
            }
            other => format!("PID{other}"),
        })
        .collect();
    let mut dedup = order.clone();
    dedup.dedup();
    println!("ETS security-object order: {dedup:?}");

    assert_eq!(ets_53, ours_53, "group key table differs from ETS");
    assert_eq!(
        ets_61, program.go_flags,
        "GO security flags differ from ETS"
    );
    assert_eq!(ets_54, vec![(0u16, vec![0u8, 0u8])]);
    assert_eq!(
        dedup,
        vec!["PID5:04", "PID5:01", "PID54", "PID53", "PID61", "PID5:02"],
        "the security-object procedure differs from ETS"
    );
    Ok(())
}
