//! Integration tests: the management layer against an in-process **mock KNX
//! device** reached through the existing mock-gateway (tunneling) pattern.
//!
//! The testkit's mock gateway relays cEMI frames, and behind it a device
//! simulator (a [`MockDevice`] hook) implements the KNX device side:
//! accept `T_Connect`, `T_ACK` our numbered data telegrams, and answer
//! `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` and `A_Memory_Read` with
//! response NDTs (which the client must in turn acknowledge). One simulated
//! device NAKs; one goes silent (models an absent address).
//!
//! These exercise the full [`DeviceConnection`] procedure surface plus the
//! sequence state machine end-to-end over UDP localhost.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::{DeviceConnection, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockError, MockGateway, Reaction, Step, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// How a simulated device reacts to a connection.
#[derive(Clone)]
enum Behavior {
    /// Answers management reads normally.
    Responds {
        mask: u16,
        manufacturer: u16,
        serial: Vec<u8>,
        order: Vec<u8>,
        memory: HashMap<u16, Vec<u8>>,
        /// The device's advertised `PID_MAX_APDU_LENGTH`. `Some(v)` answers the
        /// property with `v`; `None` returns an empty answer (models a device
        /// that does not expose it, exercising the conservative fallback).
        max_apdu: Option<u16>,
        /// The property descriptions this device answers to
        /// `A_PropertyDescription_Read` on object 0, keyed by 1-based property
        /// index. Each entry is `(pid, pdt, writable, max_elements, read_level,
        /// write_level)`. An empty map models a device that does not implement
        /// the description service (issue #72).
        descriptions: Vec<(u8, u8, bool, u16, u8, u8)>,
    },
    /// Accepts the connection but `T_NAK`s the first numbered data telegram.
    Nak,
    /// Never reacts at all (an absent address).
    Silent,
    /// Answers management reads normally, but **folds the ACK**: it emits the
    /// response NDT *before* (in fact instead of) a separate `T_ACK`. This models
    /// the real device behaviour that used to desync the connection.
    FoldsAck {
        /// The mask version reported by the device descriptor read.
        mask: u16,
    },
    /// Answers a descriptor read with the **wrong APCI** (an A_PropertyValue
    /// response selector carrying `payload` octets), so the descriptor decoder
    /// rejects it. Models the KNX Virtual IP/TP interface finding: the decoder
    /// must reject-with-hex so the raw frame is captured.
    WrongDescriptorApci {
        /// The payload octets to return with the wrong APCI.
        payload: Vec<u8>,
    },
    /// Answers a descriptor read by **echoing the request**: the response APCI is
    /// `A_DeviceDescriptor_Read` (0x0300) with an empty payload, not a `_Response`
    /// (0x0340). Models the KNX Virtual IP interface, which does not implement
    /// descriptor responses; the decoder must name the echo pattern (finding 2).
    EchoesDescriptorRead,
    /// Answers descriptor reads normally, but on the **second and later** request
    /// first **retransmits the PREVIOUS response** at its old (now one-behind)
    /// send sequence — as a device does when it never saw our `T_ACK` for the
    /// prior answer — before ACKing and answering the fresh request at the correct
    /// sequence. The client's `await_ack` must NOT treat the re-delivered previous
    /// response as evidence its new request landed; it must ACK expected-1 and
    /// keep waiting, then consume the fresh response in sequence (issue #57).
    RetransmitsPreviousResponse {
        /// The mask version reported by every descriptor read.
        mask: u16,
    },
}

/// One simulated device at an individual address.
#[derive(Clone)]
struct SimDevice {
    address: IndividualAddress,
    behavior: Behavior,
}

/// The channel id the mock gateway hands out.
const CHANNEL: u8 = 0x15;

/// Starts a testkit gateway with one hook-driven device per [`SimDevice`].
///
/// The gateway stops when the client disconnects the KNXnet/IP channel or when
/// it is dropped at the end of the test.
async fn start_mock(devices: Vec<SimDevice>) -> Result<MockGateway, MockError> {
    MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .devices(devices.into_iter().map(|sim| {
            let behavior = sim.behavior;
            MockDevice::new(sim.address)
                .with_hook(move |dev, apci, data| Some(react(&behavior, dev, apci, data)))
        }))
        .start()
        .await
}

/// The device-side reaction to one numbered management request.
fn react(behavior: &Behavior, dev: &mut MockDevice, apci_: u16, data: &[u8]) -> Reaction {
    match behavior {
        // Absent/silent: no ACK, no response.
        Behavior::Silent => Reaction::Silent,
        // Present but refusing: NAK the numbered data telegram.
        Behavior::Nak => Reaction::Nak,
        // Fold the ACK: send the response NDT *instead of* a separate T_ACK. The
        // client's await_ack must treat the folded NDT as the acknowledgement,
        // stash it and deliver it.
        Behavior::FoldsAck { mask } => Reaction::Script(vec![Step::Data(
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            mask.to_be_bytes().to_vec(),
        )]),
        // ACK, then answer with a deliberately wrong APCI (a property response
        // selector) so the descriptor decoder rejects it.
        Behavior::WrongDescriptorApci { payload } => Reaction::Script(vec![
            Step::Ack,
            Step::Data(apci::A_PROPERTY_VALUE_RESPONSE, payload.clone()),
        ]),
        // ACK, then echo the read: answer with the read's own APCI (0x0300) and
        // an empty payload, exactly as the KV IP interface does. The decoder
        // must recognise the echo.
        Behavior::EchoesDescriptorRead => Reaction::Script(vec![
            Step::Ack,
            Step::Data(apci::A_DEVICE_DESCRIPTOR_READ, Vec::new()),
        ]),
        Behavior::RetransmitsPreviousResponse { mask } => {
            // The client just sent request N. On N >= 2, first replay the
            // PREVIOUS response at its old (one-behind) send sequence, modelling
            // a device that never saw our T_ACK for the prior answer and
            // retransmits it, then ACK and answer the fresh request at the
            // correct sequence. `telegrams` already counts this request.
            let mut steps = Vec::new();
            if dev.telegrams >= 2 {
                // The current send seq points at the NEXT (fresh) response; the
                // previous response used seq-1. Replay it there.
                let cur = dev.send_seq().unwrap_or(0);
                let prev_seq = cur.wrapping_sub(1) & 0x0f;
                steps.push(Step::DataAtSeq(
                    prev_seq,
                    apci::A_DEVICE_DESCRIPTOR_RESPONSE,
                    mask.to_be_bytes().to_vec(),
                ));
                // A brief pause so the client processes the stale replay (ACK
                // expected-1, keep waiting) before the real answer.
                steps.push(Step::Pause(Duration::from_millis(20)));
            }
            steps.push(Step::Ack);
            steps.push(Step::Data(
                apci::A_DEVICE_DESCRIPTOR_RESPONSE,
                mask.to_be_bytes().to_vec(),
            ));
            Reaction::Script(steps)
        }
        Behavior::Responds { .. } => {
            // 1. ACK the client's request NDT. 2. Push the response NDT (if the
            // request has one) with our own seq.
            match device_response(behavior, apci_, data) {
                Some((resp_apci, resp_data)) => Reaction::Answer(resp_apci, resp_data),
                None => Reaction::Ack,
            }
        }
    }
}

/// Computes the response APCI + payload for a management request.
fn device_response(behavior: &Behavior, req_apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    let Behavior::Responds {
        mask,
        manufacturer,
        serial,
        order,
        memory,
        max_apdu,
        descriptions,
    } = behavior
    else {
        return None;
    };

    // Strict, spec-independent framing (implemented from the KNX standard, not
    // mirrored from the client): the descriptor type and memory octet count live
    // in the low 6 APCI bits, so the request selector is masked with 0x3C0 and a
    // strict device refuses the over-long forms.
    const APCI_SELECTOR: u16 = 0x3C0;

    if req_apci & APCI_SELECTOR == apci::A_DEVICE_DESCRIPTOR_READ {
        if !data.is_empty() {
            return None; // over-long descriptor read: a strict device refuses
        }
        return Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            mask.to_be_bytes().to_vec(),
        ));
    }

    if req_apci & APCI_SELECTOR == apci::A_MEMORY_READ {
        let count = (req_apci & 0x3f) as u8;
        if data.len() != 2 {
            return None; // strict: the payload is exactly the 2 address octets
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mem = memory
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| vec![0; count as usize]);
        // Response: count in the APCI low bits, payload = addr + data.
        let (resp_apci, payload) = apci::encode_memory_response(addr, &mem);
        return Some((resp_apci, payload));
    }

    match req_apci {
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => serial.clone(),
                apci::PID_ORDER_INFO => order.clone(),
                apci::PID_MAX_APDU_LENGTH => match max_apdu {
                    Some(v) => v.to_be_bytes().to_vec(),
                    None => Vec::new(),
                },
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0 } else { 1 };
            let mut resp = vec![
                pv.object_index,
                pv.property_id,
                (count << 4) | ((pv.start >> 8) as u8 & 0x0f),
                (pv.start & 0xff) as u8,
            ];
            resp.extend_from_slice(&value);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        apci::A_PROPERTY_DESCRIPTION_READ => {
            let pd = apci::decode_property_description_read(data)?;
            // The mock exposes descriptions only on object 0, addressed by index
            // (PID 0). A request with no descriptions configured, an unknown
            // object, or an index past the list is answered with a zero-max
            // descriptor — the spec's "no property here" signal.
            let absent = apci::PropertyDescription {
                object_index: pd.object_index,
                property_id: 0,
                property_index: pd.property_index,
                writable: false,
                pdt: 0,
                max_elements: 0,
                read_level: 0,
                write_level: 0,
            };
            if pd.object_index != apci::DEVICE_OBJECT_INDEX || pd.property_index == 0 {
                return Some((
                    apci::A_PROPERTY_DESCRIPTION_RESPONSE,
                    apci::encode_property_description_response(&absent),
                ));
            }
            let entry = descriptions.get(usize::from(pd.property_index - 1));
            let desc = match entry {
                Some(&(pid, pdt, writable, max_elements, read_level, write_level)) => {
                    apci::PropertyDescription {
                        object_index: pd.object_index,
                        property_id: pid,
                        property_index: pd.property_index,
                        writable,
                        pdt,
                        max_elements,
                        read_level,
                        write_level,
                    }
                }
                None => absent,
            };
            Some((
                apci::A_PROPERTY_DESCRIPTION_RESPONSE,
                apci::encode_property_description_response(&desc),
            ))
        }
        _ => None,
    }
}

/// A fully-responsive device fixture that does not expose `PID_MAX_APDU_LENGTH`.
fn responder(addr: &str, mask: u16, manufacturer: u16) -> Result<SimDevice, BoxError> {
    responder_with_apdu(addr, mask, manufacturer, None)
}

/// A fully-responsive device fixture advertising `max_apdu` as its
/// `PID_MAX_APDU_LENGTH` (`None` = property absent).
fn responder_with_apdu(
    addr: &str,
    mask: u16,
    manufacturer: u16,
    max_apdu: Option<u16>,
) -> Result<SimDevice, BoxError> {
    responder_with_apdu_and_descriptions(addr, mask, manufacturer, max_apdu, Vec::new())
}

/// Like [`responder_with_apdu`] but also seeds the property descriptions the
/// device answers to `A_PropertyDescription_Read` on object 0 (issue #72). Each
/// entry is `(pid, pdt, writable, max_elements, read_level, write_level)`.
fn responder_with_apdu_and_descriptions(
    addr: &str,
    mask: u16,
    manufacturer: u16,
    max_apdu: Option<u16>,
    descriptions: Vec<(u8, u8, bool, u16, u8, u8)>,
) -> Result<SimDevice, BoxError> {
    let mut memory = HashMap::new();
    memory.insert(0x0060u16, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    Ok(SimDevice {
        address: addr.parse()?,
        behavior: Behavior::Responds {
            mask,
            manufacturer,
            serial: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            order: b"MDT-JAL0410".to_vec(),
            memory,
            max_apdu,
            descriptions,
        },
    })
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    let config = ConnectionConfig::tunnel(addr);
    Ok(Transport::connect(&config).await?)
}

/// Returns the error of a call that must fail.
fn must_fail<T, E>(result: Result<T, E>) -> Result<E, BoxError> {
    match result {
        Ok(_) => Err("expected the call to fail, it succeeded".into()),
        Err(e) => Ok(e),
    }
}

/// The lease path: an L4 session driven over a [`LeaseChannel`] on the bus actor
/// must read the device correctly, *and* a concurrent group subscriber on the
/// same bus must still see the device's response frames (the single-consumer
/// fix — the old `recv` would have stolen them).
#[tokio::test]
async fn device_read_over_a_lease_and_group_subscriber_both_see_frames() -> TestResult {
    use bussard_bus::Bus;
    use bussard_mgmt::LeaseChannel;

    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    // Wait for the actor to connect.
    for _ in 0..300 {
        if handle.status() == bussard_bus::BusState::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // A concurrent group subscriber: it must observe the device's response
    // frames flowing over the shared bus while the L4 session is active.
    let mut sub = handle.subscribe();
    let observer = tokio::spawn(async move {
        // Collect whatever arrives within a short window.
        let mut seen = 0usize;
        while (tokio::time::timeout(Duration::from_secs(2), sub.recv()).await)
            .is_ok_and(|f| f.is_some())
        {
            seen += 1;
            if seen >= 1 {
                break;
            }
        }
        seen
    });

    let lease = handle.lease().await?;
    let channel = LeaseChannel::new(lease);
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(channel, target, source).await?;

    let mask = dev.device_descriptor().await?;
    assert_eq!(mask, 0x07B0, "the L4 session over a lease reads correctly");
    dev.disconnect().await?;

    let seen = observer.await?;
    assert!(
        seen >= 1,
        "a concurrent group subscriber must see the device's response frames"
    );

    let _ = handle.close().await;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn device_descriptor_property_and_memory() -> TestResult {
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let mask = dev.device_descriptor().await?;
    assert_eq!(mask, 0x07B0);

    let manu = dev.read_device_property(apci::PID_MANUFACTURER_ID).await?;
    assert_eq!(manu, vec![0x00, 0x83]);

    let serial = dev.read_device_property(apci::PID_SERIAL_NUMBER).await?;
    assert_eq!(serial, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

    let order = dev.read_device_property(apci::PID_ORDER_INFO).await?;
    assert_eq!(order, b"MDT-JAL0410");

    let mem = dev.read_memory(0x0060, 4).await?;
    assert_eq!(mem, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn max_apdu_negotiation_scales_memory_chunk() -> TestResult {
    use bussard_mgmt::Layer4Connection;

    // A device advertising a large max APDU (KNX Virtual's 66) scales to the
    // 63-octet memory ceiling; a device at the standard-frame floor (15) is capped
    // to 12-octet chunks (standard frames); a device without the property falls
    // back to the conservative 12 (issue #58).
    let devices = vec![
        responder_with_apdu("1.1.10", 0x07B0, 0x0083, Some(66))?,
        responder_with_apdu("1.1.11", 0x07B0, 0x0083, Some(15))?,
        responder_with_apdu("1.1.12", 0x07B0, 0x0083, None)?,
    ];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;

    for (target_str, expected_chunk, expect_negotiated) in [
        ("1.1.10", 63u8, true),
        ("1.1.11", 12u8, true),
        ("1.1.12", 12u8, false),
    ] {
        let target: IndividualAddress = target_str.parse()?;
        let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
        // Before negotiation the conservative default applies.
        assert_eq!(
            l4.max_memory_chunk(),
            12,
            "{target_str}: pre-negotiation must be conservative"
        );
        let negotiated = l4.negotiate_max_apdu().await?;
        assert_eq!(
            negotiated.is_some(),
            expect_negotiated,
            "{target_str}: negotiation presence mismatch"
        );
        assert_eq!(
            l4.max_memory_chunk(),
            expected_chunk,
            "{target_str}: memory chunk must scale to the advertised APDU"
        );
        l4.disconnect().await?;
    }

    drop(gw);
    Ok(())
}

#[tokio::test]
async fn retransmitted_previous_response_does_not_desync() -> TestResult {
    // A device retransmits the PREVIOUS response (its old, one-behind send seq)
    // before answering each new request — as it does when our earlier T_ACK was
    // lost. await_ack must NOT treat that stale/out-of-window NDT as the ack of
    // the new request (which would advance send_seq off stale evidence and
    // desync). It must ACK expected-1, keep waiting, then consume the fresh
    // response. Several requests in a row must all decode correctly (#57).
    let devices = vec![SimDevice {
        address: "1.1.7".parse()?,
        behavior: Behavior::RetransmitsPreviousResponse { mask: 0x07B0 },
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.7".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    // The first read is clean; every subsequent read is preceded by a replayed
    // previous response. All must yield the correct mask and stay in sync.
    for i in 0..6 {
        let mask = dev
            .device_descriptor()
            .await
            .unwrap_or_else(|e| panic!("read {i} failed: {e}"));
        assert_eq!(mask, 0x07B0, "read {i} must decode the fresh response");
    }

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn wraparound_across_many_requests() -> TestResult {
    // Issue > 16 property reads on one connection to exercise TPCI sequence
    // wraparound at 15 in both directions.
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    for _ in 0..20 {
        let manu = dev.read_device_property(apci::PID_MANUFACTURER_ID).await?;
        assert_eq!(manu, vec![0x00, 0x83]);
    }
    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn folded_ack_device_still_delivers_response() -> TestResult {
    // A device that folds its ACK (answers with the response NDT before/instead
    // of a separate T_ACK) must still yield the descriptor, and the connection
    // must stay in sync for a following request.
    let devices = vec![SimDevice {
        address: "1.1.4".parse()?,
        behavior: Behavior::FoldsAck { mask: 0x07B0 },
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let mask = dev.device_descriptor().await?;
    assert_eq!(mask, 0x07B0, "folded-ACK response must still decode");

    // A second request must also succeed: the receive sequence advanced exactly
    // once for the folded response, so nothing is dropped as a duplicate.
    let mask2 = dev.device_descriptor().await?;
    assert_eq!(
        mask2, 0x07B0,
        "connection stayed in sync after a folded ACK"
    );

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn nak_device_is_present_but_refuses() -> TestResult {
    let devices = vec![SimDevice {
        address: "1.1.7".parse()?,
        behavior: Behavior::Nak,
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.7".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let err = must_fail(dev.device_descriptor().await)?;
    assert!(matches!(err, MgmtError::Nak { .. }), "got {err:?}");
    assert!(err.device_present(), "a NAK means the device is present");
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn malformed_descriptor_error_carries_raw_hex() -> TestResult {
    // A device that answers a descriptor read with the wrong APCI + payload must
    // surface a MalformedResponse whose reason includes the raw APCI and payload
    // bytes (hex) — the KNX Virtual interface finding: the frame is captured in
    // the error text so no packet sniffer is needed.
    let devices = vec![SimDevice {
        address: "1.0.255".parse()?,
        behavior: Behavior::WrongDescriptorApci {
            payload: vec![0x00, 0x0C, 0x10, 0x01, 0x07, 0xB0],
        },
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.0.255".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let err = must_fail(dev.device_descriptor().await)?;
    match err {
        MgmtError::MalformedResponse { reason, .. } => {
            // The A_PropertyValue_Response selector is 0x03D6.
            assert!(
                reason.contains("APCI 0x03D6"),
                "reason should carry the raw APCI: {reason}"
            );
            assert!(
                reason.contains("payload [00 0C 10 01 07 B0]"),
                "reason should carry the raw payload hex: {reason}"
            );
        }
        other => panic!("expected MalformedResponse, got {other:?}"),
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn descriptor_echo_is_named_in_the_error() -> TestResult {
    // Finding 2: the KNX Virtual IP interface answers A_DeviceDescriptor_Read by
    // echoing the read (APCI 0x0300) rather than a Response (0x0340). The decoder
    // must name that echo pattern — not report a bare "unexpected response" — so
    // the operator knows the device does not implement descriptor responses.
    let devices = vec![SimDevice {
        address: "1.0.255".parse()?,
        behavior: Behavior::EchoesDescriptorRead,
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.0.255".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let err = must_fail(dev.device_descriptor().await)?;
    match err {
        MgmtError::MalformedResponse { reason, .. } => {
            assert!(
                reason.contains("echoed the descriptor read instead of answering"),
                "reason must name the echo pattern: {reason}"
            );
            assert!(
                reason.contains("APCI 0x0300"),
                "reason must name the echo APCI: {reason}"
            );
            assert!(
                reason.contains("does not implement descriptor responses"),
                "reason must state the consequence: {reason}"
            );
            assert!(
                reason.contains("KNX Virtual IP"),
                "reason must name where this is seen: {reason}"
            );
        }
        other => panic!("expected MalformedResponse, got {other:?}"),
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn silent_device_is_absent() -> TestResult {
    let devices = vec![SimDevice {
        address: "1.1.9".parse()?,
        behavior: Behavior::Silent,
    }];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.9".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    // A silent address costs `2 × ack_timeout` to rule out; the real discovery()
    // budget is 1500ms per attempt (~3s wasted here). Nothing about this test
    // depends on that duration, so use a tight budget that keeps the wall low.
    let fast = Timeouts {
        ack_timeout: Duration::from_millis(50),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(50),
        absent_on_negative_confirmation: false,
    };
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast).await?;

    let err = must_fail(dev.device_descriptor().await)?;
    assert!(matches!(err, MgmtError::NoResponse { .. }), "got {err:?}");
    assert!(!err.device_present(), "silence means the device is absent");
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn describe_property_reads_one_descriptor() -> TestResult {
    // A device that exposes property descriptions on object 0 answers a
    // single-PID-by-index A_PropertyDescription_Read with the full descriptor.
    let devices = vec![responder_with_apdu_and_descriptions(
        "1.1.4",
        0x07B0,
        0x0083,
        Some(66),
        vec![
            // (pid, pdt, writable, max_elements, read_level, write_level)
            (1u8, 0x03, false, 1, 3, 15),
            (apci::PID_SERIAL_NUMBER, 0x04, false, 1, 3, 15),
        ],
    )?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    // By index (PID 0): index 1 is the object-type property.
    let desc = dev
        .describe_property(apci::DEVICE_OBJECT_INDEX, 0, 1)
        .await?;
    assert_eq!(desc.property_id, 1u8);
    assert_eq!(desc.property_index, 1);
    assert_eq!(desc.pdt, 0x03);
    assert!(!desc.writable);
    assert_eq!(desc.max_elements, 1);
    assert_eq!(desc.read_level, 3);
    assert_eq!(desc.write_level, 15);

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn describe_object_enumerates_all_properties_and_terminates() -> TestResult {
    // Walking object 0 yields every seeded property in index order and stops
    // cleanly at the first absent index (the device returns max_elements == 0).
    let seeded = vec![
        (1u8, 0x03, false, 1, 3, 15),
        (apci::PID_SERIAL_NUMBER, 0x04, false, 1, 3, 15),
        (apci::PID_MANUFACTURER_ID, 0x04, false, 1, 3, 15),
        (apci::PID_PROGMODE, 0x10, true, 1, 3, 0),
    ];
    let devices = vec![responder_with_apdu_and_descriptions(
        "1.1.4",
        0x07B0,
        0x0083,
        Some(66),
        seeded.clone(),
    )?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let props = dev.describe_object(apci::DEVICE_OBJECT_INDEX).await?;
    assert_eq!(
        props.len(),
        seeded.len(),
        "every seeded property enumerated"
    );
    // Order and identity match the seeding, 1-based indices.
    for (i, (pid, pdt, writable, max, rl, wl)) in seeded.iter().enumerate() {
        assert_eq!(props[i].property_id, *pid);
        assert_eq!(props[i].property_index as usize, i + 1);
        assert_eq!(props[i].pdt, *pdt);
        assert_eq!(props[i].writable, *writable);
        assert_eq!(props[i].max_elements, *max);
        assert_eq!(props[i].read_level, *rl);
        assert_eq!(props[i].write_level, *wl);
    }

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn describe_object_on_device_without_descriptions_is_empty() -> TestResult {
    // A device that does not implement the description service (no descriptions
    // seeded → every index answers max_elements == 0) yields an empty list, not
    // an error: enumeration terminates cleanly at index 1.
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)?];
    let gw = start_mock(devices).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    let props = dev.describe_object(apci::DEVICE_OBJECT_INDEX).await?;
    assert!(props.is_empty(), "no descriptions → empty enumeration");

    dev.disconnect().await?;
    drop(gw);
    Ok(())
}
