//! The decode pipeline: cEMI frame → a resolved, typed [`DecodedTelegram`].
//!
//! This module is pure and unit-testable. It takes a [`TimestampedFrame`] from
//! the transport and an optional [`Model`] and produces a fully-resolved view
//! of the telegram: addresses resolved to names, the payload decoded to a
//! [`TypedValue`] using the destination GA's DPT, the sending com-object name
//! resolved from the links, and a [`DecodedTelegram::decode_note`] carrying any
//! mismatch between the wire payload and the declared DPT.
//!
//! Everything degrades gracefully. With no model, addresses stay numeric and
//! the value is raw hex; with an incomplete model, whatever can be resolved is,
//! and the rest falls back. Decoding never fails.

use std::time::SystemTime;

use bussard_model::codec::{TypedValue, decode};
use bussard_model::{ApduSize, Dpt, GroupAddress, IndividualAddress, Model};
use bussard_transport::TimestampedFrame;
use bussard_transport::cemi::{Apdu, Destination, GroupData};

/// The application-layer service kind of a telegram, classified for display and
/// filtering. [`ApciKind::Other`] preserves the raw 10-bit APCI so management
/// traffic is never lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApciKind {
    /// A `GroupValueRead` (a request for the current value).
    Read,
    /// A `GroupValueWrite` (a new value being pushed).
    Write,
    /// A `GroupValueResponse` (a reply to a read).
    Response,
    /// Any other application service, carrying its raw 10-bit APCI code.
    Other(u16),
}

impl ApciKind {
    /// A short, stable lowercase tag used in JSON output and column display.
    pub fn tag(self) -> &'static str {
        match self {
            ApciKind::Read => "read",
            ApciKind::Write => "write",
            ApciKind::Response => "response",
            ApciKind::Other(_) => "other",
        }
    }

    /// The glyph shown between source and destination in the pretty formatter.
    pub fn arrow(self) -> &'static str {
        match self {
            // Read pulls a value toward the requester.
            ApciKind::Read => "?→",
            ApciKind::Write => "→",
            ApciKind::Response => "←",
            ApciKind::Other(_) => "·",
        }
    }
}

/// The destination of a telegram: a group address (the common case) or an
/// individual address (management / point-to-point traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationRef {
    /// A group address.
    Group(GroupAddress),
    /// An individual (physical) address.
    Individual(IndividualAddress),
}

impl DestinationRef {
    /// The group address, if this destination is one.
    pub fn group(self) -> Option<GroupAddress> {
        match self {
            DestinationRef::Group(g) => Some(g),
            DestinationRef::Individual(_) => None,
        }
    }
}

impl std::fmt::Display for DestinationRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DestinationRef::Group(g) => write!(f, "{g}"),
            DestinationRef::Individual(i) => write!(f, "{i}"),
        }
    }
}

/// A fully-decoded, model-resolved telegram, ready to be formatted, stored, or
/// matched against a filter.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedTelegram {
    /// Local time the frame was received.
    pub timestamp: SystemTime,
    /// Source individual (physical) address.
    pub source: IndividualAddress,
    /// Source device name, resolved from the model (if the device is known).
    pub source_name: Option<String>,
    /// Destination address (group or individual).
    pub destination: DestinationRef,
    /// Destination name, resolved from the model (GA name; individual dest names
    /// resolve to the device name when known).
    pub destination_name: Option<String>,
    /// The application service kind.
    pub apci: ApciKind,
    /// The raw group-value payload bytes (unpacked from the small/large form).
    pub payload: Vec<u8>,
    /// The decoded typed value, using the destination GA's DPT. `None` for
    /// reads (no payload) and management traffic.
    pub value: Option<TypedValue>,
    /// The DPT used to decode, if one was found in the model.
    pub dpt: Option<Dpt>,
    /// The sending com-object name, resolved from `(source, GA)` via the links.
    pub object_name: Option<String>,
    /// A human note about any decode issue (e.g. a payload/DPT size mismatch),
    /// shown inline as a debugging signal. Never a hard failure.
    pub decode_note: Option<String>,
}

impl DecodedTelegram {
    /// Decodes and resolves a single frame against an optional model.
    ///
    /// With `model` = `None`, addresses stay numeric and the value is the raw
    /// payload; with a model, names, DPT, typed value and the sending
    /// com-object are resolved where possible.
    pub fn from_frame(frame: &TimestampedFrame, model: Option<&Model>) -> DecodedTelegram {
        let cemi = &frame.frame;
        let source = cemi.source;

        let destination = match cemi.destination {
            Destination::Group(g) => DestinationRef::Group(g),
            Destination::Individual(i) => DestinationRef::Individual(i),
        };

        let (apci, payload) = classify(&cemi.apdu);

        // Resolve source device name.
        let source_name = model.and_then(|m| device_name(m, source));

        // Resolve destination name + DPT (GA only).
        let (destination_name, dpt) = match (model, destination) {
            (Some(m), DestinationRef::Group(ga)) => {
                let group = m.groups.groups.get(&ga);
                (group.map(|g| g.name.clone()), group.and_then(|g| g.dpt))
            }
            (Some(m), DestinationRef::Individual(ia)) => (device_name(m, ia), None),
            (None, _) => (None, None),
        };

        // Resolve the sending com-object name from (source IA, GA) via links.
        let object_name = match (model, destination) {
            (Some(m), DestinationRef::Group(ga)) => sending_object_name(m, source, ga),
            _ => None,
        };

        // Decode the value using the DPT, if the service carries a payload.
        let (value, decode_note) = decode_value(apci, &payload, dpt);

        DecodedTelegram {
            timestamp: frame.received_at,
            source,
            source_name,
            destination,
            destination_name,
            apci,
            payload,
            value,
            dpt,
            object_name,
            decode_note,
        }
    }

    /// Whether this telegram's source or destination address matches `text`,
    /// where `text` is a group address, individual address, or `main/middle`
    /// GA prefix. Used by the CLI filter and store queries.
    pub fn addresses(&self) -> (IndividualAddress, DestinationRef) {
        (self.source, self.destination)
    }
}

/// Resolves the name of the device at `addr`, if the model knows it.
fn device_name(model: &Model, addr: IndividualAddress) -> Option<String> {
    model.devices.get(&addr).map(|d| d.device.name.clone())
}

/// Finds the name of the com object on `source` whose `send` GA is `ga`.
///
/// The informational com-object name lives only in `links.yaml` (issue #19), so
/// it is read straight from the matching link.
fn sending_object_name(
    model: &Model,
    source: IndividualAddress,
    ga: GroupAddress,
) -> Option<String> {
    let links = model.links.links.get(&source)?;
    for link in links {
        if link.send == Some(ga) {
            return link.name.clone();
        }
    }
    None
}

/// Classifies an APDU into an [`ApciKind`] and extracts its raw payload bytes.
fn classify(apdu: &Apdu) -> (ApciKind, Vec<u8>) {
    match apdu {
        Apdu::GroupValueRead => (ApciKind::Read, Vec::new()),
        Apdu::GroupValueWrite(d) => (ApciKind::Write, group_bytes(d)),
        Apdu::GroupValueResponse(d) => (ApciKind::Response, group_bytes(d)),
        Apdu::Other { apci, data } => (ApciKind::Other(*apci), data.clone()),
        // A transport-control frame (T_Connect/T_ACK/…) carries no application
        // layer; classify it as "other" with an empty payload.
        Apdu::Empty => (ApciKind::Other(0), Vec::new()),
    }
}

/// The raw payload bytes of a group-value service.
fn group_bytes(d: &GroupData) -> Vec<u8> {
    d.bytes()
}

/// Decodes the payload against the DPT, returning the typed value and any note.
///
/// Reads carry no payload, so they decode to `None` with no note. When a DPT is
/// known, a payload whose length disagrees with the DPT's declared size still
/// decodes (best-effort) but records a note showing both sizes.
fn decode_value(
    apci: ApciKind,
    payload: &[u8],
    dpt: Option<Dpt>,
) -> (Option<TypedValue>, Option<String>) {
    // Reads and management traffic carry no interpretable group value.
    if matches!(apci, ApciKind::Read | ApciKind::Other(_)) {
        return (None, None);
    }

    let Some(dpt) = dpt else {
        // No DPT in the model: surface the raw bytes as the value, no note (the
        // formatter dims unknown GAs on its own).
        return (Some(TypedValue::Raw(payload.to_vec())), None);
    };

    let note = size_mismatch_note(&dpt, payload);
    let value = decode(&dpt, payload);
    (Some(value), note)
}

/// Produces a note when the payload length disagrees with the DPT's declared
/// on-wire size, showing both. Returns `None` when the sizes agree or the DPT
/// size is not modelled.
fn size_mismatch_note(dpt: &Dpt, payload: &[u8]) -> Option<String> {
    let expected = dpt.expected_size()?;
    let expected_bytes = match expected {
        // Sub-byte DPTs occupy a single small-APDU octet on the wire.
        ApduSize::Bits(_) => 1,
        ApduSize::Bytes(n) => n as usize,
    };
    if payload.len() == expected_bytes {
        return None;
    }
    Some(format!(
        "payload is {} byte{}, but DPT {dpt} expects {expected}",
        payload.len(),
        if payload.len() == 1 { "" } else { "s" },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::LoadedDevice;
    use bussard_model::schema::{BussardConfig, Device, Group, Groups, Link, Links};
    use bussard_transport::cemi::CemiFrame;

    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    /// A small in-code model: two GAs (one with a DPT, one without), one device
    /// with a link whose `send` GA is 3/2/0.
    fn fixture_model() -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse().unwrap()),
                description: None,
                ..Default::default()
            },
        );
        // A GA present but with no DPT.
        groups.insert(
            ga("3/2/1"),
            Group {
                name: "Nodpt".to_string(),
                dpt: None,
                description: None,
                ..Default::default()
            },
        );
        // A GA whose DPT is 9.001 (2-byte temperature) — used for size mismatch.
        groups.insert(
            ga("3/2/2"),
            Group {
                name: "Temp".to_string(),
                dpt: Some("9.001".parse().unwrap()),
                description: None,
                ..Default::default()
            },
        );

        let mut links = BTreeMap::new();
        links.insert(
            ia("1.1.30"),
            vec![Link {
                object: 3,
                name: Some("Windalarm 1".to_string()),
                send: Some(ga("3/2/0")),
                listen: vec![],
            }],
        );

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.30"),
            LoadedDevice {
                device: Device {
                    address: ia("1.1.30"),
                    name: "Meteodata".to_string(),
                    description: None,
                    location: None,
                    replaced: None,
                    product: None,
                    channels: BTreeMap::new(),
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects: BTreeMap::new(),
                    security: None,
                },
                file_stem: "1.1.30-meteodata".to_string(),
            },
        );

        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links { links },
            devices,
        }
    }

    fn stamped(frame: CemiFrame) -> TimestampedFrame {
        TimestampedFrame {
            received_at: SystemTime::UNIX_EPOCH,
            frame,
        }
    }

    #[test]
    fn known_ga_with_dpt_resolves_everything() {
        let model = fixture_model();
        let frame = stamped(CemiFrame::group_write_packed(
            ga("3/2/0"),
            ia("1.1.30"),
            &[1],
        ));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));

        assert_eq!(d.source, ia("1.1.30"));
        assert_eq!(d.source_name.as_deref(), Some("Meteodata"));
        assert_eq!(d.destination, DestinationRef::Group(ga("3/2/0")));
        assert_eq!(d.destination_name.as_deref(), Some("Windalarm"));
        assert_eq!(d.apci, ApciKind::Write);
        assert_eq!(d.dpt, Some("1.005".parse().unwrap()));
        assert_eq!(d.object_name.as_deref(), Some("Windalarm 1"));
        assert_eq!(
            d.value,
            Some(TypedValue::Bool {
                value: true,
                label: "Alarm"
            })
        );
        assert!(d.decode_note.is_none());
    }

    #[test]
    fn ga_without_dpt_is_raw_no_note() {
        let model = fixture_model();
        let frame = stamped(CemiFrame::group_write_packed(
            ga("3/2/1"),
            ia("1.1.30"),
            &[1],
        ));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        assert_eq!(d.destination_name.as_deref(), Some("Nodpt"));
        assert_eq!(d.dpt, None);
        assert_eq!(d.value, Some(TypedValue::Raw(vec![1])));
        assert!(d.decode_note.is_none());
    }

    #[test]
    fn unknown_ga_degrades_to_numeric_and_raw() {
        let model = fixture_model();
        let frame = stamped(CemiFrame::group_write_packed(
            ga("7/7/7"),
            ia("2.2.2"),
            &[1],
        ));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        assert_eq!(d.destination_name, None);
        assert_eq!(d.source_name, None);
        assert_eq!(d.object_name, None);
        assert_eq!(d.dpt, None);
        assert_eq!(d.value, Some(TypedValue::Raw(vec![1])));
    }

    #[test]
    fn no_model_stays_numeric() {
        let frame = stamped(CemiFrame::group_write_packed(
            ga("3/2/0"),
            ia("1.1.30"),
            &[1],
        ));
        let d = DecodedTelegram::from_frame(&frame, None);
        assert_eq!(d.source_name, None);
        assert_eq!(d.destination_name, None);
        assert_eq!(d.dpt, None);
        assert_eq!(d.value, Some(TypedValue::Raw(vec![1])));
    }

    #[test]
    fn individual_destination_resolves_device_name() {
        let model = fixture_model();
        // A management-ish frame to the device at 1.1.30 (individual dest).
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0x60, 0x11, 0x01, 0x11, 0x1E, 0x02, 0x43, 0x00, 0x00,
        ];
        let frame = stamped(CemiFrame::decode(hex).unwrap());
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        match d.destination {
            DestinationRef::Individual(i) => assert_eq!(i, ia("1.1.30")),
            other => panic!("expected individual, got {other:?}"),
        }
        assert_eq!(d.destination_name.as_deref(), Some("Meteodata"));
        assert!(matches!(d.apci, ApciKind::Other(_)));
        assert_eq!(d.value, None);
    }

    #[test]
    fn size_mismatch_produces_note_but_still_decodes() {
        let model = fixture_model();
        // 3/2/2 declares DPT 9.001 (2 bytes) but we send a single byte.
        let frame = stamped(CemiFrame::group_write_packed(
            ga("3/2/2"),
            ia("1.1.30"),
            &[0x05],
        ));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        assert_eq!(d.dpt, Some("9.001".parse().unwrap()));
        let note = d.decode_note.expect("expected a size-mismatch note");
        assert!(note.contains("1 byte"), "note was {note:?}");
        assert!(note.contains("9.001"), "note was {note:?}");
        assert!(note.contains("2 bytes"), "note was {note:?}");
        // Still yields a value (raw fallback, since the payload is too short).
        assert!(d.value.is_some());
    }

    #[test]
    fn apci_other_has_no_value() {
        // A management APDU (numbered/connected TPCI).
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0x60, 0x11, 0x01, 0x11, 0x02, 0x02, 0x43, 0x00, 0x00,
        ];
        let frame = stamped(CemiFrame::decode(hex).unwrap());
        let d = DecodedTelegram::from_frame(&frame, None);
        assert!(matches!(d.apci, ApciKind::Other(_)));
        assert_eq!(d.value, None);
        assert!(d.decode_note.is_none());
    }

    #[test]
    fn read_has_no_value() {
        let model = fixture_model();
        let frame = stamped(CemiFrame::group_read(ga("3/2/0"), ia("1.1.30")));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        assert_eq!(d.apci, ApciKind::Read);
        assert!(d.payload.is_empty());
        assert_eq!(d.value, None);
    }

    #[test]
    fn response_is_classified_and_decoded() {
        let model = fixture_model();
        let frame = stamped(CemiFrame::group_response_packed(
            ga("3/2/0"),
            ia("1.1.30"),
            &[0],
        ));
        let d = DecodedTelegram::from_frame(&frame, Some(&model));
        assert_eq!(d.apci, ApciKind::Response);
        assert_eq!(
            d.value,
            Some(TypedValue::Bool {
                value: false,
                label: "No Alarm"
            })
        );
    }
}
