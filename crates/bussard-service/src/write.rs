//! The checked group write: one implementation of the write policy for every
//! surface (issue #86).
//!
//! The CLI's `bussard write`, the MCP server's `knx_write_group` and the viz
//! server's `POST /api/group-write` each used to resolve the DPT, check the
//! protected flag, encode and send on their own, with three slightly different
//! behaviours. They now all go through [`prepare_group_write`] (pure: model
//! lookups, the protected check, parsing and encoding) and
//! [`BusService::write_group_checked`] / [`BusService::send_prepared`] (the
//! send). Every refusal is a typed [`WriteRefusal`] that the surface renders in
//! its own words; the decision itself is made here.
//!
//! The order of the checks is:
//!
//! 1. **protected**: a GA marked `protected: true` in `groups.yaml` is refused
//!    unless [`WriteCheck::force`] is set. This runs first, so a protected GA is
//!    refused whatever DPT or value arrives with it.
//! 2. **DPT**: the override is parsed, then reconciled with the model's DPT
//!    under the [`DptOverridePolicy`].
//! 3. **encode**: the human value is parsed and encoded against the DPT, or a
//!    raw hex payload is decoded and its length checked against a known DPT.
//! 4. **send**: once, completion-tracked against the gateway ACK
//!    ([`bussard_bus::ops::write_group`]), and only on a service opened with a
//!    transmitting [`WritePolicy`](crate::WritePolicy).

use bussard_bus::BusError;
use bussard_bus::ops::{self, WriteOptions};
use bussard_model::{ApduSize, Dpt, GroupAddress, Model, encode, parse_value};

use crate::bus::BusService;

/// The value to write.
#[derive(Debug, Clone, Copy)]
pub enum WriteValue<'a> {
    /// A human-typed value (`on`, `75%`, `21.5`, a scene number, an HVAC mode
    /// name), parsed against the resolved DPT.
    Human(&'a str),
    /// A raw payload as an even-length hex string, sent verbatim. A DPT is
    /// optional; when one is known the byte length is checked against it and a
    /// sub-byte DPT's single byte is sent packed. With no DPT anywhere the
    /// payload is sent unpacked, the form every device reads (issue #59).
    Hex(&'a str),
}

/// How a caller-supplied DPT relates to the model's DPT for the GA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DptOverridePolicy {
    /// The override wins over the model. For surfaces with a human in the loop
    /// (the CLI asks y/N; viz is a person at a page).
    #[default]
    Trust,
    /// An override that disagrees with the model's DPT is refused
    /// ([`WriteRefusal::DptMismatch`]); it only applies to a GA the model does
    /// not type. For the MCP server, where no human confirms the write and an
    /// unchecked override could put an arbitrary payload past the model's types.
    MustMatchModel,
}

/// The options of a checked write.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteCheck<'a> {
    /// A DPT override as typed by the caller (`"1.001"`), parsed here.
    pub dpt: Option<&'a str>,
    /// How the override relates to the model's DPT.
    pub dpt_policy: DptOverridePolicy,
    /// Write a protected GA anyway (the CLI's `--force`, viz's `force`). The MCP
    /// server never sets it.
    pub force: bool,
}

/// A write that passed every check and is ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWrite {
    /// The destination group address.
    pub ga: GroupAddress,
    /// The GA's name in the model, if it has one.
    pub name: Option<String>,
    /// The DPT the payload was encoded (or checked) against. `None` only for a
    /// raw payload to a GA with no known DPT.
    pub dpt: Option<Dpt>,
    /// The parsed value as displayed (`Down`, `75 %`). `None` for a raw payload.
    pub value: Option<String>,
    /// The encoded payload.
    pub payload: Vec<u8>,
    /// Whether the payload is packed into the 6-bit APDU (sub-byte DPTs only).
    pub packed: bool,
}

/// A write that was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOutcome {
    /// What was sent.
    pub write: PreparedWrite,
    /// Whether a bus confirmation for the GA was observed within the settle
    /// window. KNX group writes are fire-and-forget, so `false` is not an error.
    pub confirmed: bool,
}

/// Why a checked write was not sent (or failed to send).
///
/// Each surface renders these in its own words (a CLI hint names `--force`, the
/// MCP server says there is no override); the [`Display`](std::fmt::Display)
/// impl is a neutral fallback.
#[derive(Debug, thiserror::Error)]
pub enum WriteRefusal {
    /// The service was opened read-only.
    #[error("bus writes are disabled on this service")]
    WritesDisabled,
    /// The GA is marked `protected: true` and the write was not forced.
    #[error("refusing to write to protected GA {ga} ({name:?})")]
    Protected {
        /// The protected GA.
        ga: GroupAddress,
        /// Its name in the model.
        name: String,
    },
    /// The DPT override did not parse.
    #[error("invalid dpt {input:?}: {reason}")]
    InvalidDpt {
        /// The override as given.
        input: String,
        /// The parse error.
        reason: String,
    },
    /// The override disagrees with the model under
    /// [`DptOverridePolicy::MustMatchModel`].
    #[error("GA {ga} is declared as DPT {declared} in the model, not {requested}")]
    DptMismatch {
        /// The GA.
        ga: GroupAddress,
        /// The model's DPT.
        declared: Dpt,
        /// The caller's DPT.
        requested: Dpt,
    },
    /// No DPT could be resolved for a human value.
    #[error("GA {ga} has no DPT")]
    NoDpt {
        /// The GA.
        ga: GroupAddress,
        /// Whether a model was loaded at all (`false`: a fresh project with no
        /// `knx/` directory).
        model_loaded: bool,
    },
    /// The human value did not parse for the DPT.
    #[error("parsing value {value:?} for GA {ga}: {reason}")]
    InvalidValue {
        /// The GA.
        ga: GroupAddress,
        /// The value as given.
        value: String,
        /// The DPT it was parsed against.
        dpt: Dpt,
        /// The parse error.
        reason: String,
    },
    /// The parsed value could not be encoded for the DPT.
    #[error("encoding {value} as DPT {dpt} for GA {ga}: {reason}")]
    Encode {
        /// The GA.
        ga: GroupAddress,
        /// The parsed value as displayed.
        value: String,
        /// The DPT.
        dpt: Dpt,
        /// The encode error.
        reason: String,
    },
    /// The raw payload is not valid hex.
    #[error("invalid payload hex {input:?}: {reason}")]
    InvalidHex {
        /// The payload as given.
        input: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The raw payload decoded to zero bytes.
    #[error("payload must decode to at least one byte")]
    EmptyPayload,
    /// The raw payload's length does not fit the known DPT.
    #[error("{0}")]
    PayloadSize(String),
    /// The send itself failed (ACK exhaustion, staleness, a gone actor).
    #[error(transparent)]
    Bus(BusError),
}

/// The name of `ga` if the model marks it `protected: true`, else `None`.
///
/// Exposed for surfaces that warn about protected GAs before they write, like
/// `bussard test`'s pre-flight.
pub fn protected_group(model: &Model, ga: GroupAddress) -> Option<&str> {
    model
        .groups
        .groups
        .get(&ga)
        .filter(|g| g.protected)
        .map(|g| g.name.as_str())
}

/// Runs every check of a group write short of sending it.
///
/// `model` is `None` for a fresh project with no `knx/` directory; a human
/// value then needs a DPT override. Pure: no bus, no I/O.
///
/// # Errors
///
/// The first [`WriteRefusal`] in the order the module docs describe.
pub fn prepare_group_write(
    model: Option<&Model>,
    ga: GroupAddress,
    value: WriteValue<'_>,
    check: &WriteCheck<'_>,
) -> Result<PreparedWrite, WriteRefusal> {
    let group = model.and_then(|m| m.groups.groups.get(&ga));

    // 1. Protected, first: whatever else arrives with the write.
    if let Some(g) = group
        && g.protected
        && !check.force
    {
        return Err(WriteRefusal::Protected {
            ga,
            name: g.name.clone(),
        });
    }
    let name = group.map(|g| g.name.clone());

    // 2. The DPT.
    let requested = match check.dpt {
        Some(s) => Some(s.parse::<Dpt>().map_err(|e| WriteRefusal::InvalidDpt {
            input: s.to_string(),
            reason: e.to_string(),
        })?),
        None => None,
    };
    let modelled = group.and_then(|g| g.dpt);
    let dpt = match (requested, modelled, check.dpt_policy) {
        (Some(requested), Some(declared), DptOverridePolicy::MustMatchModel)
            if requested != declared =>
        {
            return Err(WriteRefusal::DptMismatch {
                ga,
                declared,
                requested,
            });
        }
        (Some(requested), _, DptOverridePolicy::Trust) => Some(requested),
        (_, Some(declared), _) => Some(declared),
        (requested, None, _) => requested,
    };

    // 3. Encode.
    match value {
        WriteValue::Human(input) => {
            let dpt = dpt.ok_or(WriteRefusal::NoDpt {
                ga,
                model_loaded: model.is_some(),
            })?;
            let typed = parse_value(&dpt, input).map_err(|e| WriteRefusal::InvalidValue {
                ga,
                value: input.to_string(),
                dpt,
                reason: e.to_string(),
            })?;
            let payload = encode(&dpt, &typed).map_err(|e| WriteRefusal::Encode {
                ga,
                value: typed.to_string(),
                dpt,
                reason: e.to_string(),
            })?;
            Ok(PreparedWrite {
                ga,
                name,
                dpt: Some(dpt),
                value: Some(typed.to_string()),
                payload,
                // Pack only sub-byte DPTs into the 6-bit APDU; a byte-sized DPT
                // with a small value must be sent whole (issue #59).
                packed: dpt.is_packable(),
            })
        }
        WriteValue::Hex(input) => {
            let payload = decode_hex(input).map_err(|reason| WriteRefusal::InvalidHex {
                input: input.to_string(),
                reason,
            })?;
            if payload.is_empty() {
                return Err(WriteRefusal::EmptyPayload);
            }
            let packed = match dpt {
                Some(d) => {
                    validate_payload_size(d, &payload, ga)?;
                    d.is_packable()
                }
                // No DPT anywhere: a lone byte <= 0x3F is ambiguous between the
                // packed 1-bit form and a byte-sized value; the unpacked full
                // octet is the form every device reads correctly (issue #59).
                None => false,
            };
            Ok(PreparedWrite {
                ga,
                name,
                dpt,
                value: None,
                payload,
                packed,
            })
        }
    }
}

impl BusService {
    /// Sends a write that already passed [`prepare_group_write`], once.
    ///
    /// # Errors
    ///
    /// [`WriteRefusal::WritesDisabled`] on a read-only service, or
    /// [`WriteRefusal::Bus`] when the send fails.
    pub async fn send_prepared(&self, write: PreparedWrite) -> Result<WriteOutcome, WriteRefusal> {
        if !self.policy().transmits() {
            return Err(WriteRefusal::WritesDisabled);
        }
        let sent = ops::write_group(
            self.handle(),
            write.ga,
            &write.payload,
            write.packed,
            WriteOptions::default(),
        )
        .await
        .map_err(WriteRefusal::Bus)?;
        Ok(WriteOutcome {
            write,
            confirmed: sent.confirmed,
        })
    }

    /// The whole checked write: [`prepare_group_write`], then
    /// [`send_prepared`](Self::send_prepared).
    ///
    /// # Errors
    ///
    /// The first [`WriteRefusal`] of the checks, or the send failure.
    pub async fn write_group_checked(
        &self,
        model: Option<&Model>,
        ga: GroupAddress,
        value: WriteValue<'_>,
        check: &WriteCheck<'_>,
    ) -> Result<WriteOutcome, WriteRefusal> {
        if !self.policy().transmits() {
            return Err(WriteRefusal::WritesDisabled);
        }
        let write = prepare_group_write(model, ga, value, check)?;
        self.send_prepared(write).await
    }
}

/// Validates a raw payload's byte length against a known DPT's expected size.
///
/// A packable DPT ([`ApduSize::Bits`]) expects exactly one byte holding a value
/// that fits in the 6-bit APDU (`<= 0x3F`); a byte-sized DPT expects exactly that
/// many whole octets. A DPT whose size bussard does not model is not validated.
fn validate_payload_size(dpt: Dpt, payload: &[u8], ga: GroupAddress) -> Result<(), WriteRefusal> {
    match dpt.expected_size() {
        Some(ApduSize::Bits(_)) => {
            let [byte] = payload else {
                return Err(WriteRefusal::PayloadSize(format!(
                    "payload for GA {ga} DPT {dpt} must be 1 byte (sub-byte / packable), got {}",
                    payload.len()
                )));
            };
            // The value must fit in the low 6 bits, or packing would truncate it.
            if *byte > 0x3f {
                return Err(WriteRefusal::PayloadSize(format!(
                    "payload byte {byte:#04x} for GA {ga} DPT {dpt} exceeds the 6-bit packable range (max 0x3f)"
                )));
            }
            Ok(())
        }
        Some(ApduSize::Bytes(n)) => {
            if payload.len() != usize::from(n) {
                return Err(WriteRefusal::PayloadSize(format!(
                    "payload for GA {ga} DPT {dpt} must be {n} byte(s), got {}",
                    payload.len()
                )));
            }
            Ok(())
        }
        // Size not modelled: allow any length (mirrors is_packable's None case).
        None => Ok(()),
    }
}

/// Decodes an even-length hex string (upper- or lowercase) into bytes.
///
/// Returns a human-readable error message for an odd length or a non-hex digit.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!(
            "odd length ({} chars); hex must be byte-aligned",
            s.len()
        ));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Ok((hex_nibble(*hi)? << 4) | hex_nibble(*lo)?),
            _ => Err("odd length; hex must be byte-aligned".to_string()),
        })
        .collect()
}

/// Decodes a single ASCII hex digit into its 0..=15 value.
fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("non-hex character {:?}", other as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn model_with(protected: bool, dpt: Option<&str>) -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/0/4")?,
            Group {
                name: "Living Room Blind Move".to_string(),
                dpt: dpt.map(str::parse).transpose()?,
                description: None,
                protected,
                secure: false,
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        })
    }

    fn trust(dpt: Option<&str>, force: bool) -> WriteCheck<'_> {
        WriteCheck {
            dpt,
            dpt_policy: DptOverridePolicy::Trust,
            force,
        }
    }

    #[test]
    fn test_prepare_group_write_protected_refused_without_force() -> TestResult {
        let m = model_with(true, Some("1.008"))?;
        let r = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Human("down"),
            &trust(None, false),
        );
        assert!(
            matches!(&r, Err(WriteRefusal::Protected { name, .. }) if name.contains("Blind")),
            "{r:?}"
        );
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_protected_refused_before_dpt_checks() -> TestResult {
        // A protected GA with no DPT and a broken override is still a protected
        // refusal: the protected check comes first.
        let m = model_with(true, None)?;
        let r = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Hex("zz"),
            &trust(Some("nope"), false),
        );
        assert!(matches!(r, Err(WriteRefusal::Protected { .. })), "{r:?}");
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_protected_allowed_with_force() -> TestResult {
        let m = model_with(true, Some("1.008"))?;
        let w = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Human("down"),
            &trust(None, true),
        )?;
        assert_eq!(w.payload, vec![1]);
        assert!(w.packed);
        assert_eq!(w.name.as_deref(), Some("Living Room Blind Move"));
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_dpt_override_wins_under_trust() -> TestResult {
        let m = model_with(false, Some("1.008"))?;
        let w = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Human("255"),
            &trust(Some("5.010"), false),
        )?;
        assert_eq!(w.dpt.map(|d| d.to_string()).as_deref(), Some("5.010"));
        assert!(!w.packed);
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_mismatch_refused_under_must_match() -> TestResult {
        let m = model_with(false, Some("1.008"))?;
        let check = WriteCheck {
            dpt: Some("5.010"),
            dpt_policy: DptOverridePolicy::MustMatchModel,
            force: false,
        };
        let r = prepare_group_write(Some(&m), ga("3/0/4")?, WriteValue::Human("255"), &check);
        assert!(matches!(r, Err(WriteRefusal::DptMismatch { .. })), "{r:?}");
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_missing_dpt_reports_model_presence() -> TestResult {
        let m = model_with(false, None)?;
        let r = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Human("on"),
            &trust(None, false),
        );
        assert!(
            matches!(
                r,
                Err(WriteRefusal::NoDpt {
                    model_loaded: true,
                    ..
                })
            ),
            "{r:?}"
        );
        let r = prepare_group_write(
            None,
            ga("3/0/4")?,
            WriteValue::Human("on"),
            &trust(None, false),
        );
        assert!(
            matches!(
                r,
                Err(WriteRefusal::NoDpt {
                    model_loaded: false,
                    ..
                })
            ),
            "{r:?}"
        );
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_malformed_override_is_invalid_dpt() -> TestResult {
        let m = model_with(false, Some("1.008"))?;
        let r = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Human("on"),
            &trust(Some("not-a-dpt"), false),
        );
        assert!(matches!(r, Err(WriteRefusal::InvalidDpt { .. })), "{r:?}");
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_hex_without_dpt_is_unpacked() -> TestResult {
        let r = prepare_group_write(
            None,
            ga("1/2/3")?,
            WriteValue::Hex("01"),
            &trust(None, false),
        )?;
        assert_eq!(r.payload, vec![1]);
        assert!(!r.packed);
        assert!(r.dpt.is_none());
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_hex_size_checked_against_dpt() -> TestResult {
        let m = model_with(false, Some("1.008"))?;
        let two = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Hex("0101"),
            &trust(None, false),
        );
        assert!(matches!(two, Err(WriteRefusal::PayloadSize(_))), "{two:?}");
        let big = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Hex("40"),
            &trust(None, false),
        );
        assert!(matches!(big, Err(WriteRefusal::PayloadSize(_))), "{big:?}");
        let ok = prepare_group_write(
            Some(&m),
            ga("3/0/4")?,
            WriteValue::Hex("01"),
            &trust(None, false),
        )?;
        assert!(ok.packed);
        Ok(())
    }

    #[test]
    fn test_prepare_group_write_bad_hex_and_empty() -> TestResult {
        let odd = prepare_group_write(
            None,
            ga("1/2/3")?,
            WriteValue::Hex("0"),
            &trust(None, false),
        );
        assert!(
            matches!(odd, Err(WriteRefusal::InvalidHex { .. })),
            "{odd:?}"
        );
        let bad = prepare_group_write(
            None,
            ga("1/2/3")?,
            WriteValue::Hex("zz"),
            &trust(None, false),
        );
        assert!(
            matches!(bad, Err(WriteRefusal::InvalidHex { .. })),
            "{bad:?}"
        );
        let empty =
            prepare_group_write(None, ga("1/2/3")?, WriteValue::Hex(""), &trust(None, false));
        assert!(
            matches!(empty, Err(WriteRefusal::EmptyPayload)),
            "{empty:?}"
        );
        Ok(())
    }

    #[test]
    fn test_decode_hex_roundtrip_and_case() -> TestResult {
        assert_eq!(decode_hex("0aFf")?, vec![0x0a, 0xff]);
        Ok(())
    }

    #[test]
    fn test_protected_group_names_only_protected() -> TestResult {
        let m = model_with(true, None)?;
        assert_eq!(
            protected_group(&m, ga("3/0/4")?),
            Some("Living Room Blind Move")
        );
        let m = model_with(false, None)?;
        assert_eq!(protected_group(&m, ga("3/0/4")?), None);
        Ok(())
    }
}
