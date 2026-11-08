//! A group read and a group write in one shape each (issue #904): `bussard
//! read --json` and `knx_read_group` print [`GroupReadReport`], `bussard
//! write --json` and `knx_write_group` print [`GroupWriteReport`].

use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_model::codec::TypedValue;
use serde::Serialize;
use serde_json::{Value, json};

use crate::admission::{self, Admission};
use crate::group::{GroupOutcome, ReadResult, WriteResult};
use crate::report::{Report, is_false};

/// A typed value as JSON: the number, flag or text with its unit and label,
/// and the display string where the kind has one.
pub fn typed_value(v: &TypedValue) -> Value {
    match v {
        TypedValue::Bool { value, label } => json!({ "bool": value, "label": label }),
        TypedValue::Control {
            control,
            value,
            label,
        } => json!({
            "control": control,
            "value": value,
            "label": label,
            "display": v.to_string(),
        }),
        TypedValue::Percent(p) => json!({ "percent": p }),
        TypedValue::Unsigned { value, unit } => json!({ "unsigned": value, "unit": unit }),
        TypedValue::Signed { value, unit } => json!({ "signed": value, "unit": unit }),
        TypedValue::Float { value, unit } => json!({ "float": value, "unit": unit }),
        TypedValue::Scaled { count, unit, .. } => json!({
            "scaled": v.scaled_f64(),
            "count": count,
            "unit": unit,
            "display": v.to_string(),
        }),
        TypedValue::Enum { code, label } => json!({
            "enum": code,
            "label": label,
            "display": v.to_string(),
        }),
        TypedValue::Flags { bits, names } => json!({
            "bits": bits,
            "flags": names,
            "display": v.to_string(),
        }),
        TypedValue::Fields(fields) => {
            let map: serde_json::Map<String, Value> = fields
                .iter()
                .map(|(name, value)| ((*name).to_string(), json!(value)))
                .collect();
            json!({ "fields": map, "display": v.to_string() })
        }
        other => json!({ "display": other.to_string() }),
    }
}

/// Hex of `bytes`, lowercase, no separator.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A group read (see the module docs).
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupReadReport {
    /// A device answered.
    pub ok: bool,
    /// The group address.
    pub ga: String,
    /// Its name in the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether a device answered.
    pub answered: bool,
    /// The value as displayed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The value typed ([`typed_value`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typed: Option<Value>,
    /// The DPT it was decoded with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
    /// The raw payload, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// The device that answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The read ran under KNX Data Secure.
    pub secured: bool,
    /// Nothing was sent (a refusal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<bool>,
    /// A policy refused the read.
    #[serde(skip_serializing_if = "is_false")]
    pub refused: bool,
    /// The sender admission verdict (issue #297).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    /// How long the read waited, when nothing answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How to admit the tunnel address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// A note about a secured read without admission evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GroupReadReport {
    /// The read of `ga` (named `name`, read secured when `secured`, waiting
    /// `timeout`) that ended with `outcome`.
    pub fn of(
        ga: GroupAddress,
        name: Option<String>,
        secured: bool,
        timeout: Duration,
        outcome: &GroupOutcome<ReadResult>,
    ) -> GroupReadReport {
        let base = GroupReadReport {
            ga: ga.to_string(),
            name,
            secured,
            admission: outcome.admission.as_ref().map(|a| a.label().to_string()),
            ..GroupReadReport::default()
        };
        match &outcome.result {
            Err(refused) => GroupReadReport {
                sent: Some(false),
                refused: true,
                admission: Some(refused.label().to_string()),
                reason: refused.refusal(),
                hint: refused.admit_hint(),
                ..base
            },
            Ok(Ok(Some(read))) => {
                let o = &read.outcome;
                GroupReadReport {
                    ok: true,
                    answered: true,
                    value: o.value.as_ref().map(ToString::to_string),
                    typed: o.value.as_ref().map(typed_value),
                    dpt: o.dpt.as_ref().map(ToString::to_string),
                    raw: Some(hex_lower(&o.payload)),
                    source: Some(o.source.to_string()),
                    secured: read.secured,
                    ..base
                }
            }
            Ok(Ok(None)) => GroupReadReport {
                timeout_seconds: Some(timeout.as_secs()),
                reason: Some(if secured {
                    admission::secured_read_timeout(ga, outcome.sender)
                } else {
                    "no response within timeout".to_string()
                }),
                note: outcome.note.clone(),
                ..base
            },
            Ok(Err(err)) => GroupReadReport {
                reason: Some(format!("bus send failed: {err}")),
                ..base
            },
        }
    }

    /// A read of `ga` that could not start because `reason`; `refused`
    /// when a policy refused it.
    pub fn failed(ga: GroupAddress, reason: String, refused: bool) -> GroupReadReport {
        GroupReadReport {
            ga: ga.to_string(),
            reason: Some(reason),
            refused,
            ..GroupReadReport::default()
        }
    }
}

impl Report for GroupReadReport {
    const SCHEMA: u32 = 2;
}

/// A group write (see the module docs).
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupWriteReport {
    /// The telegram was sent.
    pub ok: bool,
    /// The group address.
    pub ga: String,
    /// Its name in the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The value as displayed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The DPT it was encoded with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
    /// The payload, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// The write ran under KNX Data Secure.
    pub secured: bool,
    /// The resolved gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Whether anything was sent.
    pub sent: bool,
    /// The interface confirmed the telegram (`L_Data.con`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<bool>,
    /// What KNX confirmed, in words (issue #297).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// A policy refused the write.
    #[serde(skip_serializing_if = "is_false")]
    pub refused: bool,
    /// The sender admission verdict (issue #297).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How to admit the tunnel address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// A note about a secured write without admission evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GroupWriteReport {
    /// The write that ended with `outcome`, through `gateway`; `refusal`
    /// words a send that failed.
    pub fn of(
        ga: GroupAddress,
        gateway: Option<String>,
        outcome: &GroupOutcome<WriteResult>,
        refusal: impl Fn(&crate::write::WriteRefusal) -> (bool, String),
    ) -> GroupWriteReport {
        let base = GroupWriteReport {
            ga: ga.to_string(),
            gateway,
            admission: outcome.admission.as_ref().map(|a| a.label().to_string()),
            note: outcome.note.clone(),
            ..GroupWriteReport::default()
        };
        match &outcome.result {
            Err(refused) => Self::admission_refused(base, refused),
            Ok(Ok(sent)) => {
                let w = &sent.write;
                GroupWriteReport {
                    ok: true,
                    name: w.name.clone(),
                    value: w.value.clone(),
                    dpt: w.dpt.as_ref().map(ToString::to_string),
                    payload: Some(hex_lower(&w.payload)),
                    secured: w.is_secured(),
                    sent: true,
                    confirmed: Some(sent.confirmed),
                    result: Some(
                        if sent.confirmed {
                            admission::WRITE_RESULT
                        } else {
                            admission::WRITE_RESULT_UNCONFIRMED
                        }
                        .to_string(),
                    ),
                    ..base
                }
            }
            Ok(Err(err)) => {
                let (refused, reason) = refusal(err);
                GroupWriteReport {
                    refused,
                    reason: Some(reason),
                    ..base
                }
            }
        }
    }

    /// A secured write refused for sender admission: nothing was sent.
    fn admission_refused(base: GroupWriteReport, refused: &Admission) -> GroupWriteReport {
        GroupWriteReport {
            secured: true,
            refused: true,
            admission: Some(refused.label().to_string()),
            reason: refused.refusal(),
            hint: refused.admit_hint(),
            ..base
        }
    }

    /// A write of `ga` that was not sent because `reason`; `refused` when
    /// a policy refused it.
    pub fn failed(ga: GroupAddress, reason: String, refused: bool) -> GroupWriteReport {
        GroupWriteReport {
            ga: ga.to_string(),
            reason: Some(reason),
            refused,
            ..GroupWriteReport::default()
        }
    }
}

impl Report for GroupWriteReport {
    const SCHEMA: u32 = 2;
}
