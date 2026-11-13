//! The outcome of a device write (issue #904): `knx_apply_device` (the
//! table and parameter write, or the full download of a `method: flash`
//! plan), `knx_restore_tables`, `knx_restore_parameters`,
//! `knx_restart_device` and `bussard restart --json`, in one shape.
//!
//! [`WriteOutcome`] is the only definition of the keys: the MCP result is
//! its serialisation plus the chat envelope (`summary`, and the job fields),
//! and a job record persisted under `.bussard/history` holds it, so the
//! summary of a job read back after a restart is derived from its
//! [`Verdict`] again.

use bussard_download::ParamChange;
use bussard_model::Model;
use bussard_model::text::capitalize;
use serde::{Deserialize, Serialize};

use crate::download::{DesiredTables, SecurityInputs};
use crate::flash_flow::LockRecord;
use crate::params::ParameterChange;
use crate::report::{Report, is_false, subject_phrase};
use crate::verify::WriteReadback;

/// What every write outcome says first: whether it worked and was read
/// back, and why not. The job table reads it back from a persisted record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// `bussard` did what was asked and nothing failed.
    #[serde(default)]
    pub ok: bool,
    /// An independent read-back compared the device with what was meant
    /// (CLAUDE.md "Device Writes"); never true without one.
    #[serde(default)]
    pub verified: bool,
    /// The pre-flight refused: nothing was written.
    #[serde(default, skip_serializing_if = "is_false")]
    pub refused: bool,
    /// Why it failed or was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What to do about a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

impl Verdict {
    /// A verified success.
    pub fn verified() -> Verdict {
        Verdict {
            ok: true,
            verified: true,
            ..Verdict::default()
        }
    }

    /// A failure with `reason`.
    pub fn failed(reason: impl Into<String>) -> Verdict {
        Verdict {
            reason: Some(reason.into()),
            ..Verdict::default()
        }
    }

    /// A pre-flight refusal: nothing was written.
    pub fn refused(reason: impl Into<String>) -> Verdict {
        Verdict {
            refused: true,
            ..Verdict::failed(reason)
        }
    }
}

/// The head of a job's persisted result: the verdict and what the write
/// was, enough for the job's summary and next step after a restart.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OutcomeHead {
    /// The verdict.
    #[serde(flatten)]
    pub verdict: Verdict,
    /// `apply`, `flash` or `restart`.
    #[serde(default)]
    pub method: Option<String>,
    /// The device.
    #[serde(default)]
    pub address: Option<String>,
    /// The line, for a line write.
    #[serde(default)]
    pub line: Option<String>,
    /// The device already held the model: nothing was written.
    #[serde(default)]
    pub noop: bool,
    /// The table backup taken before the write.
    #[serde(default)]
    pub backup: Option<String>,
    /// The group addresses declared in `groups.toml` before the write.
    #[serde(default)]
    pub declared: Vec<String>,
    /// The restart was confirmed by the device (a restart only).
    #[serde(default)]
    pub confirmed: Option<bool>,
}

impl OutcomeHead {
    /// The homeowner's sentence about a finished write, restore or
    /// restart (issue #306).
    pub fn summary(&self, model: &Model) -> String {
        let device = subject_phrase(model, self.address.as_deref(), self.line.as_deref());
        let v = &self.verdict;
        if v.refused {
            return format!(
                "Nothing was changed: bussard refused this request (`reason` says why){}.",
                if self.address.is_some() {
                    format!("; {device} is as it was")
                } else {
                    String::new()
                }
            );
        }
        if self.noop {
            return format!("{} already matches; nothing to write.", capitalize(&device));
        }
        if self.method.as_deref() == Some("restart") || self.confirmed.is_some() {
            return match (v.ok, v.verified) {
                (true, true) => format!("{} restarted and answers again.", capitalize(&device)),
                (true, false) => format!(
                    "{} was restarted and answers again; it does not confirm a restart, so \
                     that part is not checked.",
                    capitalize(&device)
                ),
                _ => format!(
                    "Restarting {device} did not work (`reason` says why); it is as it was \
                     before."
                ),
            };
        }
        if v.ok && v.verified {
            format!(
                "{} is written and checked: it now matches your project. Its previous state is \
                 backed up, so this can be undone.",
                capitalize(&device)
            )
        } else {
            format!(
                "Writing {device} did not check out: it may not behave as planned yet \
                 (`reason` and the read-back say what differs). Its previous state is backed up."
            )
        }
    }
}

/// The security object a table write programs (issue #297): addresses and
/// object numbers only, never a key.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityObject {
    /// One line: what the security object receives.
    pub summary: String,
    /// The PID 54 entries.
    pub secure_senders: Vec<SecureSender>,
    /// The group addresses keyed in the object.
    pub keyed_groups: Vec<String>,
    /// The group objects flagged secured (PID 61).
    pub secured_objects: Vec<u16>,
    /// The secured group objects with no PID 61 element (group object 0,
    /// issue #1094): their keys are written, no flag.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secured_without_flag: Vec<u16>,
}

/// One PID 54 entry.
#[derive(Debug, Clone, Serialize)]
pub struct SecureSender {
    /// The sender's individual address.
    pub address: String,
    /// The sequence number it starts from.
    pub sequence: u64,
}

impl SecurityObject {
    /// What `inputs` program for `desired`; `None` on the plain path and
    /// when nothing is written (`noop`).
    pub fn of(
        inputs: Option<&SecurityInputs>,
        desired: &DesiredTables,
        noop: bool,
    ) -> Option<SecurityObject> {
        let inputs = inputs.filter(|_| !noop)?;
        Some(SecurityObject {
            summary: inputs.describe(&desired.addresses),
            secure_senders: inputs
                .senders
                .iter()
                .map(|e| SecureSender {
                    address: e.address.to_string(),
                    sequence: e.sequence,
                })
                .collect(),
            keyed_groups: inputs
                .keyed(&desired.addresses)
                .iter()
                .map(ToString::to_string)
                .collect(),
            secured_objects: inputs
                .secure_objects
                .iter()
                .copied()
                .filter(|&o| bussard_model::secure_invariants::has_go_flag_element(o))
                .collect(),
            secured_without_flag: inputs
                .secure_objects
                .iter()
                .copied()
                .filter(|&o| !bussard_model::secure_invariants::has_go_flag_element(o))
                .collect(),
        })
    }
}

/// The System B group-object table reload of a table write (issue #540).
#[derive(Debug, Clone, Serialize)]
pub struct ObjectTableWritten {
    /// Its final load state.
    pub state: String,
    /// The entry count written.
    pub entries: usize,
    /// Whether the read-back matched byte for byte.
    pub read_back_matches: bool,
}

/// What a write did to the parameter memory.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParametersWritten {
    /// Whether parameter octets were written.
    pub written: bool,
    /// Whether their read-back matched; absent when nothing was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// How many octets were written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub octets: Option<usize>,
    /// The parameters that changed, as the plan listed them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<ParameterChange>>,
    /// Why nothing was written, or why it did not verify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What was not compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The parameters the device still holds differently from the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub differences: Option<Vec<ParamChange>>,
}

impl ParametersWritten {
    /// Nothing written, because `reason`.
    pub fn not_written(reason: impl Into<String>) -> ParametersWritten {
        ParametersWritten {
            reason: Some(reason.into()),
            ..ParametersWritten::default()
        }
    }

    /// Written but not verified, because `reason`.
    pub fn failed(reason: impl Into<Option<String>>) -> ParametersWritten {
        ParametersWritten {
            verified: Some(false),
            reason: reason.into(),
            ..ParametersWritten::default()
        }
    }
}

/// How long the device took to answer after the restart that ends a
/// write.
#[derive(Debug, Clone, Serialize)]
pub struct Restarted {
    /// Milliseconds until it answered again.
    pub answered_after_ms: u64,
}

/// The application load of a `method: flash` write (issue #750).
#[derive(Debug, Clone, Serialize)]
pub struct LoadApplication {
    /// Why it had to be loaded.
    pub why: String,
    /// The application loaded.
    pub application: String,
    /// Whether it is loaded and verified.
    pub loaded: bool,
}

/// The outcome of one device write (see the module docs). Every field but
/// the address and the verdict is there only when the write has it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WriteOutcome {
    /// `apply` (tables and parameters), `flash` (the full download) or
    /// `restart`; absent for a parameter restore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The device.
    pub address: String,
    /// The resolved gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Whether the write ran under KNX Data Secure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secured: Option<bool>,
    /// The verdict.
    #[serde(flatten)]
    pub verdict: Verdict,
    /// Whether anything was written (the table write after a download, when
    /// it was not needed or could not run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
    /// What else the write says (why it was not needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The write's own failure when a read-back failure became `reason`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_reason: Option<String>,
    /// The table write's full report when it did not verify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The table backup taken before the write (`knx_restore_tables` reads
    /// it back).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    /// The parameter backup taken before the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_backup: Option<String>,
    /// Why no parameter backup was taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_backup_note: Option<String>,
    /// The parameter backup a restore wrote back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restored_from: Option<String>,
    /// The audit snapshot recorded before the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// The group addresses declared in `groups.toml` before the write
    /// (issue #779), one sentence each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub declared: Vec<String>,
    /// What the security object received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_object: Option<SecurityObject>,
    /// The address table's final load state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_state: Option<String>,
    /// The association table's final load state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub association_state: Option<String>,
    /// The address table's entry count after the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resulting_address_count: Option<usize>,
    /// The association table's entry count after the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resulting_association_count: Option<usize>,
    /// The group-object table reload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_object_table: Option<ObjectTableWritten>,
    /// The parameter memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ParametersWritten>,
    /// The restart that ended the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restarted: Option<Restarted>,
    /// The independent read-back after the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback: Option<WriteReadback>,
    /// Whether the PID 54 table was recorded in the lock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_senders_recorded: Option<bool>,
    /// Why it was not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_senders_note: Option<String>,
    /// Whether the PID 61 flags were recorded in the lock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_flags_recorded: Option<bool>,
    /// Why they were not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_flags_note: Option<String>,
    /// The application load (issue #750).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_application: Option<LoadApplication>,
    /// A property-only load procedure ran (issue #390).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_procedure: Option<bool>,
    /// The application's load state after a download.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_state: Option<String>,
    /// The application downloaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// The download's warnings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    /// The table write after a download that writes no link table (issue
    /// #779).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Box<WriteOutcome>>,
    /// The checked source address an interface write spoke from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// An interface write's property writes, as they go on the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_writes: Option<Vec<String>>,
    /// How many of an interface write's property writes the device
    /// confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties_written: Option<usize>,
    /// The restart form: `confirmed` or `basic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    /// Why that form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_reason: Option<String>,
    /// The device confirmed the restart (`A_Restart_Response`, error code 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<bool>,
    /// The process time the device reported, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_time_s: Option<u64>,
    /// The mask the device reported before and after the restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    /// Milliseconds until the device answered again after the restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_after_ms: Option<u64>,
    /// How the write passed the support gate (issue #1089): `supported`,
    /// `unsupported` (a loopback gateway) or `forced`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<crate::support::SupportStatus>,
}

impl WriteOutcome {
    /// An outcome about `address` with nothing filled in yet.
    pub fn new(address: impl ToString) -> WriteOutcome {
        WriteOutcome {
            address: address.to_string(),
            ..WriteOutcome::default()
        }
    }

    /// Ends the outcome as failed: `ok` and `verified` false, `reason`.
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.verdict.ok = false;
        self.verdict.verified = false;
        self.verdict.reason = Some(reason.into());
    }

    /// Ends the outcome as verified.
    pub fn verify(&mut self) {
        self.verdict.ok = true;
        self.verdict.verified = true;
    }

    /// Records the lock records of a verified secured write.
    pub fn record(&mut self, record: &LockRecord) {
        let pick = |recorded: &Option<(Result<bool, String>, usize)>| match recorded {
            Some((Ok(recorded), _)) => (Some(*recorded), None),
            Some((Err(err), _)) => {
                tracing::warn!("{err}");
                (Some(false), Some(err.clone()))
            }
            None => (None, None),
        };
        let (recorded, note) = pick(&record.senders);
        if recorded.is_some() {
            self.secure_senders_recorded = recorded;
            self.secure_senders_note = note;
        }
        let (recorded, note) = pick(&record.flags);
        if recorded.is_some() {
            self.security_flags_recorded = recorded;
            self.security_flags_note = note;
        }
    }

    /// The head the summary is derived from.
    pub fn head(&self) -> OutcomeHead {
        OutcomeHead {
            verdict: self.verdict.clone(),
            method: self.method.clone(),
            address: Some(self.address.clone()),
            line: None,
            noop: false,
            backup: self.backup.clone(),
            declared: self.declared.clone(),
            confirmed: self.confirmed,
        }
    }
}

impl Report for WriteOutcome {
    /// `bussard restart <ADDRESS> --json` prints this shape.
    const SCHEMA: u32 = 2;

    fn summary(&self, model: &Model) -> Option<String> {
        Some(self.head().summary(model))
    }
}
