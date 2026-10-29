//! `flash --dry-run --resident FILE`: plan offline against a recorded device
//! state (issue #490).
//!
//! A live flash shapes its plan with what the read-only pre-flight finds on
//! the device: the load state and `PID_PROGRAM_VERSION` of the application
//! objects decide the freshness verdict, which picks the factory reset or the
//! product's `par` load procedure, and the objects' `PID_MCB_TABLE` decide
//! which re-loads the executor skips. A dry run has no device, so the offline
//! oracle (`scripts/campaign/95-offline-oracle.sh`) records what the device
//! answered ETS before the download (`knxtrace image` writes it as
//! `resident.json`) and hands it here. The plan then takes the shape the live
//! flash would take on that device; the planner, the freshness verdict, the
//! `par` procedure and the MCB match are the ones the live flash runs.
//!
//! The file is JSON:
//!
//! ```json
//! {"objects": [{"index": 4, "state": 1}, {"index": 5, "state": 0}],
//!  "app_id": "0004d14221",
//!  "mcb": {"3": "000005f600330b93"}}
//! ```
//!
//! `objects` are the application objects whose `PID_LOAD_STATE_CONTROL` was
//! read (the state octet, KNX 3/5/1 §4.2.4: 0 Unloaded, 1 Loaded), `app_id`
//! the hex `PID_PROGRAM_VERSION` of the application object, `mcb` the hex
//! first `PID_MCB_TABLE` entry per object. Every field is optional.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use bussard_download::{FlashPlan, ResidentObject, ResidentState};
use bussard_mgmt::LoadState;
use bussard_mgmt::load::McbEntry;
use serde::Deserialize;

/// The interface-object type the recorded objects are taken as: the
/// application program (KNX 3/5/1 §4.3), the objects whose load state the
/// pre-flight probe reads.
const OT_APPLICATION_PROGRAM: u16 = 3;

/// One recorded object load state.
#[derive(Debug, Deserialize)]
struct RecordedObject {
    /// The object index.
    index: u8,
    /// The `PID_LOAD_STATE_CONTROL` octet the device answered.
    state: u8,
}

/// The `--resident` file (module docs).
#[derive(Debug, Default, Deserialize)]
struct RecordedState {
    /// The application objects' load states.
    #[serde(default)]
    objects: Vec<RecordedObject>,
    /// The application object's `PID_PROGRAM_VERSION`, hex.
    #[serde(default)]
    app_id: Option<String>,
    /// The first `PID_MCB_TABLE` entry per object index, hex.
    #[serde(default)]
    mcb: BTreeMap<String, String>,
}

/// A recorded device state, read from a `--resident` file.
#[derive(Debug, Default)]
pub(crate) struct Recorded {
    /// The state the pre-flight probe would have read.
    pub(crate) state: ResidentState,
    /// The first MCB entry per object: segment size and CRC.
    mcbs: BTreeMap<u8, (u32, u16)>,
}

/// Decodes a hex string, ignoring nothing: an odd length or a non-hex digit
/// is an error.
fn hex(text: &str) -> anyhow::Result<Vec<u8>> {
    let text = text.trim();
    anyhow::ensure!(text.len().is_multiple_of(2), "odd-length hex {text:?}");
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(text.get(i..i + 2).unwrap_or_default(), 16)
                .with_context(|| format!("hex {text:?}"))
        })
        .collect()
}

impl Recorded {
    /// Reads a `--resident` file.
    pub(crate) fn read(path: &Path) -> anyhow::Result<Recorded> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the recorded device state {}", path.display()))?;
        let recorded: RecordedState = serde_json::from_str(&text)
            .with_context(|| format!("parsing the recorded device state {}", path.display()))?;
        Recorded::from_state(recorded)
    }

    /// Builds the probe state and the MCB entries from the parsed file.
    fn from_state(recorded: RecordedState) -> anyhow::Result<Recorded> {
        let objects = recorded
            .objects
            .iter()
            .map(|o| ResidentObject {
                index: o.index,
                object_type: Some(OT_APPLICATION_PROGRAM),
                state: LoadState::from_octet(o.state),
            })
            .collect::<Vec<_>>();
        let app_id = recorded
            .app_id
            .as_deref()
            .map(hex)
            .transpose()?
            .filter(|id| id.iter().any(|b| *b != 0));
        let mut mcbs = BTreeMap::new();
        for (index, entry) in &recorded.mcb {
            let index: u8 = index
                .parse()
                .with_context(|| format!("MCB object index {index:?}"))?;
            if let Some(entry) = McbEntry::decode(&hex(entry)?) {
                mcbs.insert(index, (entry.segment_size, entry.crc16));
            }
        }
        Ok(Recorded {
            state: ResidentState {
                objects,
                app_id,
                ..Default::default()
            },
            mcbs,
        })
    }

    /// Whether the file recorded any object load state. Without one there
    /// is no freshness verdict, and the dry run plans as it does without a
    /// file.
    pub(crate) fn has_states(&self) -> bool {
        !self.state.objects.is_empty()
    }

    /// Drops the re-loads the executor's resident-MCB skip would drop on
    /// this device ([`FlashPlan::skip_resident_matches`]). An object whose
    /// load state was not recorded counts as `Loaded` when its MCB was: ETS
    /// reads the MCB of the objects it keeps and not their load state, and
    /// the recorded MCB is the evidence the object holds that image.
    pub(crate) fn skip_matching(&self, plan: &mut FlashPlan) -> Vec<u8> {
        let app_obj = self
            .state
            .loaded_applications()
            .first()
            .map_or(0, |o| o.index);
        let state_of = |obj: u8| {
            self.state
                .objects
                .iter()
                .find(|o| o.index == obj)
                .map(|o| o.state)
        };
        plan.skip_resident_matches(&self.mcbs, app_obj, |obj| {
            state_of(obj).is_none_or(|s| s == LoadState::Loaded)
        })
        .into_iter()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_state_reads_objects_app_id_and_mcb() -> anyhow::Result<()> {
        let recorded: RecordedState = serde_json::from_str(
            r#"{"objects": [{"index": 4, "state": 1}, {"index": 5, "state": 0}],
                "app_id": "000420de22", "mcb": {"3": "000005f600330b93"}}"#,
        )?;
        let recorded = Recorded::from_state(recorded)?;
        assert_eq!(recorded.state.objects.len(), 2);
        assert_eq!(recorded.state.objects[0].state, LoadState::Loaded);
        assert_eq!(recorded.state.objects[1].state, LoadState::Unloaded);
        assert_eq!(
            recorded.state.app_id.as_deref(),
            Some(&[0x00, 0x04, 0x20, 0xDE, 0x22][..])
        );
        assert_eq!(recorded.mcbs.get(&3), Some(&(0x05F6, 0x0B93)));
        assert!(recorded.has_states());
        Ok(())
    }

    #[test]
    fn test_from_state_without_objects_has_no_states() -> anyhow::Result<()> {
        let recorded = Recorded::from_state(RecordedState {
            app_id: Some("0000000000".to_string()),
            ..Default::default()
        })?;
        assert!(!recorded.has_states());
        assert!(
            recorded.state.app_id.is_none(),
            "the zero placeholder is no id"
        );
        Ok(())
    }

    #[test]
    fn test_hex_rejects_odd_and_non_hex() {
        assert!(hex("abc").is_err());
        assert!(hex("zz").is_err());
        assert!(matches!(hex(" 0a0B ").as_deref(), Ok([0x0A, 0x0B])));
    }
}
