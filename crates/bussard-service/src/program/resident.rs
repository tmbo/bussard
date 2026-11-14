//! `flash --dry-run --resident FILE`: plan offline against a recorded device
//! state (issue #490).
//!
//! A live flash shapes its plan with what the read-only pre-flight finds on
//! the device: the load state and `PID_PROGRAM_VERSION` of the application
//! objects decide the freshness verdict, which picks the factory reset or the
//! product's `par` load procedure, and the `PID_MCB_TABLE` of the object ETS
//! keeps (the group-object table, issue #1127) decides whether the executor
//! leaves its re-load out. A dry run has no device, so the offline
//! oracle (`scripts/campaign/95-offline-oracle.sh`) records what the device
//! answered ETS before the download (`knxtrace image` writes it as
//! `resident.json`) and hands it here. The plan then takes the shape the live
//! flash would take on that device; the planner, the freshness verdict, the
//! `par` procedure and the keep rule are the ones the live flash runs.
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
//! `PID_MCB_TABLE` entries ETS read per object, from entry 1 (8 octets
//! each). Every field is optional.
//!
//! On a System 7 plan `objects` are the load-state machines instead (`index`
//! the LSM, 1 to 4): a record with every LSM `Unloaded` is a factory-fresh
//! device. The record shapes the freshness verdict only; the System 7
//! pre-download pass follows `--full` alone (issue #488).

use std::collections::BTreeMap;
use std::path::Path;

use super::Ctx;
use crate::ServiceError;
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
    /// The `PID_MCB_TABLE` entries per object index, from entry 1, hex.
    #[serde(default)]
    mcb: BTreeMap<String, String>,
}

/// A recorded device state, read from a `--resident` file.
#[derive(Debug, Default)]
pub struct Recorded {
    /// The state the pre-flight probe would have read.
    pub state: ResidentState,
    /// The `PID_MCB_TABLE` entries ETS read per object, from entry 1.
    mcbs: BTreeMap<u8, Vec<McbEntry>>,
}

/// Decodes a hex string: an odd length or a non-hex digit is an error.
fn hex(text: &str) -> Result<Vec<u8>, ServiceError> {
    bussard_model::text::from_hex(text.trim()).ctx(|| format!("hex {text:?}"))
}

impl Recorded {
    /// Reads a `--resident` file.
    pub fn read(path: &Path) -> Result<Recorded, ServiceError> {
        let text = std::fs::read_to_string(path)
            .ctx(|| format!("reading the recorded device state {}", path.display()))?;
        let recorded: RecordedState = serde_json::from_str(&text)
            .ctx(|| format!("parsing the recorded device state {}", path.display()))?;
        Recorded::from_state(recorded)
    }

    /// Builds the probe state and the MCB entries from the parsed file.
    fn from_state(recorded: RecordedState) -> Result<Recorded, ServiceError> {
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
                .ctx(|| format!("MCB object index {index:?}"))?;
            let entries: Vec<McbEntry> = hex(entry)?
                .as_chunks::<{ bussard_mgmt::MCB_ENTRY_LEN }>()
                .0
                .iter()
                .filter_map(|c| McbEntry::decode(c))
                .collect();
            if !entries.is_empty() {
                mcbs.insert(index, entries);
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

    /// The record read as System 7 load-state machines (issue #488): each
    /// recorded `index` is an LSM, with no interface-object type, as the
    /// System 7 pre-flight probe reports them. The MCB entries are System B
    /// only and dropped.
    pub fn into_sys7(mut self) -> Recorded {
        for object in &mut self.state.objects {
            object.object_type = None;
        }
        self.mcbs.clear();
        self
    }

    /// Whether the file recorded any object load state. Without one there
    /// is no freshness verdict, and the dry run plans as it does without a
    /// file.
    pub fn has_states(&self) -> bool {
        !self.state.objects.is_empty()
    }

    /// Drops the re-loads the executor's keep would leave out on this
    /// device ([`FlashPlan::skip_resident_matches`], the same rule): each
    /// object ETS keeps (the group-object table, where the product declares
    /// its MCB check) whose recorded MCB entries match its image. An object
    /// whose load state was not recorded counts as `Loaded`: ETS reads the
    /// MCB of the object it keeps and not its load state. Returns the kept
    /// objects.
    pub fn skip_matching(&self, plan: &mut FlashPlan) -> Vec<u8> {
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
        plan.skip_resident_matches(&self.mcbs, app_obj, state_of)
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_state_reads_objects_app_id_and_mcb() -> Result<(), Box<dyn std::error::Error>> {
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
        let entries = recorded.mcbs.get(&3).ok_or("object 3's MCB")?;
        assert_eq!(
            entries
                .iter()
                .map(|e| (e.segment_size, e.crc16))
                .collect::<Vec<_>>(),
            vec![(0x05F6, 0x0B93)]
        );
        assert!(recorded.has_states());
        Ok(())
    }

    /// Issue #488: on a System 7 plan the recorded objects are LSMs, so an
    /// all-Unloaded record reads as a probed fresh System 7 device.
    #[test]
    fn test_into_sys7_reads_the_objects_as_lsms() -> Result<(), Box<dyn std::error::Error>> {
        let recorded: RecordedState = serde_json::from_str(
            r#"{"objects": [{"index": 1, "state": 0}, {"index": 2, "state": 0},
                            {"index": 3, "state": 0}, {"index": 4, "state": 0}]}"#,
        )?;
        let recorded = Recorded::from_state(recorded)?.into_sys7();
        assert!(recorded.state.is_sys7());
        assert!(recorded.has_states());
        assert!(!recorded.state.has_loaded_application());
        Ok(())
    }

    #[test]
    fn test_from_state_without_objects_has_no_states() -> Result<(), Box<dyn std::error::Error>> {
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
