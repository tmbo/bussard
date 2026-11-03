//! Entering device certificates into the key store (issue #728, part of
//! #201): the one path every surface calls, `bussard keys add-certificate`,
//! the phone enrolment session (#729) and the MCP tools (#732).
//!
//! A certificate is the 36-character label of a KNX Secure device (serial
//! number, factory default setup key, check; see
//! [`bussard_secure::certificate`] and `dev/enroll-protocol.md`). Its serial
//! number selects the device, so labels can be entered in any order:
//!
//! - a device in the key store with that serial takes the FDSK (`stored`);
//! - so does a device whose `bussard.lock` entry records that serial (issue
//!   #752): `adopt`, `assign`, `scan` and `describe` record the serial a device
//!   reports ([`record_serials`]), so a device ETS never saw is matched too;
//! - without one the FDSK is kept under the serial (`unassigned`) until a
//!   device reports it ([`attach_serials`], called by `adopt`, `assign`, `scan`
//!   and `describe`) or an ETS keyring import brings a device with that serial;
//! - the same FDSK again changes nothing (`already_stored`);
//! - another FDSK for the serial is never overwritten (`conflict`).
//!
//! `stored` and `unassigned` mean written and read back: the store is saved
//! and loaded again, and the FDSK compared, before the outcome says so.
//!
//! # Key hygiene
//!
//! [`EnrolOutcome`] is serializable and carries the serial, the address, the
//! device name and a message, never a key. No message quotes the label text.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_model::{IndividualAddress, SerialRecord};
use bussard_project::keystore::{
    AttachOutcome, FdskEnrolment, KeyStore, KeyStoreError, SerialNumber,
};
use bussard_secure::{Certificate, Key16, Password};
use serde::{Deserialize, Serialize};

/// The status of one entered certificate (the `status` of the enrolment
/// protocol's `result` message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrolStatus {
    /// Matched to a device by its serial number and saved.
    Stored,
    /// Saved under its serial number; no device in the key store has it yet.
    Unassigned,
    /// The key store already holds this FDSK for the serial number.
    AlreadyStored,
    /// The key store holds another FDSK for the serial number; nothing was
    /// written.
    Conflict,
    /// Not a certificate: its format or check failed.
    Invalid,
    /// The key store could not be written or read back; `message` says why.
    Error,
}

/// What became of one entered certificate. Serializable for the CLI's
/// `--json`, the enrolment session and the MCP tools; it never carries a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolOutcome {
    /// The status.
    pub status: EnrolStatus,
    /// The certificate's serial number, twelve hex digits (absent when the
    /// text did not decode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// The individual address of the device the serial number matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ia: Option<String>,
    /// That device's name in the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the label's check matched (CRC-4/ITU, not yet confirmed on a
    /// real label); absent when the text did not decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_ok: Option<bool>,
    /// A sentence for the user, when there is more to say than the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl EnrolOutcome {
    /// An outcome with only a status and a message.
    fn bare(status: EnrolStatus, message: String) -> Self {
        EnrolOutcome {
            status,
            serial: None,
            ia: None,
            name: None,
            check_ok: None,
            message: Some(message),
        }
    }
}

/// Why an enrolment could not start. No variant carries a key.
#[derive(Debug, thiserror::Error)]
pub enum EnrolError {
    /// The key store did not load (a wrong password surfaces here).
    #[error("loading the key store {}: {source}", path.display())]
    Load {
        /// The store file.
        path: PathBuf,
        /// The underlying error.
        source: KeyStoreError,
    },
    /// The model directory cannot be written, so the store could not be
    /// saved.
    #[error("the key store {} cannot be written: {source}", path.display())]
    NotWritable {
        /// The store file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The key store could not be saved or read back.
    #[error("writing the key store {}: {source}", path.display())]
    Save {
        /// The store file.
        path: PathBuf,
        /// The underlying error.
        source: KeyStoreError,
    },
}

/// An open enrolment: the key store of a model directory, loaded once, and
/// the model's device names. Each certificate is saved as it is entered.
pub struct CertificateEnrolment {
    /// The model directory.
    dir: PathBuf,
    /// The key store password.
    password: Password,
    /// The loaded (or new) store.
    store: KeyStore,
    /// The model's device names by address.
    names: BTreeMap<IndividualAddress, String>,
    /// The serial numbers `bussard.lock` records, and their device (#752).
    lock_serials: BTreeMap<SerialNumber, IndividualAddress>,
}

impl std::fmt::Debug for CertificateEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateEnrolment")
            .field("dir", &self.dir)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl CertificateEnrolment {
    /// Opens the key store of the model in `dir` with `password` (creating
    /// an empty one in memory when there is none) and checks that it can be
    /// written, before any certificate is read.
    ///
    /// # Errors
    ///
    /// The store does not load (wrong password, tampered or malformed), or
    /// the directory cannot be written.
    pub fn open(dir: &Path, password: &str) -> Result<Self, EnrolError> {
        let path = KeyStore::path(dir);
        let model = bussard_model::Model::load(dir).ok();
        let store = match KeyStore::load(dir, password) {
            Ok(Some(store)) => store,
            Ok(None) => {
                let project = model
                    .as_ref()
                    .and_then(|m| m.groups.project.clone())
                    .unwrap_or_default();
                KeyStore::new(&project)
            }
            Err(source) => return Err(EnrolError::Load { path, source }),
        };
        probe_writable(dir).map_err(|source| EnrolError::NotWritable {
            path: path.clone(),
            source,
        })?;
        let lock_serials = model
            .as_ref()
            .map(|m| {
                m.devices
                    .iter()
                    .filter_map(|(ia, d)| {
                        let text = d.device.lock.serial_number.as_deref()?;
                        text.parse::<SerialNumber>().ok().map(|s| (s, *ia))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let names = model
            .map(|m| {
                m.devices
                    .iter()
                    .map(|(ia, d)| (*ia, d.device.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(CertificateEnrolment {
            dir: dir.to_path_buf(),
            password: Password::new(password),
            store,
            names,
            lock_serials,
        })
    }

    /// The key store as it stands (for a summary after the session).
    pub fn store(&self) -> &KeyStore {
        &self.store
    }

    /// Enters one certificate: decodes `text`, matches its serial number,
    /// stores the FDSK and reads it back (see the module docs).
    ///
    /// The serial number selects a device in the key store first, then a
    /// device whose lock entry records it (#752); a certificate matched by
    /// the lock also records the serial for that device in the key store.
    ///
    /// A label whose check does not match is entered only when its serial
    /// number matches a device (the check variant is not yet confirmed on a
    /// real label, #201); otherwise it is `invalid`, so a mistyped label does
    /// not become an unassigned key.
    pub fn enroll_certificate(&mut self, text: &str) -> EnrolOutcome {
        let certificate = match Certificate::decode(text) {
            Ok(c) => c,
            Err(err) => return EnrolOutcome::bare(EnrolStatus::Invalid, err.to_string()),
        };
        let serial = SerialNumber(certificate.serial);
        let in_store = self.store.device_with_serial(serial);
        let in_lock = match in_store {
            Some(_) => None,
            None => self.lock_serials.get(&serial).copied(),
        };
        let matched = in_store.or(in_lock);
        let mut outcome = EnrolOutcome {
            status: EnrolStatus::Invalid,
            serial: Some(serial.to_string()),
            ia: matched.map(|ia| ia.to_string()),
            name: matched.and_then(|ia| self.names.get(&ia).cloned()),
            check_ok: Some(certificate.check_ok),
            message: None,
        };
        if !certificate.check_ok {
            if matched.is_none() {
                outcome.message = Some(
                    "the label's check does not match and no device has its serial number; \
                     re-check the text (nothing was written)"
                        .to_string(),
                );
                return outcome;
            }
            outcome.message = Some(
                "the label's check does not match (CRC-4/ITU, not yet confirmed on a real \
                 label); entered because the serial number matched"
                    .to_string(),
            );
        }
        let fdsk = certificate.fdsk.clone();
        // A device only the lock knows by this serial: the store learns the
        // serial for it, and a certificate entered earlier moves to it.
        let mut moved = false;
        let mut claimed = None;
        if let Some(ia) = in_lock {
            let held = self.store.devices.get(&ia);
            if held.and_then(|d| d.serial).is_some_and(|s| s != serial) {
                outcome.status = EnrolStatus::Conflict;
                outcome.message = Some(format!(
                    "{ia} reported this serial number, but the key store names another one for \
                     it; nothing was written (see `bussard keys show`)"
                ));
                return outcome;
            }
            if self.store.unassigned.contains_key(&serial) {
                match self.store.attach_serial(ia, serial) {
                    AttachOutcome::Attached => moved = true,
                    AttachOutcome::NothingPending => {}
                    AttachOutcome::Conflict => {
                        outcome.status = EnrolStatus::Conflict;
                        outcome.message = Some(format!(
                            "the key store holds another factory key for {ia}; nothing was \
                             written"
                        ));
                        return outcome;
                    }
                }
            } else {
                claimed = Some((ia, held.is_none()));
                self.store.devices.entry(ia).or_default().serial = Some(serial);
            }
        }
        let result = self.store.enrol_fdsk(serial, certificate.fdsk);
        if !result.changed()
            && let Some((ia, created)) = claimed
        {
            // Nothing is written: the in-memory store goes back as it was.
            if created {
                self.store.devices.remove(&ia);
            } else if let Some(device) = self.store.devices.get_mut(&ia) {
                device.serial = None;
            }
        }
        outcome.status = match result {
            FdskEnrolment::Stored(_) => EnrolStatus::Stored,
            FdskEnrolment::Unassigned => EnrolStatus::Unassigned,
            FdskEnrolment::AlreadyStored(_) => EnrolStatus::AlreadyStored,
            FdskEnrolment::Conflict(_) => {
                outcome.message = Some(
                    "the key store holds another factory key for this serial number; nothing \
                     was written"
                        .to_string(),
                );
                EnrolStatus::Conflict
            }
        };
        if (result.changed() || moved)
            && let Err(err) = self.save_and_verify(serial, &fdsk)
        {
            outcome.status = EnrolStatus::Error;
            outcome.message = Some(err.to_string());
        }
        outcome
    }

    /// Saves the store and reads it back: the FDSK for `serial` must be
    /// `fdsk`. On failure the in-memory store is reloaded from disk.
    fn save_and_verify(&mut self, serial: SerialNumber, fdsk: &Key16) -> Result<(), EnrolError> {
        let path = KeyStore::path(&self.dir);
        let saved = self
            .store
            .save(&self.dir, self.password.expose())
            .map_err(|source| EnrolError::Save {
                path: path.clone(),
                source,
            })
            .and_then(|_| read_back(&self.dir, self.password.expose(), serial, fdsk));
        if saved.is_err()
            && let Ok(Some(on_disk)) = KeyStore::load(&self.dir, self.password.expose())
        {
            self.store = on_disk;
        }
        saved
    }
}

/// Loads the store in `dir` again and checks it holds `fdsk` for `serial`.
fn read_back(
    dir: &Path,
    password: &str,
    serial: SerialNumber,
    fdsk: &Key16,
) -> Result<(), EnrolError> {
    let path = KeyStore::path(dir);
    let back = KeyStore::load(dir, password).map_err(|source| EnrolError::Save {
        path: path.clone(),
        source,
    })?;
    if back.as_ref().and_then(|s| s.fdsk_for_serial(serial)) == Some(fdsk) {
        return Ok(());
    }
    Err(EnrolError::Save {
        path,
        source: KeyStoreError::Io {
            action: "reading back",
            path: KeyStore::path(dir),
            source: std::io::Error::other(format!(
                "the store does not hold the factory key of {serial} after the write"
            )),
        },
    })
}

/// Checks that a file can be created in `dir`, where the store is written.
fn probe_writable(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(".bussard.keys.probe");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)?;
    std::fs::remove_file(&probe)
}

/// Enters one certificate into the key store of the model in `dir`: opens
/// the store, then [`CertificateEnrolment::enroll_certificate`]. Callers
/// that enter several labels keep one [`CertificateEnrolment`] instead.
///
/// # Errors
///
/// The store does not load or the directory cannot be written; a label that
/// is not a certificate is an [`EnrolStatus::Invalid`] outcome, not an error.
pub fn enroll_certificate(
    dir: &Path,
    password: &str,
    text: &str,
) -> Result<EnrolOutcome, EnrolError> {
    Ok(CertificateEnrolment::open(dir, password)?.enroll_certificate(text))
}

/// Records that the device at `ia` reported serial number `serial` (after
/// `bussard assign`) and moves an unassigned certificate's FDSK for that
/// serial to it, saving the store. Does nothing, and writes nothing, when
/// there is no store or it holds no unassigned key for the serial.
///
/// # Errors
///
/// The store does not load, or the write or its read-back fails.
pub fn attach_serial(
    dir: &Path,
    password: &str,
    ia: IndividualAddress,
    serial: SerialNumber,
) -> Result<AttachOutcome, EnrolError> {
    let path = KeyStore::path(dir);
    let Some(mut store) = KeyStore::load(dir, password).map_err(|source| EnrolError::Load {
        path: path.clone(),
        source,
    })?
    else {
        return Ok(AttachOutcome::NothingPending);
    };
    let Some(fdsk) = store.unassigned.get(&serial).cloned() else {
        return Ok(AttachOutcome::NothingPending);
    };
    let outcome = store.attach_serial(ia, serial);
    if outcome == AttachOutcome::Attached {
        store
            .save(dir, password)
            .map_err(|source| EnrolError::Save { path, source })?;
        read_back(dir, password, serial, &fdsk)?;
    }
    Ok(outcome)
}

/// Moves the unassigned certificates whose serial a device reported to that
/// device, after `adopt`, `assign`, `scan` or `describe` read it (#752). The
/// store is loaded and saved once, and only when it holds an unassigned key
/// for one of `serials`; returns the outcome per device that had one.
///
/// # Errors
///
/// The store does not load, or the write or its read-back fails.
pub fn attach_serials(
    dir: &Path,
    password: &str,
    serials: &[(IndividualAddress, SerialNumber)],
) -> Result<Vec<(IndividualAddress, SerialNumber, AttachOutcome)>, EnrolError> {
    let path = KeyStore::path(dir);
    let Some(mut store) = KeyStore::load(dir, password).map_err(|source| EnrolError::Load {
        path: path.clone(),
        source,
    })?
    else {
        return Ok(Vec::new());
    };
    let mut outcomes = Vec::new();
    let mut attached = Vec::new();
    for (ia, serial) in serials {
        let Some(fdsk) = store.unassigned.get(serial).cloned() else {
            continue;
        };
        let outcome = store.attach_serial(*ia, *serial);
        if outcome == AttachOutcome::Attached {
            attached.push((*serial, fdsk));
        }
        outcomes.push((*ia, *serial, outcome));
    }
    if !attached.is_empty() {
        store
            .save(dir, password)
            .map_err(|source| EnrolError::Save { path, source })?;
        for (serial, fdsk) in &attached {
            read_back(dir, password, *serial, fdsk)?;
        }
    }
    Ok(outcomes)
}

/// Why [`record_serials`] could not update the lock.
#[derive(Debug, thiserror::Error)]
pub enum RecordSerialsError {
    /// The model did not load.
    #[error("loading the model to record serial numbers: {0}")]
    Load(#[from] bussard_model::LoadError),
    /// The model did not save.
    #[error("saving serial numbers to bussard.lock: {0}")]
    Save(#[from] bussard_model::SaveError),
}

/// Records the serial number each device reported in its `bussard.lock`
/// entry (#752), for `scan` and `describe`, which read it anyway. A device
/// the model does not hold is skipped. The model is saved once, and only when
/// a serial changed; returns the record per device.
///
/// # Errors
///
/// The model does not load or save.
pub fn record_serials(
    dir: &Path,
    serials: &[(IndividualAddress, SerialNumber)],
) -> Result<Vec<(IndividualAddress, SerialRecord)>, RecordSerialsError> {
    let mut model = bussard_model::Model::load(dir)?;
    let records: Vec<(IndividualAddress, SerialRecord)> = serials
        .iter()
        .map(|(ia, serial)| (*ia, model.record_serial(*ia, &serial.0)))
        .collect();
    if records.iter().any(|(_, r)| r.changed()) {
        model.save(dir)?;
    }
    Ok(records)
}

/// The secure-capable devices of `model` the store holds no factory key for,
/// ascending: the labels still to enter.
pub fn devices_without_fdsk(
    model: &bussard_model::Model,
    store: &KeyStore,
) -> Vec<IndividualAddress> {
    model
        .devices
        .iter()
        .filter(|(_, d)| d.device.security.as_ref().is_some_and(|s| s.secure_capable))
        .filter(|(ia, _)| store.devices.get(ia).is_none_or(|d| d.fdsk.is_none()))
        .map(|(ia, _)| *ia)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A synthetic password, never a real one.
    const PASSWORD: &str = "synthetic-enrol-pw";

    /// Synthetic serial and FDSK.
    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];

    fn temp_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-enrol-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn label(serial: [u8; 6], fill: u8) -> String {
        Certificate::encode(&serial, &Key16::new([fill; 16]))
    }

    #[test]
    fn test_enroll_certificate_matches_a_device_by_serial() -> TestResult {
        let dir = temp_dir("match")?;
        let mut store = KeyStore::new("synthetic");
        store.devices.entry("1.1.12".parse()?).or_default().serial = Some(SerialNumber(SERIAL));
        store.save(&dir, PASSWORD)?;
        let outcome = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0xA5))?;
        assert_eq!(outcome.status, EnrolStatus::Stored);
        assert_eq!(outcome.ia.as_deref(), Some("1.1.12"));
        assert_eq!(outcome.serial.as_deref(), Some("00FA01020304"));
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert_eq!(
            back.fdsk_for_serial(SerialNumber(SERIAL)),
            Some(&Key16::new([0xA5; 16]))
        );
        let again = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0xA5))?;
        assert_eq!(again.status, EnrolStatus::AlreadyStored);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_enroll_certificate_unassigned_then_conflict() -> TestResult {
        let dir = temp_dir("unassigned")?;
        let mut session = CertificateEnrolment::open(&dir, PASSWORD)?;
        let outcome = session.enroll_certificate(&label(SERIAL, 0x11));
        assert_eq!(outcome.status, EnrolStatus::Unassigned);
        assert!(outcome.ia.is_none());
        let conflict = session.enroll_certificate(&label(SERIAL, 0x22));
        assert_eq!(conflict.status, EnrolStatus::Conflict);
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert_eq!(
            back.unassigned.get(&SerialNumber(SERIAL)),
            Some(&Key16::new([0x11; 16]))
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_enroll_certificate_invalid_and_bad_check() -> TestResult {
        let dir = temp_dir("invalid")?;
        let mut session = CertificateEnrolment::open(&dir, PASSWORD)?;
        let outcome = session.enroll_certificate("ABC");
        assert_eq!(outcome.status, EnrolStatus::Invalid);
        assert!(outcome.serial.is_none());
        // The bad_check vector: no device has its serial, so nothing is kept.
        let bad = session.enroll_certificate("AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2X4");
        assert_eq!(bad.status, EnrolStatus::Invalid);
        assert_eq!(bad.check_ok, Some(false));
        assert!(session.store().unassigned.is_empty());
        assert!(!KeyStore::path(&dir).exists());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_enrol_outcome_serializes_without_the_key() -> TestResult {
        let dir = temp_dir("json")?;
        let outcome = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0xC3))?;
        let json = serde_json::to_string(&outcome)?;
        assert!(json.contains("\"status\":\"unassigned\""));
        assert!(!json.to_ascii_uppercase().contains("C3C3"));
        assert!(!json.contains(&label(SERIAL, 0xC3)));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_attach_serial_after_unassigned() -> TestResult {
        let dir = temp_dir("attach")?;
        enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x5A))?;
        let ia: IndividualAddress = "1.1.40".parse()?;
        assert_eq!(
            attach_serial(&dir, PASSWORD, ia, SerialNumber([0, 0xFA, 9, 9, 9, 9]))?,
            AttachOutcome::NothingPending
        );
        assert_eq!(
            attach_serial(&dir, PASSWORD, ia, SerialNumber(SERIAL))?,
            AttachOutcome::Attached
        );
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert!(back.unassigned.is_empty());
        assert_eq!(back.device_with_serial(SerialNumber(SERIAL)), Some(ia));
        // A later label for the same serial now matches the device.
        let again = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x5A))?;
        assert_eq!(again.status, EnrolStatus::AlreadyStored);
        assert_eq!(again.ia.as_deref(), Some("1.1.40"));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// A model in `dir` with one device at `ia` whose lock records `serial`.
    fn model_with_serial(dir: &Path, ia: &str, serial: [u8; 6]) -> TestResult {
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(
            dir.join("devices").join(format!("{ia}.toml")),
            format!("address = \"{ia}\"\nname = \"Synthetic actuator\"\n"),
        )?;
        let mut model = bussard_model::Model::load(dir)?;
        assert!(model.record_serial(ia.parse()?, &serial).changed());
        model.save(dir)?;
        Ok(())
    }

    #[test]
    fn test_enroll_certificate_matches_a_lock_serial() -> TestResult {
        let dir = temp_dir("lock")?;
        model_with_serial(&dir, "1.1.40", SERIAL)?;
        let mut session = CertificateEnrolment::open(&dir, PASSWORD)?;
        let outcome = session.enroll_certificate(&label(SERIAL, 0x3C));
        assert_eq!(outcome.status, EnrolStatus::Stored);
        assert_eq!(outcome.ia.as_deref(), Some("1.1.40"));
        assert_eq!(outcome.name.as_deref(), Some("Synthetic actuator"));
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert_eq!(
            back.device_with_serial(SerialNumber(SERIAL)),
            Some("1.1.40".parse()?)
        );
        assert!(back.unassigned.is_empty());
        let again = session.enroll_certificate(&label(SERIAL, 0x3C));
        assert_eq!(again.status, EnrolStatus::AlreadyStored);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_enroll_certificate_lock_serial_moves_an_unassigned_key() -> TestResult {
        let dir = temp_dir("lock-move")?;
        // Entered before any device reported the serial: unassigned.
        let first = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x4D))?;
        assert_eq!(first.status, EnrolStatus::Unassigned);
        // Then the lock learns it (scan, describe) and the label is entered again.
        model_with_serial(&dir, "1.1.41", SERIAL)?;
        let again = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x4D))?;
        assert_eq!(again.status, EnrolStatus::AlreadyStored);
        assert_eq!(again.ia.as_deref(), Some("1.1.41"));
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert!(back.unassigned.is_empty());
        assert_eq!(
            back.device_with_serial(SerialNumber(SERIAL)),
            Some("1.1.41".parse()?)
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_enroll_certificate_lock_serial_conflicts_with_the_store() -> TestResult {
        let dir = temp_dir("lock-conflict")?;
        model_with_serial(&dir, "1.1.42", SERIAL)?;
        let mut store = KeyStore::new("synthetic");
        store.devices.entry("1.1.42".parse()?).or_default().serial =
            Some(SerialNumber([0, 0xFA, 7, 7, 7, 7]));
        store.save(&dir, PASSWORD)?;
        let outcome = enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x6E))?;
        assert_eq!(outcome.status, EnrolStatus::Conflict);
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert!(back.fdsk_for_serial(SerialNumber(SERIAL)).is_none());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_record_serials_then_attach_serials() -> TestResult {
        let dir = temp_dir("record")?;
        model_with_serial(&dir, "1.1.43", [0, 0xFA, 1, 1, 1, 1])?;
        enroll_certificate(&dir, PASSWORD, &label(SERIAL, 0x7F))?;
        let ia: IndividualAddress = "1.1.43".parse()?;
        let unknown: IndividualAddress = "1.1.99".parse()?;
        let records = record_serials(
            &dir,
            &[(ia, SerialNumber(SERIAL)), (unknown, SerialNumber(SERIAL))],
        )?;
        assert!(records[0].1.changed());
        assert_eq!(records[1].1, SerialRecord::NotModelled);
        let model = bussard_model::Model::load(&dir)?;
        assert_eq!(model.device_with_serial(&SERIAL), Some(ia));
        let outcomes = attach_serials(&dir, PASSWORD, &[(ia, SerialNumber(SERIAL))])?;
        assert_eq!(
            outcomes,
            vec![(ia, SerialNumber(SERIAL), AttachOutcome::Attached)]
        );
        assert!(attach_serials(&dir, PASSWORD, &[(ia, SerialNumber(SERIAL))])?.is_empty());
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert_eq!(back.device_with_serial(SerialNumber(SERIAL)), Some(ia));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_open_wrong_password_refused() -> TestResult {
        let dir = temp_dir("password")?;
        KeyStore::new("synthetic").save(&dir, PASSWORD)?;
        let err = CertificateEnrolment::open(&dir, "another-synthetic-pw")
            .err()
            .ok_or("opened with the wrong password")?;
        assert!(matches!(err, EnrolError::Load { .. }));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
