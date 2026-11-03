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
//! - without one the FDSK is kept under the serial (`unassigned`) until a
//!   device reports it ([`attach_serial`], called by `bussard assign`) or an
//!   ETS keyring import brings a device with that serial;
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

use bussard_model::IndividualAddress;
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
        })
    }

    /// The key store as it stands (for a summary after the session).
    pub fn store(&self) -> &KeyStore {
        &self.store
    }

    /// Enters one certificate: decodes `text`, matches its serial number,
    /// stores the FDSK and reads it back (see the module docs).
    ///
    /// A label whose check does not match is entered only when its serial
    /// number matches a device in the store (the check variant is not yet
    /// confirmed on a real label, #201); otherwise it is `invalid`, so a
    /// mistyped label does not become an unassigned key.
    pub fn enroll_certificate(&mut self, text: &str) -> EnrolOutcome {
        let certificate = match Certificate::decode(text) {
            Ok(c) => c,
            Err(err) => return EnrolOutcome::bare(EnrolStatus::Invalid, err.to_string()),
        };
        let serial = SerialNumber(certificate.serial);
        let matched = self.store.device_with_serial(serial);
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
        let result = self.store.enrol_fdsk(serial, certificate.fdsk);
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
        if result.changed()
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
