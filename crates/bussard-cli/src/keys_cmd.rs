//! `bussard keys`: the bussard-owned key store, `bussard.keys` next to
//! `bussard.lock` (issue #241).
//!
//! - `keys import <file.knxkeys>` merges an ETS keyring export into the store
//!   and reports what changed (new devices, rotated keys, group keys); a
//!   factory key is never dropped.
//! - `keys export <file.knxkeys>` writes a signed export ETS accepts.
//! - `keys show` prints a redaction-safe summary.
//! - `keys add-certificate` enters device certificates (FDSK labels) through
//!   [`bussard_service::enroll`] (issue #728).
//!
//! `import` and `init` also merge the one `.knxkeys` exported next to the
//! project into the store ([`import_neighbour`], issue #241 item 2).
//!
//! The store and every `.knxkeys` it touches use one password, read from
//! `BUSSARD_KEYRING_PASSWORD` (never a CLI argument). No key material is ever
//! printed: the output is addresses, counts and presence flags.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_project::keystore::{BackboneChange, ImportReport, KeyStore, SaveOutcome};
use bussard_service::files::keyring;
use bussard_service::setup;

/// The environment variable carrying the keyring (and key store) password.
const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// Reads the keyring password from the environment.
pub(crate) fn password() -> anyhow::Result<String> {
    // The one missing-password wording (issue #228).
    bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
        .map_err(|_| bussard_service::secure::SecureKeyError::MissingPassword.into())
}

/// After an import of `project` into `dir`: merges the one `.knxkeys` next to
/// the project into `bussard.keys` (issue #241 item 2,
/// [`bussard_service::setup::import::import_neighbour`]). Never fails the
/// import: a keyring that does not load is a warning.
pub fn import_neighbour(project: &Path, dir: &Path) {
    setup::import::import_neighbour(project, dir, &mut crate::console::Console);
}

/// W042 (issue #348): the group keys an import added for group addresses the
/// model in `dir` runs plain.
fn rekeyed_warnings(dir: &Path, report: &ImportReport) -> Vec<bussard_model::Diagnostic> {
    setup::import::rekeyed_warnings(dir, report)
}

/// Prints warnings as `warning[CODE]: message` on stderr.
pub(crate) fn print_warnings(diags: &[bussard_model::Diagnostic]) {
    setup::import::warn_diagnostics(diags, &mut crate::console::Console);
}

/// Merges `file` into the store in `dir` and saves it.
fn import_quiet(dir: &Path, file: &Path) -> anyhow::Result<(ImportReport, SaveOutcome)> {
    Ok(setup::import::import_keyring(dir, file)?)
}

/// Loads the store in `dir`, failing with a hint when there is none
/// ([`bussard_service::files::keyring::load_existing`]).
fn load_existing(dir: &Path, password: &str) -> anyhow::Result<KeyStore> {
    Ok(keyring::load_existing(dir, password)?)
}

/// Runs `bussard keys import <file>`.
pub fn run_import(dir: &Path, file: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let path = KeyStore::path(dir);
    let (report, outcome) = import_quiet(dir, file)?;
    let warnings = rekeyed_warnings(dir, &report);

    if json {
        let value = serde_json::json!({
            "store": path.display().to_string(),
            "source": file.display().to_string(),
            "written": matches!(outcome, SaveOutcome::Written { .. }),
            "backup": matches!(outcome, SaveOutcome::Written { backup: true }),
            "changed": report.changed(),
            "report": report,
            "warnings": warnings.iter().map(|d| serde_json::json!({
                "code": d.code,
                "location": d.location,
                "message": d.message,
            })).collect::<Vec<_>>(),
        });
        crate::output::print(crate::output::schema::KEYS_IMPORT, &value)?;
    } else {
        print_report(&path, file, &report, outcome);
        print_warnings(&warnings);
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the import report (addresses and counts, never a key).
fn print_report(store: &Path, file: &Path, r: &ImportReport, outcome: SaveOutcome) {
    println!(
        "imported {} into {} (project {:?})",
        file.display(),
        store.display(),
        r.project
    );
    if !r.changed() {
        println!("  nothing changed");
    }
    let list = |items: &[String]| {
        if items.is_empty() {
            String::new()
        } else {
            format!(" ({})", items.join(", "))
        }
    };
    let mut devices = Vec::new();
    if !r.devices_added.is_empty() {
        devices.push(format!(
            "{} added{}",
            r.devices_added.len(),
            list(&r.devices_added)
        ));
    }
    if !r.tool_keys_rotated.is_empty() {
        devices.push(format!(
            "{} tool key(s) rotated{}",
            r.tool_keys_rotated.len(),
            list(&r.tool_keys_rotated)
        ));
    }
    if !r.device_credentials_updated.is_empty() {
        devices.push(format!(
            "{} with new KNXnet/IP credentials{}",
            r.device_credentials_updated.len(),
            list(&r.device_credentials_updated)
        ));
    }
    if !r.ets_sequences_updated.is_empty() {
        devices.push(format!(
            "{} with a new ETS sequence number",
            r.ets_sequences_updated.len()
        ));
    }
    devices.push(format!("{} unchanged", r.devices_unchanged));
    if !r.devices_kept.is_empty() {
        devices.push(format!(
            "{} kept, not in the export{}",
            r.devices_kept.len(),
            list(&r.devices_kept)
        ));
    }
    println!("  devices: {}", devices.join(", "));

    let mut groups = Vec::new();
    if !r.group_keys_added.is_empty() {
        groups.push(format!("{} added", r.group_keys_added.len()));
    }
    if !r.group_keys_rotated.is_empty() {
        groups.push(format!(
            "{} rotated{}",
            r.group_keys_rotated.len(),
            list(&r.group_keys_rotated)
        ));
    }
    groups.push(format!("{} unchanged", r.group_keys_unchanged));
    if r.group_keys_kept > 0 {
        groups.push(format!("{} kept, not in the export", r.group_keys_kept));
    }
    println!("  group keys: {}", groups.join(", "));

    let mut interfaces = Vec::new();
    if !r.interfaces_added.is_empty() {
        interfaces.push(format!(
            "{} added{}",
            r.interfaces_added.len(),
            list(&r.interfaces_added)
        ));
    }
    if !r.interfaces_updated.is_empty() {
        interfaces.push(format!(
            "{} updated{}",
            r.interfaces_updated.len(),
            list(&r.interfaces_updated)
        ));
    }
    interfaces.push(format!("{} unchanged", r.interfaces_unchanged));
    println!("  interfaces: {}", interfaces.join(", "));

    let backbone = match r.backbone {
        BackboneChange::Absent => "none",
        BackboneChange::Added => "added",
        BackboneChange::Changed => "changed",
        BackboneChange::Unchanged => "unchanged",
    };
    println!("  backbone key: {backbone}");
    if r.fdsks_kept > 0 {
        println!("  factory keys (FDSK) kept: {}", r.fdsks_kept);
    }
    match outcome {
        SaveOutcome::Written { backup: true } => println!(
            "  previous store kept as {}",
            bussard_project::keystore::KEYSTORE_BACKUP_FILE
        ),
        SaveOutcome::Written { backup: false } => println!("  created the key store"),
        SaveOutcome::Unchanged => {}
    }
    println!("  (key material is never printed)");
}

/// Runs `bussard keys export <file>`
/// ([`bussard_service::files::keyring::export_keyring`]).
pub fn run_export(dir: &Path, file: &Path, force: bool, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    let export =
        keyring::export_keyring(dir, file, &password, force, &mut crate::console::Console)?;
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "devices": export.devices,
            "group_keys": export.group_keys,
            "interfaces": export.interfaces,
            "skipped_devices": export.skipped_devices,
            "verified": export.verified,
            "group_addresses": export.group_addresses,
            "omitted_group_addresses": export.omitted_group_addresses,
            "leftovers": export.leftovers,
        });
        crate::output::print(crate::output::schema::KEYS_EXPORT, &value)?;
    } else {
        println!(
            "wrote {}: {} device(s), {} group key(s), {} interface(s), signed with {KEYRING_PASSWORD_ENV}",
            file.display(),
            export.devices,
            export.group_keys,
            export.interfaces
        );
        if !export.skipped_devices.is_empty() {
            println!(
                "  left out (no tool key, ETS needs one): {}",
                export.skipped_devices.join(", ")
            );
        }
        println!(
            "  group addresses carried: {}",
            if export.group_addresses.is_empty() {
                "none".to_string()
            } else {
                export.group_addresses.join(", ")
            }
        );
        if !export.omitted_group_addresses.is_empty() {
            println!(
                "  group addresses omitted (secure in the model or the store, no key in the \
                 export): {}",
                export.omitted_group_addresses.join(", ")
            );
        }
        if export.verified {
            println!("  verified: read back, decrypted and compared with the key store");
        } else {
            for leftover in &export.leftovers {
                eprintln!("ERROR: {leftover}");
            }
        }
        println!("  keep it out of git: the model's .gitignore lists *.knxkeys");
    }
    if !export.verified {
        eprintln!(
            "ERROR: {} does not carry the key store's keys; do not hand it on",
            file.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard keys show`.
pub fn run_show(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    let store = load_existing(dir, &password)?;
    let s = store.summary();
    // Secure-capable devices of the model whose label is still to enter.
    let without_fdsk: Vec<String> = bussard_model::Model::load(dir)
        .map(|model| {
            bussard_service::enroll::devices_without_fdsk(&model, &store)
                .iter()
                .map(|ia| {
                    let name = model
                        .devices
                        .get(ia)
                        .map(|d| d.device.name.clone())
                        .unwrap_or_default();
                    if name.is_empty() {
                        ia.to_string()
                    } else {
                        format!("{ia} ({name})")
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if json {
        let mut value = serde_json::to_value(&s)?;
        if let Some(object) = value.as_object_mut() {
            let addresses: Vec<String> = without_fdsk
                .iter()
                .map(|d| d.split(' ').next().unwrap_or_default().to_string())
                .collect();
            object.insert("devices_without_fdsk".to_string(), addresses.into());
        }
        crate::output::print(crate::output::schema::KEYS_SHOW, &value)?;
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "key store {} for project {:?}, created {}",
        KeyStore::path(dir).display(),
        s.project,
        s.created
    );
    match &s.backbone_multicast {
        Some(addr) => println!("  backbone key: present ({addr})"),
        None => println!("  backbone key: none"),
    }
    println!("  devices ({}):", s.devices.len());
    for d in &s.devices {
        let mut parts = Vec::new();
        parts.push(if d.has_tool_key {
            "tool key"
        } else {
            "no tool key"
        });
        if d.has_fdsk {
            parts.push("FDSK");
        }
        if d.has_management_password {
            parts.push("management password");
        }
        if d.has_authentication {
            parts.push("authentication code");
        }
        let serial = d
            .serial
            .as_deref()
            .map(|s| format!(" serial {s}"))
            .unwrap_or_default();
        println!("    {}{serial}: {}", d.address, parts.join(", "));
    }
    println!("  interfaces ({}):", s.interfaces.len());
    for i in &s.interfaces {
        let host = i.host.as_deref().unwrap_or("?");
        let mut line = format!(
            "    {} {} user {} (host {host})",
            if i.interface_type.is_empty() {
                "interface"
            } else {
                i.interface_type.as_str()
            },
            i.address,
            i.user_id
        );
        if !i.has_password {
            line.push_str(", no password");
        }
        if !i.has_authentication {
            line.push_str(", no authentication code");
        }
        println!("{line}");
    }
    println!("  group keys: {}", s.group_key_count);
    if !s.unassigned_certificates.is_empty() {
        println!(
            "  certificates without a device (serial numbers): {}",
            s.unassigned_certificates.join(", ")
        );
    }
    if !without_fdsk.is_empty() {
        println!(
            "  secure-capable devices without a factory key (FDSK): {}",
            without_fdsk.join(", ")
        );
        println!("    enter their labels with `bussard keys add-certificate`");
    }
    println!("  (key material is never printed)");
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard keys add-certificate`: one label per line from the terminal
/// (without echo, an empty line ends) or, with `--stdin`, every line of
/// standard input. Needs the password and a writable store before it reads a
/// label. Fails when any label was invalid, a conflict or not saved.
pub fn run_add_certificate(dir: &Path, from_stdin: bool, json: bool) -> anyhow::Result<ExitCode> {
    use std::io::{BufRead, IsTerminal};

    // Held and dropped like a key (zeroized); the labels too.
    let password = bussard_secure::Password::new(password()?);
    let mut session = bussard_service::CertificateEnrolment::open(dir, password.expose())?;
    let interactive = !from_stdin;
    if interactive && !std::io::stdin().is_terminal() {
        bail!(
            "standard input is not a terminal; pipe the labels with `bussard keys              add-certificate --stdin` (never as an argument)"
        );
    }
    let mut outcomes = Vec::new();
    let mut handle = |text: &str, outcomes: &mut Vec<bussard_service::EnrolOutcome>| {
        let outcome = session.enroll_certificate(text);
        if !json {
            println!("{}", outcome_line(&outcome));
        }
        outcomes.push(outcome);
    };
    if interactive {
        eprintln!(
            "Type or scan one certificate per line (the input is not shown); an empty line ends."
        );
        loop {
            let line = bussard_secure::Password::new(
                rpassword::prompt_password("certificate: ").context("reading a certificate")?,
            );
            if line.expose().trim().is_empty() {
                break;
            }
            handle(line.expose(), &mut outcomes);
        }
    } else {
        for line in std::io::stdin().lock().lines() {
            let line = bussard_secure::Password::new(line.context("reading standard input")?);
            if line.expose().trim().is_empty() {
                continue;
            }
            handle(line.expose(), &mut outcomes);
        }
    }
    use bussard_service::EnrolStatus;
    let failed = outcomes.iter().any(|o| {
        matches!(
            o.status,
            EnrolStatus::Invalid | EnrolStatus::Conflict | EnrolStatus::Error
        )
    });
    if json {
        crate::output::print(
            crate::output::schema::KEYS_ADD_CERTIFICATE,
            &serde_json::json!({
                "store": KeyStore::path(dir).display().to_string(),
                "results": outcomes,
            }),
        )?;
    } else {
        let count = |status: EnrolStatus| outcomes.iter().filter(|o| o.status == status).count();
        println!(
            "{} stored, {} unassigned, {} already stored, {} conflict(s), {} invalid, {} error(s) \
             (key material is never printed)",
            count(EnrolStatus::Stored),
            count(EnrolStatus::Unassigned),
            count(EnrolStatus::AlreadyStored),
            count(EnrolStatus::Conflict),
            count(EnrolStatus::Invalid),
            count(EnrolStatus::Error),
        );
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// After `adopt`, `assign`, `scan` or `describe` read the serial numbers of
/// these devices (issue #728, #752): moves a certificate entered for one of
/// them to its device in the key store. Without the password or a store, or
/// with nothing pending, it does nothing; a failure is a warning, never a
/// command failure. Messages go to stderr under `--json`.
pub fn attach_learned_serials(
    dir: &Path,
    serials: &[(bussard_model::IndividualAddress, Vec<u8>)],
    json: bool,
) {
    use bussard_project::keystore::{AttachOutcome, SerialNumber};
    let serials: Vec<(bussard_model::IndividualAddress, SerialNumber)> = serials
        .iter()
        .filter_map(|(ia, s)| {
            <[u8; 6]>::try_from(s.as_slice())
                .ok()
                .map(|s| (*ia, SerialNumber(s)))
        })
        .collect();
    if serials.is_empty() || !KeyStore::path(dir).exists() {
        return;
    }
    let Ok(password) = password().map(bussard_secure::Password::new) else {
        return;
    };
    let outcomes = match bussard_service::attach_serials(dir, password.expose(), &serials) {
        Ok(outcomes) => outcomes,
        Err(err) => {
            eprintln!("warning: certificates were not attached to the devices just read: {err}");
            return;
        }
    };
    for (ia, serial, outcome) in outcomes {
        match outcome {
            AttachOutcome::Attached => {
                let line = format!(
                    "  factory key (FDSK) of the certificate for serial {serial} attached to {ia} \
                     in the key store"
                );
                if json {
                    eprintln!("{line}");
                } else {
                    println!("{line}");
                }
            }
            AttachOutcome::NothingPending => {}
            AttachOutcome::Conflict => eprintln!(
                "warning: the key store has a certificate for serial {serial}, but its entry for \
                 {ia} names another serial number or factory key; nothing changed (see `bussard \
                 keys show`)"
            ),
        }
    }
}

/// After `scan` or `describe` read serial numbers (issue #752): records each
/// one in the `bussard.lock` entry of its device and attaches a certificate
/// entered for it before ([`attach_learned_serials`]). Only a device the
/// model holds and whose identity did not drift is recorded, and the model
/// is reloaded and saved only when a serial differs from what `model` holds.
/// A failure is a warning; messages go to stderr.
pub fn learn_serials(
    dir: &Path,
    model: Option<&bussard_model::Model>,
    read: &[(
        bussard_model::IndividualAddress,
        Vec<u8>,
        bussard_model::identity::IdentityVerdict,
    )],
    json: bool,
) {
    use bussard_model::identity::IdentityVerdict;
    use bussard_project::keystore::SerialNumber;
    let Some(model) = model else {
        return;
    };
    let fresh: Vec<(bussard_model::IndividualAddress, SerialNumber)> = read
        .iter()
        .filter(|(_, _, verdict)| *verdict != IdentityVerdict::Drift)
        .filter_map(|(ia, bytes, _)| {
            let serial = <[u8; 6]>::try_from(bytes.as_slice()).ok()?;
            let held = model.devices.get(ia)?.device.lock.serial_number.as_deref();
            let text = bussard_model::format_serial(&serial);
            (held != Some(text.as_str()) || model.device_with_serial(&serial) != Some(*ia))
                .then_some((*ia, SerialNumber(serial)))
        })
        .collect();
    if fresh.is_empty() {
        return;
    }
    let records = match bussard_service::record_serials(dir, &fresh) {
        Ok(records) => records,
        Err(err) => {
            eprintln!("warning: the serial numbers just read were not recorded: {err}");
            return;
        }
    };
    let mut recorded = Vec::new();
    for ((ia, record), (_, serial)) in records.into_iter().zip(&fresh) {
        if let bussard_model::SerialRecord::Recorded { previous, cleared } = record {
            match previous {
                Some(previous) => eprintln!(
                    "note: {ia} reports serial number {serial}, bussard.lock had {previous} (the \
                     hardware was replaced?); recorded {serial}"
                ),
                None => eprintln!("recorded serial number {serial} of {ia} in bussard.lock"),
            }
            for other in cleared {
                eprintln!(
                    "note: serial number {serial} was recorded for {other} too; removed there"
                );
            }
            recorded.push((ia, serial.0.to_vec()));
        }
    }
    attach_learned_serials(dir, &recorded, json);
}

/// One line per entered label: serial, matched address and name, status.
fn outcome_line(o: &bussard_service::EnrolOutcome) -> String {
    let status = serde_json::to_value(o.status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let mut line = format!("{} ", o.serial.as_deref().unwrap_or("------------"));
    match (&o.ia, &o.name) {
        (Some(ia), Some(name)) if !name.is_empty() => line.push_str(&format!("{ia} {name:?}: ")),
        (Some(ia), _) => line.push_str(&format!("{ia}: ")),
        (None, _) => line.push_str("no device: "),
    }
    line.push_str(&status);
    if let Some(message) = &o.message {
        line.push_str(&format!(" ({message})"));
    }
    line
}
