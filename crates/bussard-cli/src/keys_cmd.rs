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

use anyhow::{Context, anyhow, bail};
use bussard_project::keystore::{BackboneChange, ImportReport, KeyStore, SaveOutcome};

/// The environment variable carrying the keyring (and key store) password.
const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// Reads the keyring password from the environment.
pub(crate) fn password() -> anyhow::Result<String> {
    // The one missing-password wording (issue #228).
    bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
        .map_err(|_| bussard_service::secure::SecureKeyError::MissingPassword.into())
}

/// The `.knxkeys` exports in the directory of `project` (sorted).
pub fn neighbour_keyrings(project: &Path) -> Vec<std::path::PathBuf> {
    let parent = match project.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(&parent)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| e.eq_ignore_ascii_case("knxkeys"))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// Whether the key store password is set (a store can be written).
pub fn password_available() -> bool {
    bussard_model::dotenv::var_os(KEYRING_PASSWORD_ENV).is_some()
}

/// After an import of `project` into `dir`: merges the one `.knxkeys` next to
/// the project into `bussard.keys` (issue #241 item 2). Several exports are
/// listed and none is picked; without the password the command to run is
/// printed. Never fails the import: a keyring that does not load is a
/// warning.
pub fn import_neighbour(project: &Path, dir: &Path) {
    let mut found = neighbour_keyrings(project);
    match found.len() {
        0 => {}
        1 => {
            let file = found.remove(0);
            if !password_available() {
                println!(
                    "Found the ETS keyring {}. To keep its keys in {}, set                      {KEYRING_PASSWORD_ENV} and run `bussard keys import {}` (the password is                      never stored).",
                    file.display(),
                    KeyStore::path(dir).display(),
                    file.display()
                );
                return;
            }
            match import_quiet(dir, &file) {
                Ok((report, outcome)) => {
                    let what = match outcome {
                        SaveOutcome::Written { backup: false } => "created",
                        SaveOutcome::Written { backup: true } => "updated",
                        SaveOutcome::Unchanged => "already up to date",
                    };
                    println!(
                        "Imported the ETS keyring {} into {} ({what}: {} device(s) added, {} tool                          key(s) rotated, {} group key(s) added, {} rotated). It is encrypted                          with {KEYRING_PASSWORD_ENV}; keep that password, bussard never stores                          it.",
                        file.display(),
                        KeyStore::path(dir).display(),
                        report.devices_added.len(),
                        report.tool_keys_rotated.len(),
                        report.group_keys_added.len(),
                        report.group_keys_rotated.len(),
                    );
                    print_warnings(&rekeyed_warnings(dir, &report));
                }
                Err(err) => eprintln!(
                    "warning: the ETS keyring {} was not imported into the key store: {err:#}",
                    file.display()
                ),
            }
        }
        _ => {
            println!(
                "Found several ETS keyrings next to the project; import the current one with                  `bussard keys import <file>`:"
            );
            for p in &found {
                println!("  {}", p.display());
            }
        }
    }
}

/// W042 (issue #348): the group keys an import added for group addresses the
/// model in `dir` runs plain, each naming the devices the next apply would
/// secure again. Empty without a loadable model.
fn rekeyed_warnings(dir: &Path, report: &ImportReport) -> Vec<bussard_model::Diagnostic> {
    let Ok(model) = bussard_model::Model::load(dir) else {
        return Vec::new();
    };
    let added: Vec<bussard_model::GroupAddress> = report
        .group_keys_added
        .iter()
        .filter_map(|ga| ga.parse().ok())
        .collect();
    bussard_model::rekeyed_by_keys_import(&model, &added)
}

/// Prints warnings as `warning[CODE]: message` on stderr.
pub(crate) fn print_warnings(diags: &[bussard_model::Diagnostic]) {
    for d in diags {
        eprintln!("warning[{}]: {}", d.code, d.message);
    }
}

/// Merges `file` into the store in `dir` and saves it.
fn import_quiet(dir: &Path, file: &Path) -> anyhow::Result<(ImportReport, SaveOutcome)> {
    let password = password()?;
    let xml = std::fs::read_to_string(file)
        .with_context(|| format!("reading keyring {}", file.display()))?;
    let keyring = bussard_project::parse_keyring(&xml, &password).with_context(|| {
        format!(
            "loading keyring {} (the store and the export share {KEYRING_PASSWORD_ENV})",
            file.display()
        )
    })?;
    let path = KeyStore::path(dir);
    let mut store = KeyStore::load(dir, &password)
        .with_context(|| format!("loading the key store {}", path.display()))?
        .unwrap_or_else(|| KeyStore::new(&keyring.project));
    let report = store.merge_keyring(&keyring);
    let outcome = store
        .save(dir, &password)
        .with_context(|| format!("writing the key store {}", path.display()))?;
    Ok((report, outcome))
}

/// Loads the store in `dir`, failing with a hint when there is none.
fn load_existing(dir: &Path, password: &str) -> anyhow::Result<KeyStore> {
    let path = KeyStore::path(dir);
    KeyStore::load(dir, password)
        .with_context(|| format!("loading the key store {}", path.display()))?
        .ok_or_else(|| {
            anyhow!(
                "no key store at {}; create it with `bussard keys import <file.knxkeys>`",
                path.display()
            )
        })
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

/// Runs `bussard keys export <file>`.
pub fn run_export(dir: &Path, file: &Path, force: bool, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    if file.exists() && !force {
        bail!("{} exists; pass --force to overwrite it", file.display());
    }
    let store = load_existing(dir, &password)?;
    let export = store
        .export_knxkeys(&password)
        .context("building the .knxkeys export")?;
    std::fs::write(file, &export.xml).with_context(|| format!("writing {}", file.display()))?;
    // The export's time, so `validate` can tell when the key store changed
    // after it (W040, issue #348).
    if let Err(err) = bussard_model::KeyStoreMeta::record_export(dir, file) {
        eprintln!("warning: the export was not recorded: {err}");
    }
    let skipped: Vec<String> = export
        .skipped_devices
        .iter()
        .map(|ia| ia.to_string())
        .collect();
    // Verified means read back and compared (issue #349): the file as written,
    // its signature checked, decrypted and its key set compared with the store.
    let written = std::fs::read_to_string(file)
        .with_context(|| format!("reading {} back", file.display()))?;
    let check = store
        .check_export(&written, &password)
        .with_context(|| format!("reading {} back", file.display()))?;
    let omitted = omitted_group_addresses(dir, &store, &check);
    let carried: Vec<String> = check
        .group_addresses
        .iter()
        .map(ToString::to_string)
        .collect();
    let omitted_s: Vec<String> = omitted.iter().map(ToString::to_string).collect();
    let leftovers = check.leftovers();
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "devices": export.devices,
            "group_keys": export.group_keys,
            "interfaces": export.interfaces,
            "skipped_devices": skipped,
            "verified": check.verified(),
            "group_addresses": carried,
            "omitted_group_addresses": omitted_s,
            "leftovers": leftovers,
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
        if !skipped.is_empty() {
            println!(
                "  left out (no tool key, ETS needs one): {}",
                skipped.join(", ")
            );
        }
        println!(
            "  group addresses carried: {}",
            if carried.is_empty() {
                "none".to_string()
            } else {
                carried.join(", ")
            }
        );
        if !omitted_s.is_empty() {
            println!(
                "  group addresses omitted (secure in the model or the store, no key in the \
                 export): {}",
                omitted_s.join(", ")
            );
        }
        if check.verified() {
            println!("  verified: read back, decrypted and compared with the key store");
        } else {
            for leftover in &leftovers {
                eprintln!("ERROR: {leftover}");
            }
        }
        println!("  keep it out of git: the model's .gitignore lists *.knxkeys");
    }
    if !check.verified() {
        eprintln!(
            "ERROR: {} does not carry the key store's keys; do not hand it on",
            file.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// The group addresses the model marks secure or the store keys that the
/// export `check` read back does not carry, ascending. A model that does not
/// load contributes nothing (the store's own keys are still checked).
fn omitted_group_addresses(
    dir: &Path,
    store: &KeyStore,
    check: &bussard_project::keystore::ExportCheck,
) -> Vec<bussard_model::GroupAddress> {
    let mut wanted: std::collections::BTreeSet<bussard_model::GroupAddress> =
        store.group_keys.keys().copied().collect();
    if let Ok(model) = bussard_model::Model::load(dir) {
        wanted.extend(
            model
                .groups
                .groups
                .iter()
                .filter(|(_, g)| g.secure)
                .map(|(ga, _)| *ga),
        );
    }
    wanted
        .into_iter()
        .filter(|ga| !check.group_addresses.contains(ga))
        .collect()
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

/// After `bussard assign` read `serial` off the device now at `ia`: moves a
/// certificate entered for that serial to `ia` in the key store (issue
/// #728). Without the password or a store, or with nothing pending, it does
/// nothing; a failure is a warning, never an assign failure.
pub fn attach_after_assign(dir: &Path, ia: bussard_model::IndividualAddress, serial: &[u8]) {
    use bussard_project::keystore::{AttachOutcome, SerialNumber};
    let Ok(serial) = <[u8; 6]>::try_from(serial).map(SerialNumber) else {
        return;
    };
    if !KeyStore::path(dir).exists() {
        return;
    }
    let Ok(password) = password().map(bussard_secure::Password::new) else {
        return;
    };
    match bussard_service::attach_serial(dir, password.expose(), ia, serial) {
        Ok(AttachOutcome::Attached) => println!(
            "  factory key (FDSK) of the certificate for serial {serial} attached to {ia} in the \
             key store"
        ),
        Ok(AttachOutcome::NothingPending) => {}
        Ok(AttachOutcome::Conflict) => eprintln!(
            "warning: the key store has a certificate for serial {serial}, but its entry for {ia} \
             names another serial number or factory key; nothing changed (see `bussard keys \
             show`)"
        ),
        Err(err) => {
            eprintln!("warning: the certificate for serial {serial} was not attached: {err}")
        }
    }
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
