//! `bussard keys`: the bussard-owned key store, `bussard.keys` next to
//! `bussard.lock` (issue #241).
//!
//! - `keys import <file.knxkeys>` merges an ETS keyring export into the store
//!   and reports what changed (new devices, rotated keys, group keys); a
//!   factory key is never dropped.
//! - `keys export <file.knxkeys>` writes a signed export ETS accepts.
//! - `keys show` prints a redaction-safe summary.
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
fn password() -> anyhow::Result<String> {
    std::env::var(KEYRING_PASSWORD_ENV).map_err(|_| {
        anyhow!(
            "the key store password must be set in the {KEYRING_PASSWORD_ENV} environment \
             variable (never passed as a CLI argument)"
        )
    })
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

    if json {
        let value = serde_json::json!({
            "store": path.display().to_string(),
            "source": file.display().to_string(),
            "written": matches!(outcome, SaveOutcome::Written { .. }),
            "backup": matches!(outcome, SaveOutcome::Written { backup: true }),
            "changed": report.changed(),
            "report": report,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_report(&path, file, &report, outcome);
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
    let skipped: Vec<String> = export
        .skipped_devices
        .iter()
        .map(|ia| ia.to_string())
        .collect();
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "devices": export.devices,
            "group_keys": export.group_keys,
            "interfaces": export.interfaces,
            "skipped_devices": skipped,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
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
        println!("  keep it out of git: the model's .gitignore lists *.knxkeys");
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard keys show`.
pub fn run_show(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    let store = load_existing(dir, &password)?;
    let s = store.summary();
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
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
    println!("  (key material is never printed)");
    Ok(ExitCode::SUCCESS)
}
