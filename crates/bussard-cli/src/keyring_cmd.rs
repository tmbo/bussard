//! The `bussard keyring` subcommand — inspect a KNX Secure `.knxkeys` keyring
//! (issue #71).
//!
//! Loads and decrypts a `.knxkeys` file and prints a summary of what it carries:
//! the devices (by individual address), the tunnel/management interfaces, and
//! the number of group keys. **No key material is ever printed** (spec §2.3):
//! the summary is counts and addresses only.
//!
//! The keyring password is read from the `BUSSARD_KEYRING_PASSWORD` environment
//! variable, never a CLI argument (spec §2.2), mirroring how the project
//! password arrives via `BUSSARD_PROJECT_PASSWORD`.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};

/// The environment variable carrying the keyring password (spec §2.2).
const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// A redaction-safe summary of a parsed keyring, shaped for text and `--json`.
///
/// Every field here is a count or an address; no key bytes are included, so this
/// struct can be freely serialized (unlike the key-bearing `Keyring`).
#[derive(Debug, serde::Serialize)]
struct KeyringSummary {
    /// The ETS project the keyring was exported from.
    project: String,
    /// The keyring's `Created` timestamp.
    created: String,
    /// Whether a backbone (routing) key is present.
    has_backbone_key: bool,
    /// The individual addresses of the devices in the keyring (each has a tool
    /// key, not shown).
    devices: Vec<String>,
    /// The tunnel/management interface individual addresses (each has a user
    /// password and device authentication code, not shown).
    interfaces: Vec<String>,
    /// The number of per-group-address group keys (values not shown).
    group_key_count: usize,
}

/// Runs `bussard keyring`.
pub fn run(file: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let password = std::env::var(KEYRING_PASSWORD_ENV).map_err(|_| {
        anyhow!(
            "the keyring password must be set in the {KEYRING_PASSWORD_ENV} environment \
             variable (never passed as a CLI argument)"
        )
    })?;

    let xml = std::fs::read_to_string(file)
        .with_context(|| format!("reading keyring {}", file.display()))?;

    let keyring = bussard_project::parse_keyring(&xml, &password)
        .with_context(|| format!("loading keyring {}", file.display()))?;

    let summary = KeyringSummary {
        project: keyring.project.clone(),
        created: keyring.created.clone(),
        has_backbone_key: keyring.backbone.is_some(),
        devices: keyring.devices.iter().map(|d| d.ia.to_string()).collect(),
        interfaces: keyring
            .interfaces
            .iter()
            .map(|i| i.ia.to_string())
            .collect(),
        group_key_count: keyring.group_keys.len(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_text(&summary);
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the human-readable keyring summary (no key material).
fn print_text(s: &KeyringSummary) {
    println!("keyring for project {:?}, created {}", s.project, s.created);
    println!(
        "  backbone key: {}",
        if s.has_backbone_key {
            "present"
        } else {
            "none"
        }
    );
    println!("  devices ({}): {}", s.devices.len(), s.devices.join(", "));
    println!(
        "  interfaces ({}): {}",
        s.interfaces.len(),
        s.interfaces.join(", ")
    );
    println!("  group keys: {}", s.group_key_count);
    println!("  (key material is never printed)");
}
