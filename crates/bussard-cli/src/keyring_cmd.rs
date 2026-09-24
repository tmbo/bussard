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
    /// The KNXnet/IP Secure tunnelling users per interface: user id, tunnel
    /// address, host, and whether the credentials are present (never the
    /// credentials themselves; issue #71 Phase B).
    tunnelling_users: Vec<TunnellingUser>,
    /// The devices that carry KNXnet/IP Secure device credentials (management
    /// password and/or device authentication code, not shown).
    ip_secure_devices: Vec<String>,
}

/// One tunnelling user of a KNXnet/IP Secure interface, redaction-safe.
#[derive(Debug, serde::Serialize)]
struct TunnellingUser {
    /// The tunnel individual address the interface assigns to this user.
    tunnel_address: String,
    /// The individual address of the interface itself (`Host`), if listed.
    host: Option<String>,
    /// The user id presented in SESSION_AUTHENTICATE.
    user_id: u8,
    /// Whether the user password is present.
    has_password: bool,
    /// Whether the interface's device authentication code is present.
    has_device_authentication: bool,
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
        tunnelling_users: keyring
            .interfaces
            .iter()
            .filter(|i| i.interface_type.eq_ignore_ascii_case("Tunneling"))
            .map(|i| TunnellingUser {
                tunnel_address: i.ia.to_string(),
                host: i.host.map(|h| h.to_string()),
                user_id: i.user_id,
                has_password: i.password.is_some(),
                // The code is on the interface, or on the host device's
                // entry (as the tunnel client resolves it).
                has_device_authentication: i.authentication.is_some()
                    || i.host.is_some_and(|host| {
                        keyring
                            .devices
                            .iter()
                            .any(|d| d.ia == host && d.authentication.is_some())
                    }),
            })
            .collect(),
        ip_secure_devices: keyring
            .devices
            .iter()
            .filter(|d| d.management_password.is_some() || d.authentication.is_some())
            .map(|d| d.ia.to_string())
            .collect(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_text(&summary);
    }
    Ok(ExitCode::SUCCESS)
}

/// One tunnelling user as `user <id> -> <tunnel IA> (host <IA>)`, with a note
/// when the keyring lacks a credential the secure session needs. Never a
/// credential itself.
fn tunnelling_user_line(u: &TunnellingUser) -> String {
    let host = u.host.as_deref().unwrap_or("?");
    let mut line = format!("user {} -> {} (host {host})", u.user_id, u.tunnel_address);
    if !u.has_password {
        line.push_str(", no password in the keyring");
    } else if !u.has_device_authentication {
        line.push_str(", no device authentication code (interface identity not verified)");
    }
    line
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
    // One line per user (issue #188): the id, the tunnel address and the
    // interface, never a credential.
    if s.tunnelling_users.is_empty() {
        println!("  KNXnet/IP Secure tunnelling users: none");
    } else {
        println!(
            "  KNXnet/IP Secure tunnelling users ({}):",
            s.tunnelling_users.len()
        );
        for u in &s.tunnelling_users {
            println!("    {}", tunnelling_user_line(u));
        }
    }
    if !s.ip_secure_devices.is_empty() {
        println!(
            "  KNXnet/IP Secure device credentials: {}",
            s.ip_secure_devices.join(", ")
        );
    }
    println!("  (key material is never printed)");
}
