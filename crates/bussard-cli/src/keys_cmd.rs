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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_service::files::report::FileOutcome;
use bussard_service::enroll_session::{CertificateOutcome, EnrollTally};
use bussard_service::files::keyring;
use bussard_service::keys::keystore::{BackboneChange, ImportReport, KeyStore, SaveOutcome};
use bussard_service::setup;

use crate::cli::{Resolved, Run, Spec};
use crate::style::{Cell, Style, Symbol, Table, Tone};

/// The `bussard keys` subcommands (issue #241).
#[derive(Debug, clap::Subcommand)]
pub(crate) enum KeysCommand {
    /// Merge an ETS keyring export (`.knxkeys`) into the key store
    /// (`bussard.keys` next to `bussard.lock`), creating it on first use.
    ///
    /// New devices, rotated tool keys, changed credentials and group keys are
    /// taken from the export; entries it lacks are kept and a factory key
    /// is never dropped. Prints what changed, never a key.
    Import {
        /// The `.knxkeys` file to import.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Write the key store as a signed `.knxkeys` export for ETS.
    Export {
        /// The `.knxkeys` file to write.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Overwrite FILE if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Summarize the key store: devices, interfaces and group addresses,
    /// never a key.
    Show,
    /// Enter device certificates (the 36-character code that carries the
    /// factory key, FDSK) into the
    /// key store (issue #728).
    ///
    /// On a terminal it asks for one certificate per line, without echo, until an
    /// empty line; with `--stdin` it reads every line of standard input. A
    /// certificate is never a command-line argument (shell history). Its
    /// serial number selects the device; an unknown serial is kept until
    /// `bussard assign` reads it off a device. Prints the serial, the matched
    /// address and the status per certificate, never a key.
    AddCertificate {
        /// Read the certificates from standard input, one per line.
        #[arg(long)]
        stdin: bool,
    },
    /// Take device certificates from a phone: prints a link, its QR code and
    /// the session code, then one line per certificate the phone scans.
    ///
    /// The phone encrypts each certificate to this session; the page's server and
    /// the relay only see ciphertext. Ends when the phone finishes, on `q`
    /// and Enter, or on Ctrl-C. Prints serials and addresses, never a key.
    Enroll(crate::enroll_cmd::EnrollArgs),
}

impl Run for KeysCommand {
    fn spec(&self) -> Spec {
        Spec::FILES.json().no_products()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let (dir, json) = (g.dir(), g.json);
        match self {
            KeysCommand::Import { file } => run_import(dir, &file, json),
            KeysCommand::Export { file, force } => run_export(dir, &file, force, json),
            KeysCommand::Show => run_show(dir, json),
            KeysCommand::AddCertificate { stdin } => run_add_certificate(dir, stdin, json),
            KeysCommand::Enroll(args) => crate::enroll_cmd::run(dir, args, json),
        }
    }
}

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
fn run_import(dir: &Path, file: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let path = KeyStore::path(dir);
    let (report, outcome) = import_quiet(dir, file)?;
    let warnings = rekeyed_warnings(dir, &report);

    if json {
        crate::output::report(&FileOutcome::keyring_imported(
            dir, file, report, outcome, &warnings,
        ))?;
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
            bussard_service::keys::keystore::KEYSTORE_BACKUP_FILE
        ),
        SaveOutcome::Written { backup: false } => println!("  created the key store"),
        SaveOutcome::Unchanged => {}
    }
    println!("  (key material is never printed)");
}

/// Runs `bussard keys export <file>`
/// ([`bussard_service::files::keyring::export_keyring`]).
fn run_export(dir: &Path, file: &Path, force: bool, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    let export =
        keyring::export_keyring(dir, file, &password, force, &mut crate::console::Console)?;
    fn joined<T: std::fmt::Display>(items: &[T]) -> String {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }
    if json {
        crate::output::report(&FileOutcome::keyring_exported(file, export.clone(), Vec::new()))?;
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
                joined(&export.skipped_devices)
            );
        }
        println!(
            "  group addresses carried: {}",
            if export.group_addresses.is_empty() {
                "none".to_string()
            } else {
                joined(&export.group_addresses)
            }
        );
        if !export.omitted_group_addresses.is_empty() {
            println!(
                "  group addresses omitted (secure in the model or the store, no key in the \
                 export): {}",
                joined(&export.omitted_group_addresses)
            );
        }
        if export.verified {
            println!("  verified: read back, decrypted and compared with the key store");
        } else {
            let style = Style::stderr();
            for leftover in &export.leftovers {
                eprintln!("{}", style.error_line(leftover));
            }
        }
        println!("  keep it out of git: the model's .gitignore lists *.knxkeys");
    }
    if !export.verified {
        eprintln!(
            "{}",
            Style::stderr().error_line(&format!(
                "{} does not carry the key store's keys; do not hand it on",
                file.display()
            ))
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard keys show`.
fn run_show(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let password = password()?;
    let store = load_existing(dir, &password)?;
    let s = store.summary();
    let model = bussard_model::Model::load(dir).ok();
    // Devices of the project that support Secure and have no factory key yet.
    let without_fdsk: Vec<bussard_model::IndividualAddress> = model
        .as_ref()
        .map(|model| bussard_service::enroll::devices_without_fdsk(model, &store))
        .unwrap_or_default();
    if json {
        let mut value = serde_json::to_value(&s)?;
        if let Some(object) = value.as_object_mut() {
            let addresses: Vec<String> = without_fdsk.iter().map(ToString::to_string).collect();
            object.insert("devices_without_fdsk".to_string(), addresses.into());
        }
        crate::output::print(crate::output::schema::KEYS_SHOW, &value)?;
        return Ok(ExitCode::SUCCESS);
    }
    let name_of = |address: &str| -> String {
        address
            .parse::<bussard_model::IndividualAddress>()
            .ok()
            .and_then(|ia| model.as_ref()?.devices.get(&ia))
            .map(|d| d.device.name.clone())
            .unwrap_or_default()
    };
    print!(
        "{}",
        render_show(
            &KeyStore::path(dir),
            &s,
            &without_fdsk
                .iter()
                .map(|ia| (ia.to_string(), name_of(&ia.to_string())))
                .collect::<Vec<_>>(),
            &name_of,
            Style::stdout()
        )
    );
    Ok(ExitCode::SUCCESS)
}

/// The text of `bussard keys show`: what the key store holds, as presence
/// flags and counts, never a key.
fn render_show(
    path: &Path,
    s: &bussard_service::keys::keystore::KeyStoreSummary,
    without_fdsk: &[(String, String)],
    name_of: &dyn Fn(&str) -> String,
    style: Style,
) -> String {
    let mut out = format!(
        "{} {}\n{}\n",
        style.bold("Key store"),
        path.display(),
        style.dim(&format!("project {:?}, created {}", s.project, s.created))
    );

    out.push_str(&format!(
        "\n{}\n",
        style.bold(&crate::style::count(s.devices.len(), "device", "devices"))
    ));
    if !s.devices.is_empty() {
        let mut table = Table::new(&["Address", "Name", "Serial number", "Keys"]);
        for d in &s.devices {
            let mut keys = Vec::new();
            if d.has_tool_key {
                keys.push("tool key");
            }
            if d.has_fdsk {
                keys.push("factory key");
            }
            if d.has_management_password {
                keys.push("management password");
            }
            if d.has_authentication {
                keys.push("authentication code");
            }
            let keys = if d.has_tool_key {
                Cell::plain(keys.join(", "))
            } else {
                let mut text = vec!["no tool key"];
                text.extend(keys);
                Cell::new(text.join(", "), Tone::Warn)
            };
            table.row(vec![
                Cell::plain(d.address.as_str()),
                Cell::plain(name_of(&d.address)),
                match &d.serial {
                    Some(serial) => Cell::plain(serial.as_str()),
                    None => Cell::new(style.symbol(Symbol::Missing), Tone::Dim),
                },
                keys,
            ]);
        }
        indent(&mut out, &table.render(style));
    }

    out.push_str(&format!(
        "\n{}\n",
        style.bold(&crate::style::count(
            s.interfaces.len(),
            "interface",
            "interfaces"
        ))
    ));
    if !s.interfaces.is_empty() {
        let mut table = Table::new(&["Address", "Type", "User", "Host", "Missing"]);
        for i in &s.interfaces {
            let mut missing = Vec::new();
            if !i.has_password {
                missing.push("password");
            }
            if !i.has_authentication {
                missing.push("authentication code");
            }
            table.row(vec![
                Cell::plain(i.address.as_str()),
                Cell::plain(if i.interface_type.is_empty() {
                    "interface"
                } else {
                    i.interface_type.as_str()
                }),
                Cell::plain(i.user_id.to_string()),
                Cell::plain(i.host.as_deref().unwrap_or("-")),
                Cell::new(missing.join(", "), Tone::Warn),
            ]);
        }
        indent(&mut out, &table.render(style));
    }

    out.push('\n');
    out.push_str(&format!(
        "{} {}\n",
        style.dim("Group keys:"),
        s.group_key_count
    ));
    out.push_str(&format!(
        "{} {}\n",
        style.dim("Backbone key:"),
        match &s.backbone_multicast {
            Some(addr) => format!("present ({addr})"),
            None => "none".to_string(),
        }
    ));
    if !s.unassigned_certificates.is_empty() {
        out.push_str(&format!(
            "{} {}\n",
            style.warn(&format!(
                "{} with no device yet (serial numbers):",
                crate::style::count(
                    s.unassigned_certificates.len(),
                    "certificate",
                    "certificates"
                )
            )),
            s.unassigned_certificates.join(", ")
        ));
    }
    let mut steps = Vec::new();
    if !without_fdsk.is_empty() {
        let devices: Vec<String> = without_fdsk
            .iter()
            .map(|(ia, name)| {
                if name.is_empty() {
                    ia.clone()
                } else {
                    format!("{ia} {name}")
                }
            })
            .collect();
        out.push_str(&format!(
            "{} {}\n",
            style.warn(&format!(
                "{} that support Secure without a factory key:",
                crate::style::count(without_fdsk.len(), "device", "devices")
            )),
            devices.join(", ")
        ));
        steps.push((
            "bussard keys enroll",
            "scan their certificates with your phone (or type them with `bussard keys \
             add-certificate`)",
        ));
    }
    if !s.unassigned_certificates.is_empty() {
        steps.push((
            "bussard scan <LINE>",
            "saves the serial numbers of your devices and matches the certificates that have \
             no device yet",
        ));
    }
    out.push_str(&style.dim("Codes and keys are never shown."));
    out.push('\n');
    let block = style.next_steps(&steps);
    if !block.is_empty() {
        out.push('\n');
        out.push_str(&block);
    }
    out
}

/// Appends `text`'s lines to `out`, two spaces in.
fn indent(out: &mut String, text: &str) {
    for line in text.lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
}

/// Runs `bussard keys add-certificate`: one label per line from the terminal
/// (without echo, an empty line ends) or, with `--stdin`, every line of
/// standard input. Needs the password and a writable store before it reads a
/// label. Fails when any label was invalid, a conflict or not saved.
fn run_add_certificate(dir: &Path, from_stdin: bool, json: bool) -> anyhow::Result<ExitCode> {
    use std::io::{BufRead, IsTerminal};

    // Held and dropped like a key (zeroized); the labels too.
    let password = bussard_service::secure::Password::new(password()?);
    let mut session = bussard_service::CertificateEnrolment::open(dir, password.expose())?;
    let interactive = !from_stdin;
    if interactive && !std::io::stdin().is_terminal() {
        bail!(
            "standard input is not a terminal; pipe the certificates with `bussard keys add-certificate --stdin` (never as an argument)"
        );
    }
    let mut outcomes = Vec::new();
    let style = Style::stdout();
    let mut handle = |text: &str, outcomes: &mut Vec<bussard_service::EnrolOutcome>| {
        let outcome = session.enroll_certificate(text);
        if !json {
            println!(
                "{}",
                crate::certificate_view::line(&CertificateOutcome::from(outcome.clone()), style)
            );
        }
        outcomes.push(outcome);
    };
    if interactive {
        eprintln!(
            "Type or scan one certificate per line (the input is not shown); an empty line ends."
        );
        loop {
            let line = bussard_service::secure::Password::new(
                rpassword::prompt_password("certificate: ").context("reading a certificate")?,
            );
            if line.expose().trim().is_empty() {
                break;
            }
            handle(line.expose(), &mut outcomes);
        }
    } else {
        for line in std::io::stdin().lock().lines() {
            let line =
                bussard_service::secure::Password::new(line.context("reading standard input")?);
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
        crate::output::report(&bussard_service::enroll_session::CertificatesReport {
            store: KeyStore::path(dir).display().to_string(),
            results: outcomes.clone(),
        })?;
    } else {
        let tally = EnrollTally::of(
            &outcomes
                .iter()
                .cloned()
                .map(CertificateOutcome::from)
                .collect::<Vec<_>>(),
        );
        print!("{}", add_certificate_ending(&tally, style));
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// What [`learn_serials`] and [`attach_learned_serials`] did, for the
/// command to show in its own layout (issue #792). Never a key.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SerialNews {
    /// Devices whose serial number was saved to the project, with it.
    pub saved: Vec<(bussard_model::IndividualAddress, String)>,
    /// Devices a waiting certificate was attached to.
    pub attached: Vec<bussard_model::IndividualAddress>,
    /// Facts worth a line: a replaced device, a serial number moved.
    pub notes: Vec<String>,
    /// Problems: nothing changed for these.
    pub warnings: Vec<String>,
}

impl SerialNews {
    /// Whether the device's serial number was saved just now.
    pub(crate) fn saved(&self, address: bussard_model::IndividualAddress) -> bool {
        self.saved.iter().any(|(a, _)| *a == address)
    }

    /// The lines of the attached certificates and the notes, without the
    /// saved serial numbers (a table shows those).
    pub(crate) fn lines(&self, style: crate::style::Style) -> Vec<String> {
        let mut lines: Vec<String> = self
            .attached
            .iter()
            .map(|ia| style.ok(&format!("certificate for {ia} attached")))
            .collect();
        lines.extend(self.notes.iter().map(|n| style.dim(n)));
        lines
    }

    /// Prints everything for a command without a table (`describe`,
    /// `assign`, `adopt`): one line per saved serial number, attached
    /// certificate and note on stdout (stderr under `--json`), the warnings
    /// on stderr.
    pub(crate) fn print(&self, json: bool) {
        let style = if json {
            crate::style::Style::stderr()
        } else {
            crate::style::Style::stdout()
        };
        let mut lines: Vec<String> = self
            .saved
            .iter()
            .map(|(ia, serial)| format!("  serial number {serial} of {ia} saved to your project"))
            .collect();
        lines.extend(self.lines(style).into_iter().map(|l| format!("  {l}")));
        for line in lines {
            if json {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
        }
        self.print_warnings();
    }

    /// Prints the warnings on stderr.
    pub(crate) fn print_warnings(&self) {
        let style = crate::style::Style::stderr();
        for warning in &self.warnings {
            eprintln!("{}", style.warning_line(warning));
        }
    }

    /// Adds `other`'s entries after this one's.
    fn extend(&mut self, other: SerialNews) {
        self.saved.extend(other.saved);
        self.attached.extend(other.attached);
        self.notes.extend(other.notes);
        self.warnings.extend(other.warnings);
    }
}

/// After `adopt`, `assign`, `scan` or `describe` read the serial numbers of
/// these devices (issue #728, #752): moves a certificate entered for one of
/// them to its device in the key store. Without the password or a store, or
/// with nothing pending, it does nothing; a failure is a warning, never a
/// command failure. The caller shows the result ([`SerialNews`]).
pub(crate) fn attach_learned_serials(
    dir: &Path,
    serials: &[(bussard_model::IndividualAddress, Vec<u8>)],
) -> SerialNews {
    use bussard_service::keys::keystore::{AttachOutcome, SerialNumber};
    let mut news = SerialNews::default();
    let serials: Vec<(bussard_model::IndividualAddress, SerialNumber)> = serials
        .iter()
        .filter_map(|(ia, s)| {
            <[u8; 6]>::try_from(s.as_slice())
                .ok()
                .map(|s| (*ia, SerialNumber(s)))
        })
        .collect();
    if serials.is_empty() || !KeyStore::path(dir).exists() {
        return news;
    }
    let Ok(password) = password().map(bussard_service::secure::Password::new) else {
        return news;
    };
    let outcomes = match bussard_service::attach_serials(dir, password.expose(), &serials) {
        Ok(outcomes) => outcomes,
        Err(err) => {
            news.warnings.push(format!(
                "certificates were not attached to the devices just read: {err}"
            ));
            return news;
        }
    };
    for (ia, serial, outcome) in outcomes {
        match outcome {
            AttachOutcome::Attached => news.attached.push(ia),
            AttachOutcome::NothingPending => {}
            AttachOutcome::Conflict => news.warnings.push(format!(
                "your key store has a certificate for serial number {serial}, but holds another \
                 serial number or factory key for {ia}; nothing changed (see `bussard keys show`)"
            )),
        }
    }
    news
}

/// After `scan` or `describe` read serial numbers (issue #752): saves each
/// one to the project (the `bussard.lock` entry of its device) and attaches
/// a certificate entered for it before ([`attach_learned_serials`]). Only a
/// device the project holds and whose identity did not drift is saved, and
/// the project is reloaded and saved only when a serial differs from what
/// `model` holds. A failure is a warning; the caller shows the result.
pub(crate) fn learn_serials(
    dir: &Path,
    model: Option<&bussard_model::Model>,
    read: &[(
        bussard_model::IndividualAddress,
        Vec<u8>,
        bussard_model::identity::IdentityVerdict,
    )],
) -> SerialNews {
    use bussard_model::identity::IdentityVerdict;
    use bussard_service::keys::keystore::SerialNumber;
    let mut news = SerialNews::default();
    let Some(model) = model else {
        return news;
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
        return news;
    }
    let records = match bussard_service::record_serials(dir, &fresh) {
        Ok(records) => records,
        Err(err) => {
            news.warnings.push(format!(
                "the serial numbers just read were not saved to your project: {err}"
            ));
            return news;
        }
    };
    let mut recorded = Vec::new();
    for ((ia, record), (_, serial)) in records.into_iter().zip(&fresh) {
        if let bussard_model::SerialRecord::Recorded { previous, cleared } = record {
            if let Some(previous) = previous {
                news.notes.push(format!(
                    "{ia} reports serial number {serial}, your project had {previous} (was the \
                     device replaced?); saved {serial}"
                ));
            }
            for other in cleared {
                news.notes.push(format!(
                    "serial number {serial} was saved for {other} too; removed there"
                ));
            }
            news.saved.push((ia, serial.to_string()));
            recorded.push((ia, serial.0.to_vec()));
        }
    }
    news.extend(attach_learned_serials(dir, &recorded));
    news
}

/// The end of `keys add-certificate`: the summary line and the next steps.
fn add_certificate_ending(tally: &EnrollTally, style: Style) -> String {
    let mut out = format!(
        "\n{}\n{}\n",
        crate::certificate_view::summary(tally, style),
        style.dim("Codes and keys are never shown.")
    );
    // The session's steps, with this command for the certificates to retype.
    let steps: Vec<(&str, &str)> = tally
        .next_steps()
        .iter()
        .map(|step| match step.command {
            "bussard keys enroll" => (
                "bussard keys add-certificate",
                "type the invalid or failed certificates again",
            ),
            command => (command, step.why),
        })
        .collect();
    let block = style.next_steps(&steps);
    if !block.is_empty() {
        out.push('\n');
        out.push_str(&block);
    }
    out
}
