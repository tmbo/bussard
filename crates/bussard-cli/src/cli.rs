//! What every subcommand shares: the [`Run`] trait each `*Args` struct
//! implements, the resolved global options it runs with ([`Resolved`]), and
//! the argument groups several subcommands flatten into their own.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_service::secure::ToolKeySource;
use clap::Args;

use crate::conn_cmd::ConnOverrides;

/// What a subcommand does with the global options, as far as resolving them
/// is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Creates a model (`init`, `import`): the directory is `--dir`,
    /// `BUSSARD_DIR` or `knx`, never discovered upward.
    Creates,
    /// Talks to the bus; `slot` says whether the keyring also feeds the
    /// command itself (tool keys, group keys) or only the tunnel.
    Bus {
        /// The command consumes the keyring beyond opening the tunnel.
        slot: bool,
    },
    /// Works on the model files only (or on nothing: `diff`, `keyring`).
    Files,
}

/// How a subcommand treats the global options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spec {
    /// What it does with the directory and the keyring.
    pub role: Role,
    /// Whether it has a machine-readable output for `--json`.
    pub json: bool,
    /// Whether it was given `--tool-key`. A keyring that did not come from
    /// `--keyring` then serves the tunnel only: the two are mutually exclusive
    /// tool-key sources.
    pub tool_key: bool,
    /// Whether it takes `--device-management` (it manages a KNX IP interface
    /// itself, issue #523).
    pub device_management: bool,
    /// Whether the product store is prepared before it runs (issue #228);
    /// `diff` and `keys` work without a model.
    pub products: bool,
}

impl Spec {
    /// A command on the model files only.
    pub(crate) const FILES: Spec = Spec {
        role: Role::Files,
        json: false,
        tool_key: false,
        device_management: false,
        products: true,
    };
    /// A command that creates a model (`init`, `import`).
    pub(crate) const CREATES: Spec = Spec {
        role: Role::Creates,
        ..Spec::FILES
    };
    /// A bus command that also takes tool keys or group keys from the keyring.
    pub(crate) const BUS: Spec = Spec {
        role: Role::Bus { slot: true },
        ..Spec::FILES
    };
    /// A bus command whose keyring only opens the tunnel (`test`).
    pub(crate) const TUNNEL: Spec = Spec {
        role: Role::Bus { slot: false },
        ..Spec::FILES
    };

    /// With a `--json` output.
    pub(crate) const fn json(self) -> Spec {
        Spec { json: true, ..self }
    }

    /// With `--tool-key` given or not.
    pub(crate) const fn tool_key(self, given: bool) -> Spec {
        Spec {
            tool_key: given,
            ..self
        }
    }

    /// Taking `--device-management`.
    pub(crate) const fn device_management(self) -> Spec {
        Spec {
            device_management: true,
            ..self
        }
    }

    /// Without the product store preparation.
    pub(crate) const fn no_products(self) -> Spec {
        Spec {
            products: false,
            ..self
        }
    }
}

/// A subcommand's arguments, which know how the command treats the global
/// options and run the command.
pub(crate) trait Run {
    /// How the command treats the global options.
    fn spec(&self) -> Spec {
        Spec::FILES
    }

    /// The consent a command needs before it starts: its `--yes` and the
    /// action a refusal names (issue #228). These commands refuse before the
    /// model loads because their first bus action already acts on whatever is
    /// in programming mode (`assign`, `adopt`, `replace`, `commission`), or
    /// because every step asks (`learn`). `flash`, `apply`, `restore`, `write`
    /// and `test` first read and show what they will change, so they refuse at
    /// their prompt, through the same `confirm::confirm` and the same text.
    fn early_consent(&self) -> Option<(bool, String)> {
        None
    }

    /// Runs the command, returning the process exit code on success.
    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode>
    where
        Self: Sized;
}

/// The global options, resolved once for the subcommand: flag, then
/// environment, then `bussard.toml`, then discovery or the built-in default.
#[derive(Debug, Clone)]
pub(crate) struct Resolved {
    /// The model directory.
    pub dir: PathBuf,
    /// `--gateway`, else `BUSSARD_GATEWAY`; `bussard.toml` is consulted later,
    /// by [`crate::conn_cmd::resolve_config`].
    pub gateway: Option<String>,
    /// `--routing`.
    pub routing: bool,
    /// `--device-management`.
    pub device_management: bool,
    /// The keyring the command itself consumes (tool keys, group keys), when
    /// it has a use for one beyond the tunnel.
    pub keyring: Option<PathBuf>,
    /// `--json`.
    pub json: bool,
    /// `--allow-remote-gateway`.
    pub allow_remote_gateway: bool,
    /// `--skip-address-check`.
    pub skip_address_check: bool,
    /// `--refresh-facts`.
    pub refresh_facts: bool,
    /// The `-v` repeat count.
    pub verbose: u8,
}

impl Resolved {
    /// The model directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The keyring the command consumes, if any.
    pub(crate) fn keyring(&self) -> Option<&Path> {
        self.keyring.as_deref()
    }

    /// Connection overrides for a management command that consults the
    /// device facts (`reconstruct`, `describe`, `flash`, `plan`, `apply`).
    pub(crate) fn mgmt_with_facts(&self) -> ConnOverrides {
        ConnOverrides {
            refresh_facts: self.refresh_facts,
            ..self.mgmt()
        }
    }

    /// Connection overrides for a management command: the source-address
    /// check is consulted, the device facts are not.
    pub(crate) fn mgmt(&self) -> ConnOverrides {
        ConnOverrides {
            skip_address_check: self.skip_address_check,
            ..self.group()
        }
    }

    /// Connection overrides for a group-communication command (no
    /// source-address check, no device facts).
    pub(crate) fn group(&self) -> ConnOverrides {
        ConnOverrides {
            gateway: self.gateway.clone(),
            routing: self.routing,
            skip_address_check: false,
            refresh_facts: false,
            device_management: self.device_management,
        }
    }

    /// The keyring and tool key a management command identifies devices with.
    pub(crate) fn tool_keys<'a>(&'a self, tool_key: Option<&'a str>) -> ToolKeySource<'a> {
        ToolKeySource {
            keyring: self.keyring.as_deref(),
            tool_key,
        }
    }

    /// The options a step of a composite command (`commission`, `replace`)
    /// runs `flash` and `apply` with: no JSON, no `-v` memory plan, the stored
    /// device facts as they are.
    pub(crate) fn step(&self) -> Resolved {
        Resolved {
            json: false,
            verbose: 0,
            refresh_facts: false,
            ..self.clone()
        }
    }
}

/// `--tool-key` of the commands that read a device's tables.
#[derive(Debug, Clone, Default, Args)]
pub(crate) struct ToolKey {
    /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
    /// escape hatch for a simulator or a device with a synthetic key. Prefer
    /// `--keyring` for a real installation: a process argument is visible to
    /// other users on the machine.
    #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
    pub tool_key: Option<String>,
}

/// `--tool-key` of the commands that write a device back to a known state.
#[derive(Debug, Clone, Default, Args)]
pub(crate) struct BenchToolKey {
    /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
    /// escape hatch.
    #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
    pub tool_key: Option<String>,
}

/// `--yes` of a command that asks before it changes something.
#[derive(Debug, Clone, Copy, Default, Args)]
pub(crate) struct Consent {
    /// Skip the confirmation prompt. Without a terminal the command is
    /// refused unless this is given.
    #[arg(long)]
    pub yes: bool,
}

/// `--product` and `--application` of the commands that read a device's
/// parameters back (`plan`, `reconstruct`).
#[derive(Debug, Clone, Default, Args)]
pub(crate) struct ProductSelection {
    /// The device's vendor `.knxprod`, to read back and decode its parameter
    /// memory too. Default: the archive `bussard.lock` pins for
    /// the device in `<dir>/products/`. One that contradicts the lock is
    /// used with a warning.
    // Issue #119.
    #[arg(long, value_name = "FILE", conflicts_with = "line")]
    pub product: Option<PathBuf>,
    /// The application program id to decode the parameters with (default:
    /// the program the lock pins, else the order number's, else the sole one).
    #[arg(long, value_name = "REF", conflicts_with = "line")]
    pub application: Option<String>,
}

impl ProductSelection {
    /// The selection as the service takes it.
    pub(crate) fn selection(&self) -> bussard_service::params::Selection<'_> {
        bussard_service::params::Selection {
            product: self.product.as_deref(),
            application: self.application.as_deref(),
        }
    }
}
