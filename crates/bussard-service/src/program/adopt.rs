//! The adopt flow once (issue #902): `bussard adopt` and `knx_add_device`
//! give the device in programming mode an address, read it back, attach its
//! product data and write its device file and lock entry through these two
//! functions.
//!
//! 1. [`plan`] (read-only): what the device is (when asked, under its tool
//!    key for a Data Secure device, #201), the address it gets
//!    ([`flow::adopt_target`]) and the check that nothing answers there.
//! 2. [`run`]: the confirmation, the address write and the read-back of
//!    [`AssignFlow::assign`], the product data, the device file with its
//!    com-object table, for a Data Secure-activated device what ETS
//!    programmed into it (read over `A_SecureData`), for a KNX IP interface
//!    its KNXnet/IP settings, the history snapshot and the file itself.
//!
//! The steps underneath are [`crate::assign`] and [`crate::adopt::flow`];
//! the surfaces keep the wizard text, the questions and the rendering.

use std::path::{Path, PathBuf};

use bussard_model::history::SnapshotReason;
use bussard_model::knxnet::KnxnetFacts;
use bussard_model::schema::Device;
use bussard_model::{IndividualAddress, Model};

use super::assign::{Assign, AssignFlow, Assigned, Stop};
use super::{Event, Observer, Question, Step, chain};
use crate::adopt::flow::{self as adopt, SecureSummary, SelectedProduct};
use crate::assign::{Occupant, Verified, VerifyKey, identify, write_device_file};
use crate::identity::SecureStatus;
use crate::params::{MissingProduct, ParseHook, Selection};
use crate::secure::{SecureMaterial, ToolKeys};

/// The key material of an adopt run: the keyring's tool keys and the
/// keyring's path (for the refusal that names it).
#[derive(Clone, Copy)]
pub struct Keys<'a> {
    /// The loaded keyring (or nothing).
    pub keys: &'a ToolKeys,
    /// The keyring's path.
    pub keyring: Option<&'a Path>,
}

impl Keys<'_> {
    /// The refusal for a device that hides its mask while the keyring has no
    /// tool key for it.
    fn hidden(&self, target: IndividualAddress, current: IndividualAddress) -> Stop {
        Stop::Refused(adopt::activated_without_key(
            target,
            current,
            self.keys,
            self.keyring,
        ))
    }
}

/// What [`plan`] decided, before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// Where the device answered the programming-mode broadcast.
    pub current: IndividualAddress,
    /// The address it gets (`current` for a secured device).
    pub target: IndividualAddress,
    /// The keyring lists the device: it is adopted where ETS put it, over
    /// `A_SecureData` (issue #201).
    pub secured: bool,
    /// What it reported, when [`PlanRequest::identify`] asked.
    pub identified: Option<Verified>,
    /// What answers at `target`, when `force` let the plan through anyway.
    pub forced: Option<Occupant>,
}

/// The inputs of [`plan`].
#[derive(Clone, Copy)]
pub struct PlanRequest<'a> {
    /// The address asked for, else the next free one.
    pub address: Option<&'a str>,
    /// The model the address is checked against.
    pub model: Option<&'a Model>,
    /// The keyring.
    pub keys: Keys<'a>,
    /// Read what the device is before anything is written (the chat's
    /// `identified` step).
    pub identify: bool,
    /// Go on although another device answers at the target (`--force`).
    pub force: bool,
}

/// Plans the adoption of the device in programming mode at `current`:
/// what it is (when asked), the address it gets and the check that nothing
/// answers there. Read-only.
///
/// # Errors
///
/// The identification failed, the device hides its mask without a key, the
/// address is refused, or something answers at it.
pub async fn plan<O: Observer>(
    flow: &AssignFlow<'_>,
    current: IndividualAddress,
    req: PlanRequest<'_>,
    observer: &mut O,
) -> Result<Planned, Stop> {
    let secured = req.keys.keys.lists(current);
    let identified = if req.identify {
        observer.event(Event::Step(Step::Identify { at: current }));
        let key = secured.then(|| req.keys.keys.tool_key(current)).flatten();
        let identified = identify(flow.service, flow.source, current, key)
            .await
            .map_err(|source| Stop::Identify { current, source })?;
        if identified.secure == SecureStatus::ActivatedNoKey {
            return Err(req.keys.hidden(current, current));
        }
        Some(identified)
    } else {
        None
    };
    let target = adopt::adopt_target(req.address, current, secured, req.model)?;
    // A device that keeps its address is the one answering there.
    let forced = if target == current {
        None
    } else {
        flow.check_free(target, req.force, observer).await?
    };
    Ok(Planned {
        current,
        target,
        secured,
        identified,
        forced,
    })
}

/// The product data a run attaches, asked for once the device was read
/// back: called with the order number the device reported.
pub type ProductHook<'h> = &'h mut (dyn FnMut(Option<&str>) -> Option<SelectedProduct> + Send);

/// The inputs of [`run`].
pub struct RunRequest<'a, 'h> {
    /// The model directory.
    pub dir: &'a Path,
    /// The model, when there is one.
    pub model: Option<&'a Model>,
    /// The keyring.
    pub keys: Keys<'a>,
    /// The question before the write.
    pub question: &'a Question,
    /// Probe the target once more right before the write (the chat's yes
    /// came a while ago).
    pub recheck_target: bool,
    /// The product data, given the order number the device reported.
    pub product: ProductHook<'h>,
    /// The `.knxprod` the parameters of a secured device decode with
    /// (`--product`), else the stored archive.
    pub product_file: Option<&'a Path>,
    /// Hears each product parse (the CLI's `--timing`).
    pub on_parse: Option<ParseHook>,
    /// The history snapshot taken before the device file is written.
    pub snapshot: SnapshotReason,
}

/// What a read of the KNXnet/IP parameter object gave (issue #391).
#[derive(Debug, Clone, PartialEq)]
pub enum Knxnet {
    /// Not read: the device file already has a `[knxnet]` table.
    Kept,
    /// The device has no KNXnet/IP parameter object.
    None,
    /// The settings read, recorded in the device file.
    Read(Box<KnxnetFacts>),
    /// The read failed; the device file has no `[knxnet]` table.
    Failed(String),
}

/// An adopted device.
#[derive(Debug, Clone)]
pub struct Adopted {
    /// The address write and its read-back.
    pub assigned: Assigned,
    /// The product data attached, if any.
    pub selected: Option<SelectedProduct>,
    /// The device reported an order number the product data does not list:
    /// the order number read.
    pub order_mismatch: Option<String>,
    /// The device file written.
    pub device: Device,
    /// Its path.
    pub path: PathBuf,
    /// What a Data Secure adoption recorded.
    pub secure: Option<SecureSummary>,
    /// The KNXnet/IP settings.
    pub knxnet: Knxnet,
}

/// Adopts the planned device: asks, writes the address and reads it back
/// ([`AssignFlow::assign`]), attaches the product data, records what a
/// secured device holds and its KNXnet/IP settings, snapshots the history
/// and writes the device file with its lock entry (the serial, #752).
///
/// # Errors
///
/// The key material, the question, the address write or the read-back, the
/// secured read, or the device file failed.
pub async fn run<O: Observer>(
    flow: &AssignFlow<'_>,
    plan: &Planned,
    req: RunRequest<'_, '_>,
    observer: &mut O,
) -> Result<Adopted, Stop> {
    let (current, target) = (plan.current, plan.target);
    let material = if plan.secured {
        req.keys.keys.material(current, true).map_err(Stop::other)?
    } else {
        SecureMaterial::default()
    };
    if req.recheck_target && target != current {
        flow.check_free(target, false, observer).await?;
    }
    // A keyring-listed device is verified over A_SecureData with its tool
    // key; adopt does not clear programming mode in the read-back.
    let key = VerifyKey {
        tool_key: material.tool_key.clone(),
        from_old_address: false,
    };
    let assigned = flow
        .assign(
            &Assign {
                current,
                target,
                question: Some(req.question),
                key: &key,
                clear_programming_mode: false,
                identified: plan.identified.as_ref(),
                refuse_hidden: true,
                require_identified: false,
                forget_facts: None,
            },
            observer,
        )
        .await
        .map_err(|stop| match stop {
            Stop::Hidden(_) => req.keys.hidden(target, current),
            other => other,
        })?;
    let verified = &assigned.verified;

    let selected = (req.product)(verified.order.as_deref());
    let order_mismatch = match (&selected, verified.order.as_deref()) {
        (Some(sel), Some(read))
            if !sel.order_numbers.is_empty() && !adopt::order_matches(read, &sel.order_numbers) =>
        {
            Some(read.to_string())
        }
        _ => None,
    };

    observer.event(Event::Step(Step::DeviceFile));
    let device = adopt::build_device(target, verified, selected.as_ref());
    // A Data Secure device is commissioned: read what ETS programmed into it
    // (links, parameters, security object) over A_SecureData (issue #201).
    let (mut device, model_out, secure) = if verified.secure == SecureStatus::Activated {
        observer.event(Event::Step(Step::ReadSecured { target }));
        let inputs = SecuredInputs {
            dir: req.dir,
            model: req.model,
            product_file: req.product_file,
            on_parse: req.on_parse,
        };
        let (device, model, summary) =
            read_secured(flow, plan, inputs, device, selected.as_ref(), &material).await?;
        (device, Some(model), Some(summary))
    } else {
        (device, None, None)
    };
    // A KNX IP interface (issue #391): its KNXnet/IP settings become the
    // device file's `[knxnet]` table. A table the model holds is the user's.
    let had_knxnet = device.knxnet.is_some()
        || req
            .model
            .and_then(|m| m.devices.get(&target))
            .is_some_and(|d| d.device.knxnet.is_some());
    let knxnet = if had_knxnet {
        Knxnet::Kept
    } else {
        match adopt::read_knxnet_settings(flow.service, flow.source, target, req.dir, &material)
            .await
        {
            Ok(Some(facts)) => {
                device.knxnet = Some(facts.as_config());
                Knxnet::Read(Box::new(facts))
            }
            Ok(None) => Knxnet::None,
            Err(err) => Knxnet::Failed(chain(&err)),
        }
    };
    crate::setup::import::snapshot(req.dir, req.snapshot, observer);
    let path = write_device_file(
        model_out.as_ref().or(req.model),
        req.dir,
        device.clone(),
        verified.serial.as_deref(),
        "device file",
    )?;
    Ok(Adopted {
        assigned,
        selected,
        order_mismatch,
        device,
        path,
        secure,
        knxnet,
    })
}

/// What the secured read takes from a [`RunRequest`].
#[derive(Clone, Copy)]
struct SecuredInputs<'a> {
    /// The model directory.
    dir: &'a Path,
    /// The model.
    model: Option<&'a Model>,
    /// `--product`.
    product_file: Option<&'a Path>,
    /// The parse hook.
    on_parse: Option<ParseHook>,
}

/// The secured read of an activated device and its record in a copy of the
/// model ([`adopt::read_secured`], [`adopt::record_secured`]).
async fn read_secured(
    flow: &AssignFlow<'_>,
    plan: &Planned,
    req: SecuredInputs<'_>,
    device: Device,
    selected: Option<&SelectedProduct>,
    material: &SecureMaterial,
) -> Result<(Device, Model, SecureSummary), Stop> {
    let target = plan.target;
    // The product the parameter read-back decodes with, found through the
    // device file being written (its order number and application).
    let with_device = adopt::with_device(req.model, &device, target);
    let mut notes = Vec::new();
    let lookup = crate::params::resolve_product(
        req.dir,
        Selection {
            product: req.product_file,
            application: selected.map(|s| s.application_ref.as_str()),
        },
        Some(&with_device),
        target,
        MissingProduct::Warn,
        req.on_parse,
    );
    let product = match lookup {
        Ok(lookup) => {
            if let Some(warning) = lookup.warning {
                notes.push(format!("parameters not read: {warning}"));
            }
            lookup.source
        }
        Err(err) => {
            notes.push(format!("parameters not read: {}", chain(&err)));
            None
        }
    };
    let read = adopt::read_secured(
        flow.service,
        flow.source,
        target,
        &with_device,
        product.as_ref(),
        material,
        notes,
    )
    .await
    .map_err(|source| {
        Stop::other(crate::ServiceError::context(
            format!("reading {target} over A_SecureData with its tool key"),
            source,
        ))
    })?;
    adopt::record_secured(
        req.model,
        device,
        target,
        selected,
        &read,
        material,
        plan.current,
    )
    .map_err(Stop::other)
}
