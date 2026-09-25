//! The lock-side facts of one device, derived from its application program
//! and parameter values: channel handles, object keys, parameter keys and the
//! channel labels `bussard.lock` records (see "Key derivation" in
//! `docs/model-format.md`).
//!
//! `bussard import` derives them from the ETS project's values and `bussard
//! adopt` from the vendor defaults, through the same two calls:
//! [`derive_facts`] evaluates the application's Dynamic section and names what
//! it shows, and [`apply_facts`] writes the result into a [`Device`] so a save
//! produces the readable device file and its lock entry.
//!
//! The rules, in short:
//!
//! * **Channel handle:** the slug of the channel `Name` when it is a plain
//!   label (letters, digits, spaces; at most 24 characters as a slug), else
//!   the slug of the channel's translated `Text` without its label; then
//!   `-<Number>` (for a channel of a module instance, the instance ordinal)
//!   unless the slug already ends with it; otherwise `ch-<ordinal>`, the
//!   ordinal being the channel's 1-based position in walk order. Handles that
//!   collide get `-<ordinal>` appended.
//! * **Object key:** the first of slug(`FunctionText`), slug(`Text` +
//!   `FunctionText`) and those two with `-<number>` that no other object of
//!   the same scope (channel, or the device level) also yields. No key when the
//!   vendor gives neither text.
//! * **Parameter key:** slug of the ref's `Text` override, else the
//!   parameter's `Text`, else its `Name`, when unique in the scope; else
//!   `<page>.<slug>` with the innermost titled `ParameterBlock` that makes it
//!   unique (falling back outward); else the escape hatch `<slug>@<ref>`. A
//!   parameter belongs to a channel's scope only when the evaluated tree shows
//!   it inside that channel; everything else is device level. A channel's
//!   label parameter gets no key.
//!
//! One parameter per memory cell is listed (see
//! [`bussard_ets::dynamic::visible_parameter_refs`]); parameters of type
//! `TypeNone` (headings and notes, no value) are left out.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bussard_ets::application::{
    ApplicationProgram, BlockRef, ChannelRef, ParameterType, ResolvedComObject,
};
use bussard_ets::dynamic::{
    ActiveComObject, ActiveParameter, DynamicConfig, Placement, evaluate_dynamic, selector_key,
    visible_parameter_refs,
};
use bussard_model::param_model::enum_label;
use bussard_model::schema::{Channel, ComObject, Device, LockedParameter, Spelling};
use bussard_model::{Dpt, Flags, label_mem_key, param_mem_key, slug};

use crate::build::{base_offset_args, resolve_placeholders};

/// Keys a channel table cannot give a parameter or object: `name` is the
/// channel label, and a table of only `send`/`listen`/`name` reads as an
/// object.
const RESERVED: [&str; 3] = ["name", "send", "listen"];

/// Module-instance argument values, keyed by the project module-instance
/// selector (`MD-1_M-3_MI-1`) and then by app-relative argument id
/// (`MD-1_A-2`): what `{{Arg…}}` placeholders resolve against.
pub type ModuleArgs = HashMap<String, HashMap<String, String>>;

/// Everything `bussard.lock` records about one device's channels, objects and
/// parameters, before it is written into a [`Device`] by [`apply_facts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceFacts {
    /// The channels the evaluated configuration shows, in walk order.
    pub channels: Vec<ChannelFact>,
    /// The com-objects the configuration instantiates, by number.
    pub objects: Vec<ObjectFact>,
    /// One entry per parameter memory cell, in walk order.
    pub parameters: Vec<ParameterFact>,
    /// The memory base offset of every reached module instance that has one,
    /// keyed by module-instance selector (`MD-1_M-3_MI-1`), read from the
    /// application's `<Module>` arguments.
    pub module_bases: BTreeMap<String, u32>,
}

/// One `channels[]` entry of the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelFact {
    /// The handle, `[channel.<key>]` in the device file.
    pub key: String,
    /// The channel id in device form (`CH-2`, `MD-1_M-3_MI-1_CH-1`).
    pub id: String,
    /// The vendor's channel number.
    pub number: Option<u32>,
    /// The vendor's channel text with the label and module arguments filled
    /// in.
    pub text: Option<String>,
    /// The ref of the text parameter that labels the channel, in device form
    /// (`MD-1_M-3_MI-1_P-1_R-1`). Only a text parameter counts as a label.
    pub label_ref: Option<String>,
    /// The label parameter's effective value under the derivation's values.
    pub label: Option<String>,
    /// The module instance's memory base offset, for a module channel.
    pub base: Option<u32>,
}

/// One `objects[]` entry of the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFact {
    /// The com-object number.
    pub number: u16,
    /// The key the device file uses, when one could be derived.
    pub key: Option<String>,
    /// The owning channel id (a [`ChannelFact::id`]).
    pub channel: Option<String>,
    /// The object `Text`, label and arguments filled in.
    pub text: Option<String>,
    /// The object `FunctionText`.
    pub function: Option<String>,
    /// The DPT (declared, else derived from the object size).
    pub dpt: Option<Dpt>,
    /// The object size, lowercase, only when there is no DPT.
    pub size: Option<String>,
    /// The flags (base merged with the ref).
    pub flags: Flags,
    /// The com-object ref in device form (`MD-1_M-3_MI-1_O-2-0_R-38`).
    pub reference: String,
}

/// One `parameters[]` entry of the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterFact {
    /// The key the device file uses (`betriebsart`, `sollwerte.komfort`, or
    /// the escape hatch `<slug>@<ref>`).
    pub key: String,
    /// The owning channel id (a [`ChannelFact::id`]), if any.
    pub channel: Option<String>,
    /// The visible ref in device form (`MD-3_M-18_MI-1_P-14_R-14`).
    pub reference: String,
    /// The app-relative parameter id, the memory cell (`MD-3_P-14`).
    pub param: String,
    /// For an enumeration, its `(code, text)` pairs.
    pub enum_labels: Vec<(i64, String)>,
}

/// Derives the lock-side facts of a device running `app` with parameter
/// `values` (keyed by app-relative ref with the module-instance selector, the
/// form ETS projects and device files use; empty for the vendor defaults).
/// `module_args` supplies text arguments for `{{Arg…}}` placeholders; the
/// application's own numeric `<Module>` arguments fill in what it lacks.
pub fn derive_facts(
    app: &ApplicationProgram,
    values: &BTreeMap<String, String>,
    module_args: &ModuleArgs,
) -> DeviceFacts {
    let config = if app.dynamic.is_empty() {
        everything_shown(app)
    } else {
        evaluate_dynamic(app, values)
    };
    let ctx = Ctx {
        app,
        config: &config,
        args: merged_args(&config, module_args),
    };

    let channels = derive_channels(&ctx);
    let label_params: BTreeSet<String> = channels
        .iter()
        .filter_map(|c| c.label_ref.as_deref())
        .filter_map(|r| param_key_of_ref(app, r))
        .collect();
    let objects = derive_objects(&ctx, &channels);
    let parameters = derive_parameters(&ctx, &channels, &objects, &label_params);
    let module_bases = module_bases(app, &config);
    let channels = channels
        .into_iter()
        .map(|mut c| {
            if let Some(selector) = channel_selector(&c.id) {
                c.base = module_bases.get(selector).copied();
            }
            c
        })
        .collect();
    DeviceFacts {
        channels,
        objects,
        parameters,
        module_bases,
    }
}

/// Writes `facts` into `device`: channel handles, texts and labels, object
/// keys and texts, the lock's parameter index, and the parameter values.
///
/// `stored` holds the values the device file keeps (the non-default ones),
/// keyed by app-relative ref with the module-instance selector. Each is keyed
/// in memory the way the loader keys it ([`param_mem_key`] through the fact's
/// file key, [`label_mem_key`] for a channel label, the `<slug>@<ref>` escape
/// hatch otherwise), and an enum value whose code has a usable label is
/// recorded to be written as that label. Objects the device already carries
/// (from the ETS project, with its flag and DPT overrides) keep those and gain
/// the derived key, texts and channel; the others are added. A device without
/// module bases (a fresh one) takes the facts' bases.
pub fn apply_facts(
    device: &mut Device,
    app: &ApplicationProgram,
    facts: &DeviceFacts,
    stored: &BTreeMap<String, String>,
) {
    for ch in &facts.channels {
        let label = ch
            .label_ref
            .as_deref()
            .and_then(|r| stored.get(r))
            .filter(|v| !v.trim().is_empty());
        let name = label
            .cloned()
            .or_else(|| ch.text.clone())
            .unwrap_or_default();
        device.channels.insert(
            ch.id.clone(),
            Channel {
                name,
                key: Some(ch.key.clone()),
                number: ch.number,
                text: ch.text.clone(),
            },
        );
        match &ch.label_ref {
            Some(r) => {
                device.lock.channel_labels.insert(ch.id.clone(), r.clone());
            }
            None => {
                device.lock.channel_labels.remove(&ch.id);
            }
        }
    }
    // The project's bases are authoritative; a fresh device has none.
    if device.module_bases.is_empty() {
        device.module_bases = facts.module_bases.clone();
    }

    for o in &facts.objects {
        let co = device
            .com_objects
            .entry(o.number)
            .or_insert_with(|| ComObject {
                dpt: o.dpt,
                size: o.size.clone(),
                flags: o.flags,
                reference: Some(o.reference.clone()),
                ..ComObject::default()
            });
        co.key = o.key.clone();
        co.channel = o.channel.clone();
        co.text = o.text.clone();
        co.function = o.function.clone();
    }

    device.lock.parameters = facts
        .parameters
        .iter()
        .map(|p| {
            (
                p.reference.clone(),
                LockedParameter {
                    key: p.key.clone(),
                    channel: p.channel.clone(),
                    param: Some(p.param.clone()),
                },
            )
        })
        .collect();

    let labels: BTreeSet<&str> = facts
        .channels
        .iter()
        .filter_map(|c| c.label_ref.as_deref())
        .collect();
    let by_ref: BTreeMap<&str, &ParameterFact> = facts
        .parameters
        .iter()
        .map(|p| (p.reference.as_str(), p))
        .collect();
    let keys_by_param: BTreeMap<String, &str> = facts
        .parameters
        .iter()
        .filter_map(|p| Some((param_key_of_ref(app, &p.reference)?, p.key.as_str())))
        .collect();
    device.parameters.clear();
    device.lock.spellings.clear();
    for (reference, value) in stored {
        let (key, enum_labels) = if labels.contains(reference.as_str()) {
            (label_mem_key(reference), Vec::new())
        } else if let Some(p) = by_ref.get(reference.as_str()) {
            (param_mem_key(&p.key, reference), p.enum_labels.clone())
        } else {
            let sibling =
                param_key_of_ref(app, reference).and_then(|k| keys_by_param.get(&k).copied());
            (
                escape_key(app, reference, sibling),
                enum_labels_of_ref(app, reference),
            )
        };
        if let Some(text) = enum_label(&enum_labels, value) {
            device.lock.spellings.insert(
                key.clone(),
                Spelling {
                    code: value.clone(),
                    text: text.to_string(),
                },
            );
        }
        device.parameters.insert(key, value.clone());
    }
}

// ---------------------------------------------------------------------------
// Shared context
// ---------------------------------------------------------------------------

/// What every derivation step reads.
struct Ctx<'a> {
    app: &'a ApplicationProgram,
    config: &'a DynamicConfig,
    /// Argument values per module-instance selector, as strings.
    args: ModuleArgs,
}

impl Ctx<'_> {
    /// The project selector (`MD-1_M-3_MI-1`) of module `module`.
    fn selector(&self, module: Option<usize>) -> Option<String> {
        self.config
            .module_instance_id(module)
            .map(|id| format!("{id}_MI-1"))
    }

    /// `text` with `{{Arg…}}` resolved in module `module` and numbered
    /// tokens stripped, whitespace-normalized; `None` when nothing remains.
    fn clean(&self, text: &str, module: Option<usize>) -> Option<String> {
        let selector = self.selector(module);
        resolve_placeholders(text, self.app, selector.as_deref(), &self.args)
    }

    /// `text` with its label placeholder filled from `label_ref`, then
    /// cleaned like [`Ctx::clean`].
    fn labelled(
        &self,
        text: &str,
        module: Option<usize>,
        label_ref: Option<&str>,
    ) -> Option<String> {
        let filled = self.config.labelled_text(self.app, module, text, label_ref);
        self.clean(&filled, module)
    }
}

/// The configuration of a program without a Dynamic section: every
/// com-object ref and parameter ref is part of the device, at the device
/// level, in id order.
fn everything_shown(app: &ApplicationProgram) -> DynamicConfig {
    let prefix = format!("{}_", app.id);
    let relative = |id: &str| id.strip_prefix(&prefix).unwrap_or(id).to_string();
    let mut objects: Vec<String> = app.com_object_refs.keys().map(|k| relative(k)).collect();
    objects.sort();
    let mut params: Vec<String> = app.parameter_refs.keys().map(|k| relative(k)).collect();
    params.sort();
    let shown = Placement {
        shown: true,
        ..Placement::default()
    };
    let mut config = DynamicConfig::default();
    config.com_object_placements = vec![shown.clone(); objects.len()];
    config.com_objects = objects
        .into_iter()
        .map(|com_object_ref_id| ActiveComObject {
            module: None,
            com_object_ref_id,
        })
        .collect();
    config.parameter_placements = vec![shown; params.len()];
    config.parameters = params
        .into_iter()
        .map(|param_ref_id| ActiveParameter {
            module: None,
            param_ref_id,
        })
        .collect();
    config
}

/// The module arguments per selector: the project's, completed by the
/// numeric `<Module>` arguments of the reached instances.
fn merged_args(config: &DynamicConfig, project: &ModuleArgs) -> ModuleArgs {
    let mut out = project.clone();
    for m in &config.modules {
        let entry = out.entry(format!("{}_MI-1", m.id)).or_default();
        for (arg, value) in &m.args {
            entry
                .entry(arg.clone())
                .or_insert_with(|| value.to_string());
        }
    }
    out
}

/// The module-instance selector of a device-form channel id.
fn channel_selector(id: &str) -> Option<&str> {
    let (selector, _) = id.rsplit_once("_CH-")?;
    (selector.starts_with("MD-") && selector.contains("_MI-")).then_some(selector)
}

/// The module definition (`MD-1`) of an app-relative id, if it has one.
fn module_def_of(id: &str) -> Option<&str> {
    id.starts_with("MD-")
        .then(|| id.split_once('_').map(|(md, _)| md))
        .flatten()
}

/// The module the channel of `placement` belongs to: the placement's module
/// when the channel is one of that module definition's, else the
/// application.
fn channel_module(ctx: &Ctx<'_>, placement: &Placement, channel: &ChannelRef) -> Option<usize> {
    let module = placement.module?;
    let def = &ctx.config.modules.get(module)?.module_def;
    (module_def_of(&channel.id) == Some(def.as_str())).then_some(module)
}

/// The device-form id of the channel a placement sits in.
fn placed_channel_id(ctx: &Ctx<'_>, placement: &Placement) -> Option<String> {
    let channel = placement.channel.as_ref()?;
    let module = channel_module(ctx, placement, channel);
    let instance = ctx.config.module_instance_id(module);
    Some(selector_key(instance, &channel.id))
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

/// The channels the placements name, in first-seen (walk) order, with their
/// handles.
fn derive_channels(ctx: &Ctx<'_>) -> Vec<ChannelFact> {
    let shown_params = ctx.config.parameter_placements.iter().filter(|p| p.shown);
    let placements = shown_params.chain(ctx.config.com_object_placements.iter());

    // (device id) -> (channel ref, module) in first-seen order.
    let mut seen: Vec<(String, ChannelRef, Option<usize>)> = Vec::new();
    for placement in placements {
        let Some(channel) = &placement.channel else {
            continue;
        };
        let module = channel_module(ctx, placement, channel);
        let id = selector_key(ctx.config.module_instance_id(module), &channel.id);
        if !seen.iter().any(|(s, _, _)| *s == id) {
            seen.push((id, channel.clone(), module));
        }
    }

    let mut out: Vec<ChannelFact> = Vec::new();
    let mut handles: Vec<String> = Vec::new();
    for (index, (id, channel, module)) in seen.iter().enumerate() {
        let ordinal = index + 1;
        let name = channel
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty());
        let module_ordinal = module
            .and_then(|m| ctx.config.modules.get(m))
            .map(|m| m.ordinal);
        // The handle reads the text without its label (a placeholder's
        // default text stays), so renaming the channel does not move it.
        let handle_text = channel
            .text
            .as_deref()
            .and_then(|t| ctx.clean(&placeholder_defaults(t), *module));
        handles.push(base_handle(
            name,
            handle_text.as_deref(),
            module_ordinal.is_some(),
            module_ordinal.or(channel.number),
            ordinal,
        ));

        let label_ref = channel
            .text_parameter_ref
            .as_deref()
            .filter(|r| is_text_parameter(ctx.app, r));
        let label = label_ref.and_then(|r| ctx.config.label(ctx.app, *module, r));
        let text = channel
            .text
            .as_deref()
            .and_then(|t| ctx.labelled(t, *module, label_ref));
        let label_ref = label_ref.map(|r| {
            let scope = ref_scope(ctx, *module, r);
            selector_key(ctx.config.module_instance_id(scope), r)
        });
        out.push(ChannelFact {
            key: String::new(),
            id: id.clone(),
            number: channel.number,
            text,
            label_ref,
            label,
            base: None,
        });
    }

    let keys = unique_handles(&handles);
    for (fact, key) in out.iter_mut().zip(keys) {
        fact.key = key;
    }
    out
}

/// A channel's handle before collisions: the slug of the channel `Name` when
/// it is a plain label (see [`is_plain_label`]) that the text, if any,
/// contains, else the slug of its `Text`
/// (label placeholder stripped), followed by `-<n>` unless the slug already
/// ends with it; `ch-<ordinal>` when neither gives a slug. `n` is the module
/// instance ordinal for a module channel and the channel `Number` otherwise.
///
/// A module channel's `Name` is shared by every instance, while its `Text`
/// is filled in from the instance's arguments: when that text ends with a
/// number (`Ventilausgang 3`), it is the instance's own number, so the text
/// is the handle as is.
fn base_handle(
    name: Option<&str>,
    text: Option<&str>,
    in_module: bool,
    n: Option<u32>,
    ordinal: usize,
) -> String {
    let text_stem = text.map(slug).filter(|s| s != "x");
    if in_module
        && let Some(stem) = &text_stem
        && ends_with_number(stem)
    {
        return stem.clone();
    }
    // A plain Name the text does not contain is in another language than
    // the texts (ABB's `Manual operation` next to `Manuelle Bedienung`).
    let stem = name
        .filter(|n| is_plain_label(n))
        .map(slug)
        .filter(|n| text_stem.as_ref().is_none_or(|t| t.contains(n.as_str())))
        .or(text_stem);
    match (stem, n) {
        (Some(stem), Some(n)) => {
            let n = n.to_string();
            if stem == n || stem.ends_with(&format!("-{n}")) {
                stem
            } else {
                format!("{stem}-{n}")
            }
        }
        (Some(stem), None) => stem,
        (None, _) => format!("ch-{ordinal}"),
    }
}

/// Whether a slug's last `-`-separated part is a number.
fn ends_with_number(stem: &str) -> bool {
    stem.rsplit('-')
        .next()
        .is_some_and(|last| !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
        && stem.contains('-')
}

/// `text` with each numbered placeholder that carries a default text
/// (`{{0: Eingang g+h}}`) replaced by that text; placeholders without one
/// (`{{0}}`, `{{0:...}}`) are left for [`Ctx::clean`] to strip.
fn placeholder_defaults(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let Some(close) = rest[open..].find("}}").map(|c| open + c) else {
            break;
        };
        out.push_str(&rest[..open]);
        let token = &rest[open + 2..close];
        let default = token
            .split_once(':')
            .filter(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .map(|(_, d)| d.trim())
            .filter(|d| !d.is_empty() && !d.chars().all(|c| c == '.' || c == '…'));
        match default {
            Some(d) => out.push_str(d),
            None => out.push_str(&rest[open..close + 2]),
        }
        rest = &rest[close + 2..];
    }
    out.push_str(rest);
    out
}

/// The longest slug a channel `Name` may have to count as a plain label.
const PLAIN_LABEL_MAX: usize = 24;

/// Whether a channel `Name` reads as a label rather than an internal id:
/// only letters (umlauts included), digits and spaces, at least one letter,
/// and a slug of at most [`PLAIN_LABEL_MAX`] characters. `SMOD0_Motion_MP`,
/// `LICHTAUSGANG_1` and `W1 - TSM - Wippe 1` are not.
fn is_plain_label(name: &str) -> bool {
    name.chars().any(char::is_alphabetic)
        && name
            .chars()
            .all(|c| c.is_alphabetic() || c.is_ascii_digit() || c == ' ')
        && slug(name).len() <= PLAIN_LABEL_MAX
}

/// The handles made unique: every handle that repeats gets `-<ordinal>` (the
/// channel's 1-based position) appended.
fn unique_handles(handles: &[String]) -> Vec<String> {
    let mut taken: BTreeSet<String> = BTreeSet::new();
    handles
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let repeated = handles.iter().filter(|o| *o == h).count() > 1;
            let mut key = if repeated {
                format!("{h}-{}", i + 1)
            } else {
                h.clone()
            };
            while taken.contains(&key) {
                key.push_str(&format!("-{}", i + 1));
            }
            taken.insert(key.clone());
            key
        })
        .collect()
}

/// The module a ref resolves in when read from `module`: the instance for
/// one of its own (or any module) refs, the application for an application
/// ref (the walk's scoping rule).
fn ref_scope(ctx: &Ctx<'_>, module: Option<usize>, ref_id: &str) -> Option<usize> {
    module
        .filter(|_| ref_id.starts_with("MD-"))
        .filter(|m| ctx.config.modules.get(*m).is_some())
}

/// Whether the app-relative parameter ref points at a text parameter.
fn is_text_parameter(app: &ApplicationProgram, param_ref: &str) -> bool {
    matches!(
        parameter_kind(app, param_ref),
        Some(ParameterType::Text { .. })
    )
}

/// The type of the parameter an app-relative ref points at.
fn parameter_kind<'a>(app: &'a ApplicationProgram, param_ref: &str) -> Option<&'a ParameterType> {
    let pref = app.parameter_ref(param_ref)?;
    let param = app.parameters.get(&pref.ref_id)?;
    let ty = param.parameter_type.as_deref()?;
    app.parameter_types.get(ty).map(|d| &d.kind)
}

/// The device-form parameter key (`MD-1_M-3_MI-1_P-1`) of a device-form ref.
fn param_key_of_ref(app: &ApplicationProgram, reference: &str) -> Option<String> {
    let (instance, rel) = bussard_ets::dynamic::split_selector(reference);
    let pref = app.parameter_ref(&rel)?;
    let prefix = format!("{}_", app.id);
    let pid = pref.ref_id.strip_prefix(&prefix).unwrap_or(&pref.ref_id);
    Some(selector_key(instance.as_deref(), pid))
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

/// The instantiated com-objects with their keys.
fn derive_objects(ctx: &Ctx<'_>, channels: &[ChannelFact]) -> Vec<ObjectFact> {
    let app = ctx.app;
    let prefix = format!("{}_", app.id);
    let mut by_number: BTreeMap<u16, (ObjectFact, Option<String>, Option<String>)> =
        BTreeMap::new();
    for (active, placement) in ctx
        .config
        .com_objects
        .iter()
        .zip(&ctx.config.com_object_placements)
    {
        let Some((base, cref)) = app.resolve(&active.com_object_ref_id) else {
            continue;
        };
        let offset = base
            .base_number_ref
            .as_deref()
            .map(|arg| arg.strip_prefix(&prefix).unwrap_or(arg))
            .and_then(|arg| ctx.config.module_args(active.module)?.get(arg).copied())
            .unwrap_or(0);
        let Ok(number) = u16::try_from(i64::from(base.number) + offset) else {
            continue;
        };
        if by_number.contains_key(&number) {
            continue;
        }
        let rc = ResolvedComObject { base, cref };
        let raw_text = cref
            .text
            .as_deref()
            .or(base.text.as_deref())
            .filter(|t| !t.trim().is_empty());
        let key_text = raw_text.and_then(|t| ctx.clean(t, placement.module));
        let text =
            raw_text.and_then(|t| ctx.labelled(t, placement.module, rc.text_parameter_ref()));
        let function = rc
            .function_text()
            .and_then(|t| ctx.clean(t, placement.module));
        let size = rc.object_size().map(|s| s.trim().to_ascii_lowercase());
        let dpt = rc.dpt().or_else(|| {
            rc.object_size()
                .and_then(crate::dpt_map::dpt_from_object_size)
        });
        let channel =
            placed_channel_id(ctx, placement).filter(|id| channels.iter().any(|c| c.id == *id));
        let cref_rel = cref.id.strip_prefix(&prefix).unwrap_or(&cref.id);
        let instance = ctx.config.module_instance_id(active.module);
        by_number.insert(
            number,
            (
                ObjectFact {
                    number,
                    key: None,
                    channel,
                    text,
                    function: function.clone(),
                    dpt,
                    size: if dpt.is_some() { None } else { size },
                    flags: rc.flags(),
                    reference: selector_key(instance, cref_rel),
                },
                key_text,
                function,
            ),
        );
    }

    // Candidate keys per object, then the first one unique in its scope.
    let candidates: BTreeMap<u16, (Option<String>, Vec<String>)> = by_number
        .iter()
        .map(|(n, (o, text, function))| {
            let list = object_candidates(
                *n,
                text.as_deref(),
                function.as_deref(),
                o.channel.is_some(),
            );
            (*n, (o.channel.clone(), list))
        })
        .collect();
    let mut out = Vec::with_capacity(by_number.len());
    for (n, (mut fact, _, _)) in by_number {
        let (scope, list) = &candidates[&n];
        fact.key = list
            .iter()
            .find(|c| {
                candidates
                    .iter()
                    .filter(|(m, (s, l))| **m != n && s == scope && l.contains(c))
                    .count()
                    == 0
            })
            .cloned();
        out.push(fact);
    }
    out
}

/// An object's key candidates, shortest first: slug(function), slug(text +
/// function), each with `-<number>`. Numeric and reserved spellings are
/// skipped (a bare number already names the object by number).
fn object_candidates(
    number: u16,
    text: Option<&str>,
    function: Option<&str>,
    in_channel: bool,
) -> Vec<String> {
    let mut plain: Vec<String> = Vec::new();
    if let Some(f) = function {
        plain.push(slug(f));
    }
    if let Some(t) = text {
        let joined = match function {
            Some(f) => format!("{t} {f}"),
            None => t.to_string(),
        };
        plain.push(slug(&joined));
    }
    let numbered: Vec<String> = plain.iter().map(|p| format!("{p}-{number}")).collect();
    let mut out: Vec<String> = Vec::new();
    for c in plain.into_iter().chain(numbered) {
        let bad = c.parse::<u16>().is_ok() || (in_channel && RESERVED.contains(&c.as_str()));
        if !bad && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// One parameter on its way to a key.
struct Pending {
    fact: ParameterFact,
    /// slug of the parameter text.
    base: String,
    /// Page slugs, innermost block first.
    pages: Vec<String>,
    /// Whether the evaluated tree shows it (an `<Assign>` target is not).
    shown: bool,
}

/// The visible parameters with their keys.
fn derive_parameters(
    ctx: &Ctx<'_>,
    channels: &[ChannelFact],
    objects: &[ObjectFact],
    label_params: &BTreeSet<String>,
) -> Vec<ParameterFact> {
    let app = ctx.app;
    let mut pending: Vec<Pending> = Vec::new();
    for v in visible_parameter_refs(app, ctx.config) {
        if label_params.contains(&v.key) {
            continue;
        }
        let Some(pref) = app.parameter_ref(&v.param_ref_id) else {
            continue;
        };
        let Some(param) = app.parameters.get(&pref.ref_id) else {
            continue;
        };
        let kind = param
            .parameter_type
            .as_deref()
            .and_then(|t| app.parameter_types.get(t))
            .map(|d| &d.kind);
        if matches!(kind, Some(ParameterType::None)) {
            continue;
        }
        let Some(placement) = ctx.config.parameter_placements.get(v.index) else {
            continue;
        };
        let channel = placement
            .shown
            .then(|| placed_channel_id(ctx, placement))
            .flatten()
            .filter(|id| channels.iter().any(|c| c.id == *id));
        let text = pref
            .text
            .as_deref()
            .or(param.text.as_deref())
            .and_then(|t| ctx.clean(t, placement.module))
            .or_else(|| param.name.clone())
            .unwrap_or_default();
        let pages = placement
            .blocks
            .iter()
            .rev()
            .filter_map(|b| block_title(ctx, b, placement.module))
            .map(|t| slug(&t))
            .collect();
        let enum_labels = match kind {
            Some(ParameterType::Enum { values, .. }) => {
                values.iter().map(|e| (e.value, e.text.clone())).collect()
            }
            _ => Vec::new(),
        };
        pending.push(Pending {
            fact: ParameterFact {
                key: String::new(),
                channel,
                reference: v.ref_key.clone(),
                param: v.parameter_id.clone(),
                enum_labels,
            },
            base: slug(&text),
            pages,
            shown: placement.shown,
        });
    }

    // Key the parameters scope by scope.
    let scopes: BTreeSet<Option<String>> = pending.iter().map(|p| p.fact.channel.clone()).collect();
    for scope in scopes {
        let taken: BTreeSet<String> = match &scope {
            // A channel table holds its objects and its `name` too.
            Some(id) => objects
                .iter()
                .filter(|o| o.channel.as_ref() == Some(id))
                .filter_map(|o| o.key.clone())
                .chain(RESERVED.iter().map(|r| r.to_string()))
                .collect(),
            // `[parameters]` holds parameters only.
            None => RESERVED.iter().map(|r| r.to_string()).collect(),
        };
        // Shown parameters pick first; the ones only an `<Assign>` touches
        // take what is left, so they never lengthen a key the user edits.
        let members = |shown: bool| -> Vec<usize> {
            (0..pending.len())
                .filter(|&i| pending[i].fact.channel == scope && pending[i].shown == shown)
                .collect()
        };
        let (first, second) = (members(true), members(false));
        assign_parameter_keys(&mut pending, &first, &taken);
        let mut taken = taken;
        for &i in &first {
            let key = &pending[i].fact.key;
            taken.insert(key.clone());
            if let Some((page, _)) = key.split_once('.').filter(|_| !key.contains('@')) {
                taken.insert(page.to_string());
            }
        }
        assign_parameter_keys(&mut pending, &second, &taken);
    }
    pending.into_iter().map(|p| p.fact).collect()
}

/// The title of a parameter block for a page key: its text (placeholders
/// stripped, the label left out so the key does not move with it), else the
/// text of the parameter ref that titles it.
fn block_title(ctx: &Ctx<'_>, block: &BlockRef, module: Option<usize>) -> Option<String> {
    if let Some(t) = block.text.as_deref().and_then(|t| ctx.clean(t, module)) {
        return Some(t);
    }
    let pref = ctx.app.parameter_ref(block.param_ref.as_deref()?)?;
    let text = pref.text.clone().or_else(|| {
        ctx.app
            .parameters
            .get(&pref.ref_id)
            .and_then(|p| p.text.clone())
    })?;
    ctx.clean(&text, module)
}

/// Assigns keys to the parameters `members` of one scope, whose flat keys
/// must also avoid `taken` (object keys and reserved words).
fn assign_parameter_keys(pending: &mut [Pending], members: &[usize], taken: &BTreeSet<String>) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for &i in members {
        *counts.entry(pending[i].base.clone()).or_default() += 1;
    }
    // Flat keys: unique text slug.
    let mut flat: BTreeSet<String> = taken.clone();
    let mut rest: Vec<usize> = Vec::new();
    for &i in members {
        let base = pending[i].base.clone();
        if counts.get(&base) == Some(&1) && !taken.contains(&base) {
            flat.insert(base.clone());
            pending[i].fact.key = base;
        } else {
            rest.push(i);
        }
    }
    // Page-qualified keys: the innermost page that makes the key unique among
    // the remaining parameters, with a page name no flat key uses.
    let candidates: Vec<(usize, Vec<String>)> = rest
        .iter()
        .map(|&i| {
            let p = &pending[i];
            let list = if RESERVED.contains(&p.base.as_str()) {
                Vec::new()
            } else {
                p.pages
                    .iter()
                    .filter(|page| !flat.contains(*page))
                    .map(|page| format!("{page}.{}", p.base))
                    .filter(|key| !taken.contains(key))
                    .collect()
            };
            (i, list)
        })
        .collect();
    for (i, list) in &candidates {
        let unique = list.iter().find(|c| {
            candidates
                .iter()
                .filter(|(j, l)| j != i && l.contains(c))
                .count()
                == 0
        });
        let key = match unique {
            Some(k) => k.clone(),
            None => format!("{}@{}", pending[*i].base, pending[*i].fact.reference),
        };
        pending[*i].fact.key = key;
    }
}

// ---------------------------------------------------------------------------
// Values and bases
// ---------------------------------------------------------------------------

/// The escape-hatch in-memory key of a stored value whose ref the lock does
/// not list: `<slug>@<ref>`, the slug being the file key of the same
/// parameter's listed ref (an alternative ref of a visible parameter), else
/// the ref's text, the parameter's text or its name.
fn escape_key(app: &ApplicationProgram, reference: &str, sibling: Option<&str>) -> String {
    let head = sibling
        .map(|k| k.split_once('@').map_or(k, |(h, _)| h).to_string())
        .or_else(|| {
            let (_, rel) = bussard_ets::dynamic::split_selector(reference);
            let pref = app.parameter_ref(&rel)?;
            let param = app.parameters.get(&pref.ref_id);
            [
                pref.text.as_deref(),
                param.and_then(|p| p.text.as_deref()),
                param.and_then(|p| p.name.as_deref()),
            ]
            .into_iter()
            .flatten()
            .find_map(strip_tokens)
        })
        .unwrap_or_default();
    format!("{}@{reference}", slug(&head))
}

/// `text` without its `{{…}}` tokens, `None` when nothing remains.
fn strip_tokens(text: &str) -> Option<String> {
    let stub = ApplicationProgram::default();
    resolve_placeholders(text, &stub, None, &HashMap::new())
}

/// The enum `(code, text)` pairs of the parameter a device-form ref points
/// at, empty for other kinds.
fn enum_labels_of_ref(app: &ApplicationProgram, reference: &str) -> Vec<(i64, String)> {
    let (_, rel) = bussard_ets::dynamic::split_selector(reference);
    match parameter_kind(app, &rel) {
        Some(ParameterType::Enum { values, .. }) => {
            values.iter().map(|e| (e.value, e.text.clone())).collect()
        }
        _ => Vec::new(),
    }
}

/// The memory base offset of each reached module instance, from its
/// `<Module>` argument named by the module's `BaseOffset` parameters.
fn module_bases(app: &ApplicationProgram, config: &DynamicConfig) -> BTreeMap<String, u32> {
    let args = base_offset_args(&[app]);
    let mut out = BTreeMap::new();
    for m in &config.modules {
        let Some(arg) = args.get(&m.module_def) else {
            continue;
        };
        let Some(base) = m.args.get(arg).and_then(|v| u32::try_from(*v).ok()) else {
            continue;
        };
        // A nested module reached twice keeps its first reach.
        out.entry(format!("{}_MI-1", m.id)).or_insert(base);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(base: &str, pages: &[&str], channel: Option<&str>, reference: &str) -> Pending {
        Pending {
            fact: ParameterFact {
                key: String::new(),
                channel: channel.map(str::to_string),
                reference: reference.to_string(),
                param: String::new(),
                enum_labels: Vec::new(),
            },
            base: base.to_string(),
            pages: pages.iter().map(|p| p.to_string()).collect(),
            shown: true,
        }
    }

    fn keys(pending: &[Pending]) -> Vec<&str> {
        pending.iter().map(|p| p.fact.key.as_str()).collect()
    }

    #[test]
    fn test_assign_parameter_keys_unique_text_is_flat() {
        let mut p = vec![
            pending("betriebsart", &["allgemein"], None, "P-1_R-1"),
            pending("verzoegerung", &["zeiten"], None, "P-2_R-2"),
        ];
        assign_parameter_keys(&mut p, &[0, 1], &BTreeSet::new());
        assert_eq!(keys(&p), ["betriebsart", "verzoegerung"]);
    }

    #[test]
    fn test_assign_parameter_keys_repeated_text_takes_the_innermost_unique_page() {
        let mut p = vec![
            pending("komfort", &["heizen", "sollwerte"], None, "P-1_R-1"),
            pending("komfort", &["kuehlen", "sollwerte"], None, "P-2_R-2"),
        ];
        assign_parameter_keys(&mut p, &[0, 1], &BTreeSet::new());
        assert_eq!(keys(&p), ["heizen.komfort", "kuehlen.komfort"]);
    }

    #[test]
    fn test_assign_parameter_keys_falls_back_outward() {
        // The innermost page is shared, the outer one tells them apart.
        let mut p = vec![
            pending("zeit", &["extra", "kanal-a"], None, "P-1_R-1"),
            pending("zeit", &["extra", "kanal-b"], None, "P-2_R-2"),
        ];
        assign_parameter_keys(&mut p, &[0, 1], &BTreeSet::new());
        assert_eq!(keys(&p), ["kanal-a.zeit", "kanal-b.zeit"]);
    }

    #[test]
    fn test_assign_parameter_keys_escape_hatch_when_pages_do_not_help() {
        let mut p = vec![
            pending("zeit", &["seite"], None, "P-1_R-1"),
            pending("zeit", &["seite"], None, "MD-1_M-2_MI-1_P-2_R-2"),
            pending("zeit", &[], None, "P-3_R-3"),
        ];
        assign_parameter_keys(&mut p, &[0, 1, 2], &BTreeSet::new());
        assert_eq!(
            keys(&p),
            ["zeit@P-1_R-1", "zeit@MD-1_M-2_MI-1_P-2_R-2", "zeit@P-3_R-3"]
        );
    }

    #[test]
    fn test_assign_parameter_keys_avoid_object_keys_and_reserved_words() {
        let taken: BTreeSet<String> = ["sperre", "name"].iter().map(|s| s.to_string()).collect();
        let mut p = vec![
            pending("sperre", &["sicherheit"], Some("CH-1"), "P-1_R-1"),
            pending("name", &["allgemein"], Some("CH-1"), "P-2_R-2"),
            // A page named like a flat key cannot hold a page-qualified key.
            pending("dauer", &["modus"], Some("CH-1"), "P-3_R-3"),
            pending("dauer", &["modus"], Some("CH-1"), "P-4_R-4"),
            pending("modus", &[], Some("CH-1"), "P-5_R-5"),
        ];
        assign_parameter_keys(&mut p, &[0, 1, 2, 3, 4], &taken);
        assert_eq!(
            keys(&p),
            [
                "sicherheit.sperre",
                "name@P-2_R-2",
                "dauer@P-3_R-3",
                "dauer@P-4_R-4",
                "modus"
            ]
        );
    }

    #[test]
    fn test_base_handle_plain_name_takes_the_number() {
        assert_eq!(
            base_handle(Some("Dimmkanal"), Some("Dimmkanal"), false, Some(1), 3),
            "dimmkanal-1"
        );
        // A module channel counts instances, which the caller passes as `n`.
        assert_eq!(
            base_handle(Some("Output"), None, true, Some(2), 1),
            "output-2"
        );
        assert_eq!(base_handle(Some("Output"), None, false, None, 4), "output");
    }

    #[test]
    fn test_base_handle_module_text_with_its_own_number_wins() {
        // The instance's argument says which valve it is, not the ordinal.
        assert_eq!(
            base_handle(
                Some("Ventilausgang"),
                Some("Ventilausgang 1"),
                true,
                Some(6),
                1
            ),
            "ventilausgang-1"
        );
        assert_eq!(
            base_handle(
                Some("Relaisausgänge"),
                Some("Relaisausgänge"),
                true,
                Some(1),
                3
            ),
            "relaisausgaenge-1"
        );
    }

    #[test]
    fn test_base_handle_internal_name_uses_the_text() {
        assert_eq!(
            base_handle(
                Some("SMOD0_MotionDetector1_MP_CT_1"),
                Some("Bewegungsmelder 1:"),
                false,
                Some(2),
                2
            ),
            "bewegungsmelder-1-2"
        );
        assert_eq!(
            base_handle(
                Some("LICHTAUSGANG_1"),
                Some("Lichtausgang 1"),
                false,
                Some(1),
                1
            ),
            "lichtausgang-1"
        );
        assert_eq!(
            base_handle(
                Some("Relaisausgänge 1+2"),
                Some("Relaisausgänge 1/2"),
                false,
                Some(1),
                1
            ),
            "relaisausgaenge-1-2-1"
        );
        assert_eq!(
            base_handle(
                Some("W1 - TSM - Wippe 1"),
                Some("TSM - Wippe 1"),
                false,
                Some(17),
                5
            ),
            "tsm-wippe-1-17"
        );
    }

    #[test]
    fn test_base_handle_name_in_another_language_yields_to_the_text() {
        assert_eq!(
            base_handle(
                Some("Manual operation"),
                Some("Manuelle Bedienung"),
                false,
                Some(2),
                2
            ),
            "manuelle-bedienung-2"
        );
        // A name the text contains is kept.
        assert_eq!(
            base_handle(
                Some("Regler"),
                Some("Raumtemperaturregler"),
                true,
                Some(12),
                7
            ),
            "regler-12"
        );
    }

    #[test]
    fn test_base_handle_falls_back_to_the_ordinal() {
        assert_eq!(base_handle(None, None, false, Some(7), 2), "ch-2");
        assert_eq!(base_handle(Some("A_B"), None, false, Some(7), 2), "ch-2");
        assert_eq!(
            base_handle(Some("A_B"), Some("()"), false, Some(7), 3),
            "ch-3"
        );
    }

    #[test]
    fn test_placeholder_defaults_keep_a_default_text_only() {
        assert_eq!(placeholder_defaults("{{0: Eingang g+h}}"), "Eingang g+h");
        assert_eq!(placeholder_defaults("Eingang f: {{0}}"), "Eingang f: {{0}}");
        assert_eq!(
            placeholder_defaults("Relais ({{0:...}}) {{ArgX}}"),
            "Relais ({{0:...}}) {{ArgX}}"
        );
        assert_eq!(placeholder_defaults("open {{0: x"), "open {{0: x");
    }

    #[test]
    fn test_ends_with_number_needs_a_numeric_last_part() {
        assert!(ends_with_number("ventilausgang-3"));
        assert!(!ends_with_number("relaisausgaenge"));
        assert!(!ends_with_number("12"));
    }

    #[test]
    fn test_is_plain_label_accepts_words_and_rejects_ids() {
        assert!(is_plain_label("Relaisausgänge"));
        assert!(is_plain_label("Dimmkanal 1"));
        assert!(!is_plain_label("LICHTAUSGANG_1"));
        assert!(!is_plain_label("E - Eingang"));
        assert!(!is_plain_label("Funktionsblock 1 (FB1)"));
        assert!(!is_plain_label("12"));
        assert!(!is_plain_label("Sehr langer Kanalname mit vielen Worten"));
    }

    #[test]
    fn test_unique_handles_append_the_ordinal_on_collision() {
        let handles: Vec<String> = ["kanal-1", "kanal-1", "licht-2", "kanal-1-2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            unique_handles(&handles),
            ["kanal-1-1", "kanal-1-2", "licht-2", "kanal-1-2-4"]
        );
    }

    #[test]
    fn test_object_candidates_order_and_skips() {
        assert_eq!(
            object_candidates(144, Some("Jalousie 1"), Some("Langzeitbetrieb"), true),
            [
                "langzeitbetrieb",
                "jalousie-1-langzeitbetrieb",
                "langzeitbetrieb-144",
                "jalousie-1-langzeitbetrieb-144"
            ]
        );
        // A numeric function text would read as an object number.
        assert_eq!(object_candidates(5, None, Some("12"), false), ["12-5"]);
        // `name` is the channel label inside a channel table.
        assert_eq!(object_candidates(3, None, Some("Name"), true), ["name-3"]);
        assert!(object_candidates(1, None, None, true).is_empty());
    }
}
