//! The adopt flow (issues #26, #201, #749): product data, the assign steps of
//! [`crate::assign`], the device file with its com-object table and lock
//! facts, links scaffolding, and for a Data Secure-activated device the
//! secured read of what ETS programmed into it.
//!
//! `bussard adopt` and `knx_add_device` both run these steps. Nothing here
//! prints or asks: the CLI keeps its wizard lines and prompts, the MCP tool
//! its questions and JSON.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_mgmt::manufacturers;
use bussard_model::schema::{ComObject, Device, Group, Product, SecureSender};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, LoadedDevice, Model};
use bussard_product::{ApplicationProgram, IndexEntry, ProductData, ResolvedComObject};
use bussard_secure::SequenceHighWater;

use super::SecureAdoption;
use crate::assign::{Verified, empty_model};
use crate::params::ProductSource;
use crate::secure::{SecureKeyError, SecureMaterial, ToolKeys};
use crate::{BusService, L4Options, ServiceError};

/// Wraps a read error.
fn read_err<E: std::error::Error + Send + Sync + 'static>(err: E) -> ServiceError {
    ServiceError::other(err)
}

// ---------------------------------------------------------------------------
// Product data
// ---------------------------------------------------------------------------

/// A product application selected for the new device, flattened to what the
/// later steps need: identity, order numbers (for the read-back cross-check)
/// and a pre-shaped com-object table.
#[derive(Debug, Clone)]
pub struct SelectedProduct {
    /// The application program id the product is known by.
    pub identity_id: String,
    /// The application's display name.
    pub name: Option<String>,
    /// The manufacturer reference (`M-0083`).
    pub manufacturer_ref: Option<String>,
    /// The application reference.
    pub application_ref: String,
    /// The mask version the application needs (`07B0`).
    pub mask_version: Option<String>,
    /// The order numbers the product data lists for the application.
    pub order_numbers: Vec<String>,
    /// The com objects by number.
    pub com_objects: BTreeMap<u16, ComObjectShape>,
    /// The parsed program, when the product data is at hand: the lock facts
    /// (channel handles, object and parameter keys) are derived from it.
    pub app: Option<ApplicationProgram>,
}

impl SelectedProduct {
    /// The application's name, else its id.
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.identity_id.clone())
    }
}

/// A com-object shaped the way the importer emits it (number → dpt/flags/size),
/// ready to fold into a device-file [`ComObject`].
#[derive(Debug, Clone)]
pub struct ComObjectShape {
    /// The object's text (button or sensor label).
    pub text: Option<String>,
    /// The datapoint type.
    pub dpt: Option<Dpt>,
    /// The communication flags.
    pub flags: Flags,
    /// The object size when no DPT implies it.
    pub size: Option<String>,
    /// The com-object reference id.
    pub ref_id: String,
}

/// Flattens an application and its product data into a [`SelectedProduct`].
pub fn shape_selected(app: &ApplicationProgram, data: &ProductData) -> SelectedProduct {
    SelectedProduct {
        identity_id: app.id.clone(),
        name: app.name.clone(),
        manufacturer_ref: app.id.split('_').next().map(str::to_string),
        application_ref: app.id.clone(),
        mask_version: app.mask_version.clone(),
        order_numbers: bussard_product::product_model::order_numbers_for(app, data),
        com_objects: shape_com_objects(app),
        app: Some(app.clone()),
    }
}

/// The resolved com-objects keyed by number, smallest-ref-id wins on collision.
fn shape_com_objects(app: &ApplicationProgram) -> BTreeMap<u16, ComObjectShape> {
    let mut map: BTreeMap<u16, ComObjectShape> = BTreeMap::new();
    for rc in app.resolved_com_objects() {
        let number = rc.number();
        let candidate = shape_one(&rc);
        match map.get(&number) {
            Some(existing) if existing.ref_id <= candidate.ref_id => {}
            _ => {
                map.insert(number, candidate);
            }
        }
    }
    map
}

/// One resolved com object, shaped.
fn shape_one(rc: &ResolvedComObject<'_>) -> ComObjectShape {
    let dpt = rc.dpt();
    ComObjectShape {
        text: rc.text().map(str::to_string),
        dpt,
        flags: rc.flags(),
        // Carry size only when no DPT implies it, matching the device schema.
        size: if dpt.is_none() {
            rc.object_size().map(str::to_string)
        } else {
            None
        },
        ref_id: rc.cref.id.clone(),
    }
}

/// The application for the order number a device reported: the one the
/// product data lists under it, else the first.
pub fn application_for_order(data: &ProductData, order: &str) -> Option<ApplicationProgram> {
    bussard_download::resolve_by_order_number(data, order)
        .ok()
        .cloned()
        .or_else(|| data.applications.first().cloned())
}

/// Where the product data for an order number comes from.
#[derive(Debug, Clone)]
pub enum ProductPlan {
    /// The model's product store has it (`bussard.lock` pins the archive).
    Cached {
        /// The archive.
        path: PathBuf,
    },
    /// bussard's product index points at a vendor download: fetching it
    /// needs the human's download consent.
    Download {
        /// The index entry.
        entry: Box<IndexEntry>,
    },
    /// Neither: the device is adopted product-less.
    Missing {
        /// The sentence that says where to get it.
        sentence: String,
    },
}

/// Where the product data for `order` would come from: the store, the
/// index (a download), or nowhere. Reads only the lock and the index.
pub fn product_plan(dir: &Path, order: &str) -> ProductPlan {
    if let Ok(Some(path)) = crate::params::archive_for_order(dir, order) {
        return ProductPlan::Cached { path };
    }
    match crate::setup::products::load_index() {
        Ok(index) => match index.lookup(order) {
            Some(entry) => ProductPlan::Download {
                entry: Box::new(entry.clone()),
            },
            None => ProductPlan::Missing {
                sentence: crate::setup::products::not_found_sentence(order, dir),
            },
        },
        Err(err) => ProductPlan::Missing {
            sentence: format!(
                "{order}: the product index did not load ({})",
                crate::util::chain(&err)
            ),
        },
    }
}

/// The product of an archive in the store, for the order number the device
/// reported. `Err` is the sentence why it could not be used.
///
/// # Errors
///
/// The archive does not read, or carries no application program.
pub fn selected_from_archive(
    path: &Path,
    dir: &Path,
    order: &str,
) -> Result<SelectedProduct, String> {
    let data = crate::setup::products::read_in_model_language(path, dir, None)
        .map_err(|err| crate::util::chain(&err))?;
    let app = application_for_order(&data, order)
        .ok_or_else(|| format!("{} carries no application program", path.display()))?;
    Ok(shape_selected(&app, &data))
}

/// Whether a read-back order number matches one of the product's order numbers.
/// Comparison is case-insensitive and tolerant of surrounding whitespace, and
/// also accepts a substring match either way (vendors abbreviate order strings).
pub fn order_matches(read: &str, candidates: &[String]) -> bool {
    let read = read.trim().to_ascii_uppercase();
    candidates.iter().any(|c| {
        let c = c.trim().to_ascii_uppercase();
        read == c || read.contains(&c) || c.contains(&read)
    })
}

// ---------------------------------------------------------------------------
// The device file
// ---------------------------------------------------------------------------

/// Builds the device from the verified read-back and the selected product,
/// with the lock facts under the vendor defaults when the program is at hand.
pub fn build_device(
    address: IndividualAddress,
    v: &Verified,
    selected: Option<&SelectedProduct>,
) -> Device {
    let name = selected
        .and_then(|s| s.name.clone())
        .unwrap_or_else(|| "New device (adopt)".to_string());

    let product = build_product(v, selected);
    let com_objects = selected
        .map(|s| {
            s.com_objects
                .iter()
                .map(|(num, shape)| {
                    (
                        *num,
                        ComObject {
                            dpt: shape.dpt,
                            size: shape.size.clone(),
                            flags: shape.flags,
                            reference: Some(shape.ref_id.clone()),
                            channel: None,
                            secure: false,
                            function: None,
                            key: None,
                            text: None,
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let mut device = Device {
        address,
        name,
        description: None,
        location: None,
        replaced: None,
        product,
        channels: Default::default(),
        parameters: Default::default(),
        module_bases: Default::default(),
        com_objects,
        // KNX Secure state is populated only by the knxproj importer (issue #71);
        // an adopted-from-bus device carries none.
        security: None,
        application_override: None,
        knxnet: None,
        lock: Default::default(),
    };
    // The lock facts under the vendor defaults: the objects the program
    // shows, with channel handles and keys from day one.
    if let Some(app) = selected.and_then(|s| s.app.as_ref()) {
        let facts = bussard_product::lock_keys::derive_lock_keys(
            app,
            &BTreeMap::new(),
            &Default::default(),
        );
        device.com_objects.clear();
        bussard_product::lock_keys::apply_lock_keys(&mut device, app, &facts, &BTreeMap::new());
    }
    device
}

/// The device's product block: identity from the matched application where we
/// have it, filled in from the bus read-back otherwise.
pub fn build_product(v: &Verified, selected: Option<&SelectedProduct>) -> Option<Product> {
    let manufacturer = v.manufacturer_id.map(manufacturers::display);
    let order_number = selected
        .and_then(|s| s.order_numbers.first().cloned())
        .or_else(|| v.order.clone());
    // Mask strings use the importer's bare-hex form ("07B0"), whether they come
    // from the product data or the live descriptor read-back.
    let mask = selected
        .and_then(|s| s.mask_version.clone())
        .or_else(|| v.mask.map(|m| format!("{m:04X}")));
    let manufacturer_ref = selected.and_then(|s| s.manufacturer_ref.clone());
    let application_ref = selected.map(|s| s.application_ref.clone());

    if manufacturer.is_none()
        && manufacturer_ref.is_none()
        && order_number.is_none()
        && application_ref.is_none()
        && mask.is_none()
    {
        return None;
    }
    Some(Product {
        manufacturer,
        manufacturer_ref,
        order_number,
        hardware_ref: None,
        application_ref,
        mask,
    })
}

// ---------------------------------------------------------------------------
// Links scaffolding
// ---------------------------------------------------------------------------

/// The device-file table header and entry key for com object `num`:
/// `[channel.<handle>]` for a channel object, `[links]` otherwise, and the key
/// the lock assigns (else the number).
pub fn object_placement(device: &Device, num: u16) -> (String, String) {
    let co = device.com_objects.get(&num);
    let table = match co.and_then(|c| c.channel.as_deref()) {
        Some(id) => {
            let handle = device
                .channels
                .get(id)
                .and_then(|c| c.key.clone())
                .unwrap_or_else(|| id.to_string());
            format!("[channel.{handle}]")
        }
        None => "[links]".to_string(),
    };
    let key = co
        .and_then(|c| c.key.clone())
        .unwrap_or_else(|| num.to_string());
    (table, key)
}

/// One com object of the links scaffolding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsefulObject {
    /// The object number.
    pub number: u16,
    /// The datapoint type.
    pub dpt: Option<Dpt>,
    /// The communication flags.
    pub flags: Flags,
    /// The object's text from the product data.
    pub text: Option<String>,
    /// The device-file table it is wired in (`[links]`, `[channel.<handle>]`).
    pub table: String,
    /// The key it is wired under.
    pub key: String,
}

/// The device's com objects in the order a human wires them: transmit-capable
/// first (most likely a sensor or button source), then by number.
pub fn useful_objects(device: &Device, selected: Option<&SelectedProduct>) -> Vec<UsefulObject> {
    let mut objs: Vec<(&u16, &ComObject)> = device.com_objects.iter().collect();
    objs.sort_by_key(|(num, co)| (!co.flags.contains(Flags::TRANSMIT), **num));
    objs.into_iter()
        .map(|(num, co)| {
            let (table, key) = object_placement(device, *num);
            UsefulObject {
                number: *num,
                dpt: co.dpt,
                flags: co.flags,
                text: selected
                    .and_then(|s| s.com_objects.get(num))
                    .and_then(|shape| shape.text.clone()),
                table,
                key,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A KNX Data Secure-activated device (issue #201, tier 1)
// ---------------------------------------------------------------------------

/// The failure for a device that hides its mask (Data Secure-activated) while
/// the keyring holds no tool key for it: the resolver's "no tool key" message
/// plus what to do. No device file is written.
pub fn activated_without_key(
    target: IndividualAddress,
    current: IndividualAddress,
    keys: &ToolKeys,
    keyring: Option<&Path>,
) -> String {
    let moved = if target == current {
        String::new()
    } else {
        format!(" The address {target} was written; the device answers there.")
    };
    match keyring {
        Some(path) => {
            let no_entry = SecureKeyError::NoEntry {
                path: path.to_path_buf(),
                target,
                devices: keys.listed().len(),
            };
            format!(
                "{target} is secured (it hides its mask from an unsecured read) and cannot be \
                 adopted: {no_entry} Export the keyring from ETS again after the \
                 device's secure commissioning, so it lists {target}, and point \
                 --keyring (or connection.keyring in bussard.toml) at it. No device file was written.{moved}"
            )
        }
        None => format!(
            "{target} is secured (it hides its mask from an unsecured read) and cannot be \
             adopted without its tool key: {}. No device file was written.{moved}",
            crate::guidance::tool_key_hint()
        ),
    }
}

/// The refusal for a keyring-listed device asked to move to another address:
/// adopt reads a secured device where ETS put it.
pub fn secured_move_refusal(current: IndividualAddress, target: IndividualAddress) -> String {
    format!(
        "{current} is secured and the ETS keyring holds its tool key under \
         {current}: adopt reads a secured device at the address ETS gave it and never \
         re-addresses it. Adopt it at {current} (`bussard adopt {current}`), or \
         re-address it first with `bussard assign {target} --keyring <file.knxkeys>` and \
         export the keyring from ETS again. Nothing was written."
    )
}

/// The address adopt gives the device in programming mode at `current`:
/// `explicit` checked against the model, else for a device the keyring lists
/// (`secured`, issue #201) its current address (the keyring looks its tool
/// key up there), else the next free one. A secured device is never moved.
///
/// # Errors
///
/// The address is invalid or taken, nothing can be allocated, or a secured
/// device would move.
pub fn adopt_target(
    explicit: Option<&str>,
    current: IndividualAddress,
    secured: bool,
    model: Option<&Model>,
) -> Result<IndividualAddress, ServiceError> {
    use crate::assign::{target_address, validate_explicit_address};
    let target = match explicit {
        Some(s) => validate_explicit_address(s, model)?,
        None if secured => validate_explicit_address(&current.to_string(), model)?,
        None => target_address(
            None,
            model,
            "re-run with a modelled line or pass the target ADDRESS",
        )?,
    };
    if secured && target != current {
        return Err(ServiceError::Refused(secured_move_refusal(current, target)));
    }
    Ok(target)
}

/// `model` (or an empty one) with `device` in it at `target`: the model the
/// parameter read-back of a secured device decodes with.
pub fn with_device(model: Option<&Model>, device: &Device, target: IndividualAddress) -> Model {
    let mut with_device = model.cloned().unwrap_or_else(empty_model);
    with_device.devices.insert(
        target,
        LoadedDevice {
            device: device.clone(),
            file_stem: target.to_string(),
        },
    );
    with_device
}

/// What the secured session read from an activated device.
pub struct SecuredRead {
    /// The live tables, or `None` for a mask no table reader speaks.
    pub tables: Option<bussard_mgmt::tables::DeviceTables>,
    /// The security object read-back (PID 61, PID 54).
    pub security: bussard_download::SecurityReadback,
    /// The parameter read-back, when product data was at hand.
    pub params: Option<crate::params::ParamState>,
    /// Why a part is missing.
    pub notes: Vec<String>,
}

/// Reads an activated device's tables, security object and parameters in one
/// management session over `A_SecureData`. Read-only: descriptor, property,
/// extended-property and memory reads (the `reconstruct` path plus the
/// security object's PID 61 and PID 54). `with_device` is the model holding
/// the device file being written ([`with_device`]); `product` the product
/// data the parameters decode with; `notes` what the caller already knows is
/// missing.
///
/// # Errors
///
/// The secured session or a read on it failed.
pub async fn read_secured(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    with_device: &Model,
    product: Option<&ProductSource>,
    material: &SecureMaterial,
    mut notes: Vec<String>,
) -> Result<SecuredRead, ServiceError> {
    let options = L4Options::secured(source, material.tool_key.clone(), SequenceHighWater::new());
    let (tables, security, params) = service
        .with_l4(target, &options, async |l4| {
            // The APDU budget sizes the PID 61 chunks as ETS does.
            let _ = l4.negotiate_max_apdu().await;
            let tables = match bussard_download::read_live_tables(
                l4,
                bussard_download::Sys7TableBases::default(),
            )
            .await
            .map_err(read_err)?
            {
                bussard_download::LiveRead::Tables(live) => Some(live),
                bussard_download::LiveRead::UnsupportedMask { mask, .. } => {
                    tracing::info!("{target}: no table reader for mask {mask:04X}");
                    None
                }
            };
            let security = bussard_download::read_security_object(l4)
                .await
                .map_err(read_err)?;
            let params = match (&tables, product) {
                (Some(live), Some(product)) => Some(
                    crate::params::read_state(
                        l4,
                        product,
                        Some(with_device),
                        target,
                        live.tables().mask,
                    )
                    .await,
                ),
                _ => None,
            };
            Ok::<_, ServiceError>((tables.map(|t| t.tables().clone()), security, params))
        })
        .await?;
    if tables.is_none() {
        notes.push(
            "the link tables were not read: bussard has no table reader for this mask".into(),
        );
    }
    if product.is_none() && notes.is_empty() {
        notes.push(
            "parameters not read: no product data (pass --product or cache the .knxprod)".into(),
        );
    }
    Ok(SecuredRead {
        tables,
        security,
        params,
        notes,
    })
}

/// What the secured adoption recorded, for the summary.
#[derive(Debug, Clone)]
pub struct SecureSummary {
    /// Links recorded in the device file.
    pub links: usize,
    /// Parameters recorded (values that differ from the vendor defaults).
    pub parameters: usize,
    /// The Data Secure view.
    pub adoption: SecureAdoption,
    /// The PID 54 senders, or `None` when not read.
    pub senders: Option<Vec<SecureSender>>,
    /// Why a part is missing.
    pub notes: Vec<String>,
}

/// Records a secured read in a copy of the model: the device's parameters and
/// objects (lock facts under the values it holds), its links, the groups they
/// use, and the Data Secure state. Returns the device to write, the model to
/// write it into and the summary.
///
/// # Errors
///
/// Only an internal inconsistency (the device missing from its own copy).
pub fn record_secured(
    model: Option<&Model>,
    mut device: Device,
    target: IndividualAddress,
    selected: Option<&SelectedProduct>,
    read: &SecuredRead,
    material: &SecureMaterial,
    current: IndividualAddress,
) -> Result<(Device, Model, SecureSummary), ServiceError> {
    let mut notes = read.notes.clone();
    notes.extend(read.security.notes.iter().cloned());
    let mut parameters = 0;
    // The parameters the device holds: the lock facts (visible objects,
    // channels, keys) follow its values, and the file keeps the non-defaults.
    if let (Some(app), Some(state)) = (selected.and_then(|s| s.app.as_ref()), read.params.as_ref())
    {
        match &state.detail {
            Some(detail) => {
                let keys: std::collections::BTreeSet<&str> = detail
                    .decoded
                    .non_default
                    .iter()
                    .map(|r| r.key.as_str())
                    .collect();
                let stored: BTreeMap<String, String> = detail
                    .decoded
                    .values
                    .iter()
                    .filter(|(k, _)| keys.contains(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                parameters = stored.len();
                let facts = bussard_product::lock_keys::derive_lock_keys(
                    app,
                    &detail.decoded.values,
                    &Default::default(),
                );
                device.com_objects.clear();
                bussard_product::lock_keys::apply_lock_keys(&mut device, app, &facts, &stored);
            }
            None => {
                if let Some(note) = &state.readback.note {
                    notes.push(format!("parameters: {note}"));
                }
            }
        }
    }

    // The links, sending on an object's first address when it transmits.
    let resolved: Vec<(u16, GroupAddress)> = read
        .tables
        .as_ref()
        .map(|t| t.resolved.iter().map(|l| (l.object, l.ga)).collect())
        .unwrap_or_default();
    let links = super::links_from_tables(&resolved, |object| {
        device.com_objects.get(&object).map(|co| co.flags)
    });
    for link in &links {
        device
            .com_objects
            .entry(link.object)
            .or_insert_with(|| super::placeholder_object(link));
    }

    let mut out = model.cloned().unwrap_or_else(empty_model);
    let placeholder = |ga: GroupAddress| format!("GA {ga} (adopted from {target})");
    for link in &links {
        for ga in link.send.iter().chain(link.listen.iter()) {
            out.groups.groups.entry(*ga).or_insert_with(|| Group {
                name: placeholder(*ga),
                ..Default::default()
            });
        }
    }
    let empty = std::collections::HashMap::new();
    let group_keys = material.group_keys.as_ref().unwrap_or(&empty);
    let device_flags = read.security.secured_objects();
    let adoption = super::derive_secure_adoption(&links, group_keys, device_flags.as_ref());
    let senders: Option<Vec<SecureSender>> = read.security.senders.as_ref().map(|entries| {
        entries
            .iter()
            .map(|e| SecureSender {
                address: e.address,
                sequence: e.sequence,
            })
            .collect()
    });
    let link_count = links.len();
    if !links.is_empty() {
        out.links.links.insert(target, links);
    }
    out.devices.insert(
        target,
        LoadedDevice {
            device,
            file_stem: target.to_string(),
        },
    );
    super::apply_secure_adoption(
        &mut out,
        target,
        &adoption,
        material.device_sequences.get(&current).copied(),
        senders.as_deref().unwrap_or_default(),
        placeholder,
    );
    let device = out
        .devices
        .remove(&target)
        .map(|loaded| loaded.device)
        .ok_or_else(|| {
            ServiceError::Refused("the adopted device vanished from your project".into())
        })?;
    let summary = SecureSummary {
        links: link_count,
        parameters,
        adoption,
        senders,
        notes,
    };
    Ok((device, out, summary))
}

// ---------------------------------------------------------------------------
// A KNX IP interface (issue #391)
// ---------------------------------------------------------------------------

/// Reads the KNXnet/IP parameter object of `target` on a fresh connection,
/// storing it with the device facts: `None` for a device that has none.
/// Read-only.
///
/// # Errors
///
/// The session or a read on it failed.
pub async fn read_knxnet_settings(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    dir: &Path,
    material: &SecureMaterial,
) -> Result<Option<bussard_model::knxnet::KnxnetFacts>, ServiceError> {
    let options = L4Options::secured(source, material.tool_key.clone(), SequenceHighWater::new());
    let facts = crate::FactsCache::new(dir, false);
    service
        .with_l4(target, &options, async |l4| {
            let mask = bussard_mgmt::read_device_descriptor(l4)
                .await
                .map_err(read_err)?;
            let mut established = facts
                .establish(l4, mask, crate::FactsWant::Table)
                .await
                .map_err(read_err)?;
            crate::knxnet::read_knxnet_with_facts(l4, &facts, &mut established)
                .await
                .map_err(read_err)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn selected(com: BTreeMap<u16, ComObjectShape>) -> SelectedProduct {
        SelectedProduct {
            identity_id: "M-0083_A-1234-11-ABCD".to_string(),
            name: Some("Taster".to_string()),
            manufacturer_ref: Some("M-0083".to_string()),
            application_ref: "M-0083_A-1234-11-ABCD".to_string(),
            mask_version: Some("07B0".to_string()),
            order_numbers: vec!["MDT-BE-04001.02".to_string()],
            com_objects: com,
            app: None,
        }
    }

    #[test]
    fn test_order_matches_is_case_and_substring_tolerant() {
        let cands = vec!["MDT-BE-04001.02".to_string()];
        assert!(order_matches("mdt-be-04001.02", &cands));
        assert!(order_matches("MDT-BE-04001.02 ", &cands));
        assert!(order_matches("MDT-BE-04001", &cands));
        assert!(!order_matches("JUNG-4093TSM", &cands));
    }

    #[test]
    fn test_build_product_prefers_product_over_readback() -> TestResult {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: Some("READBACK-ORDER".to_string()),
            ..Verified::default()
        };
        let p = build_product(&v, Some(&selected(BTreeMap::new()))).ok_or("a product")?;
        assert_eq!(p.order_number.as_deref(), Some("MDT-BE-04001.02"));
        assert_eq!(p.application_ref.as_deref(), Some("M-0083_A-1234-11-ABCD"));
        assert_eq!(p.manufacturer_ref.as_deref(), Some("M-0083"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert_eq!(p.manufacturer.as_deref(), Some("MDT"));
        Ok(())
    }

    #[test]
    fn test_build_product_falls_back_to_readback_without_product() -> TestResult {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: Some("MDT-JAL0410".to_string()),
            ..Verified::default()
        };
        let p = build_product(&v, None).ok_or("a product")?;
        assert_eq!(p.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert!(p.application_ref.is_none());
        Ok(())
    }

    #[test]
    fn test_build_device_carries_com_objects_and_useful_objects_order() -> TestResult {
        let mut com = BTreeMap::new();
        com.insert(
            0u16,
            ComObjectShape {
                text: Some("Switch".to_string()),
                dpt: Some(Dpt::new(1, Some(1))),
                flags: "CW".parse()?,
                size: None,
                ref_id: "R-0".to_string(),
            },
        );
        com.insert(
            3u16,
            ComObjectShape {
                text: Some("Status".to_string()),
                dpt: Some(Dpt::new(1, Some(1))),
                flags: "CRT".parse()?,
                size: None,
                ref_id: "R-3".to_string(),
            },
        );
        let sel = selected(com);
        let dev = build_device("1.1.7".parse()?, &Verified::default(), Some(&sel));
        assert_eq!(dev.name, "Taster");
        assert_eq!(dev.com_objects.len(), 2);
        let co = dev.com_objects.get(&0).ok_or("object 0")?;
        assert_eq!(co.reference.as_deref(), Some("R-0"));
        let useful = useful_objects(&dev, Some(&sel));
        assert_eq!(useful[0].number, 3, "transmit-capable first");
        assert_eq!(useful[0].text.as_deref(), Some("Status"));
        assert_eq!(useful[0].table, "[links]");
        Ok(())
    }
}
