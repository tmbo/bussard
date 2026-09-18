//! `.knxprod` product-data reading (clean-room — never depends on GPL
//! implementations): application programs, com objects, parameters, and load
//! procedures.
//!
//! A `.knxprod` is a plain ZIP holding `knx_master.xml`, one or more `M-XXXX/`
//! manufacturer folders (each with `Hardware.xml`, `Catalog.xml`, and the
//! ApplicationProgram XML files), and — for ETS-produced files — RSA signature
//! entries that bussard ignores. Application-program files reach ~28 MB, so
//! parsing is streaming (via `bussard-ets`); no DOM is ever built.
//!
//! # Entry points
//!
//! * [`read_knxprod`] opens a `.knxprod` file and returns [`ProductData`].
//! * [`application::parse_application_program`] parses one ApplicationProgram
//!   XML string in isolation (used for testing against `.knxproj` folders).
//!
//! # Shared ETS-XML layer
//!
//! The ApplicationProgram / `Hardware.xml` parsers, DPT/flag mapping,
//! translation resolution and capped zip reading all live in `bussard-ets` and
//! are shared with `bussard-project`; this crate's [`application`], [`hardware`],
//! [`dpt_map`] and [`flag_map`] modules re-export them for stable paths.

pub mod application;
mod container;
pub mod dpt_map;
mod error;
pub mod fetch;
pub mod flag_map;
pub mod hardware;
pub mod image;
pub mod index;

use std::collections::HashMap;
use std::path::Path;

pub use application::{
    ApplicationProgram, CodeSegment, ComObject, ComObjectRef, EnumValue, LoadOp, LoadProcedure,
    Memory, Parameter, ParameterRef, ParameterType, ParameterTypeDecl, ResolvedComObject,
    ResolvedParameter, SegmentKind, parse_application_program,
};
pub use bussard_ets::master::{
    HawkConfig, HawkResource, MaskLoadProcedure, MasterTemplate, parse_master_template,
};
pub use container::AppEntry;
pub use error::{ProdError, Result};
pub use fetch::{DownloadConsent, MAX_DOWNLOAD_BYTES, fetch_entry};
pub use hardware::HardwareCatalog;
pub use image::compute_parameter_image;
pub use index::{IndexEntry, ProductIndex, normalize_order_number};

/// The parsed contents of a `.knxprod`.
#[derive(Debug, Default)]
pub struct ProductData {
    /// Manufacturer ids present in the archive, e.g. `["M-0004"]`.
    pub manufacturers: Vec<String>,
    /// Order number → application-program refs, joined across all manufacturers.
    pub hardware: HardwareCatalog,
    /// Every ApplicationProgram in the archive, sorted by id.
    pub applications: Vec<ApplicationProgram>,
    /// The `knx_master.xml` load-procedure templates, when the archive carries a
    /// master file. `None` for a self-contained archive without one — the flash
    /// then stays on the single-object path (no template to splice against).
    pub master: Option<MasterTemplate>,
}

impl ProductData {
    /// Looks up the application programs a given order number maps to, resolving
    /// each ref to its parsed [`ApplicationProgram`].
    ///
    /// Returns them in the order the hardware declared (primary first), skipping
    /// refs whose application program is not present in the archive.
    pub fn application_for_order_number(&self, order_number: &str) -> Vec<&ApplicationProgram> {
        let Some(refs) = self.hardware.order_to_apps.get(order_number) else {
            return Vec::new();
        };
        let by_id: HashMap<&str, &ApplicationProgram> = self
            .applications
            .iter()
            .map(|a| (a.id.as_str(), a))
            .collect();
        refs.iter()
            .filter_map(|r| by_id.get(r.as_str()).copied())
            .collect()
    }

    /// The application program with the given id, if present.
    pub fn application_by_id(&self, id: &str) -> Option<&ApplicationProgram> {
        self.applications.iter().find(|a| a.id == id)
    }
}

/// Reads a `.knxprod` file into [`ProductData`].
///
/// Streams every ApplicationProgram XML with bounded memory. Signature entries
/// and binary baggage are ignored. Errors if the archive cannot be opened or an
/// application-program XML is malformed.
pub fn read_knxprod(path: &Path) -> Result<ProductData> {
    let mut container = container::Container::open(path)?;

    let manufacturers = container.manufacturer_ids();

    // Join every manufacturer's Hardware.xml into one order-number catalogue.
    let mut hardware = HardwareCatalog::default();
    for m in &manufacturers {
        if let Some(xml) = container.hardware_xml(m)? {
            hardware.extend(hardware::parse_hardware(&xml)?);
        }
    }

    // Parse each ApplicationProgram, one at a time (bounded memory).
    let entries = container.application_entries();
    let mut applications = Vec::with_capacity(entries.len());
    for entry in &entries {
        let xml = container.read_to_string(&entry.entry)?;
        // parse_application_program now takes &[u8] (skips an eager whole-file
        // UTF-8 validation); behavior here is identical.
        let app = parse_application_program(&entry.application_id, xml.as_bytes())?;
        applications.push(app);
    }
    applications.sort_by(|a, b| a.id.cmp(&b.id));

    // The master template is optional; a `.knxprod` without `knx_master.xml`
    // (or produced without one) parses fine and stays on the single-object path.
    let master = container
        .master_xml()?
        .map(|xml| parse_master_template(xml.as_bytes(), "knx_master.xml"))
        .transpose()?;

    Ok(ProductData {
        manufacturers,
        hardware,
        applications,
        master,
    })
}
