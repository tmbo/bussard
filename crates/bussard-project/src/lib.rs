//! `.knxproj` import for bussard.
//!
//! Parses ETS 6 project exports — including password-protected ones (a
//! WinZip-AES inner archive with an ETS6 PBKDF2-derived password) — and streams
//! their XML into the [`bussard_model`] representation.
//!
//! The public entry points are [`import`] (from a `.knxproj` file) and
//! [`import_from_json`] (from an `xknxproject` JSON dump — an escape hatch and
//! the test-oracle format). Both return a [`Model`] ready to
//! [`save`](bussard_model::loader::Model::save).
//!
//! Manufacturer application-program XML can be tens of megabytes, so it is read
//! with the shared streaming parser in `bussard-ets` (bounded memory, no DOM).
//! Import consumes the com-object tables, channel definitions, mask version and
//! program identity; parameters and load procedures are parsed but unused here
//! (later phases and `.knxprod` reading need them).

#![warn(missing_docs)]

mod build;
mod container;
mod dpt_map;
mod error;
mod flag_map;
mod from_json;
mod hardware;
mod knx_master;
mod manufacturer;
mod password;
mod project;
mod version;

use std::path::Path;

pub use bussard_model::loader::Model;
pub use error::ImportError;
pub use password::derive_zip_password;

use container::Container;

/// Imports a `.knxproj` file into a [`Model`].
///
/// `password` is the user's project password; it is only needed if the inner
/// project archive is encrypted. Returns [`ImportError::PasswordRequired`] if
/// the archive is encrypted and no password was supplied, and
/// [`ImportError::WrongPassword`] if the supplied password does not decrypt it.
pub fn import(path: &Path, password: Option<&str>) -> Result<Model, ImportError> {
    let mut container = Container::open(path, password)?;
    let schema = container.schema();
    tracing::info!(
        schema_version = schema.version(),
        family = ?schema.family(),
        "detected ETS schema version"
    );
    let mut raw = project::parse_project(container.project_xml(), schema)?;

    // `project.xml` carries the project name and the group-address style, which
    // `0.xml` does not. Read it (when present) to populate the name and to
    // refuse projects whose address style bussard cannot represent.
    if let Some(info_xml) = container.project_info_xml() {
        let info = project::parse_project_info(info_xml)?;
        if let Some(style) = info.group_address_style {
            if style != project::GroupAddressStyle::ThreeLevel {
                return Err(ImportError::UnsupportedGroupAddressStyle {
                    style: style.to_string(),
                });
            }
        }
        if raw.project_name.is_none() {
            raw.project_name = info.name;
        }
    }

    let mut model = build::build_model(raw, &mut container)?;
    // Record provenance.
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        model.groups.imported_from = Some(name.to_string());
    }
    Ok(model)
}

/// Imports an `xknxproject` JSON dump into a [`Model`].
///
/// This is a convenience/escape-hatch path that needs no password or archive:
/// it consumes the same JSON that the test oracle uses.
pub fn import_from_json(path: &Path) -> Result<Model, ImportError> {
    let text = std::fs::read_to_string(path).map_err(|source| ImportError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut model = from_json::model_from_json(&text)?;
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        model.groups.imported_from = Some(name.to_string());
    }
    Ok(model)
}

/// Imports an `xknxproject` JSON dump from an in-memory string.
pub fn import_from_json_str(json: &str) -> Result<Model, ImportError> {
    from_json::model_from_json(json)
}
