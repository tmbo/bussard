//! `.knxproj` import.
//!
//! Parses ETS 4, 5 and 6 project exports — including password-protected ones
//! (a WinZip-AES inner archive with an ETS6 PBKDF2-derived password) — and
//! streams their XML into the [`bussard_model`] representation with the
//! crate's streaming parsers (bounded memory, no DOM).
//!
//! The entry point is [`import`] (from a `.knxproj` file); it returns a
//! [`Model`] ready to [`save`](bussard_model::loader::Model::save).

mod build;
mod container;
mod knx_master;
mod password;
mod project;
mod version;

use std::path::Path;

use bussard_model::loader::Model;

use crate::error::ProductError;
use container::Container;

pub use password::derive_zip_password;

pub(crate) use build::{base_offset_args, resolve_placeholders};

/// Imports a `.knxproj` file into a [`Model`].
///
/// `password` is the user's project password; it is only needed if the inner
/// project archive is encrypted. Returns [`ProductError::PasswordRequired`] if
/// the archive is encrypted and no password was supplied, and
/// [`ProductError::WrongPassword`] if the supplied password does not decrypt it.
pub fn import(path: &Path, password: Option<&str>) -> Result<Model, ProductError> {
    import_with(path, password, &ImportOptions::default())
}

/// Options for [`import_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// The language to derive texts in (an ETS identifier such as `de-DE`).
    /// `None` lets the import choose: the project's stated language, else the
    /// language every program offers (see "Text language" in
    /// `docs/reference/files/`).
    pub language: Option<String>,
}

impl ImportOptions {
    /// The options for importing into the model directory `dir`: the language
    /// its `bussard.toml` sets under `[import]`, else the one its
    /// `bussard.lock` records, so a re-import keeps the texts it wrote.
    pub fn for_dir(dir: &Path) -> Self {
        Self {
            language: bussard_model::import_language(dir),
        }
    }
}

/// [`import`] with [`ImportOptions`].
pub fn import_with(
    path: &Path,
    password: Option<&str>,
    options: &ImportOptions,
) -> Result<Model, ProductError> {
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
    let mut language = options.language.clone();
    if let Some(info_xml) = container.project_info_xml() {
        let info = project::parse_project_info(info_xml)?;
        if let Some(style) = info.group_address_style
            && style != project::GroupAddressStyle::ThreeLevel
        {
            return Err(ProductError::UnsupportedGroupAddressStyle {
                style: style.to_string(),
            });
        }
        if raw.project_name.is_none() {
            raw.project_name = info.name;
        }
        if language.is_none() {
            language = info.language;
        }
    }

    let mut model = build::build_model(raw, &mut container, language.as_deref())?;
    // Record provenance.
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        model.groups.imported_from = Some(name.to_string());
    }
    Ok(model)
}
