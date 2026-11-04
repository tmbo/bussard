//! "Declare where first used": the group addresses the device files link but
//! `groups.toml` does not define yet are added to it, named after the object
//! that uses them first (see [`bussard_model::declare`]).
//!
//! `bussard apply`, `bussard apply --line` and both forms of
//! `knx_apply_device` call [`declare_used`] before they validate and write,
//! so both front ends leave the same `groups.toml` behind (issue #779).
//! `validate` alone only warns (E001).

use std::path::{Path, PathBuf};

use bussard_model::history::SnapshotReason;
use bussard_model::{DeclaredGroup, Model};

use crate::setup::Output;

/// Why [`declare_used`] could not write `groups.toml`.
#[derive(Debug, thiserror::Error)]
#[error("writing {}", path.display())]
pub struct DeclareError {
    /// The `groups.toml` that could not be written.
    pub path: PathBuf,
    /// The underlying save error.
    #[source]
    pub source: bussard_model::loader::SaveError,
}

/// Adds the group addresses the device files link but `groups.toml` does not
/// define, saves `groups.toml` behind a history snapshot named `verb`, and
/// updates `model` to the declared one.
///
/// Returns what was added, in order; an empty list writes nothing. A
/// snapshot that cannot be written is a warning on `out`, as for every
/// command that snapshots before it writes. The caller reports the additions
/// ([`DeclaredGroup::sentence`]) in its own channel.
///
/// # Errors
///
/// `groups.toml` cannot be written; `model` is then left unchanged.
pub fn declare_used(
    dir: &Path,
    model: &mut Model,
    verb: &str,
    out: &mut dyn Output,
) -> Result<Vec<DeclaredGroup>, DeclareError> {
    let mut edited = model.clone();
    let added = bussard_model::declare_used_groups(&mut edited);
    if added.is_empty() {
        return Ok(added);
    }
    crate::setup::import::snapshot(
        dir,
        SnapshotReason::new(verb)
            .with_result("before declaring the group addresses the device files use"),
        out,
    );
    let path = dir.join("groups.toml");
    bussard_model::loader::save_groups(&path, &edited.groups)
        .map_err(|source| DeclareError { path, source })?;
    *model = edited;
    Ok(added)
}
