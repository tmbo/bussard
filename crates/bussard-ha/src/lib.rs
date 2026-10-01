//! Home Assistant KNX config generation from the bussard YAML model.
//!
//! This crate turns a loaded bussard [`Model`] into the Home Assistant KNX
//! integration YAML (the `knx:` platform schema documented at
//! <https://www.home-assistant.io/integrations/knx/>) — so the KNX-as-code repo
//! stays the single source of truth for Home Assistant too.
//!
//! # How it works
//!
//! Entities are *derived heuristically* from the model's group addresses, the
//! links, and each device's com-object table (DPTs +
//! flags). See [`derive`] for the mapping rules. Anything that cannot be mapped
//! is reported in a commented summary at the end of the output rather than
//! being silently dropped.
//!
//! An optional `ha.toml` file in the model directory ([`overrides`]) tunes the
//! result: exclusions, switch↔light promotion, name and device_class overrides,
//! and merging extra GAs onto an entity.
//!
//! # Talking to Home Assistant
//!
//! For the MCP server's Home Assistant tier (issue #280), [`api`] is a small
//! REST client (status reads and the `knx.reload` service), [`plan`] diffs the
//! generated YAML against the file Home Assistant reads, entity by entity, and
//! [`apply`] writes that file atomically with a backup. [`automation`] renders
//! the small rules an assistant proposes into bussard-managed Home Assistant
//! automations.
//!
//! # Determinism
//!
//! Output is fully sorted (by platform, then entity name, then primary GA) and
//! stable across runs, so re-generating produces a minimal diff.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use bussard_model::Model;
//! use bussard_ha::{Overrides, generate};
//!
//! let dir = Path::new("knx");
//! let model = Model::load(dir)?;
//! let overrides = Overrides::load(dir)?;
//! let yaml = generate(&model, &overrides)?;
//! print!("{yaml}");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]

pub mod api;
pub mod apply;
pub mod automation;
pub mod derive;
pub mod emit;
pub mod entities;
pub mod overrides;
pub mod plan;

pub use derive::{Derived, derive};
pub use overrides::{Overrides, OverridesError};

use bussard_model::Model;

/// An error generating the Home Assistant config.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    /// Serializing the derived entities to YAML failed.
    #[error("serializing Home Assistant YAML: {0}")]
    Yaml(#[from] serde_norway::Error),
}

/// Generates the Home Assistant KNX YAML for a model under the given overrides.
///
/// The returned string is the complete file contents: a generated-by header, the
/// `knx:` platform document, and a summary footer (entity counts + unmapped GAs).
pub fn generate(model: &Model, overrides: &Overrides) -> Result<String, GenerateError> {
    let derived = derive::derive(model, overrides);
    Ok(emit::render(&derived)?)
}
