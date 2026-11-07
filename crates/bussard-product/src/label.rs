//! Filling the `{{0}}` label placeholder of Dynamic-section texts.
//!
//! The substitution lives in `bussard-model` next to the Dynamic evaluator
//! (issue #345); this module re-exports it so download-side callers keep
//! their paths.

pub use bussard_model::label::substitute_label;
