//! The integration tests of `bussard-prod`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod blocks;
mod builtin_templates;
mod enum_default_leniency;
mod evaluator_conformance;
mod fetch;
mod knxprod;
mod parameter_calculations_corpus;
mod parameter_image;
mod selected;
mod synthetic_products;
mod sys7_visible_parameters;
mod value_sets;
mod wrapper;
