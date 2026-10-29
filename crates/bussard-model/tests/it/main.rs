//! The integration tests of `bussard-model`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod change_golden;
mod codec_robustness;
mod device_blocks;
mod device_view;
mod doc_render;
mod ets_export_golden;
mod labels;
mod lint_rules;
mod loader_adversarial;
mod lock_v2;
mod module_capabilities;
mod parameter_names;
mod parse_hints;
mod reimport_merge;
mod scaffold_output;
mod toml_format;
