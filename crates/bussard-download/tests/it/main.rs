//! The integration tests of `bussard-download`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod apply_mock;
mod apply_object_table_mock;
mod builtin_template;
mod compare_rel_mem;
mod enum_default_plan;
mod ets_golden;
mod flash_corpus;
mod flash_dryrun_corpus;
mod flash_dryrun_system7;
mod flash_mock;
mod flash_mock_system7;
mod golden_images;
mod golden_tables;
mod knxnet_ip_mock;
mod param_readback_roundtrip;
mod partial_segment;
mod property_procedure;
mod sweep_fixtures;
mod syn_property_param;
mod sys7_jung_m2_plan;
mod sys7_lsm5_plan;
mod sys7_split_segment;
mod sys7_theben_0701_plan;
// The fixture applications and the random value sets of bussard-prod's
// evaluator conformance test, shared with the view acceptance test.
#[path = "../../../bussard-prod/tests/it/value_sets.rs"]
mod value_sets;
mod view_acceptance;
