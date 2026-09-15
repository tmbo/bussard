//! DPT string mapping lives in the shared `bussard-ets` layer; re-exported here
//! for a stable path. See [`bussard_ets::dpt`].

pub use bussard_ets::dpt::{dpt_from_object_size, parse_ets_dpt};
