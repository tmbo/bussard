//! `serve` binary: an alias for the `knx-sim` entrypoint used by the local
//! flash loop (`serve <config>`). Thin wrapper around
//! [`knx_sim::run::run_from_first_arg`].

use anyhow::Result;

fn main() -> Result<()> {
    knx_sim::run::run_from_first_arg()
}
