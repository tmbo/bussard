//! `knx-sim` binary: load an installation config and serve a KNXnet/IP
//! tunnelling gateway backed by the virtual bus. Thin wrapper around
//! [`knx_sim::run::run_from_first_arg`].

use anyhow::Result;

fn main() -> Result<()> {
    knx_sim::run::run_from_first_arg()
}
