//! Golden test: computing the reference device's tables from the real `knx/`
//! model must reproduce its live tables byte-for-byte, once the four known ghost
//! links are removed.
//!
//! The live tables live in `fixtures/private/1.1.4-tables-live.json` (a real
//! device read-back, never committed). This test is env-gated like the oracle
//! tests: it skips cleanly when the fixture is absent, so CI without the private
//! fixture stays green.
//!
//! ## What "minus the ghosts" means
//!
//! The reference device (Jung 23024, 1.1.4) carries four stale ETS links —
//! objects 59, 106, 153, 200 → GAs 4/2/12, 4/2/5, 4/2/13, 4/2/14 — that are not
//! in the current model (they show up as `on_device_not_in_model` in
//! `reconstruct`). The model, computed fresh, therefore lacks them. To compare,
//! we strip those four associations (and any address only they used) from the
//! live fixture and re-index the remaining TSAPs through the shrunk address
//! table, then assert the computed tables equal the stripped-and-reindexed live
//! tables exactly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_download::compute_tables;
use bussard_model::{GroupAddress, IndividualAddress, Model};
use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn live_fixture() -> Option<Value> {
    let p = repo_root().join("fixtures/private/1.1.4-tables-live.json");
    if !p.exists() {
        return None;
    }
    let text = std::fs::read_to_string(&p).expect("read live fixture");
    Some(serde_json::from_str(&text).expect("parse live fixture"))
}

/// The four known ghost com-objects on 1.1.4.
const GHOST_OBJECTS: [u16; 4] = [59, 106, 153, 200];

#[test]
fn computed_tables_reproduce_the_live_reference_minus_ghosts()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(live) = live_fixture() else {
        eprintln!(
            "skipping golden table test: fixtures/private/1.1.4-tables-live.json not available"
        );
        return Ok(());
    };

    // Load the real model and compute the tables for 1.1.4.
    let model = Model::load(&repo_root().join("knx"))?;
    let device: IndividualAddress = "1.1.4".parse()?;
    let links = model
        .links
        .links
        .get(&device)
        .ok_or("links for 1.1.4 in the model")?;
    let computed = compute_tables(links);

    // Parse the live tables from the fixture.
    let live_addresses: Vec<GroupAddress> = live["addresses"]
        .as_array()
        .ok_or("fixture addresses must be an array")?
        .iter()
        .map(|v| -> Result<GroupAddress, Box<dyn std::error::Error>> {
            Ok(v.as_str()
                .ok_or("fixture address must be a string")?
                .parse()?)
        })
        .collect::<Result<_, _>>()?;
    let live_assocs: Vec<(u16, u16)> = live["associations"]
        .as_array()
        .ok_or("fixture associations must be an array")?
        .iter()
        .map(|a| -> Result<(u16, u16), Box<dyn std::error::Error>> {
            Ok((
                a["tsap"].as_u64().ok_or("fixture tsap must be a number")? as u16,
                a["asap"].as_u64().ok_or("fixture asap must be a number")? as u16,
            ))
        })
        .collect::<Result<_, _>>()?;

    // Strip ghost associations, then rebuild the expected address table from the
    // GAs the remaining associations actually reference, and re-index TSAPs.
    let ghosts: std::collections::HashSet<u16> = GHOST_OBJECTS.into_iter().collect();
    let old_tsap_to_ga: BTreeMap<u16, GroupAddress> = live_addresses
        .iter()
        .enumerate()
        .map(|(i, ga)| ((i + 1) as u16, *ga))
        .collect();

    let surviving: Vec<(u16, GroupAddress)> = live_assocs
        .iter()
        .filter(|(_, asap)| !ghosts.contains(asap))
        .map(|(tsap, asap)| (*asap, old_tsap_to_ga[tsap]))
        .collect();

    // Expected address table: the sorted-unique GAs still referenced.
    let mut expected_addrs: Vec<GroupAddress> = surviving.iter().map(|(_, ga)| *ga).collect();
    expected_addrs.sort_unstable();
    expected_addrs.dedup();

    assert_eq!(
        computed.addresses, expected_addrs,
        "computed group-address table must match the live table minus ghost-only GAs"
    );

    // Expected association table: re-index the surviving live entries through the
    // new (shrunk) address table, preserving the live table order.
    let new_tsap: BTreeMap<GroupAddress, u16> = expected_addrs
        .iter()
        .enumerate()
        .map(|(i, ga)| (*ga, (i + 1) as u16))
        .collect();
    let expected_assocs: Vec<(u16, u16)> = live_assocs
        .iter()
        .filter(|(_, asap)| !ghosts.contains(asap))
        .map(|(tsap, asap)| (new_tsap[&old_tsap_to_ga[tsap]], *asap))
        .collect();

    assert_eq!(
        computed.associations, expected_assocs,
        "computed association table must byte-match the live table minus the four ghost links"
    );

    // Sanity: the ghost removal shrank both tables as expected.
    assert_eq!(
        live_assocs.len() - computed.associations.len(),
        GHOST_OBJECTS.len(),
        "exactly the four ghost associations should be removed"
    );
    Ok(())
}
