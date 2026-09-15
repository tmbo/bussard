//! Integration tests for `.knxproj` import.
//!
//! Two kinds of tests live here:
//!
//! * [`from_json_tiny_fixture`] runs always: it imports a small, hand-written
//!   `xknxproject` JSON dump (fabricated data — no real project content) and
//!   checks the resulting model shape.
//! * The `oracle_*` tests compare a real `.knxproj` import against an
//!   `xknxproject` JSON dump of the same file (the acceptance oracle). They are
//!   skipped unless the private fixtures and the project password are present,
//!   so CI passes without the private data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_model::{GroupAddress, IndividualAddress};
use serde_json::Value;

/// The repository root (two levels up from this crate).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
fn from_json_tiny_fixture() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny.xknxproject.json");
    let model = bussard_project::import_from_json(&fixture).expect("import tiny fixture");

    // Group addresses.
    assert_eq!(model.groups.groups.len(), 2);
    let ga1: GroupAddress = "1/0/1".parse().unwrap();
    let g1 = model.groups.groups.get(&ga1).expect("1/0/1");
    assert_eq!(g1.name, "Living room light switch");
    assert_eq!(g1.dpt.map(|d| d.to_string()).as_deref(), Some("1.001"));

    // Ranges flattened from the two-level tree.
    assert_eq!(
        model.groups.ranges.get("1").map(|r| r.name.as_str()),
        Some("Ground floor")
    );
    assert_eq!(
        model.groups.ranges.get("1/0").map(|r| r.name.as_str()),
        Some("Lighting")
    );

    // Device.
    let ia: IndividualAddress = "1.1.1".parse().unwrap();
    let dev = &model.devices.get(&ia).expect("device 1.1.1").device;
    assert_eq!(dev.name, "Test Switch Actuator");
    assert_eq!(
        dev.product.as_ref().and_then(|p| p.manufacturer.as_deref()),
        Some("Test Manufacturer")
    );
    // Two generated com objects. The DPT is present, so the redundant `size`
    // is not stored (issue #17); the informational name lives in links.yaml
    // only, not on the com-object (issue #19).
    assert_eq!(dev.com_objects.len(), 2);
    let co0 = dev.com_objects.get(&0).unwrap();
    assert_eq!(co0.dpt.map(|d| d.to_string()).as_deref(), Some("1.001"));
    assert!(co0.size.is_none(), "size derived from dpt, not stored");

    // Links: object 0 has no transmit flag -> listen only; object 1 has
    // transmit -> send. The name lives here.
    let links = model.links.links.get(&ia).expect("links for 1.1.1");
    let obj0 = links.iter().find(|l| l.object == 0).unwrap();
    assert_eq!(obj0.name.as_deref(), Some("Switch output A"));
    assert!(obj0.send.is_none());
    assert_eq!(obj0.listen, vec!["1/0/1".parse().unwrap()]);
    let obj1 = links.iter().find(|l| l.object == 1).unwrap();
    assert_eq!(obj1.send, Some("1/0/2".parse().unwrap()));
    assert!(obj1.listen.is_empty());
}

// ---------------------------------------------------------------------------
// Oracle comparison against the real project (env/fixture-gated).
// ---------------------------------------------------------------------------

/// Path to the real `.knxproj` under test, if present.
fn real_knxproj() -> Option<PathBuf> {
    let p = repo_root().join("home_test.knxproj");
    p.exists().then_some(p)
}

/// Path to the oracle JSON dump, if present.
fn oracle_json() -> Option<PathBuf> {
    let p = repo_root().join("fixtures/private/home_test.xknxproject.json");
    p.exists().then_some(p)
}

/// The project password from the environment, if set.
fn project_password() -> Option<String> {
    std::env::var("BUSSARD_PROJECT_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Imports the real `.knxproj` and parses the oracle JSON exactly once per test
/// binary, sharing the result across all `oracle_*` tests.
///
/// Importing the real project decrypts a WinZip-AES archive and streams ~15 MB
/// of XML; at the test profile's opt-level that costs ~14 s. The three oracle
/// tests previously each did this independently (~42 s of redundant work per
/// run). Caching it in a process-wide [`OnceLock`] makes the second and third
/// tests effectively free. Nextest runs each test binary in its own process, so
/// this cache is scoped to this binary's oracle tests (which is all of them).
///
/// The value is `Option`: `None` means a prerequisite (private fixture, oracle
/// dump, or password) is missing, in which case every oracle test skips.
type RealAndOracle = Option<(bussard_model::Model, Value)>;

fn shared_real_and_oracle() -> &'static RealAndOracle {
    use std::sync::OnceLock;
    static CACHE: OnceLock<RealAndOracle> = OnceLock::new();
    CACHE.get_or_init(|| {
        let knxproj = real_knxproj()?;
        let oracle_path = oracle_json()?;
        let password = project_password()?;
        let model = bussard_project::import(&knxproj, Some(&password))
            .expect("import real .knxproj with password");
        let oracle: Value =
            serde_json::from_str(&std::fs::read_to_string(oracle_path).expect("read oracle"))
                .expect("parse oracle");
        Some((model, oracle))
    })
}

/// Borrows the shared real import and oracle, or returns `None` (skipping the
/// test) when any prerequisite is missing.
fn load_real_and_oracle() -> Option<(&'static bussard_model::Model, &'static Value)> {
    shared_real_and_oracle()
        .as_ref()
        .map(|(model, oracle)| (model, oracle))
}

/// A DPT string in the model's canonical form, from an oracle dpt object.
fn oracle_dpt_string(dpt: &Value) -> Option<String> {
    if dpt.is_null() {
        return None;
    }
    let main = dpt.get("main")?.as_u64()?;
    match dpt.get("sub").and_then(Value::as_u64) {
        Some(sub) => Some(format!("{main}.{sub:03}")),
        None => Some(format!("{main}")),
    }
}

#[test]
fn oracle_group_addresses_match() {
    let Some((model, oracle)) = load_real_and_oracle() else {
        eprintln!("skipping oracle_group_addresses_match: fixtures/password not available");
        return;
    };

    let oga = oracle["group_addresses"].as_object().unwrap();
    assert_eq!(
        model.groups.groups.len(),
        oga.len(),
        "group-address count mismatch"
    );

    for (addr, ov) in oga {
        let ga: GroupAddress = addr.parse().expect("parse oracle GA");
        let mine = model
            .groups
            .groups
            .get(&ga)
            .unwrap_or_else(|| panic!("missing GA {addr}"));
        assert_eq!(&mine.name, ov["name"].as_str().unwrap(), "name for {addr}");
        assert_eq!(
            mine.dpt.map(|d| d.to_string()),
            oracle_dpt_string(&ov["dpt"]),
            "dpt for {addr}"
        );
    }
}

#[test]
fn oracle_devices_match() {
    let Some((model, oracle)) = load_real_and_oracle() else {
        eprintln!("skipping oracle_devices_match: fixtures/password not available");
        return;
    };

    let odev = oracle["devices"].as_object().unwrap();
    assert_eq!(model.devices.len(), odev.len(), "device count mismatch");

    for (addr, ov) in odev {
        let ia: IndividualAddress = addr.parse().expect("parse oracle IA");
        let mine = model
            .devices
            .get(&ia)
            .unwrap_or_else(|| panic!("missing device {addr}"));
        assert_eq!(
            mine.device.name,
            ov["name"].as_str().unwrap(),
            "name for {addr}"
        );
    }
}

#[test]
fn oracle_com_object_links_match() {
    let Some((model, oracle)) = load_real_and_oracle() else {
        eprintln!("skipping oracle_com_object_links_match: fixtures/password not available");
        return;
    };

    // Oracle: device -> object number -> set of linked GAs.
    let mut oracle_links: BTreeMap<String, BTreeMap<u64, BTreeSet<String>>> = BTreeMap::new();
    for co in oracle["communication_objects"]
        .as_object()
        .unwrap()
        .values()
    {
        let dev = co["device_address"].as_str().unwrap().to_string();
        let num = co["number"].as_u64().unwrap();
        let gas: BTreeSet<String> = co["group_address_links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap().to_string())
            .collect();
        if !gas.is_empty() {
            oracle_links.entry(dev).or_default().insert(num, gas);
        }
    }

    // Mine: device -> object number -> set of linked GAs (send + listen).
    let mut my_links: BTreeMap<String, BTreeMap<u64, BTreeSet<String>>> = BTreeMap::new();
    for (ia, entries) in &model.links.links {
        for link in entries {
            let mut gas: BTreeSet<String> = link.listen.iter().map(|g| g.to_string()).collect();
            if let Some(send) = link.send {
                gas.insert(send.to_string());
            }
            if !gas.is_empty() {
                my_links
                    .entry(ia.to_string())
                    .or_default()
                    .insert(u64::from(link.object), gas);
            }
        }
    }

    // Compare the two maps device-by-device, object-by-object.
    let all_devices: BTreeSet<&String> = oracle_links.keys().chain(my_links.keys()).collect();
    let mut problems = Vec::new();
    for dev in all_devices {
        let empty = BTreeMap::new();
        let o = oracle_links.get(dev).unwrap_or(&empty);
        let m = my_links.get(dev).unwrap_or(&empty);
        let nums: BTreeSet<u64> = o.keys().chain(m.keys()).copied().collect();
        for num in nums {
            match (o.get(&num), m.get(&num)) {
                (Some(og), Some(mg)) if og == mg => {}
                (Some(og), Some(mg)) => {
                    problems.push(format!("{dev} obj {num}: mine {mg:?} vs oracle {og:?}"))
                }
                (Some(og), None) => {
                    problems.push(format!("{dev} obj {num}: missing (oracle {og:?})"))
                }
                (None, Some(mg)) => problems.push(format!("{dev} obj {num}: extra (mine {mg:?})")),
                (None, None) => unreachable!(),
            }
        }
    }

    assert!(
        problems.is_empty(),
        "{} com-object link mismatches:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
