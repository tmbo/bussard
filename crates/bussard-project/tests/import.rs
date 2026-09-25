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
fn repo_root() -> std::io::Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
}

#[test]
fn from_json_tiny_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny.xknxproject.json");
    let model = bussard_project::import_from_json(&fixture)?;

    // Group addresses.
    assert_eq!(model.groups.groups.len(), 2);
    let ga1: GroupAddress = "1/0/1".parse()?;
    let g1 = model.groups.groups.get(&ga1).ok_or("1/0/1")?;
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
    let ia: IndividualAddress = "1.1.1".parse()?;
    let dev = &model.devices.get(&ia).ok_or("device 1.1.1")?.device;
    assert_eq!(dev.name, "Test Switch Actuator");
    assert_eq!(
        dev.product.as_ref().and_then(|p| p.manufacturer.as_deref()),
        Some("Test Manufacturer")
    );
    // Two generated com objects. The DPT is present, so the redundant `size`
    // is not stored (issue #17); the informational name lives in the device files' links
    // only, not on the com-object (issue #19).
    assert_eq!(dev.com_objects.len(), 2);
    let co0 = dev
        .com_objects
        .get(&0)
        .ok_or("dev.com_objects.get(&0) missing")?;
    assert_eq!(co0.dpt.map(|d| d.to_string()).as_deref(), Some("1.001"));
    assert!(co0.size.is_none(), "size derived from dpt, not stored");

    // Links: object 0 has no transmit flag -> listen only; object 1 has
    // transmit -> send. The name lives here.
    let links = model.links.links.get(&ia).ok_or("links for 1.1.1")?;
    let obj0 = links
        .iter()
        .find(|l| l.object == 0)
        .ok_or("links.iter().find(|l| l.object == 0) missing")?;
    assert_eq!(obj0.name.as_deref(), Some("Switch output A"));
    assert!(obj0.send.is_none());
    assert_eq!(obj0.listen, vec!["1/0/1".parse()?]);
    let obj1 = links
        .iter()
        .find(|l| l.object == 1)
        .ok_or("links.iter().find(|l| l.object == 1) missing")?;
    assert_eq!(obj1.send, Some("1/0/2".parse()?));
    assert!(obj1.listen.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Oracle comparison against the real project (env/fixture-gated).
// ---------------------------------------------------------------------------

/// Path to the real `.knxproj` under test, if present.
fn real_knxproj() -> std::io::Result<Option<PathBuf>> {
    let p = repo_root()?.join("home_test.knxproj");
    Ok(p.exists().then_some(p))
}

/// Path to the oracle JSON dump, if present.
fn oracle_json() -> std::io::Result<Option<PathBuf>> {
    let p = repo_root()?.join("fixtures/private/home_test.xknxproject.json");
    Ok(p.exists().then_some(p))
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
/// dump, or password) is missing, in which case every oracle test skips. An
/// `Err` (import or oracle parse failed) fails every oracle test.
type RealAndOracle = Result<Option<(bussard_model::Model, Value)>, String>;

fn shared_real_and_oracle() -> &'static RealAndOracle {
    use std::sync::OnceLock;
    static CACHE: OnceLock<RealAndOracle> = OnceLock::new();
    CACHE.get_or_init(|| {
        let load =
            || -> Result<Option<(bussard_model::Model, Value)>, Box<dyn std::error::Error>> {
                let (Some(knxproj), Some(oracle_path), Some(password)) =
                    (real_knxproj()?, oracle_json()?, project_password())
                else {
                    return Ok(None);
                };
                let model = bussard_project::import(&knxproj, Some(&password))?;
                let oracle: Value = serde_json::from_str(&std::fs::read_to_string(oracle_path)?)?;
                Ok(Some((model, oracle)))
            };
        load().map_err(|e| e.to_string())
    })
}

/// Borrows the shared real import and oracle, or returns `None` (skipping the
/// test) when any prerequisite is missing.
fn load_real_and_oracle()
-> Result<Option<(&'static bussard_model::Model, &'static Value)>, Box<dyn std::error::Error>> {
    match shared_real_and_oracle() {
        Ok(loaded) => Ok(loaded.as_ref().map(|(model, oracle)| (model, oracle))),
        Err(e) => Err(e.clone().into()),
    }
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

/// One combined oracle test: the decrypt+parse of the real project dominates
/// (~7.5s) and nextest isolates processes, so three separate tests paid it
/// three times. One test, three assertion sections.
#[test]
fn oracle_matches() -> Result<(), Box<dyn std::error::Error>> {
    oracle_group_addresses_match()?;
    oracle_devices_match()?;
    oracle_com_object_links_match()?;
    real_module_bases_match()?;
    real_project_name_is_extracted()?;
    Ok(())
}

/// The real project's name is read from `project.xml` and populated on the
/// model (issue #62). Before this fix `project.xml` was never read, so
/// `groups.project` was always `None`. The real `home_test.knxproj`'s
/// `ProjectInformation@Name` is "Bocklisch / Alpha" with a `ThreeLevel`
/// group-address style, so import must succeed and carry that name.
fn real_project_name_is_extracted() -> Result<(), Box<dyn std::error::Error>> {
    let Some((model, _)) = load_real_and_oracle()? else {
        eprintln!("skipping real_project_name_is_extracted: fixtures/password not available");
        return Ok(());
    };
    assert_eq!(
        model.groups.project.as_deref(),
        Some("Bocklisch / Alpha"),
        "project name should be read from project.xml"
    );
    Ok(())
}

/// The per-module-instance memory base offsets (issue #48) resolve to the real
/// `ModuleInstance` `ParamOffsBase` argument values for the reference actuator
/// (Jung 23024 at 1.1.4). These bases are the byte a channel's module parameters
/// are placed relative to; the flasher adds a parameter's declared Offset to them.
///
/// Evidence (extracted from the real project's `ModuleInstance` arguments): the
/// 12-channel MD-1 module steps its `ParamOffsBase` by 496 per channel — M-1 =
/// 805, M-2 = 1301, M-3 = 1797, … M-12 = 6261 — and the map is keyed by the
/// module-instance selector `MD-1_M-<m>_MI-1`, exactly what `compute_parameter_image`
/// looks up in its `base_offsets` and what a parameter key reduces to once its
/// `_P-<p>_R-<r>` suffix is stripped.
fn real_module_bases_match() -> Result<(), Box<dyn std::error::Error>> {
    let Some((model, _)) = load_real_and_oracle()? else {
        eprintln!("skipping real_module_bases_match: fixtures/password not available");
        return Ok(());
    };
    let ia: IndividualAddress = "1.1.4".parse()?;
    let dev = &model.devices.get(&ia).ok_or("device 1.1.4 present")?.device;

    // The full 12-channel progression (start 805, step 496).
    let expected: Vec<(String, u32)> = (1..=12)
        .map(|m| (format!("MD-1_M-{m}_MI-1"), 805 + (m - 1) * 496))
        .collect();
    for (selector, base) in &expected {
        assert_eq!(
            dev.module_bases.get(selector).copied(),
            Some(*base),
            "module base for {selector}"
        );
    }
    // The known anchors called out in issue #48's derivation notes.
    assert_eq!(dev.module_bases["MD-1_M-1_MI-1"], 805);
    assert_eq!(dev.module_bases["MD-1_M-3_MI-1"], 1797);
    // Exactly the 12 module instances are keyed; no stray entries.
    assert_eq!(dev.module_bases.len(), 12, "one base per module instance");

    // Round-trip: the map survives a save/load byte-for-byte and remains keyed by
    // the flasher's selector format.
    let dir = tempfile::tempdir()?;
    model.save(dir.path())?;
    let reloaded = bussard_model::Model::load(dir.path())?;
    assert_eq!(
        reloaded.devices[&ia].device.module_bases, dev.module_bases,
        "module_bases round-trips through save/load"
    );
    Ok(())
}

fn oracle_group_addresses_match() -> Result<(), Box<dyn std::error::Error>> {
    let Some((model, oracle)) = load_real_and_oracle()? else {
        eprintln!("skipping oracle_group_addresses_match: fixtures/password not available");
        return Ok(());
    };

    let oga = oracle["group_addresses"]
        .as_object()
        .ok_or("oracle[\"group_addresses\"].as_object() missing")?;
    assert_eq!(
        model.groups.groups.len(),
        oga.len(),
        "group-address count mismatch"
    );

    for (addr, ov) in oga {
        let ga: GroupAddress = addr.parse()?;
        let mine = model
            .groups
            .groups
            .get(&ga)
            .unwrap_or_else(|| panic!("missing GA {addr}"));
        assert_eq!(
            &mine.name,
            ov["name"].as_str().ok_or("ov[\"name\"].as_str() missing")?,
            "name for {addr}"
        );
        assert_eq!(
            mine.dpt.map(|d| d.to_string()),
            oracle_dpt_string(&ov["dpt"]),
            "dpt for {addr}"
        );
    }
    Ok(())
}

fn oracle_devices_match() -> Result<(), Box<dyn std::error::Error>> {
    let Some((model, oracle)) = load_real_and_oracle()? else {
        eprintln!("skipping oracle_devices_match: fixtures/password not available");
        return Ok(());
    };

    let odev = oracle["devices"]
        .as_object()
        .ok_or("oracle[\"devices\"].as_object() missing")?;
    assert_eq!(model.devices.len(), odev.len(), "device count mismatch");

    for (addr, ov) in odev {
        let ia: IndividualAddress = addr.parse()?;
        let mine = model
            .devices
            .get(&ia)
            .unwrap_or_else(|| panic!("missing device {addr}"));
        assert_eq!(
            mine.device.name,
            ov["name"].as_str().ok_or("ov[\"name\"].as_str() missing")?,
            "name for {addr}"
        );
    }
    Ok(())
}

fn oracle_com_object_links_match() -> Result<(), Box<dyn std::error::Error>> {
    let Some((model, oracle)) = load_real_and_oracle()? else {
        eprintln!("skipping oracle_com_object_links_match: fixtures/password not available");
        return Ok(());
    };

    // Oracle: device -> object number -> set of linked GAs.
    let mut oracle_links: BTreeMap<String, BTreeMap<u64, BTreeSet<String>>> = BTreeMap::new();
    for co in oracle["communication_objects"]
        .as_object()
        .ok_or("oracle[\"communication_objects\"].as_object() missing")?
        .values()
    {
        let dev = co["device_address"]
            .as_str()
            .ok_or("co[\"device_address\"].as_str() missing")?
            .to_string();
        let num = co["number"]
            .as_u64()
            .ok_or("co[\"number\"].as_u64() missing")?;
        let gas: BTreeSet<String> = co["group_address_links"]
            .as_array()
            .ok_or("co[\"group_address_links\"].as_array() missing")?
            .iter()
            .map(|g| {
                g.as_str()
                    .map(str::to_string)
                    .ok_or("GA link is not a string")
            })
            .collect::<Result<_, _>>()?;
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
    Ok(())
}
