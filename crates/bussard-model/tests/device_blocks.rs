//! `bussard device` / `knx_show_device` on an application without channels
//! of its own (issue #298), and the capability lookup over the product
//! model's parameter and choice texts.
//!
//! The product model is `fixtures/blocks_app.yaml`, written by the importer
//! from the fabricated System 7 application in
//! `crates/bussard-prod/tests/fixtures/blocks_app.xml`: universal channels A,
//! B and C are ETS pages behind "enable" parameters (C behind B), each with a
//! "Channel function" whose first choice is a brightness threshold. The
//! device enables A with the temperature function; B and C are spare.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_model::capabilities::{cache_path, capability_lookup};
use bussard_model::device_view::{
    device_view, ignored_overrides, parameter_pages, parameter_visibility, unindexed_parameters,
};
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-00FA_A-0298-10-0000";

const PRODUCT: &str = include_str!("fixtures/blocks_app.yaml");

const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.30"
product = "WS-298"
application = "M-00FA_A-0298-10-0000"
mask = "0701"
channels = [
  { key = "generic-0", id = "CH-0", number = 0 },
]
objects = [
  { number = 0, key = "brightness", channel = "generic-0", text = "Brightness", function = "Physical value", dpt = "9.004", flags = "CRT", ref = "O-0_R-0" },
]
parameters = [
  { key = "universal-channel-a-enable", channel = "generic-0", ref = "P-1_R-1", param = "P-1" },
  { key = "universal-channel-b-enable", channel = "generic-0", ref = "P-2_R-2", param = "P-2" },
  { key = "channel-function", channel = "generic-0", ref = "P-11_R-11", param = "P-11" },
]
"#;

const DEVICE: &str = r#"address = "1.1.30"
name = "Weather station"
product = "WS-298"

[channel.generic-0]
universal-channel-a-enable = "yes"
channel-function = "Temperature sensor"
brightness.send = "4/1/5"
"#;

const GROUPS: &str =
    "groups = [\n  { address = \"4/1/5\", name = \"Brightness\", dpt = \"9.004\" },\n]\n";

fn files() -> [(&'static str, &'static str); 4] {
    [
        ("bussard.lock", LOCK),
        ("devices/1.1.30.toml", DEVICE),
        ("groups.toml", GROUPS),
        ("bussard.toml", "[connection]\ntransport = \"tunnel\"\n"),
    ]
}

fn model() -> Result<Model, Box<dyn std::error::Error>> {
    let files: BTreeMap<String, String> = files()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Ok(Model::from_texts(&files)?)
}

fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let mut products = ProductModels::default();
    products
        .by_app_ref
        .insert(APP.to_string(), ProductModel::from_yaml(PRODUCT, APP)?);
    Ok(products)
}

fn ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.30".parse()?)
}

/// A scratch model directory with the files and the product model, removed
/// on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-device-blocks-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::create_dir_all(dir.join(".bussard/models"))?;
        for (name, text) in files() {
            std::fs::write(dir.join(name), text)?;
        }
        std::fs::write(dir.join(format!(".bussard/models/{APP}.yaml")), PRODUCT)?;
        Ok(Scratch(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn test_device_view_groups_a_channel_less_app_by_page() -> TestResult {
    let view = device_view(&model()?, &products()?, ia()?, None)?;
    let rows: Vec<(&str, bool)> = view
        .blocks
        .iter()
        .map(|b| (b.handle.as_str(), b.active))
        .collect();
    // B's objects page is folded into B (the same switch shows it), and C
    // sits behind B's switch and its own.
    assert_eq!(
        rows,
        [
            ("general", true),
            ("universal-channel-a-function", true),
            ("universal-channel-b-function", false),
            ("universal-channel-c-function", false),
        ]
    );
    let general = &view.blocks[0];
    assert_eq!((general.parameters, general.objects), (2, 0));
    let a = &view.blocks[1];
    assert_eq!(a.parameters, 1);
    assert!(a.inactive.is_none());

    let b = &view.blocks[2];
    assert_eq!(b.includes, ["PB-21"]);
    let inactive = b.inactive.as_ref().ok_or("B is inactive")?;
    assert_eq!(inactive.enable.len(), 1);
    let step = &inactive.enable[0];
    assert_eq!(step.key.as_deref(), Some("universal-channel-b-enable"));
    assert_eq!(step.set_to, "yes");
    assert_eq!(step.default.as_deref(), Some("no"));
    let shown: Vec<(u16, Option<&str>)> = inactive
        .would_show
        .iter()
        .map(|o| (o.number, o.function.as_deref()))
        .collect();
    assert_eq!(shown, [(2, Some("Switch"))]);
    // The model says what kind of push it is; the surfaces say how.
    assert_eq!(inactive.needs, bussard_model::device_view::NEEDS_FLASH);

    // C needs B first, then its own switch (a parameter the configuration
    // does not show yet, so no key).
    let c = view.blocks[3].inactive.as_ref().ok_or("C is inactive")?;
    let steps: Vec<(Option<&str>, &str)> = c
        .enable
        .iter()
        .map(|e| (e.key.as_deref(), e.set_to.as_str()))
        .collect();
    assert_eq!(
        steps,
        [(Some("universal-channel-b-enable"), "yes"), (None, "yes")]
    );
    assert_eq!(
        c.enable[1].text.as_deref(),
        Some("Universal channel C enable")
    );

    let summary = view.summary.as_deref().ok_or("a summary")?;
    assert_eq!(
        summary,
        "2 of 4 pages inactive: 2 Universal channel B: function .. Universal channel C: function"
    );

    let text = view.render_table();
    assert!(
        text.contains("pages (ETS parameter blocks, in ETS order):"),
        "{text}"
    );
    assert!(
        text.contains(
            "inactive: set universal-channel-b-enable = \"yes\" (default \"no\"); shows 1 object(s)"
        ),
        "{text}"
    );
    assert!(text.contains(&format!("summary: {summary}")), "{text}");
    // The terminal says how to run the push.
    assert!(text.contains("`bussard flash 1.1.30`"), "{text}");
    Ok(())
}

#[test]
fn test_device_view_details_an_inactive_page() -> TestResult {
    let view = device_view(
        &model()?,
        &products()?,
        ia()?,
        Some("universal-channel-b-function"),
    )?;
    let scope = view.scope.as_ref().ok_or("no scope")?;
    assert_eq!(scope.block.as_deref(), Some("universal-channel-b-function"));
    assert!(scope.inactive.is_some());
    let params: Vec<(&str, Option<&str>)> = scope
        .parameters
        .iter()
        .map(|p| (p.key.as_str(), p.default.as_deref()))
        .collect();
    assert_eq!(
        params,
        [
            (
                "channel-function",
                Some("Brightness sensor 1 .. 100 000 lx")
            ),
            ("dusk-threshold-in-lx", Some("10")),
        ]
    );
    let objects: Vec<u16> = scope.objects.iter().map(|o| o.number).collect();
    assert_eq!(objects, [2]);

    // An active page lists the device's own parameters on it.
    let view = device_view(
        &model()?,
        &products()?,
        ia()?,
        Some("universal-channel-a-function"),
    )?;
    let scope = view.scope.as_ref().ok_or("no scope")?;
    assert!(scope.inactive.is_none());
    let keys: Vec<(&str, Option<&str>)> = scope
        .parameters
        .iter()
        .map(|p| (p.key.as_str(), p.value.as_deref()))
        .collect();
    assert_eq!(keys, [("channel-function", Some("Temperature sensor"))]);
    Ok(())
}

#[test]
fn test_capability_lookup_finds_a_choice_on_an_inactive_page() -> TestResult {
    let scratch = Scratch::new("lookup")?;
    let model = Model::load(scratch.path())?;
    let hits = capability_lookup(&model, scratch.path(), "brightness sensor", 50);
    let got: Vec<(Option<&str>, bool, bool, &str)> = hits
        .iter()
        .map(|h| {
            (
                h.block_or_channel.as_deref(),
                h.active,
                h.selected,
                h.status.as_str(),
            )
        })
        .collect();
    // Spare capacity (B and C, inactive) before repurposing A, which is
    // active with another function.
    assert_eq!(
        got,
        [
            (
                Some("Universal channel B: function"),
                false,
                false,
                "could provide"
            ),
            (
                Some("Universal channel C: function"),
                false,
                false,
                "could provide"
            ),
            (
                Some("Universal channel A: function"),
                true,
                false,
                "could provide"
            ),
        ]
    );
    let b = &hits[0];
    assert_eq!(b.device_ia, "1.1.30");
    assert_eq!(b.parameter, "Channel function");
    assert_eq!(
        b.choice.as_deref(),
        Some("Brightness sensor 1 .. 100 000 lx")
    );
    assert_eq!(b.handle.as_deref(), Some("universal-channel-b-function"));
    assert_eq!(
        b.enable.first().and_then(|e| e.key.as_deref()),
        Some("universal-channel-b-enable")
    );
    assert_eq!(
        b.needs.as_deref(),
        Some(bussard_model::device_view::NEEDS_FLASH)
    );

    // A parameter text matches too, and an active one the device shows
    // provides it.
    let hits = capability_lookup(&model, scratch.path(), "temperature", 50);
    assert_eq!(hits.first().map(|h| h.status.as_str()), Some("provides"));
    assert_eq!(
        hits.first().and_then(|h| h.key.as_deref()),
        Some("channel-function")
    );

    // Case does not matter. A's dusk threshold is on an active page but
    // hidden by its function, so it could provide, not provides.
    let hits = capability_lookup(&model, scratch.path(), "DUSK threshold", 50);
    let got: Vec<(Option<&str>, &str)> = hits
        .iter()
        .map(|h| (h.block_or_channel.as_deref(), h.status.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("Universal channel B: function"), "could provide"),
            (Some("Universal channel A: function"), "could provide"),
        ]
    );
    Ok(())
}

#[test]
fn test_capability_lookup_caches_the_model_and_rebuilds_a_stale_cache() -> TestResult {
    let scratch = Scratch::new("cache")?;
    let model = Model::load(scratch.path())?;
    let cache = cache_path(scratch.path(), APP);
    assert!(!cache.exists());
    let first = capability_lookup(&model, scratch.path(), "brightness", 50);
    assert!(cache.is_file(), "the lookup caches the parsed model");

    // A cache read gives the same answer.
    let again = capability_lookup(&model, scratch.path(), "brightness", 50);
    assert_eq!(first, again);

    // A model file newer than the cache is parsed again: rename a choice.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let renamed = PRODUCT.replace("Wind sensor", "Anemometer");
    let yaml = scratch.path().join(format!(".bussard/models/{APP}.yaml"));
    std::fs::write(&yaml, renamed)?;
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
    std::fs::File::options()
        .write(true)
        .open(&yaml)?
        .set_modified(future)?;
    let hits = capability_lookup(&model, scratch.path(), "anemometer", 50);
    assert_eq!(hits.len(), 3, "{hits:?}");
    Ok(())
}

#[test]
fn test_collapse_enable_chains_keeps_the_own_switch() -> TestResult {
    let mut view = device_view(&model()?, &products()?, ia()?, None)?;
    view.collapse_enable_chains();
    let b = view.blocks[2].inactive.as_ref().ok_or("B is inactive")?;
    assert_eq!(b.enable.len(), 1);
    assert!(b.also_needs.is_empty());
    let c = view.blocks[3].inactive.as_ref().ok_or("C is inactive")?;
    let refs: Vec<&str> = c.enable.iter().map(|e| e.reference.as_str()).collect();
    assert_eq!(refs, ["P-3_R-3"]);
    assert_eq!(c.also_needs, ["universal-channel-b-function"]);
    assert!(
        view.render_table()
            .contains("after universal-channel-b-function: set"),
        "{}",
        view.render_table()
    );
    // A scope keeps its full chain.
    let mut scoped = device_view(
        &model()?,
        &products()?,
        ia()?,
        Some("universal-channel-c-function"),
    )?;
    scoped.collapse_enable_chains();
    let scope = scoped.scope.as_ref().ok_or("no scope")?;
    assert_eq!(scope.inactive.as_ref().map(|i| i.enable.len()), Some(2));
    Ok(())
}

#[test]
fn test_parameter_visibility_evaluates_the_conditions_inside_a_page() -> TestResult {
    let mut model = model()?;
    let products = products()?;
    let seen = parameter_visibility(&model, &products, ia()?)?;
    let shown = |r: &str| seen.get(r).map(|v| v.shown);
    // Channel A shows its function; the dusk threshold only under the
    // brightness function, and the device runs the temperature function.
    assert_eq!(shown("P-11_R-11"), Some(true));
    assert_eq!(shown("P-12_R-12"), Some(false));
    assert_eq!(
        seen.get("P-12_R-12").and_then(|v| v.condition.as_deref()),
        Some("Channel function = Brightness sensor 1 .. 100 000 lx")
    );
    assert_eq!(
        seen.get("P-11_R-11").and_then(|v| v.condition.as_deref()),
        None
    );
    // Channel B's page is inactive: nothing on it shows.
    assert_eq!(shown("P-21_R-21"), Some(false));

    // Back to the brightness function: the threshold shows.
    let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
    let key = device
        .parameters
        .keys()
        .find(|k| k.ends_with("@P-11_R-11"))
        .cloned()
        .ok_or("no channel function stored")?;
    device
        .parameters
        .insert(key, "Brightness sensor 1 .. 100 000 lx".to_string());
    let seen = parameter_visibility(&model, &products, ia()?)?;
    assert_eq!(seen.get("P-12_R-12").map(|v| v.shown), Some(true));
    assert!(parameter_visibility(&model, &ProductModels::default(), ia()?)?.is_empty());
    Ok(())
}

/// Issue #321: what an unshown ref needs, the values it tests, and the
/// stored values that are never written.
#[test]
fn test_ignored_overrides_lists_stored_values_on_unshown_refs() -> TestResult {
    let mut model = model()?;
    let products = products()?;
    let seen = parameter_visibility(&model, &products, ia()?)?;
    let dusk = seen.get("P-12_R-12").ok_or("no P-12_R-12")?;
    assert_eq!(
        dusk.needs.as_deref(),
        Some("Channel function = Brightness sensor 1 .. 100 000 lx")
    );
    assert_eq!(
        dusk.now.as_deref(),
        Some("Channel function is Temperature sensor")
    );
    let b = seen.get("P-21_R-21").ok_or("no P-21_R-21")?;
    assert_eq!(b.needs.as_deref(), Some("Universal channel B enable = yes"));
    assert_eq!(seen.get("P-11_R-11").and_then(|v| v.needs.as_deref()), None);
    assert!(ignored_overrides(&model, &products, ia()?)?.is_empty());

    // A value at the default is no override; another one is ignored.
    let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
    device.parameters.insert(
        "dusk-threshold-in-lx@P-12_R-12".to_string(),
        "10".to_string(),
    );
    assert!(ignored_overrides(&model, &products, ia()?)?.is_empty());
    let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
    device.parameters.insert(
        "dusk-threshold-in-lx@P-12_R-12".to_string(),
        "42".to_string(),
    );
    let ignored = ignored_overrides(&model, &products, ia()?)?;
    assert_eq!(ignored.len(), 1, "{ignored:?}");
    assert_eq!(ignored[0].reference, "P-12_R-12");
    assert_eq!(ignored[0].value, "42");
    assert!(
        ignored[0].sentence().ends_with(
            "= 42 ignored: not shown under the current values (needs Channel function = \
             Brightness sensor 1 .. 100 000 lx)"
        ),
        "{}",
        ignored[0].sentence()
    );
    Ok(())
}

#[test]
fn test_parameter_pages_maps_refs_to_page_handles() -> TestResult {
    let pages = parameter_pages(&model()?, &products()?, ia()?)?;
    assert_eq!(
        pages.get("P-11_R-11").map(String::as_str),
        Some("universal-channel-a-function")
    );
    assert_eq!(pages.get("P-1_R-1").map(String::as_str), Some("general"));
    assert_eq!(
        parameter_pages(&model()?, &ProductModels::default(), ia()?)?.len(),
        0
    );
    Ok(())
}

#[test]
fn test_unindexed_parameters_lists_what_the_pages_hold_beyond_the_lock() -> TestResult {
    let more = unindexed_parameters(&model()?, &products()?, ia()?)?;
    let rows: Vec<(&str, &str, Option<&str>)> = more
        .iter()
        .map(|(r, u)| (r.as_str(), u.key.as_str(), u.page.as_deref()))
        .collect();
    assert_eq!(
        rows,
        [
            (
                "P-12_R-12",
                "dusk-threshold-in-lx",
                Some("universal-channel-a-function")
            ),
            (
                "P-13_R-13",
                "if-temperature",
                Some("universal-channel-a-function")
            ),
            (
                "P-13_R-15",
                "if-temperature",
                Some("universal-channel-a-function")
            ),
            (
                "P-14_R-14",
                "wind-threshold",
                Some("universal-channel-a-function")
            ),
            (
                "P-21_R-21",
                "channel-function",
                Some("universal-channel-b-function")
            ),
            (
                "P-22_R-22",
                "dusk-threshold-in-lx",
                Some("universal-channel-b-function")
            ),
            (
                "P-31_R-31",
                "channel-function",
                Some("universal-channel-c-function")
            ),
            ("P-3_R-3", "universal-channel-c-enable", Some("general")),
        ]
    );
    assert!(unindexed_parameters(&model()?, &ProductModels::default(), ia()?)?.is_empty());
    Ok(())
}

/// The model of [`LOCK`] and [`DEVICE`] with `lock_extra` appended to the
/// device's lock entry and the device file's channel table replaced by
/// `channel`.
fn model_with(lock_extra: &str, channel: &str) -> Result<Model, Box<dyn std::error::Error>> {
    let mut files: BTreeMap<String, String> = files()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    files.insert("bussard.lock".to_string(), format!("{LOCK}{lock_extra}"));
    let head = DEVICE
        .split("[channel.generic-0]")
        .next()
        .ok_or("no channel table")?;
    files.insert(
        "devices/1.1.30.toml".to_string(),
        format!("{head}[channel.generic-0]\n{channel}"),
    );
    Ok(Model::from_texts(&files)?)
}

/// Issue #326: channel A's wind threshold sits behind "If temperature" =
/// Wind sensor, a ref whose ETS `ParameterRef` value (4) differs from its
/// parameter's default (2). Nothing stored: the ref value holds the
/// condition, as the download side evaluates it, so a stored threshold is
/// live, not "ignored".
#[test]
fn test_parameter_visibility_takes_the_ref_value_of_a_condition() -> TestResult {
    let channel = "universal-channel-a-enable = \"yes\"\nchannel-function = \"Wind sensor\"\n\
                   brightness.send = \"4/1/5\"\n";
    let mut model = model_with("", channel)?;
    let products = products()?;
    let seen = parameter_visibility(&model, &products, ia()?)?;
    let wind = seen.get("P-14_R-14").ok_or("no P-14_R-14")?;
    assert!(wind.shown, "{wind:?}");
    assert_eq!(wind.needs, None);
    assert_eq!(
        wind.condition.as_deref(),
        Some("Channel function = Wind sensor and If temperature = Wind sensor")
    );
    assert_eq!(seen.get("P-13_R-13").map(|v| v.shown), Some(true));
    // The other ref of the parameter keeps the parameter's default and its
    // own branch (the temperature function).
    assert_eq!(seen.get("P-13_R-15").map(|v| v.shown), Some(false));

    let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
    device
        .parameters
        .insert("wind-threshold@P-14_R-14".to_string(), "8".to_string());
    assert!(ignored_overrides(&model, &products, ia()?)?.is_empty());
    Ok(())
}

/// Issue #326: a value ETS stored for the steering ref (the lock's
/// `hidden[]`, written by a flash as is) wins over its ref value, on both
/// sides: 2 closes the wind branch and the stored threshold is ignored, 4
/// opens it.
#[test]
fn test_ignored_overrides_follow_a_stored_value_over_the_ref_value() -> TestResult {
    let channel = "universal-channel-a-enable = \"yes\"\nchannel-function = \"Wind sensor\"\n\
                   brightness.send = \"4/1/5\"\n";
    let products = products()?;
    for (stored, shown) in [("2", false), ("4", true)] {
        let lock = format!("hidden = [\n  {{ ref = \"P-13_R-13\", value = \"{stored}\" }},\n]\n");
        let mut model = model_with(&lock, channel)?;
        let seen = parameter_visibility(&model, &products, ia()?)?;
        let wind = seen.get("P-14_R-14").ok_or("no P-14_R-14")?;
        assert_eq!(wind.shown, shown, "{stored}: {wind:?}");
        let device = &mut model.devices.get_mut(&ia()?).ok_or("no device")?.device;
        device
            .parameters
            .insert("wind-threshold@P-14_R-14".to_string(), "8".to_string());
        let ignored = ignored_overrides(&model, &products, ia()?)?;
        if shown {
            assert!(ignored.is_empty(), "{ignored:?}");
        } else {
            assert_eq!(ignored.len(), 1, "{ignored:?}");
            assert_eq!(ignored[0].reference, "P-14_R-14");
            assert_eq!(
                ignored[0].needs, "If temperature = Wind sensor",
                "{ignored:?}"
            );
        }
    }
    Ok(())
}

/// Issue #326: a lock row without a `default` of its own takes the ref
/// value as its default, so a stored value equal to it is at the default
/// and the row says so.
#[test]
fn test_device_view_marks_a_value_at_the_ref_value_as_default() -> TestResult {
    let lock = LOCK.replace(
        "  { key = \"channel-function\"",
        "  { key = \"if-temperature\", channel = \"generic-0\", ref = \"P-13_R-13\", param = \
         \"P-13\" },\n  { key = \"channel-function\"",
    );
    let mut files: BTreeMap<String, String> = files()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    files.insert("bussard.lock".to_string(), lock);
    files.insert(
        "devices/1.1.30.toml".to_string(),
        DEVICE.replace(
            "channel-function = \"Temperature sensor\"",
            "channel-function = \"Wind sensor\"\nif-temperature = \"Wind sensor\"",
        ),
    );
    let model = Model::from_texts(&files)?;
    let view = device_view(
        &model,
        &products()?,
        ia()?,
        Some("universal-channel-a-function"),
    )?;
    let scope = view.scope.as_ref().ok_or("no scope")?;
    let row = scope
        .parameters
        .iter()
        .find(|p| p.key == "if-temperature")
        .ok_or("no if-temperature row")?;
    assert_eq!(row.default.as_deref(), Some("Wind sensor"));
    assert_eq!(row.at_default, Some(true));
    Ok(())
}
