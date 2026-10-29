//! Module channels and capability rows (issues #302 and #311): the channels
//! of a module instance the configuration does not reach show as inactive
//! with what enables them, an enable step never names an internal parameter,
//! and the capability lookup merges rows that differ only in their channel
//! or device and puts the device that sends the queried value first.
//!
//! The product model is a fabrication shaped like a Jung switch actuator
//! (2-gang / 1-gang blinds): "Funktion" picks one blinds module instance or
//! two switch instances, "Logikfunktionen" shows an application channel, a
//! "Logik" channel sits behind an internal parameter nothing sets, and a
//! "Szenen" channel behind an internal parameter an `<Assign>` sets from a
//! user parameter.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_model::capabilities::capability_lookup;
use bussard_model::device_view::{NEEDS_ETS, NEEDS_FLASH, device_view};
use bussard_model::{IndividualAddress, Model, ProductModel, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-0004_A-20DE-22-0000";

const PRODUCT: &str = r#"identity:
  id: M-0004_A-20DE-22-0000
com_objects:
  50:
    text: Logik Ausgang
    function_text: Schalten
    dpt: '1.001'
    flags: CRT
    ref_id: M-0004_A-20DE-22-0000_O-50_R-50
  60:
    text: Helligkeit
    function_text: Messwert
    dpt: '9.004'
    flags: CRT
    ref_id: M-0004_A-20DE-22-0000_O-60_R-60
parameters:
  - id: M-0004_A-20DE-22-0000_P-747
    text: Funktion
    type: !enum
      values:
        - { value: 0, text: 1 x Jalousie }
        - { value: 1, text: 2 x Schalten }
    default: '0'
    refs:
      P-747_R-84: {}
  - id: M-0004_A-20DE-22-0000_P-1542
    text: Logikfunktionen
    type: !enum
      values:
        - { value: 0, text: gesperrt }
        - { value: 1, text: freigegeben }
    default: '0'
    refs:
      P-1542_R-2234: {}
  - id: M-0004_A-20DE-22-0000_P-1600
    text: Logik Treppenhauszeit
    type: !int
      min: 1
      max: 600
    default: '60'
    refs:
      P-1600_R-1600: {}
  - id: M-0004_A-20DE-22-0000_P-32
    text: CalcParam
    type: !int
      min: 0
      max: 255
    default: '0'
    refs:
      P-32_R-104:
        internal: true
      P-32_R-105:
        internal: true
  - id: M-0004_A-20DE-22-0000_P-34
    text: Szenen aktivieren
    type: !enum
      values:
        - { value: 0, text: nein }
        - { value: 1, text: ja }
    default: '0'
    refs:
      P-34_R-106: {}
  - id: M-0004_A-20DE-22-0000_P-1700
    text: Logik Verknuepfung
    type: !int
      min: 0
      max: 9
    default: '0'
    refs:
      P-1700_R-1700: {}
  - id: M-0004_A-20DE-22-0000_P-1800
    text: Szene Treppenhaus
    type: !int
      min: 0
      max: 63
    default: '0'
    refs:
      P-1800_R-1800: {}
  - id: M-0004_A-20DE-22-0000_P-1900
    text: Helligkeit senden
    type: !enum
      values:
        - { value: 0, text: nein }
        - { value: 1, text: ja }
    default: '0'
    refs:
      P-1900_R-1900: {}
  - id: M-0004_A-20DE-22-0000_MD-3_P-14
    text: Betriebsart
    type: !enum
      values:
        - { value: 1, text: Rollladen }
        - { value: 2, text: Jalousie }
    default: '1'
    refs:
      MD-3_P-14_R-14: {}
  - id: M-0004_A-20DE-22-0000_MD-4_P-12
    text: Treppenhausfunktion
    type: !enum
      values:
        - { value: 0, text: gesperrt }
        - { value: 1, text: freigegeben }
    default: '0'
    refs:
      MD-4_P-12_R-12: {}
dynamic:
  - {"channel":{"id":"CH-1","text":"Allgemein","number":1,"nodes":[{"p":"P-747_R-84"},{"p":"P-1542_R-2234"},{"p":"P-34_R-106"},{"p":"P-1900_R-1900"},{"o":"O-60_R-60"},{"choose":{"ref":"P-34_R-106","when":[{"test":"1","nodes":[{"assign":{"target":"P-32_R-105","value":"1"}}]}]}}]}}
  - {"choose":{"ref":"P-747_R-84","when":[{"test":"0","nodes":[{"module":{"id":"MD-3_M-18","def":"MD-3"}}]},{"test":"1","nodes":[{"module":{"id":"MD-4_M-19","def":"MD-4"}},{"module":{"id":"MD-4_M-20","def":"MD-4"}}]}]}}
  - {"choose":{"ref":"P-1542_R-2234","when":[{"test":"1","nodes":[{"channel":{"id":"CH-6","text":"Logikfunktionen","number":6,"nodes":[{"p":"P-1600_R-1600"},{"o":"O-50_R-50"}]}}]}]}}
  - {"choose":{"ref":"P-32_R-104","when":[{"test":"1","nodes":[{"channel":{"id":"CH-7","text":"Logik","number":7,"nodes":[{"p":"P-1700_R-1700"}]}}]}]}}
  - {"choose":{"ref":"P-32_R-105","when":[{"test":"1","nodes":[{"channel":{"id":"CH-8","text":"Szenen","number":8,"nodes":[{"p":"P-1800_R-1800"}]}}]}]}}
module_dynamics:
  MD-3:
    - {"channel":{"id":"MD-3_CH-25","text":"Relaisausgänge {{ArgBeschriftung}} ({{0:...}})","number":25,"nodes":[{"p":"MD-3_P-14_R-14"},{"o":"MD-3_O-3_R-4"}]}}
  MD-4:
    - {"channel":{"id":"MD-4_CH-1","text":"Relaisausgang {{ArgBeschriftung}}","number":1,"nodes":[{"p":"MD-4_P-12_R-12"},{"o":"MD-4_O-2_R-2"}]}}
"#;

/// The lock of a blinds device (1.1.47, "1 x Jalousie") and, with
/// `switches`, two switch devices of the same application (1.1.48 and
/// 1.1.49, "2 x Schalten", the same settings) that also send the brightness.
fn lock(switches: bool) -> String {
    let mut out = format!(
        r#"version = 3

[[device]]
address = "1.1.47"
product = "2300"
application = "{APP}"
mask = "07B0"
channels = [
  {{ key = "allgemein-1", id = "CH-1", number = 1, text = "Allgemein" }},
  {{ key = "relaisausgaenge-1", id = "MD-3_M-18_MI-1_CH-25", number = 25, text = "Relaisausgänge" }},
]
parameters = [
  {{ key = "funktion", channel = "allgemein-1", ref = "P-747_R-84", param = "P-747" }},
  {{ key = "logikfunktionen", channel = "allgemein-1", ref = "P-1542_R-2234", param = "P-1542" }},
  {{ key = "szenen-aktivieren", channel = "allgemein-1", ref = "P-34_R-106", param = "P-34" }},
  {{ key = "betriebsart", channel = "relaisausgaenge-1", ref = "MD-3_M-18_MI-1_P-14_R-14", param = "MD-3_P-14" }},
]
"#
    );
    if switches {
        for ia in ["1.1.48", "1.1.49"] {
            out.push_str(&format!(
                r#"
[[device]]
address = "{ia}"
product = "2300"
application = "{APP}"
mask = "07B0"
channels = [
  {{ key = "allgemein-1", id = "CH-1", number = 1, text = "Allgemein" }},
  {{ key = "relaisausgang-1", id = "MD-4_M-19_MI-1_CH-1", number = 1, text = "Relaisausgang" }},
  {{ key = "relaisausgang-2", id = "MD-4_M-20_MI-1_CH-1", number = 1, text = "Relaisausgang" }},
]
objects = [
  {{ number = 60, key = "helligkeit", channel = "allgemein-1", text = "Helligkeit", function = "Messwert", dpt = "9.004", flags = "CRT", ref = "O-60_R-60" }},
]
parameters = [
  {{ key = "funktion", channel = "allgemein-1", ref = "P-747_R-84", param = "P-747" }},
  {{ key = "helligkeit-senden", channel = "allgemein-1", ref = "P-1900_R-1900", param = "P-1900" }},
  {{ key = "treppenhausfunktion", channel = "relaisausgang-1", ref = "MD-4_M-19_MI-1_P-12_R-12", param = "MD-4_P-12" }},
  {{ key = "treppenhausfunktion", channel = "relaisausgang-2", ref = "MD-4_M-20_MI-1_P-12_R-12", param = "MD-4_P-12" }},
]
"#
            ));
        }
    }
    out
}

const BLINDS: &str = r#"address = "1.1.47"
name = "Jalousieaktor"
product = "2300"

[channel.allgemein-1]
funktion = "1 x Jalousie"

[channel.relaisausgaenge-1]
betriebsart = "Jalousie"
"#;

/// A switch device: both outputs alike, the brightness linked on 1.1.49.
fn switch(ia: &str, link: bool) -> String {
    let send = if link {
        "helligkeit.send = \"4/1/5\"\n"
    } else {
        ""
    };
    format!(
        r#"address = "{ia}"
name = "Schaltaktor"
product = "2300"

[channel.allgemein-1]
funktion = "2 x Schalten"
helligkeit-senden = "ja"
{send}
[channel.relaisausgang-1]
treppenhausfunktion = "freigegeben"

[channel.relaisausgang-2]
treppenhausfunktion = "freigegeben"
"#
    )
}

const GROUPS: &str =
    "groups = [\n  { address = \"4/1/5\", name = \"Helligkeit\", dpt = \"9.004\" },\n]\n";

/// A scratch model directory with the files and the product model, removed
/// on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str, switches: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-module-capabilities-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::create_dir_all(dir.join(".bussard/models"))?;
        std::fs::write(dir.join("bussard.lock"), lock(switches))?;
        std::fs::write(dir.join("devices/1.1.47.toml"), BLINDS)?;
        if switches {
            std::fs::write(dir.join("devices/1.1.48.toml"), switch("1.1.48", false))?;
            std::fs::write(dir.join("devices/1.1.49.toml"), switch("1.1.49", true))?;
        }
        std::fs::write(dir.join("groups.toml"), GROUPS)?;
        std::fs::write(
            dir.join("bussard.toml"),
            "[connection]\ntransport = \"tunnel\"\n",
        )?;
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

fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
    let mut products = ProductModels::default();
    products.insert(APP.to_string(), ProductModel::from_yaml(PRODUCT, APP)?);
    Ok(products)
}

fn blinds_model() -> Result<Model, Box<dyn std::error::Error>> {
    let files: BTreeMap<String, String> = [
        ("bussard.lock", lock(false)),
        ("devices/1.1.47.toml", BLINDS.to_string()),
        (
            "bussard.toml",
            "[connection]\ntransport = \"tunnel\"\n".to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Ok(Model::from_texts(&files)?)
}

#[test]
fn test_module_channels_of_keys_instance_channels_by_selector() -> TestResult {
    let product = ProductModel::from_yaml(PRODUCT, APP)?;
    let channels = bussard_model::blocks::module_channels_of(&product);
    let got: Vec<(&str, Option<&str>, Option<&str>)> = channels
        .iter()
        .map(|c| (c.id.as_str(), c.text.as_deref(), c.module.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "MD-3_M-18_MI-1_CH-25",
                Some("Relaisausgänge"),
                Some("MD-3_M-18")
            ),
            (
                "MD-4_M-19_MI-1_CH-1",
                Some("Relaisausgang"),
                Some("MD-4_M-19")
            ),
            (
                "MD-4_M-20_MI-1_CH-1",
                Some("Relaisausgang"),
                Some("MD-4_M-20")
            ),
        ]
    );
    let switch = &channels[1];
    assert_eq!(switch.parameters, ["MD-4_M-19_MI-1_P-12_R-12"]);
    assert_eq!(switch.when.len(), 1);
    assert_eq!(switch.when[0].reference, "P-747_R-84");
    assert_eq!(switch.when[0].test, "1");
    // The application's own pages come first, unchanged.
    let all = product.blocks_with_module_channels();
    assert_eq!(all.len(), product.blocks().len() + channels.len());
    assert!(product.blocks().iter().all(|b| b.module.is_none()));
    Ok(())
}

#[test]
fn test_device_view_marks_an_unreached_module_channel_inactive() -> TestResult {
    let model = blinds_model()?;
    let view = device_view(&model, &products()?, "1.1.47".parse()?, None)?;
    let rows: Vec<(&str, &str)> = view
        .inactive_channels
        .iter()
        .map(|r| (r.handle.as_str(), r.id.as_str()))
        .collect();
    // The application's channels, then one "Relaisausgang" row: the second
    // instance's channel is the same output under the same switch.
    assert_eq!(
        rows,
        [
            ("logikfunktionen", "CH-6"),
            ("logik", "CH-7"),
            ("szenen", "CH-8"),
            ("relaisausgang", "MD-4_M-19_MI-1_CH-1"),
        ],
        "{:?}",
        view.inactive_channels
    );
    let relay = &view.inactive_channels[3];
    let inactive = relay.inactive.as_ref().ok_or("no inactive detail")?;
    assert_eq!(inactive.enable.len(), 1);
    assert_eq!(inactive.enable[0].key.as_deref(), Some("funktion"));
    assert_eq!(inactive.enable[0].set_to, "2 x Schalten");
    // Its object has a module number the product model does not give: it
    // counts, and makes the push a flash.
    assert_eq!(inactive.module_objects, 1);
    assert!(inactive.would_show.is_empty());
    assert_eq!(inactive.needs, NEEDS_FLASH);
    assert_eq!(relay.parameters, 1);
    assert_eq!(relay.objects, 1);
    assert_eq!(
        view.summary.as_deref(),
        Some("4 channels inactive: Logikfunktionen, Logik, Szenen, Relaisausgang")
    );
    Ok(())
}

#[test]
fn test_enable_step_never_names_an_internal_parameter() -> TestResult {
    let model = blinds_model()?;
    let view = device_view(&model, &products()?, "1.1.47".parse()?, None)?;
    let row = |id: &str| {
        view.inactive_channels
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.inactive.as_ref())
            .ok_or(format!("no inactive row {id}"))
    };
    // Nothing sets CalcParam: only ETS enables "Logik".
    let logik = row("CH-7")?;
    assert_eq!(logik.enable.len(), 1);
    assert!(logik.enable[0].ets_only);
    assert_eq!(logik.enable[0].text.as_deref(), Some("enabled by ETS only"));
    assert_eq!(logik.enable[0].key, None);
    assert_eq!(logik.needs, NEEDS_ETS);
    // An `<Assign>` sets the internal ref when "Szenen aktivieren" is "ja":
    // the step names that parameter.
    let szenen = row("CH-8")?;
    assert_eq!(szenen.enable.len(), 1);
    assert!(!szenen.enable[0].ets_only);
    assert_eq!(szenen.enable[0].reference, "P-34_R-106");
    assert_eq!(szenen.enable[0].key.as_deref(), Some("szenen-aktivieren"));
    assert_eq!(szenen.enable[0].text.as_deref(), Some("Szenen aktivieren"));
    assert_eq!(szenen.enable[0].set_to, "ja");
    Ok(())
}

#[test]
fn test_capability_lookup_offers_an_unreached_module_channel() -> TestResult {
    let scratch = Scratch::new("module", false)?;
    let model = Model::load(scratch.path())?;
    let hits = capability_lookup(&model, scratch.path(), "Treppenhaus", 50);
    let relay = hits
        .iter()
        .find(|h| h.parameter == "Treppenhausfunktion")
        .ok_or("no Treppenhausfunktion row")?;
    assert_eq!(relay.status, "could provide");
    assert!(!relay.active);
    assert_eq!(relay.handle.as_deref(), Some("relaisausgang"));
    assert_eq!(relay.block_or_channel.as_deref(), Some("Relaisausgang"));
    assert_eq!(
        relay.enable.first().map(|e| e.set_to.as_str()),
        Some("2 x Schalten")
    );
    assert_eq!(relay.needs.as_deref(), Some(NEEDS_FLASH));
    // The second instance, the same output under the same switch, is not a
    // row of its own.
    assert_eq!(
        hits.iter()
            .filter(|h| h.parameter == "Treppenhausfunktion")
            .count(),
        1,
        "{hits:?}"
    );
    Ok(())
}

#[test]
fn test_capability_lookup_merges_channels_and_devices() -> TestResult {
    let scratch = Scratch::new("merge", true)?;
    let model = Model::load(scratch.path())?;
    let hits = capability_lookup(&model, scratch.path(), "Treppenhausfunktion", 50);
    let provides: Vec<_> = hits.iter().filter(|h| h.status == "provides").collect();
    // Two outputs of 1.1.48 and of 1.1.49 alike: one row. (The query names
    // no measured value, so the brightness 1.1.49 sends does not rank.)
    assert_eq!(provides.len(), 1, "{hits:?}");
    let row = provides[0];
    assert_eq!(row.channels, ["relaisausgang-1", "relaisausgang-2"]);
    assert_eq!(row.handle.as_deref(), Some("relaisausgang-1"));
    assert_eq!(row.key.as_deref(), Some("treppenhausfunktion"));
    assert_eq!(row.device_ia, "1.1.48");
    assert_eq!(row.also_on, ["1.1.49"]);
    Ok(())
}

#[test]
fn test_capability_lookup_ranks_a_device_sending_the_value_first() -> TestResult {
    let scratch = Scratch::new("rank", true)?;
    let model = Model::load(scratch.path())?;
    let hits = capability_lookup(&model, scratch.path(), "Helligkeit", 50);
    // 1.1.49 sends 9.004 to a group address, 1.1.48 sends it unlinked, 1.1.47
    // only has the parameter text.
    let order: Vec<&str> = hits.iter().map(|h| h.device_ia.as_str()).collect();
    assert_eq!(order.first(), Some(&"1.1.49"), "{hits:?}");
    let first = &hits[0];
    assert_eq!(first.status, "provides");
    assert_eq!(first.sends, ["60 Helligkeit (9.004) -> 4/1/5"]);
    let blinds = order
        .iter()
        .position(|ia| *ia == "1.1.47")
        .ok_or("1.1.47 missing")?;
    let unlinked = order
        .iter()
        .position(|ia| *ia == "1.1.48")
        .ok_or("1.1.48 missing")?;
    assert!(unlinked < blinds, "{order:?}");
    Ok(())
}

#[test]
fn test_device_view_for_blocks_details_only_the_wanted_rows() -> TestResult {
    // The lookup evaluates only the pages holding a match: the detail of a
    // page without one stays empty in the view it builds, and the full view
    // still has it.
    let model = blinds_model()?;
    let ia: IndividualAddress = "1.1.47".parse()?;
    let products = products()?;
    let wanted = ["CH-8".to_string()].into_iter().collect();
    let view = bussard_model::device_view::device_view_for_blocks(&model, &products, ia, wanted)?;
    let detail: Vec<(&str, bool)> = view
        .inactive_channels
        .iter()
        .map(|r| (r.id.as_str(), r.inactive.is_some()))
        .collect();
    assert_eq!(
        detail,
        [
            ("CH-6", false),
            ("CH-7", false),
            ("CH-8", true),
            ("MD-4_M-19_MI-1_CH-1", false),
        ]
    );
    let full = device_view(&model, &products, ia, None)?;
    assert!(full.inactive_channels.iter().all(|r| r.inactive.is_some()));
    Ok(())
}
