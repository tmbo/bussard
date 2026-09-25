//! Lock keys end to end: a fabricated `.knxproj` whose device runs the
//! `dynamic_tree.app.xml` program (channels, parameter blocks, module
//! instances, a label parameter, an enum) is imported, saved and loaded again.
//! The device file must read by handles and keys, the lock must record them,
//! and a load/save cycle must reproduce both.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_ets::application::parse_application_program;
use bussard_model::{IndividualAddress, Model};
use bussard_project::facts::{apply_facts, derive_facts};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-00FA_A-00D1-10-0001";
const APP_XML: &[u8] = include_bytes!("fixtures/dynamic_tree.app.xml");

/// A project with one device on 1.1.30 running the fixture program: a
/// channel label, a heating delay, the first output's mode (an enum) and the
/// second output's label set away from the defaults, a value for a ref the
/// configuration does not show (`P-4_R-6`, the alternative of the shown
/// `P-4_R-5`), and object 0 linked.
const PROJECT_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-9999">
  <Installations><Installation>
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-9999-0_DI-1" Address="30" Name="Fixture actuator" Hardware2ProgramRefId="M-00FA_H-1_HP-00D1-10-0001">
     <ParameterInstanceRefs>
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_P-1_R-1" Value="Bath" />
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_P-2_R-3" Value="9" />
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_P-4_R-5" Value="60" />
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_P-4_R-6" Value="30" />
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_MD-1_M-1_MI-1_P-2_R-2" Value="1" />
      <ParameterInstanceRef RefId="M-00FA_A-00D1-10-0001_MD-1_M-2_MI-1_P-1_R-1" Value="Garage" />
     </ParameterInstanceRefs>
     <ComObjectInstanceRefs>
      <ComObjectInstanceRef RefId="O-0_R-1" Links="GA-1" />
     </ComObjectInstanceRefs>
    </DeviceInstance>
   </Line></Area></Topology>
   <GroupAddresses><GroupRanges>
    <GroupRange Id="P-9999-0_GR-1" RangeStart="2048" RangeEnd="4095" Name="Licht">
     <GroupAddress Id="P-9999-0_GA-1" Address="2049" Name="Licht Bad" />
    </GroupRange>
   </GroupRanges></GroupAddresses>
  </Installation></Installations>
 </Project>
</KNX>"#;

fn tmp(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-lock-keys-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Writes the unencrypted `.knxproj` and returns its path.
fn write_knxproj(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("fixture.knxproj");
    let mut zw = ZipWriter::new(std::fs::File::create(&path)?);
    let opts = SimpleFileOptions::default();
    zw.start_file("knx_master.xml", opts)?;
    zw.write_all(br#"<KNX xmlns="http://knx.org/xml/project/21"/>"#)?;
    zw.start_file("P-9999/0.xml", opts)?;
    zw.write_all(PROJECT_XML.as_bytes())?;
    zw.start_file(format!("M-00FA/{APP_ID}.xml"), opts)?;
    zw.write_all(APP_XML)?;
    zw.finish()?;
    Ok(path)
}

/// Imports the fixture and saves it into a fresh model directory.
fn imported() -> Result<(PathBuf, Model), Box<dyn std::error::Error>> {
    let dir = tmp("import")?;
    let knxproj = write_knxproj(&dir)?;
    let model = bussard_project::import(&knxproj, None)?;
    let out = dir.join("knx");
    model.save(&out)?;
    Ok((out, model))
}

fn read(dir: &Path, rel: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(dir.join(rel))?)
}

#[test]
fn test_import_writes_handles_keys_labels_and_enum_labels() -> TestResult {
    let (dir, _) = imported()?;
    let file = read(&dir, "devices/1.1.30.toml")?;
    // Channel order is by vendor number (both module instances are 1, the
    // device-level channel is 7), then handle.
    let expected = r#"address = "1.1.30"
name = "Fixture actuator"

[channel.output-1]
output-mode = "Heating"

[channel.output-2]
name = "Garage"

[channel.heating-7]
name = "Bath"
heating-delay = "9"
on-off.listen = ["1/0/1"]
"#;
    assert_eq!(file, expected);
    Ok(())
}

#[test]
fn test_import_populates_the_lock() -> TestResult {
    let (dir, _) = imported()?;
    let lock = read(&dir, "bussard.lock")?;
    for line in [
        r#"  { key = "heating-7", id = "CH-1", number = 7, text = "Heating (Bath)", label_ref = "P-1_R-1" },"#,
        r#"  { key = "output-2", id = "MD-1_M-2_MI-1_CH-1", number = 1, text = "Output (Garage)", label_ref = "MD-1_M-2_MI-1_P-1_R-1", base = 40 },"#,
        r#"  { key = "output-1", id = "MD-1_M-1_MI-1_CH-1", number = 1, text = "Output", label_ref = "MD-1_M-1_MI-1_P-1_R-1", base = 20 },"#,
        r#"  { number = 0, key = "on-off", channel = "heating-7", text = "Switch (Bath)", function = "On/Off", dpt = "1.001", flags = "CW", ref = "O-0_R-1" },"#,
        r#"  { key = "heating-delay", channel = "heating-7", ref = "P-2_R-3", param = "P-2" },"#,
        r#"  { key = "output-mode", channel = "output-1", ref = "MD-1_M-1_MI-1_P-2_R-2", param = "MD-1_P-2" },"#,
    ] {
        assert!(lock.contains(line), "lock lacks {line}\n{lock}");
    }
    // Only the parameters the device file sets are listed; the others
    // (vendor defaults) are in the product model.
    for absent in [
        r#"key = "hidden""#,
        r#"key = "cycle""#,
        r#"key = "mode""#,
        r#"channel = "output-2", ref"#,
    ] {
        assert!(!lock.contains(absent), "lock lists {absent}\n{lock}");
    }
    // The value of the ref ETS does not show is the lock's, not the file's.
    assert!(
        lock.contains("hidden = [\n  { ref = \"P-4_R-6\", value = \"30\" },\n]\n"),
        "{lock}"
    );
    // Without an override the one language the program offers is used.
    assert!(lock.contains("\nlanguage = \"en-US\"\n"), "{lock}");
    // The label parameters have no key.
    assert!(!lock.contains(r#"ref = "P-1_R-1", param"#), "{lock}");
    Ok(())
}

#[test]
fn test_import_with_language_records_it_for_the_reimport() -> TestResult {
    let dir = tmp("language")?;
    let knxproj = write_knxproj(&dir)?;
    let out = dir.join("knx");
    let options = bussard_project::ImportOptions {
        language: Some("de-DE".to_string()),
    };
    bussard_project::import_with(&knxproj, None, &options)?.save(&out)?;
    let lock = read(&out, "bussard.lock")?;
    assert!(lock.contains("\nlanguage = \"de-DE\"\n"), "{lock}");
    // The program has no de-DE layer, so its untranslated texts are used.
    assert!(lock.contains(r#"text = "Heizung (Bath)""#), "{lock}");
    let file = read(&out, "devices/1.1.30.toml")?;
    assert!(file.contains("verzoegerung-heizen = \"9\""), "{file}");

    // A re-import into the directory keeps the recorded language ...
    assert_eq!(bussard_project::ImportOptions::for_dir(&out), options);
    let again = bussard_project::import_with(&knxproj, None, &options)?;
    again.save(&out)?;
    assert_eq!(read(&out, "bussard.lock")?, lock);
    assert_eq!(read(&out, "devices/1.1.30.toml")?, file);
    // ... unless `bussard.toml` overrides it.
    std::fs::write(
        out.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n\n[import]\nlanguage = \"en-US\"\n",
    )?;
    assert_eq!(
        bussard_project::ImportOptions::for_dir(&out)
            .language
            .as_deref(),
        Some("en-US")
    );
    Ok(())
}

/// A product model for the fixture program, as `import-product` writes it
/// (only the enum the device sets).
const MODEL_YAML: &str = "parameters:
  - id: M-00FA_A-00D1-10-0001_MD-1_P-2
    type: !enum
      values:
        - value: 0
          text: Off
        - value: 1
          text: Heating
    default: '0'
";

#[test]
fn test_import_load_save_round_trip_with_product_model() -> TestResult {
    let (dir, model) = imported()?;
    std::fs::create_dir_all(dir.join("models"))?;
    std::fs::write(dir.join(format!("models/{APP_ID}.yaml")), MODEL_YAML)?;
    let before_file = read(&dir, "devices/1.1.30.toml")?;
    let before_lock = read(&dir, "bussard.lock")?;
    let loaded = Model::load(&dir)?;
    let ia: IndividualAddress = "1.1.30".parse()?;
    let imported = &model.devices[&ia].device;
    let device = &loaded.devices[&ia].device;
    // The enum label reads back as its code; the labels as the channel names.
    assert_eq!(device.parameters, imported.parameters);
    assert_eq!(
        device.parameters.get("label@P-1_R-1"),
        Some(&"Bath".to_string())
    );
    assert_eq!(device.channels, imported.channels);
    assert_eq!(device.com_objects, imported.com_objects);
    assert_eq!(device.lock.parameters, imported.lock.parameters);
    loaded.save(&dir)?;
    assert_eq!(read(&dir, "devices/1.1.30.toml")?, before_file);
    assert_eq!(read(&dir, "bussard.lock")?, before_lock);

    // A changed code is written as its label.
    let mut changed = Model::load(&dir)?;
    if let Some(d) = changed.devices.get_mut(&ia) {
        d.device
            .parameters
            .insert("output-mode@MD-1_M-1_MI-1_P-2_R-2".into(), "0".into());
    }
    changed.save(&dir)?;
    let file = read(&dir, "devices/1.1.30.toml")?;
    assert!(file.contains("output-mode = \"Off\""), "{file}");
    Ok(())
}

/// The fixture's product model with the parameter refs listed, so a key the
/// lock does not list resolves through it.
const MODEL_WITH_REFS_YAML: &str = "parameters:
  - id: M-00FA_A-00D1-10-0001_MD-1_P-2
    text: Output mode
    type: !enum
      values:
        - value: 0
          text: Off
        - value: 1
          text: Heating
    default: '0'
    refs: [M-00FA_A-00D1-10-0001_MD-1_P-2_R-2]
  - id: M-00FA_A-00D1-10-0001_P-3
    text: Mode
    type: !int
      min: 0
    refs: [M-00FA_A-00D1-10-0001_P-3_R-4]
";

#[test]
fn test_unlisted_key_resolves_through_the_product_model_else_e023() -> TestResult {
    let (dir, _) = imported()?;
    let file = read(&dir, "devices/1.1.30.toml")?;
    let edited = file
        .replace(
            "[channel.heating-7]\n",
            "[channel.heating-7]\nmode = \"0\"\n",
        )
        .replace(
            "[channel.output-2]\nname = \"Garage\"\n",
            "[channel.output-2]\nname = \"Garage\"\noutput-mode = \"Heating\"\n",
        );
    assert_ne!(edited, file);
    std::fs::write(dir.join("devices/1.1.30.toml"), &edited)?;

    // Without a product model the keys are unknown.
    let model = Model::load(&dir)?;
    let e023 = bussard_model::validate::validate_in_dir(&model, &dir)
        .into_iter()
        .filter(|d| d.code == "E023")
        .count();
    assert_eq!(e023, 2);

    // With one they resolve, and a save lists them in the lock.
    std::fs::create_dir_all(dir.join("models"))?;
    std::fs::write(
        dir.join(format!("models/{APP_ID}.yaml")),
        MODEL_WITH_REFS_YAML,
    )?;
    let model = Model::load(&dir)?;
    let e023 = bussard_model::validate::validate_in_dir(&model, &dir)
        .into_iter()
        .filter(|d| d.code == "E023")
        .count();
    assert_eq!(e023, 0);
    let ia: IndividualAddress = "1.1.30".parse()?;
    let params = &model.devices[&ia].device.parameters;
    assert_eq!(params.get("mode@P-3_R-4"), Some(&"0".to_string()));
    assert_eq!(
        params.get("output-mode@MD-1_M-2_MI-1_P-2_R-2"),
        Some(&"1".to_string())
    );
    model.save(&dir)?;
    let lock = read(&dir, "bussard.lock")?;
    for line in [
        r#"  { key = "mode", channel = "heating-7", ref = "P-3_R-4", param = "P-3" },"#,
        r#"  { key = "output-mode", channel = "output-2", ref = "MD-1_M-2_MI-1_P-2_R-2", param = "MD-1_P-2" },"#,
    ] {
        assert!(lock.contains(line), "lock lacks {line}\n{lock}");
    }
    assert_eq!(read(&dir, "devices/1.1.30.toml")?, edited);
    Ok(())
}

#[test]
fn test_import_load_without_product_model_keeps_the_label() -> TestResult {
    let (dir, _) = imported()?;
    let loaded = Model::load(&dir)?;
    let ia: IndividualAddress = "1.1.30".parse()?;
    assert_eq!(
        loaded.devices[&ia]
            .device
            .parameters
            .get("output-mode@MD-1_M-1_MI-1_P-2_R-2"),
        Some(&"Heating".to_string())
    );
    let before = read(&dir, "devices/1.1.30.toml")?;
    loaded.save(&dir)?;
    assert_eq!(read(&dir, "devices/1.1.30.toml")?, before);
    Ok(())
}

#[test]
fn test_import_keeps_codes_in_memory() -> TestResult {
    let (_, model) = imported()?;
    let ia: IndividualAddress = "1.1.30".parse()?;
    let device = &model.devices[&ia].device;
    assert_eq!(
        device.parameters.get("output-mode@MD-1_M-1_MI-1_P-2_R-2"),
        Some(&"1".to_string())
    );
    assert_eq!(
        device.parameters.get("heating-delay@P-2_R-3"),
        Some(&"9".to_string())
    );
    // The hidden value stays in memory for the flash.
    assert_eq!(
        device.parameters.get("hidden@P-4_R-6"),
        Some(&"30".to_string())
    );
    Ok(())
}

#[test]
fn test_reimport_replaces_hidden_values() -> TestResult {
    let (dir, _) = imported()?;
    let ia: IndividualAddress = "1.1.30".parse()?;
    let loaded = Model::load(&dir)?;
    assert_eq!(
        loaded.devices[&ia].device.parameters.get("hidden@P-4_R-6"),
        Some(&"30".to_string())
    );
    // The project changes the hidden value; the merge takes the fresh one.
    let mut fresh = loaded.clone();
    if let Some(d) = fresh.devices.get_mut(&ia) {
        d.device.parameters.remove("hidden@P-4_R-6");
        d.device
            .parameters
            .insert("hidden@P-4_R-7".into(), "12".into());
    }
    let (merged, _) = bussard_model::merge(&loaded, &fresh);
    merged.save(&dir)?;
    let lock = read(&dir, "bussard.lock")?;
    assert!(
        lock.contains(r#"{ ref = "P-4_R-7", value = "12" }"#),
        "{lock}"
    );
    assert!(!lock.contains("P-4_R-6"), "{lock}");
    assert!(!read(&dir, "devices/1.1.30.toml")?.contains("P-4_R-"));
    Ok(())
}

#[test]
fn test_derive_facts_with_vendor_defaults() -> TestResult {
    let app = parse_application_program(APP_ID, APP_XML)?;
    let facts = derive_facts(&app, &BTreeMap::new(), &Default::default());
    let handles: Vec<(&str, &str)> = facts
        .channels
        .iter()
        .map(|c| (c.key.as_str(), c.id.as_str()))
        .collect();
    assert_eq!(
        handles,
        [
            ("heating-7", "CH-1"),
            ("output-2", "MD-1_M-2_MI-1_CH-1"),
            ("output-1", "MD-1_M-1_MI-1_CH-1"),
        ]
    );
    // The vendor default label fills the text.
    assert_eq!(facts.channels[0].text.as_deref(), Some("Heating (Kitchen)"));
    assert_eq!(facts.channels[0].label.as_deref(), Some("Kitchen"));

    let mut device = bussard_model::schema::Device {
        address: "1.1.9".parse()?,
        name: "fresh".into(),
        description: None,
        location: None,
        replaced: None,
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects: BTreeMap::new(),
        application_override: None,
        lock: Default::default(),
        security: None,
    };
    apply_facts(&mut device, &app, &facts, &BTreeMap::new());
    assert!(device.parameters.is_empty());
    // Nothing stored, nothing listed.
    assert!(device.lock.parameters.is_empty());
    assert_eq!(
        device.com_objects.get(&0).and_then(|c| c.key.as_deref()),
        Some("on-off")
    );
    // Without a stored label the channel name is the vendor text.
    assert_eq!(device.channels["CH-1"].name, "Heating (Kitchen)");
    assert_eq!(device.module_bases.get("MD-1_M-1_MI-1"), Some(&20));
    Ok(())
}

/// A minimal application with two parameters sharing the same text: one
/// visible (`P-94_R-94`), the other `Access="None"` (`P-103_R-160`), matching
/// the Jung 230021SU shape that motivated this test (`MD-3_P-103`'s text
/// equals `MD-3_P-94`'s).
const ACCESS_NONE_APP_ID: &str = "M-0001_A-1-1-0001";
const ACCESS_NONE_APP_XML: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21">
 <ManufacturerData><Manufacturer RefId="M-0001"><ApplicationPrograms>
  <ApplicationProgram Id="M-0001_A-1-1-0001" ApplicationNumber="1" ApplicationVersion="1" MaskVersion="MV-07B0" Name="Access Fixture" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ParameterTypes>
     <ParameterType Id="M-0001_A-1-1-0001_PT-Byte" Name="Byte"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
    </ParameterTypes>
    <Parameters>
     <Parameter Id="M-0001_A-1-1-0001_P-94" Name="Windalarm" Text="Freigabe Ueberwachungszeit Windalarme" ParameterType="M-0001_A-1-1-0001_PT-Byte" Value="10">
      <Memory CodeSegment="M-0001_A-1-1-0001_RS-1" Offset="0" BitOffset="0" />
     </Parameter>
     <Parameter Id="M-0001_A-1-1-0001_P-103" Name="WindalarmHidden" Text="Freigabe Ueberwachungszeit Windalarme" ParameterType="M-0001_A-1-1-0001_PT-Byte" Value="10">
      <Memory CodeSegment="M-0001_A-1-1-0001_RS-1" Offset="1" BitOffset="0" />
     </Parameter>
    </Parameters>
    <ParameterRefs>
     <ParameterRef Id="M-0001_A-1-1-0001_P-94_R-94" RefId="M-0001_A-1-1-0001_P-94" />
     <ParameterRef Id="M-0001_A-1-1-0001_P-103_R-160" RefId="M-0001_A-1-1-0001_P-103" Access="None" />
    </ParameterRefs>
   </Static>
   <Dynamic>
    <Channel Id="M-0001_A-1-1-0001_CH-1" Name="Main" Text="Main" Number="1">
     <ParameterBlock Id="M-0001_A-1-1-0001_PB-1" Name="Main" Text="Main">
      <ParameterRefRef RefId="M-0001_A-1-1-0001_P-94_R-94" />
      <ParameterRefRef RefId="M-0001_A-1-1-0001_P-103_R-160" />
     </ParameterBlock>
    </Channel>
   </Dynamic>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

#[test]
fn test_access_none_parameter_value_goes_to_hidden_not_the_file() -> TestResult {
    let app = parse_application_program(ACCESS_NONE_APP_ID, ACCESS_NONE_APP_XML)?;
    let mut values = BTreeMap::new();
    values.insert("P-94_R-94".to_string(), "20".to_string());
    values.insert("P-103_R-160".to_string(), "20".to_string());
    let facts = derive_facts(&app, &values, &Default::default());

    // The Access="None" ref never competes for a key: the visible sibling
    // with the same text gets the plain key, not an escape hatch.
    assert_eq!(facts.parameters.len(), 1, "{:?}", facts.parameters);
    assert_eq!(facts.parameters[0].reference, "P-94_R-94");
    assert_eq!(
        facts.parameters[0].key,
        "freigabe-ueberwachungszeit-windalarme"
    );

    let mut device = bussard_model::schema::Device {
        address: "1.1.47".parse()?,
        name: "fixture".into(),
        description: None,
        location: None,
        replaced: None,
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects: BTreeMap::new(),
        application_override: None,
        lock: Default::default(),
        security: None,
    };
    apply_facts(&mut device, &app, &facts, &values);

    // The visible value is a normal file-keyed parameter...
    assert_eq!(
        device
            .parameters
            .get("freigabe-ueberwachungszeit-windalarme@P-94_R-94"),
        Some(&"20".to_string())
    );
    // ...the Access="None" value stays in memory (for a flash) under the
    // hidden key, and is never listed as a device-file parameter key.
    assert_eq!(
        device.parameters.get("hidden@P-103_R-160"),
        Some(&"20".to_string())
    );
    assert!(!device.lock.parameters.contains_key("P-103_R-160"));
    Ok(())
}

/// Regression: an activated Data Secure device (ETS wrote `ToolKey` and
/// `LoadedToolKey` into its `<Security>` element) must get `[security]` in
/// its device file on a fresh import — `secure_capable` alone (no tool key at
/// all) must not, and the device's product identity facts stay in the lock.
/// No application program is needed: the security fields come straight off
/// `RawDevice`, independent of product data.
#[test]
fn test_import_writes_security_for_an_activated_device() -> TestResult {
    let dir = tmp("security-import")?;
    let knxproj = dir.join("secure.knxproj");
    let project_xml = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-8888">
  <Installations><Installation>
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-8888-0_DI-1" Address="47" Name="Heizungsaktor">
     <Security ToolKey="cGxhY2Vob2xkZXI=" LoadedToolKey="cGxhY2Vob2xkZXI=" SequenceNumber="239362131378" />
    </DeviceInstance>
    <DeviceInstance Id="P-8888-0_DI-2" Address="30" Name="Nur faehig" />
   </Line></Area></Topology>
   <GroupAddresses><GroupRanges></GroupRanges></GroupAddresses>
  </Installation></Installations>
 </Project>
</KNX>"#;
    {
        let mut zw = ZipWriter::new(std::fs::File::create(&knxproj)?);
        let opts = SimpleFileOptions::default();
        zw.start_file("knx_master.xml", opts)?;
        zw.write_all(br#"<KNX xmlns="http://knx.org/xml/project/21"/>"#)?;
        zw.start_file("P-8888/0.xml", opts)?;
        zw.write_all(project_xml.as_bytes())?;
        zw.finish()?;
    }

    let model = bussard_project::import(&knxproj, None)?;
    let out = dir.join("knx");
    model.save(&out)?;

    let activated = read(&out, "devices/1.1.47.toml")?;
    assert!(activated.contains("[security]"), "{activated}");
    assert!(activated.contains("activated = true"), "{activated}");
    // The product/security facts stay in the lock, not the file.
    for generated in ["secure_capable", "has_fdsk_certificate", "sequence_number"] {
        assert!(
            !activated.contains(generated),
            "{generated} in the device file:\n{activated}"
        );
    }
    let lock = read(&out, "bussard.lock")?;
    assert!(lock.contains("sequence_number = 239362131378"), "{lock}");

    // A device with no tool key at all gets no `[security]` table: nothing
    // to activate or commission yet, even though it may be secure-capable
    // once its product data is known.
    let capable = read(&out, "devices/1.1.30.toml")?;
    assert!(!capable.contains("[security]"), "{capable}");

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
