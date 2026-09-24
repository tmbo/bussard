//! `bussard doc` rendering (issue #97): the documentation set renders on the
//! synthetic fixture and on a reconstructed model with placeholder names, and two
//! runs on the same model are byte-identical.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bussard_model::doc::{DocFile, DocFormat, InstallationDoc, write_files};
use bussard_model::schema::{ComObject, Device, Link, Location};
use bussard_model::{Model, ProductModels};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/small-installation/knx")
}

fn render(dir: &Path, model: &Model, format: DocFormat) -> Vec<DocFile> {
    InstallationDoc::build(model, &ProductModels::load(dir), dir).render(format)
}

fn paths(files: &[DocFile]) -> Vec<&str> {
    files.iter().map(|f| f.path.as_str()).collect()
}

#[test]
fn test_render_small_fixture_is_deterministic() -> TestResult {
    let dir = fixture_dir();
    let model = Model::load(&dir)?;
    for format in [DocFormat::Markdown, DocFormat::Html] {
        let first = render(&dir, &model, format);
        let second = render(&dir, &Model::load(&dir)?, format);
        assert_eq!(
            first, second,
            "two runs must be byte-identical ({format:?})"
        );
    }
    let md = render(&dir, &model, DocFormat::Markdown);
    assert_eq!(
        paths(&md),
        [
            "index.md",
            "devices.md",
            "groups.md",
            "connection.md",
            "changelog.md"
        ]
    );
    let file = |name: &str| -> Result<&DocFile, String> {
        md.iter()
            .find(|f| f.path == name)
            .ok_or_else(|| format!("{name} missing"))
    };
    assert!(
        file("devices.md")?
            .content
            .contains("| 1.0.2 | Switch Kitchen |")
    );
    assert!(file("connection.md")?.content.contains("127.0.0.1:13671"));
    assert!(
        file("groups.md")?
            .content
            .contains("| 1/0/1 | Light Kitchen |")
    );
    assert!(file("index.md")?.content.contains("[Devices](devices.md)"));
    Ok(())
}

#[test]
fn test_render_html_is_self_contained() -> TestResult {
    let dir = fixture_dir();
    let html = render(&dir, &Model::load(&dir)?, DocFormat::Html);
    let index = html
        .iter()
        .find(|f| f.path == "index.html")
        .ok_or("index.html missing")?;
    assert!(index.content.starts_with("<!DOCTYPE html>"));
    assert!(index.content.contains("<a href=\"devices.html\">"));
    assert!(!index.content.contains("<script"));
    assert!(!index.content.contains("<link "));
    Ok(())
}

/// The shape `bussard reconstruct` produces: placeholder device names, no link
/// names, GAs that `groups.yaml` never names, no product data.
fn reconstructed_model() -> Result<Model, Box<dyn std::error::Error>> {
    let mut model = Model {
        config: Default::default(),
        groups: Default::default(),
        links: Default::default(),
        devices: BTreeMap::new(),
    };
    let address = "1.1.7".parse()?;
    let mut device = Device {
        address,
        name: "device 1.1.7".to_string(),
        description: None,
        location: Some(Location {
            floor: None,
            room: Some("Room 1".to_string()),
        }),
        product: None,
        channels: BTreeMap::new(),
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects: BTreeMap::new(),
        security: None,
        replaced: None,
        application_override: None,
        lock: Default::default(),
    };
    device.com_objects.insert(0, ComObject::default());
    model.links.links.insert(
        address,
        vec![
            Link {
                object: 0,
                name: None,
                send: Some("4/2/12".parse()?),
                listen: vec!["4/2/13".parse()?],
            },
            Link {
                object: 5,
                name: None,
                send: None,
                listen: Vec::new(),
            },
        ],
    );
    model.devices.insert(
        address,
        bussard_model::LoadedDevice {
            device,
            file_stem: "1.1.7-device".to_string(),
        },
    );
    Ok(model)
}

#[test]
fn test_render_reconstructed_model_degrades_to_addresses() -> TestResult {
    let model = reconstructed_model()?;
    // A directory outside any repository: no change log, silently.
    let dir = std::env::temp_dir();
    let doc = InstallationDoc::build(&model, &ProductModels::default(), &dir);
    let md = doc.render(DocFormat::Markdown);
    assert_eq!(md, doc.render(DocFormat::Markdown));
    let room = md
        .iter()
        .find(|f| f.path == "rooms/unassigned-room-1.md")
        .ok_or("room sheet missing")?;
    assert!(
        room.content
            .contains("- com object 0 controls 4/2/12; status from 4/2/13."),
        "{}",
        room.content
    );
    assert!(
        room.content
            .contains("com object 5 is not linked to a group address.")
    );
    Ok(())
}

#[test]
fn test_write_files_creates_room_directory() -> TestResult {
    let model = reconstructed_model()?;
    let doc = InstallationDoc::build(&model, &ProductModels::default(), &std::env::temp_dir());
    let out = std::env::temp_dir().join(format!("bussard-doc-test-{}", std::process::id()));
    let files = doc.render(DocFormat::Markdown);
    write_files(&files, &out)?;
    let written = std::fs::read_to_string(out.join("rooms/unassigned-room-1.md"))?;
    std::fs::remove_dir_all(&out)?;
    assert!(written.starts_with("# unassigned / Room 1"));
    Ok(())
}
