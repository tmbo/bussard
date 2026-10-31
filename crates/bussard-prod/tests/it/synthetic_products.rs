//! The synthetic product catalogue (epic #596) reads with `read_knxprod`.
//!
//! `tests-support/synthetic-products/<name>/xml/` holds the product XML that
//! `generate.py` renders from `<name>/product.toml` (committed; Python is not a
//! test dependency). Each product's XML is zipped here with the stub
//! `knx_master.xml` the catalogue ships, the way `generate.py --zip` packs it,
//! and must read back as one application whose id is the file name, reachable
//! from the order number in `Hardware.xml`.

use std::io::Write;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/` in the repository.
fn catalogue_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/synthetic-products")
}

/// Every product directory (one holding a `product.toml`), sorted.
fn products() -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(catalogue_dir())? {
        let dir = entry?.path();
        if dir.join("product.toml").is_file() {
            out.push(dir);
        }
    }
    out.sort();
    Ok(out)
}

/// The files under `dir`, as `(path relative to dir with '/', absolute path)`.
fn files_under(dir: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(rel) = p.strip_prefix(dir) {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, p));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Zips `<product>/xml/` with a stub master into `out`.
fn zip_product(product: &Path, out: &Path) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (rel, path) in files_under(&product.join("xml"))? {
        zip.start_file(rel, opts)?;
        zip.write_all(&std::fs::read(path)?)?;
    }
    zip.finish()?;
    Ok(())
}

/// The value of the first `attr="..."` in `xml`.
fn attribute<'a>(xml: &'a str, attr: &str) -> Option<&'a str> {
    let needle = format!("{attr}=\"");
    let start = xml.find(&needle)? + needle.len();
    let len = xml[start..].find('"')?;
    Some(&xml[start..start + len])
}

#[test]
fn test_read_knxprod_synthetic_catalogue() -> TestResult {
    let products = products()?;
    let names: Vec<String> = products
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert!(
        names.iter().any(|n| n == "syn-minimal"),
        "the baseline product is missing: {names:?}"
    );
    let tmp = tempfile::tempdir()?;
    for (product, name) in products.iter().zip(&names) {
        let manufacturer_dir = product.join("xml/M-00FA");
        let app_files: Vec<String> = files_under(&manufacturer_dir)?
            .into_iter()
            .filter(|(rel, _)| rel.contains("_A-"))
            .map(|(rel, _)| rel.trim_end_matches(".xml").to_string())
            .collect();
        assert_eq!(
            app_files.len(),
            1,
            "{name}: application files {app_files:?}"
        );
        let expected_id = &app_files[0];
        // The generator leaves the fingerprint to the signer: `..-0000`.
        // Application numbers 0x27xx to 0x2Axx (System B, System 7, Secure,
        // RF and IP; #604).
        let family = ["M-00FA_A-27", "M-00FA_A-28", "M-00FA_A-29", "M-00FA_A-2A"];
        assert!(
            family.iter().any(|f| expected_id.starts_with(f)) && expected_id.ends_with("-0000"),
            "{name}: {expected_id} is outside the synthetic id rule"
        );

        let path = tmp.path().join(format!("{name}.knxprod"));
        zip_product(product, &path)?;
        let data = bussard_prod::read_knxprod(&path)?;
        assert_eq!(data.manufacturers, vec!["M-00FA".to_string()], "{name}");
        assert_eq!(data.applications.len(), 1, "{name}");
        let app = &data.applications[0];
        assert_eq!(&app.id, expected_id, "{name}");

        let hardware = std::fs::read_to_string(manufacturer_dir.join("Hardware.xml"))?;
        let order = attribute(&hardware, "OrderNumber").ok_or("no OrderNumber in Hardware.xml")?;
        let by_order = data.application_for_order_number(order);
        assert_eq!(by_order.len(), 1, "{name}: order number {order}");
        assert_eq!(&by_order[0].id, expected_id, "{name}");
    }
    Ok(())
}

#[test]
fn test_read_knxprod_synthetic_minimal_contents() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_product(&catalogue_dir().join("syn-minimal"), &path)?;
    let data = bussard_prod::read_knxprod(&path)?;
    let app = data.applications.first().ok_or("no application")?;
    assert_eq!(app.id, "M-00FA_A-2700-10-0000");
    assert_eq!(app.application_number, Some(0x2700));
    assert_eq!(app.application_version, Some(0x10));
    assert_eq!(app.mask_version.as_deref(), Some("07B0"));
    assert_eq!(app.resolved_com_objects().len(), 2);
    assert_eq!(app.parameters.len(), 2);
    // The stub master carries no load-procedure template; the built-in one
    // takes its place (issue #607).
    assert_eq!(
        data.master
            .as_ref()
            .and_then(|m| m.full_load_procedure("07B0"))
            .cloned(),
        bussard_prod::MasterTemplate::builtin_for_mask("07B0")
    );
    Ok(())
}

/// Issue #448: the hidden 16-bit parameter at +3 of the parameter segment
/// (default `12 34` over the template `FF FF`) is written at its default
/// where ETS wrote it (System B, and System 7 with `MinEtsVersion` 6.0) and
/// keeps the template where ETS kept it (System 7 with `MinEtsVersion` 4.0,
/// in project/23 and in project/11), as the captures of the four synthetic
/// products show.
#[test]
fn test_downloads_invisible_parameters_synthetic_twins() -> TestResult {
    let tmp = tempfile::tempdir()?;
    for (name, segment, writes, at_3) in [
        ("syn-hidden-default", "_RS-04-00000", true, [0x12, 0x34]),
        ("syn-s7-hidden-default", "_AS-4440", true, [0x12, 0x34]),
        ("syn-s7-hidden-default-p11", "_AS-4440", false, [0xFF, 0xFF]),
        (
            "syn-s7-hidden-default-ets4",
            "_AS-4440",
            false,
            [0xFF, 0xFF],
        ),
    ] {
        let path = tmp.path().join(format!("{name}.knxprod"));
        zip_product(&catalogue_dir().join(name), &path)?;
        let data = bussard_prod::read_knxprod(&path)?;
        let app = data.applications.first().ok_or("no application")?;
        assert_eq!(app.downloads_invisible_parameters(), writes, "{name}");
        let images = bussard_prod::compute_parameter_image(
            app,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        )?;
        let image = images
            .iter()
            .find(|(id, _)| id.ends_with(segment))
            .map(|(_, octets)| octets)
            .ok_or(format!("{name}: no image of {segment}"))?;
        assert_eq!(image.get(3..5), Some(&at_3[..]), "{name}");
    }
    Ok(())
}

#[test]
fn test_evaluate_dynamic_synthetic_choose_never_shown_takes_no_branch() -> TestResult {
    // `syn-choose-never-shown` (#604 row 14): ETS 6.4.1 leaves object 2,
    // behind a default-only `<choose>` on the never-shown virtual
    // `ghost_seen`, out of the group-object table (issue #474).
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-choose-never-shown.knxprod");
    zip_product(&catalogue_dir().join("syn-choose-never-shown"), &path)?;
    let data = bussard_prod::read_knxprod(&path)?;
    let app = data.applications.first().ok_or("no application")?;
    let config = bussard_prod::dynamic::evaluate_dynamic(app, &Default::default());
    let objects: Vec<&str> = config
        .com_objects
        .iter()
        .map(|c| c.com_object_ref_id.as_str())
        .collect();
    assert_eq!(objects, ["O-0_R-1", "O-1_R-2"]);
    assert!(
        config
            .parameters
            .iter()
            .all(|p| p.param_ref_id != "P-4_R-4"),
        "ghost_sensitivity reached"
    );
    Ok(())
}

/// `syn-param-calculation` read and turned into the cached product model,
/// with the application program the plan builds its image from.
fn param_calculation_product() -> Result<
    (
        bussard_prod::ApplicationProgram,
        bussard_model::ProductModels,
    ),
    Box<dyn std::error::Error>,
> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-param-calculation.knxprod");
    zip_product(&catalogue_dir().join("syn-param-calculation"), &path)?;
    let data = bussard_prod::read_knxprod(&path)?;
    let app = data.applications.first().ok_or("no application")?.clone();
    let yaml = bussard_prod::product_model::model_yaml(&app, &data)?;
    let mut products = bussard_model::ProductModels::default();
    products.insert(
        app.id.clone(),
        bussard_model::ProductModel::from_yaml(&yaml, &app.id)?,
    );
    Ok((app, products))
}

/// The model of the `calc-input` capture
/// (`captures/synthetic/syn-param-calculation/calc-input/model/`): device
/// 1.1.1 with `delay-s` set to `delay`, or at its defaults without one.
fn param_calculation_model(
    app_id: &str,
    delay: Option<&str>,
) -> Result<bussard_model::Model, Box<dyn std::error::Error>> {
    let lock = format!(
        r#"version = 3

[[device]]
address = "1.1.1"
product = "NEST-CALC"
application = "{app_id}"
mask = "07B0"
parameters = [
  {{ key = "delay-s", ref = "P-2_R-2", param = "P-2" }},
  {{ key = "twice-the-delay-plus-one", ref = "P-3_R-3", param = "P-3" }},
]
"#
    );
    let mut device = "address = \"1.1.1\"\nname = \"syn-param-calculation\"\n\
                      product = \"NEST-CALC\"\n"
        .to_string();
    if let Some(delay) = delay {
        device.push_str(&format!("\n[parameters]\ndelay-s = {delay}\n"));
    }
    let files: std::collections::BTreeMap<String, String> = [
        ("bussard.lock".to_string(), lock),
        ("devices/1.1.1.toml".to_string(), device),
        (
            "bussard.toml".to_string(),
            "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:3671\"\n".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    Ok(bussard_model::Model::from_texts(&files)?)
}

/// What the plan's parameter image holds for parameter `param_id` (full id),
/// decoded the way a read-back decodes it.
fn planned_value(
    app: &bussard_prod::ApplicationProgram,
    overrides: &std::collections::BTreeMap<String, String>,
    param_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let images = bussard_prod::image::compute_parameter_image(app, overrides, &Default::default())?;
    let param = app.parameters.get(param_id).ok_or("no parameter")?;
    let memory = param.memory.as_ref().ok_or("no memory")?;
    let segment = memory.code_segment.as_deref().ok_or("no segment")?;
    let image = images.get(segment).ok_or("no image of the segment")?;
    let value = bussard_prod::image::decode_parameter_value(
        app,
        param,
        image,
        memory.offset.ok_or("no offset")? as usize,
        memory.bit_offset.unwrap_or(0),
    );
    Ok(value.ok_or("undecodable")?)
}

/// The views show a calculation output with the value the plan writes
/// (issue #712): `delay` set off its default (the `calc-input` capture, 500)
/// runs `PC-1`, so the shown output `prey_double` is 1001 and the hidden
/// `prey_patch` 507 in the device view, the doc and the image alike. At the
/// defaults no calculation runs (the trigger rule) and nothing is computed.
#[test]
fn test_device_view_synthetic_param_calculation_agrees_with_the_plan() -> TestResult {
    use bussard_model::device_view::{DEVICE_SCOPE, Evaluated, device_view};

    let (app, products) = param_calculation_product()?;
    let ia: bussard_model::IndividualAddress = "1.1.1".parse()?;
    let product = products.get(&app.id).ok_or("no product model")?;
    assert_eq!(
        product.calculations.len(),
        1,
        "the cached model carries PC-1"
    );

    let model = param_calculation_model(&app.id, Some("500"))?;
    let view = device_view(&model, &products, ia, Some(DEVICE_SCOPE))?;
    let rows = view.scope.ok_or("no scope")?.parameters;
    let shown = rows
        .iter()
        .find(|p| p.reference == "P-3_R-3")
        .ok_or("prey_double not shown")?;
    let overrides: std::collections::BTreeMap<String, String> =
        [("P-2_R-2".to_string(), "500".to_string())].into();
    let plan_double = planned_value(&app, &overrides, &format!("{}_P-3", app.id))?;
    assert_eq!(plan_double, "1001");
    assert_eq!(shown.computed.as_deref(), Some(plan_double.as_str()));
    assert_eq!(shown.computed_by.as_deref(), Some("PC-1"));
    assert_eq!(shown.at_default, Some(false));
    assert!(
        view_table_marks(&model, &products, ia)?.contains("computed by calculation PC-1"),
        "the table marks the computed output"
    );

    // The hidden output, which the doc lists, is written computed too.
    let device = &model.devices.get(&ia).ok_or("no device")?.device;
    let computed = Evaluated::of_device(product, device).computed_parameters();
    let plan_patch = planned_value(&app, &overrides, &format!("{}_P-4", app.id))?;
    assert_eq!(plan_patch, "507");
    assert_eq!(
        computed.get("P-4_R-4"),
        Some(&("PC-1".to_string(), plan_patch))
    );
    let doc = bussard_model::doc::InstallationDoc::build(&model, &products, Path::new("."));
    let doc_device = doc
        .devices
        .iter()
        .find(|d| d.address == "1.1.1")
        .ok_or("no doc device")?;
    let doc_double = doc_device
        .parameters
        .iter()
        .find(|p| p.key.ends_with("@P-3_R-3"))
        .ok_or("prey_double not in the doc")?;
    assert_eq!(doc_double.value, plan_double);
    assert_eq!(doc_double.computed_by.as_deref(), Some("PC-1"));

    // At the defaults no calculation runs, in the view as in the plan.
    let defaults = param_calculation_model(&app.id, None)?;
    let view = device_view(&defaults, &products, ia, Some(DEVICE_SCOPE))?;
    let rows = view.scope.ok_or("no scope")?.parameters;
    let shown = rows
        .iter()
        .find(|p| p.reference == "P-3_R-3")
        .ok_or("prey_double not shown")?;
    assert_eq!(shown.computed, None);
    assert_eq!(shown.effective(), Some("0"));
    assert_eq!(
        planned_value(&app, &Default::default(), &format!("{}_P-3", app.id))?,
        "0"
    );
    Ok(())
}

/// The device view's table of 1.1.1 at the device scope.
fn view_table_marks(
    model: &bussard_model::Model,
    products: &bussard_model::ProductModels,
    ia: bussard_model::IndividualAddress,
) -> Result<String, Box<dyn std::error::Error>> {
    let view = bussard_model::device_view::device_view(
        model,
        products,
        ia,
        Some(bussard_model::device_view::DEVICE_SCOPE),
    )?;
    Ok(view.render_table())
}

/// `bussard diff` and the MCP diff tools name a calculation output that
/// changes because its input did (issue #712).
#[test]
fn test_name_parameters_synthetic_param_calculation_names_the_computed_output() -> TestResult {
    let (app, products) = param_calculation_product()?;
    let old = param_calculation_model(&app.id, None)?;
    let new = param_calculation_model(&app.id, Some("500"))?;
    let mut changes = bussard_model::change::describe(&old, &new);
    bussard_model::change::name_parameters(&mut changes, [&new, &old], &products);
    let sentences: Vec<&str> = changes
        .changes
        .iter()
        .map(|c| c.sentence.as_str())
        .collect();
    let double = changes
        .changes
        .iter()
        .find(|c| c.field.as_deref() == Some("twice-the-delay-plus-one@P-3_R-3"))
        .ok_or_else(|| format!("no change of prey_double: {sentences:?}"))?;
    assert_eq!(double.from.as_deref(), Some("0"));
    assert_eq!(double.to.as_deref(), Some("1001"));
    assert!(
        double.sentence.starts_with("Twice the delay plus one on ")
            && double.sentence.ends_with("Computed by calculation PC-1."),
        "{}",
        double.sentence
    );
    assert!(
        changes.changes.iter().any(
            |c| c.field.as_deref() == Some("P-4_R-4@P-4_R-4") && c.to.as_deref() == Some("507")
        ),
        "{sentences:?}"
    );
    Ok(())
}
