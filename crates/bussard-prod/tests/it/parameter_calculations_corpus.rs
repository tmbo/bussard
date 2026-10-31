//! Real-product check for issue #427: the `<ParameterCalculation>`s of the
//! Ekinex EK-E72-TP (`M-00B6_A-4537-03-DE59`, `APEKE72TP03.knxprod` in
//! `tests-support/product-corpus-extra`) run inside the Dynamic evaluation
//! and compute what their VBScript says.
//!
//! The two scripts (`Weighted`, `Ventilation`) are re-implemented here in
//! Rust, independently of the interpreter, and compared with the evaluated
//! outputs over a sample of input combinations drawn from each input's
//! enumeration. On a real installation these are the fan-block octets that
//! differed from ETS's download before calculations ran.
//!
//! Set `BUSSARD_PRODUCT_CORPUS=<vendor-dir>` to run it; skipped when unset
//! (the vendor product data is copyrighted and never committed).

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;

use bussard_prod::dynamic::{ParameterCalculation, evaluate_dynamic};
use bussard_prod::{ApplicationProgram, ParameterType};

/// A test result carrying any error.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const PRODUCT: &str = "APEKE72TP03.knxprod";
const APP_ID: &str = "M-00B6_A-4537-03-DE59";

/// The EK-E72 application from the corpus, or `None` when it is absent.
fn corpus_app() -> TestResult<Option<ApplicationProgram>> {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping {APP_ID}.");
        return Ok(None);
    };
    let dir = PathBuf::from(dir);
    let Some(path) = [dir.join("cache/vendor"), dir.join("vendor"), dir]
        .into_iter()
        .map(|d| d.join(PRODUCT))
        .find(|p| p.is_file())
    else {
        eprintln!("{PRODUCT} not in the corpus; skipping {APP_ID}.");
        return Ok(None);
    };
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&path)?)?;
    let mut xml = Vec::new();
    zip.by_name(&format!("M-00B6/{APP_ID}.xml"))?
        .read_to_end(&mut xml)?;
    Ok(Some(bussard_prod::parse_application_program(APP_ID, &xml)?))
}

/// The script variable of each input and output of `calc`: its `AliasName`,
/// else its parameter's `Name`, with its ref id.
fn variables(app: &ApplicationProgram, calc: &ParameterCalculation) -> Vec<(String, String)> {
    calc.inputs
        .iter()
        .chain(&calc.outputs)
        .filter_map(|p| {
            let pref = app
                .parameter_refs
                .get(&format!("{APP_ID}_{}", p.param_ref))?;
            let name = p
                .alias
                .clone()
                .or_else(|| app.parameters.get(&pref.ref_id)?.name.clone())?;
            Some((name, p.param_ref.clone()))
        })
        .collect()
}

/// The enumeration codes of the parameter behind `param_ref`.
fn codes(app: &ApplicationProgram, param_ref: &str) -> Vec<i64> {
    let Some(param) = app
        .parameter_refs
        .get(&format!("{APP_ID}_{param_ref}"))
        .and_then(|r| app.parameters.get(&r.ref_id))
    else {
        return Vec::new();
    };
    match param
        .parameter_type
        .as_deref()
        .and_then(|t| app.parameter_types.get(t))
        .map(|t| &t.kind)
    {
        Some(ParameterType::Enum { values, .. }) => values.iter().map(|v| v.value).collect(),
        _ => Vec::new(),
    }
}

/// `Weighted`, as its VBScript reads.
fn weighted(v: &BTreeMap<String, i64>) -> i64 {
    let (sensor, room) = (v["TemperatureSensor"], v["RoomTemp"]);
    if sensor == 1 && room == 1 {
        7
    } else if sensor == 1 {
        1
    } else if room == 1 {
        4
    } else {
        0
    }
}

/// `Ventilation`, as its VBScript reads.
fn ventilation(v: &BTreeMap<String, i64>) -> i64 {
    let co = v["CommandCO"];
    let heating_virtual = v["HeatingTypeVirtual"];
    let aux_heating = v["AuxiliaryHeating"] == 1 && v["AuxHeatingVentilation"] == 1;
    let aux_cooling = v["AuxiliaryCooling"] == 1 && v["AuxCoolingVentilation"] == 1;
    let cooling_fan = v["CoolingType"] == 2;
    let mut out = 0;
    match v["ThermostatFunction"] {
        1 => {
            if (co == 1 || co == 0) && heating_virtual == 2 {
                out = 1;
            }
            out += 2 * i64::from(aux_heating) + 4 * i64::from(cooling_fan);
            out += 8 * i64::from(aux_cooling);
        }
        0 => {
            if co == 1 && heating_virtual == 2 {
                out += 16;
            }
            if co == 0 && heating_virtual == 2 {
                out += 16;
            }
            out += 32 * i64::from(aux_heating);
        }
        2 => {
            out += 64 * i64::from(cooling_fan) + 128 * i64::from(aux_cooling);
        }
        _ => {}
    }
    out
}

#[test]
fn test_evaluate_dynamic_runs_the_ek_e72_calculations() -> TestResult<()> {
    let Some(app) = corpus_app()? else {
        return Ok(());
    };
    assert_eq!(app.calculations.len(), 2, "Weighted and Ventilation");
    let mut checked = 0;
    for (calc, expected) in app
        .calculations
        .iter()
        .zip([weighted as fn(&BTreeMap<String, i64>) -> i64, ventilation])
    {
        let vars = variables(&app, calc);
        assert_eq!(
            vars.len(),
            calc.inputs.len() + calc.outputs.len(),
            "{}",
            calc.id
        );
        let inputs = &vars[..calc.inputs.len()];
        let (output_name, output_ref) = &vars[calc.inputs.len()];
        // A deterministic sample of input combinations, each input drawn from
        // its own enumeration (a small LCG keeps the run short and stable).
        let choices: Vec<Vec<i64>> = inputs
            .iter()
            .map(|(_, r)| {
                let c = codes(&app, r);
                if c.is_empty() { vec![0, 1, 2] } else { c }
            })
            .collect();
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..60 {
            let mut overrides = BTreeMap::new();
            for ((_, param_ref), options) in inputs.iter().zip(&choices) {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let code = options[(seed >> 33) as usize % options.len()];
                overrides.insert(param_ref.clone(), code.to_string());
            }
            let config = evaluate_dynamic(&app, &overrides);
            // The script sees each input as the evaluation holds it: the
            // product's own `<Assign>`s win over an override (the E72 assigns
            // `CoolingType`, for one).
            let mut values = BTreeMap::new();
            for (name, param_ref) in inputs {
                let value = config
                    .value(&app, None, param_ref)
                    .ok_or_else(|| format!("{name} has no value"))?;
                values.insert(name.clone(), value.trim().parse::<i64>()?);
            }
            assert!(
                config.refused_calculations.is_empty(),
                "{:?}",
                config.refused_calculations
            );
            let got = config.value(&app, None, output_ref);
            assert_eq!(
                got.as_deref(),
                Some(expected(&values).to_string().as_str()),
                "{} {output_name} for {values:?}",
                calc.id
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 120);
    Ok(())
}
