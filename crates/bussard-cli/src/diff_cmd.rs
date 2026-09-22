//! The `bussard diff` subcommand (issue #99).
//!
//! Loads two projects into memory, each a `.knxproj`, a `.bussard` bundle, an
//! xknxproject `.json` dump or a model directory, and prints what changes from
//! the first to the second as the same plain sentences `bussard status` uses
//! ([`bussard_model::change::describe`]). Nothing is written.
//!
//! Group addresses are keyed by address, so an integrator renaming a GA shows
//! as one rename, not a removal and an addition. Parameter changes use the
//! parameter's text from a model directory's cached `models/*.yaml` when there
//! is one, and the key otherwise.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::Model;
use bussard_model::bundle::{self, Bundle};
use bussard_model::change::{ChangeSet, describe, name_parameters, render_text};
use bussard_model::param_model::ProductModels;

/// One side of a diff, loaded into memory.
pub struct Side {
    /// The model.
    pub model: Model,
    /// The cached product models, when the side is a model directory.
    pub products: ProductModels,
    /// The model files as text, for `--raw`.
    pub files: BTreeMap<String, String>,
}

/// Runs `bussard diff <a> <b> [--json] [--raw]`. Always exits 0: "no
/// differences" is an answer.
pub fn run(
    a: &Path,
    b: &Path,
    json: bool,
    raw: bool,
    password: Option<String>,
    password_b: Option<String>,
) -> anyhow::Result<ExitCode> {
    let env = std::env::var("BUSSARD_PROJECT_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    let pw_a = password.clone().or_else(|| env.clone());
    let pw_b = password_b.or(password).or(env);
    let side_a = load_side(a, pw_a.as_deref())?;
    let side_b = load_side(b, pw_b.as_deref())?;

    if raw {
        print_raw(a, b, &side_a.files, &side_b.files);
        return Ok(ExitCode::SUCCESS);
    }

    let changes = diff(&side_a, &side_b);
    if json {
        let value = serde_json::json!({
            "a": a.display().to_string(),
            "b": b.display().to_string(),
            "summary": changes.summary(),
            "touches_protected": changes.touches_protected(),
            "changes": changes.changes,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(ExitCode::SUCCESS);
    }
    if changes.is_empty() {
        println!(
            "No differences between {} and {}.",
            a.display(),
            b.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{} change(s) from {} to {}:",
        changes.len(),
        a.display(),
        b.display()
    );
    for line in render_text(&changes).lines() {
        println!("  {line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// The change set from `a` to `b`, with parameter texts from either side's
/// product models.
pub fn diff(a: &Side, b: &Side) -> ChangeSet {
    let mut changes = describe(&a.model, &b.model);
    let mut products = a.products.clone();
    products.by_app_ref.extend(b.products.by_app_ref.clone());
    name_parameters(&mut changes, [&b.model, &a.model], &products);
    changes
}

/// Loads one side from whatever `path` names.
pub fn load_side(path: &Path, password: Option<&str>) -> anyhow::Result<Side> {
    if path.is_dir() {
        let model = Model::load(path)
            .with_context(|| format!("loading the model in {}", path.display()))?;
        let files = texts(bundle::model_files(path)?)?;
        return Ok(Side {
            model,
            products: ProductModels::load(path),
            files,
        });
    }
    if bundle::is_bundle_path(path) {
        let bundle =
            Bundle::read(path).with_context(|| format!("reading bundle {}", path.display()))?;
        let model = bundle.model()?;
        return Ok(Side {
            model,
            products: ProductModels::default(),
            files: texts(bundle.model_files)?,
        });
    }
    let is_json = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    let model = if is_json {
        bussard_project::import_from_json(path)?
    } else {
        match bussard_project::import(path, password) {
            Ok(model) => model,
            Err(bussard_project::ImportError::PasswordRequired) => anyhow::bail!(
                "{} is password-protected; pass --password (or --password-b for the second \
                 side) or set BUSSARD_PROJECT_PASSWORD",
                path.display()
            ),
            Err(err) => {
                return Err(err).with_context(|| format!("importing {}", path.display()));
            }
        }
    };
    let files = model.to_texts()?;
    Ok(Side {
        model,
        products: ProductModels::default(),
        files,
    })
}

/// Model files as text; a non-UTF-8 file reads lossily (it is only printed).
fn texts(files: BTreeMap<String, Vec<u8>>) -> anyhow::Result<BTreeMap<String, String>> {
    Ok(files
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8_lossy(&v).into_owned()))
        .collect())
}

/// Prints the file-level diff between the two sides' model files.
fn print_raw(a: &Path, b: &Path, old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) {
    let names: std::collections::BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut any = false;
    for name in names {
        let before = old.get(name).map(String::as_str).unwrap_or_default();
        let after = new.get(name).map(String::as_str).unwrap_or_default();
        if before == after {
            continue;
        }
        any = true;
        println!("--- {}/{name}", a.display());
        println!("+++ {}/{name}", b.display());
        print!("{}", crate::history_cmd::unified_body(before, after));
    }
    if !any {
        println!(
            "No file differences between {} and {}.",
            a.display(),
            b.display()
        );
    }
}
