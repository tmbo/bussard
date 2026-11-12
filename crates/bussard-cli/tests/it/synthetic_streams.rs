//! What bussard sends to a device, over the synthetic product catalogue
//! (epic #596, steps 7 and 8).
//!
//! **Golden request streams (step 7).** For every product under
//! `tests-support/synthetic-products/`, `bussard flash 1.1.10 --yes` writes a
//! seeded configuration (the vendor defaults with a few links, the sim loop's
//! [`Configuration::defaults`]) into a fresh knx-sim device. knx-sim records
//! the session (`gateway.pcap`), `tools/knxtrace/knxtrace.py ops` normalizes
//! it (no KNXnet/IP layer, no Layer 4 acks, memory writes as address, length
//! and content hash), and the result must equal the committed
//! `requests/flash.txt` next to the product. A product the catalogue captured
//! with a `links` or `partial` run variant also gets `requests/apply.txt`:
//! from the flashed state (the sim replays the flash capture), `bussard apply
//! 1.1.10 --yes` writes the sim loop's partial change (a few parameters that
//! keep the object table, a link added, a link removed). A change to a write
//! path is thereby a reviewable diff of these files (the Device Writes rules
//! in `CLAUDE.md`); `BUSSARD_UPDATE_GOLDENS=1` rewrites them.
//!
//! **Parameter change, reload and Data Secure (issue #1054).** `params.txt`,
//! for [`PARAMETER_PRODUCTS`] and every plain product the catalogue captured
//! with a `params` or `partial` run variant ([`has_params_variant`]), is
//! `bussard apply` of a parameter-only change
//! ([`Configuration::parameter_change`]) over the flashed defaults.
//! `reload.txt`, for a product captured with a `reload` variant, is `bussard
//! flash` of the same defaults again over the flashed device (ETS's reload
//! row); on [`SECURE_PRODUCT`] that is `reload-secure.txt`, over the secured
//! flash. For
//! [`SECURE_PRODUCT`], knx-sim starts the device `activated` (security mode
//! on, a synthetic tool key set) and the model holds the keys in its key
//! store: `flash-secure.txt` is the secured flash (tables, parameters and the
//! security object over `A_SecureData`), `params-secure.txt` a parameter
//! change applied over it. Their frames are decrypted with the key store's
//! keyring export; the clock-seeded sending sequence and a Sync_Req the
//! device ignored within its 1 s window are normalized away
//! ([`secure_stable`]).
//!
//! **CLI and MCP equivalence (step 8, the #314 class).** For every product,
//! the same write runs through both surfaces from the same flashed state, on
//! two simulators, and the two normalized streams are compared:
//!
//! - the apply: `bussard plan 1.1.10 --json` then `bussard apply 1.1.10
//!   --yes`, against `knx_plan_device` then `knx_apply_device`;
//! - the parameter-only change of the products [`has_params_variant`] names
//!   and, secured, of
//!   [`SECURE_PRODUCT`] (an apply), and the secured flash of
//!   [`SECURE_PRODUCT`] into its unloaded activated device (issue #1054);
//! - the reshape, for a product with an enable switch that shows or hides a
//!   com-object: the MCP tier writes that as a flash (`method: flash`, issue
//!   #303), or as an apply that reloads the object table when the planner
//!   decides so; the CLI side runs `bussard plan` and then `bussard flash` or
//!   `bussard apply` as the MCP plan says.
//!
//! An apply (`method: apply`, the partial change and a reshape the planner
//! writes as an object-table reload) must send the very same requests on
//! both surfaces, every read before the write included: the same
//! connections, the same device facts reuse (no second descriptor, maximum
//! APDU length or object-type discovery, issue #761), the same digest-check
//! re-read that `bussard apply` makes as its own plan ([`compare_apply`]).
//!
//! A flash is compared more loosely: before the first write the MCP session
//! may read more than the CLI (its `knx_apply_device` re-reads the device to
//! check the plan digest, where `bussard flash` reads no tables), but never
//! skip a read the CLI makes (the identity gate, the plan's reads); from the
//! first write on (the write, the read-back and the memory image) the two
//! must be identical ([`compare_streams`]). That comparison drops the
//! session plumbing whose count depends on how often a surface opens a
//! connection: `T_Connect`/`T_Disconnect`, the authorize, the device
//! descriptor, the maximum APDU length and the object-type (`PID_1`)
//! discovery ([`PLUMBING`]).
//!
//! Both tests need the knx-sim `serve` binary (`BUSSARD_KNX_SIM_BIN`, set by
//! the `sim-conformance` CI job) and `python3`; without the binary they skip
//! green. Nothing is gated on vendor data: the products and their streams are
//! ours. The products are split over [`SHARDS`] test functions per test.
//! `test_synthetic_streams_goldens_cover_the_catalogue` runs without either
//! and checks that every product has its golden files and that no golden is
//! left without its product.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bussard_product::ApplicationProgram;
use bussard_product::dynamic::{evaluate_dynamic, visible_parameter_refs};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::mcp_stdio_client::McpServer;
use crate::sim_catalog_loop::{
    Configuration, DEVICE, KEY_STORE_PASSWORD, SECURE_DEVICE_TABLE, SIM_MASKS, SplitMix64,
    activated_sim_block, draw_for, knxnet_table, knxnet_tunnels, object_shape,
    read_synthetic_refusals, secure_groups, switches, synthetic_knxprods, write_key_store,
};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;

/// How many test functions split the catalogue, per test.
const SHARDS: usize = 4;

/// The seed of every product's configurations. Changing it rewrites every
/// golden.
const SEED: u64 = 596;

/// The seed of the parameter-change and Data Secure scenarios (issue #1054),
/// apart from [`SEED`] so the other goldens keep their draws.
const SEED_1054: u64 = 1054;

/// The product of the Data Secure scenarios (issue #1054): the catalogue's
/// only Data Secure capable product. knx-sim starts it `activated` (security
/// mode on, the tool key below set), the start state ETS's reload, partial
/// and apply rows meet, and bussard writes it with the key store of the
/// model: `flash-secure.txt` is the secured flash, `params-secure.txt` a
/// parameter change applied over it.
const SECURE_PRODUCT: &str = "syn-secure";

/// The plain products of the parameter-change scenario (issue #1054,
/// `params.txt`): a parameter the load procedure writes as a property, and a
/// `<choose>` whose branches pick the parameters shown.
const PARAMETER_PRODUCTS: [&str; 2] = ["syn-property-param", "syn-choose-per-ref"];

/// How long the simulator may take to load the product and listen.
const SIM_START_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the MCP job of one write may run.
const JOB_TIMEOUT: Duration = Duration::from_secs(180);

/// Normalized operations that are session plumbing, not programming: their
/// count follows the connections a surface opens and the device facts it
/// caches. Matched against the op line (`kind detail…`).
const PLUMBING: [&str; 6] = [
    "connect T_Connect",
    "disconnect T_Disconnect",
    "authorize ",
    "descriptor ",
    "prop-read obj0/PID_MAX_APDU_LENGTH ",
    "/PID_1 count=",
];

/// The environment every bussard process of these tests runs with, CLI and
/// MCP alike, so a difference in the streams is never a difference in knobs.
const BUSSARD_ENV: [(&str, &str); 3] = [
    ("BUSSARD_NO_DOTENV", "1"),
    ("BUSSARD_FLASH_REBOOT_WAIT_MS", "200"),
    ("NO_COLOR", "1"),
];

macro_rules! shard_tests {
    ($run:ident: $($name:ident = $index:expr),* $(,)?) => {
        $(
            /// One shard of the catalogue.
            #[test]
            fn $name() -> TestResult {
                $run($index)
            }
        )*
    };
}

shard_tests!(run_golden_shard:
    test_synthetic_streams_golden_shard_0 = 0,
    test_synthetic_streams_golden_shard_1 = 1,
    test_synthetic_streams_golden_shard_2 = 2,
    test_synthetic_streams_golden_shard_3 = 3,
);

shard_tests!(run_equivalence_shard:
    test_synthetic_streams_cli_mcp_shard_0 = 0,
    test_synthetic_streams_cli_mcp_shard_1 = 1,
    test_synthetic_streams_cli_mcp_shard_2 = 2,
    test_synthetic_streams_cli_mcp_shard_3 = 3,
);

/// The catalogue directory.
fn catalogue() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/synthetic-products")
}

/// The repository root.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether the catalogue captured `product` with one of `variants`.
fn has_variant(product: &str, variants: &[&str]) -> bool {
    let dir = repo().join("captures/synthetic").join(product);
    variants.iter().any(|variant| dir.join(variant).is_dir())
}

/// Whether the catalogue captured `product` with a run variant that writes
/// to a loaded device (`links`, `partial`, `apply`): such a product gets an
/// apply golden too.
fn has_apply_variant(product: &str) -> bool {
    has_variant(product, &["links", "partial", "apply"])
}

/// Whether `product` gets the plain parameter-change scenario (`params.txt`
/// and its CLI/MCP comparison): one of [`PARAMETER_PRODUCTS`], or a plain
/// product the catalogue captured with ETS's parameter editor (`params`) or
/// its parameter-only download (`partial`, issue #1054). [`SECURE_PRODUCT`]
/// has its secured scenario instead.
fn has_params_variant(product: &str) -> bool {
    PARAMETER_PRODUCTS.contains(&product)
        || (product != SECURE_PRODUCT && has_variant(product, &["params", "partial"]))
}

/// Whether the catalogue captured `product` with the `reload` variant (ETS's
/// download over the device it loaded): it gets `reload.txt`, or on
/// [`SECURE_PRODUCT`] `reload-secure.txt`.
fn has_reload_variant(product: &str) -> bool {
    has_variant(product, &["reload"])
}

/// The golden files of `product`: `flash.txt`, `apply.txt` with an apply
/// run variant, `params.txt` with a parameter variant
/// ([`has_params_variant`]), `reload.txt` with a reload variant, and
/// `flash-secure.txt`, `params-secure.txt` (and `reload-secure.txt` with a
/// reload variant) for [`SECURE_PRODUCT`].
fn goldens_of(product: &str) -> Vec<&'static str> {
    let mut out = vec!["flash.txt"];
    if has_apply_variant(product) {
        out.push("apply.txt");
    }
    if has_params_variant(product) {
        out.push("params.txt");
    }
    if product == SECURE_PRODUCT {
        out.extend(["flash-secure.txt", "params-secure.txt"]);
        if has_reload_variant(product) {
            out.push("reload-secure.txt");
        }
    } else if has_reload_variant(product) {
        out.push("reload.txt");
    }
    out
}

/// The application id a product's rendered XML carries
/// (`xml/M-00FA/M-00FA_A-<nnnn>-<vv>-0000.xml`).
fn rendered_application(product: &Path) -> Result<Option<String>, BoxError> {
    let dir = product.join("xml/M-00FA");
    if !dir.is_dir() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(&dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_suffix(".xml").filter(|n| n.contains("_A-")) {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

/// The products the streams cover: every catalogue product but those the
/// sim loop lists as refused (no knx-sim profile for the mask, #604).
fn covered_products() -> Result<Vec<(String, String)>, BoxError> {
    let refusals = read_synthetic_refusals()?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(catalogue())? {
        let product = entry?.path();
        if !product.join("product.toml").is_file() {
            continue;
        }
        let Some(app) = rendered_application(&product)? else {
            continue;
        };
        if refusals.contains_key(&app) {
            continue;
        }
        let name = product
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or("product directory without a name")?;
        out.push((name, app));
    }
    out.sort();
    Ok(out)
}

/// Every covered product has its golden files, and no golden file is left
/// without its product or variant. Runs without the simulator.
#[test]
fn test_synthetic_streams_goldens_cover_the_catalogue() -> TestResult {
    let covered = covered_products()?;
    assert!(
        covered.iter().any(|(p, _)| p == "syn-minimal"),
        "the baseline product is missing: {covered:?}"
    );
    let mut problems = Vec::new();
    for (product, _) in &covered {
        let dir = catalogue().join(product).join("requests");
        let expected: Vec<String> = goldens_of(product)
            .into_iter()
            .map(str::to_string)
            .collect();
        for file in &expected {
            if !dir.join(file).is_file() {
                problems.push(format!("{product}: requests/{file} is missing"));
            }
        }
        if dir.is_dir() {
            for entry in std::fs::read_dir(&dir)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if !expected.contains(&name) {
                    problems.push(format!("{product}: requests/{name} has no scenario"));
                }
            }
        }
    }
    for entry in std::fs::read_dir(catalogue())? {
        let product = entry?.path();
        let name = product
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if product.join("requests").is_dir() && !covered.iter().any(|(p, _)| *p == name) {
            problems.push(format!(
                "{name}: requests/ for a product the streams do not cover"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "golden request streams out of step with the catalogue (regenerate with \
         BUSSARD_UPDATE_GOLDENS=1 and BUSSARD_KNX_SIM_BIN):\n{}",
        problems.join("\n")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The two tests
// ---------------------------------------------------------------------------

/// Step 7: compares (or, with `BUSSARD_UPDATE_GOLDENS=1`, writes) the golden
/// streams of the products in shard `slot`.
fn run_golden_shard(slot: usize) -> TestResult {
    let Some(bench) = Catalogue::open("golden", slot)? else {
        return Ok(());
    };
    let update = std::env::var_os("BUSSARD_UPDATE_GOLDENS").is_some_and(|v| v == "1");
    let mut mismatches = Vec::new();
    for product in &bench.products {
        let started = Instant::now();
        let mut rng = SplitMix64::new(SEED);
        let base = Configuration::defaults(&product.app, &mut rng);
        let work = product.work(&bench.root, "golden")?;
        let flash = work.flash(&base)?;
        let mut goldens = vec![(
            "flash.txt",
            golden_text(product, "flash", FRESH, &base, &flash.ops),
        )];
        if has_apply_variant(&product.name) {
            let change = base.partial_change(&product.app, &mut rng);
            let cli = work.fork("apply")?;
            cli.write_device(&change)?;
            let run = cli.run(Some(&flash.pcap), "apply", |port| {
                cli.bussard(port, &["apply", DEVICE, "--yes"]).map(|_| ())
            })?;
            goldens.push((
                "apply.txt",
                golden_text(product, "apply", AFTER_FLASH, &change, &run),
            ));
        }
        if has_params_variant(&product.name) {
            let change = parameter_change(product, &base)?;
            let cli = work.fork("params")?;
            cli.write_device(&change)?;
            let run = cli.run(Some(&flash.pcap), "params", |port| {
                cli.bussard(port, &["apply", DEVICE, "--yes"]).map(|_| ())
            })?;
            goldens.push((
                "params.txt",
                golden_text(product, "apply", AFTER_FLASH, &change, &run),
            ));
        }
        if product.name != SECURE_PRODUCT && has_reload_variant(&product.name) {
            let cli = work.fork("reload")?;
            cli.write_device(&base)?;
            let run = cli.run(Some(&flash.pcap), "reload", |port| {
                cli.bussard(port, &["flash", DEVICE, "--yes"]).map(|_| ())
            })?;
            goldens.push((
                "reload.txt",
                golden_text(product, "flash", AFTER_FLASH, &base, &run),
            ));
        }
        if product.name == SECURE_PRODUCT {
            let secure = product.secure_work(&bench.root, "golden")?;
            let flash = secure.flash(&base)?;
            goldens.push((
                "flash-secure.txt",
                golden_text(product, "flash", ACTIVATED, &base, &flash.ops),
            ));
            let change = parameter_change(product, &base)?;
            let cli = secure.fork("params")?;
            cli.write_device(&change)?;
            let run = cli.run(Some(&flash.pcap), "params", |port| {
                cli.bussard(port, &["apply", DEVICE, "--yes"]).map(|_| ())
            })?;
            goldens.push((
                "params-secure.txt",
                golden_text(product, "apply", AFTER_SECURE_FLASH, &change, &run),
            ));
            if has_reload_variant(&product.name) {
                let cli = secure.fork("reload")?;
                cli.write_device(&base)?;
                let run = cli.run(Some(&flash.pcap), "reload", |port| {
                    cli.bussard(port, &["flash", DEVICE, "--yes"]).map(|_| ())
                })?;
                goldens.push((
                    "reload-secure.txt",
                    golden_text(product, "flash", AFTER_SECURE_FLASH, &base, &run),
                ));
            }
        }
        for (file, text) in goldens {
            let path = catalogue().join(&product.name).join("requests").join(file);
            let committed = std::fs::read_to_string(&path).unwrap_or_default();
            if committed == text {
                continue;
            }
            if update {
                std::fs::create_dir_all(path.parent().ok_or("golden without a parent")?)?;
                std::fs::write(&path, &text)?;
                eprintln!("wrote {}", path.display());
            } else {
                mismatches.push(format!(
                    "{}/requests/{file}:\n{}",
                    product.name,
                    line_diff(&committed, &text)
                ));
            }
        }
        eprintln!(
            "golden {:<32} {:>5.1}s",
            product.name,
            started.elapsed().as_secs_f64()
        );
    }
    bench.finish();
    assert!(
        mismatches.is_empty(),
        "bussard's request streams differ from the committed goldens. A deliberate change to a \
         write path regenerates them with BUSSARD_UPDATE_GOLDENS=1; review the diff like a \
         wire change (CLAUDE.md, Device Writes).\n\n{}",
        mismatches.join("\n\n")
    );
    Ok(())
}

/// Step 8: the CLI and the MCP server write the same requests for the same
/// change, for the products in shard `slot`.
fn run_equivalence_shard(slot: usize) -> TestResult {
    let Some(bench) = Catalogue::open("cli-mcp", slot)? else {
        return Ok(());
    };
    let mut divergences = Vec::new();
    for product in &bench.products {
        let started = Instant::now();
        let mut rng = SplitMix64::new(SEED);
        let base = Configuration::defaults(&product.app, &mut rng);
        let work = product.work(&bench.root, "equivalence")?;
        let flash = work.flash(&base)?;
        let change = base.partial_change(&product.app, &mut rng);
        let mut checked = Vec::new();
        if change.links.is_empty() || change.device_toml() == base.device_toml() {
            // Both surfaces refuse to plan a device without links, and an
            // empty change writes nothing; there is no write to compare.
            checked.push("apply: the partial change is empty".to_string());
        } else {
            let (method, cli, mcp) = work.compare(Some(&flash.pcap), "apply", &change)?;
            if method != "apply" && method != "noop" {
                return Err(format!(
                    "{}: the partial change keeps the object table, yet the plan says \
                     {method:?}",
                    product.name
                )
                .into());
            }
            match compare_apply(&cli, &mcp) {
                None => checked.push(if method == "noop" {
                    "apply: a no-op on both".to_string()
                } else {
                    "apply identical".to_string()
                }),
                Some(diff) => divergences.push(format!("{} apply:\n{diff}", product.name)),
            }
        }
        if let Some(reshape) = reshaping_change(&product.app, &base, &mut rng) {
            // The planner decides between a flash and an apply that reloads
            // the object table; both surfaces must write the same either way.
            let (method, cli, mcp) = work.compare(Some(&flash.pcap), "reshape", &reshape)?;
            let differs = if method == "flash" {
                compare_streams(&cli, &mcp)
            } else {
                compare_apply(&cli, &mcp)
            };
            match differs {
                None => checked.push(format!("reshape as {method} identical")),
                Some(diff) => {
                    divergences.push(format!("{} reshape as {method}:\n{diff}", product.name));
                }
            }
        } else {
            checked.push("reshape: no parameter shows or hides a com-object".to_string());
        }
        if has_params_variant(&product.name) {
            // The parameter-only write (issue #1054): an apply on both.
            let change = parameter_change(product, &base)?;
            let (method, cli, mcp) = work.compare(Some(&flash.pcap), "params", &change)?;
            match (method.as_str(), compare_apply(&cli, &mcp)) {
                ("apply", None) => checked.push("params identical".to_string()),
                ("apply", Some(diff)) => {
                    divergences.push(format!("{} params:\n{diff}", product.name));
                }
                (other, _) => {
                    return Err(format!(
                        "{}: a parameter change that keeps the object table planned as \
                         {other:?}",
                        product.name
                    )
                    .into());
                }
            }
        }
        if product.name == SECURE_PRODUCT {
            // The secured flash into the activated device, then a parameter
            // change applied over it (issue #1054, the #314 class under Data
            // Secure).
            let secure = product.secure_work(&bench.root, "equivalence")?;
            let (method, cli, mcp) = secure.compare(None, "flash-secure", &base)?;
            let differs = if method == "flash" {
                compare_streams(&cli, &mcp)
            } else {
                Some(format!(
                    "knx_plan_device planned {method:?} for an unloaded activated device, not a \
                     flash"
                ))
            };
            match differs {
                None => checked.push("secure flash identical".to_string()),
                Some(diff) => divergences.push(format!("{} secure flash:\n{diff}", product.name)),
            }
            let flash = secure.flash(&base)?;
            let change = parameter_change(product, &base)?;
            let (method, cli, mcp) = secure.compare(Some(&flash.pcap), "params-secure", &change)?;
            match (method.as_str(), compare_apply(&cli, &mcp)) {
                ("apply", None) => checked.push("secure params identical".to_string()),
                ("apply", Some(diff)) => {
                    divergences.push(format!("{} secure params:\n{diff}", product.name));
                }
                (other, _) => {
                    return Err(format!(
                        "{}: a secured parameter change planned as {other:?}",
                        product.name
                    )
                    .into());
                }
            }
        }
        eprintln!(
            "cli-mcp {:<32} {:>5.1}s {}",
            product.name,
            started.elapsed().as_secs_f64(),
            checked.join(", ")
        );
    }
    bench.finish();
    assert!(
        divergences.is_empty(),
        "the CLI and the MCP server write different request streams for the same change \
         (the #314 class): the MCP path must call the CLI's write path, not re-implement \
         it.\n\n{}",
        divergences.join("\n\n")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The bench
// ---------------------------------------------------------------------------

/// The products of one shard, zipped into a scratch directory.
struct Catalogue {
    root: PathBuf,
    products: Vec<Product>,
}

impl Catalogue {
    /// The products of shard `slot`, or `None` (skip) without the simulator.
    fn open(test: &str, slot: usize) -> Result<Option<Catalogue>, BoxError> {
        let Some(sim) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
            eprintln!("BUSSARD_KNX_SIM_BIN unset; skipping the synthetic request streams.");
            return Ok(None);
        };
        if !sim.is_file() {
            return Err(format!("BUSSARD_KNX_SIM_BIN={} is not a file", sim.display()).into());
        }
        let root = std::env::temp_dir().join(format!(
            "bussard-synthetic-streams-{test}-{}-{slot}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let archives = root.join("archives");
        std::fs::create_dir_all(&archives)?;
        synthetic_knxprods(&archives)?;
        let covered = covered_products()?;
        let mut products = Vec::new();
        for (i, (name, id)) in covered.iter().enumerate() {
            if i % SHARDS != slot {
                continue;
            }
            let archive = archives.join(format!("{name}.knxprod"));
            let data = bussard_product::read_knxprod(&archive)?;
            let app = data
                .applications
                .into_iter()
                .find(|a| &a.id == id)
                .ok_or_else(|| format!("{name}: {id} is not in the archive"))?;
            let mask = app
                .mask_version
                .as_deref()
                .map(|m| m.trim().trim_start_matches("MV-").to_ascii_uppercase())
                .unwrap_or_default();
            if !SIM_MASKS.contains(&mask.as_str()) {
                return Err(format!(
                    "{name}: mask {mask} is not simulated; list it in sim-loop-refusals.json"
                )
                .into());
            }
            products.push(Product {
                name: name.clone(),
                archive,
                app,
                mask,
                sim: sim.clone(),
            });
        }
        Ok(Some(Catalogue { root, products }))
    }

    /// Removes the scratch directory unless `BUSSARD_SYNTHETIC_STREAMS_KEEP`
    /// asks to keep it for a look at the captures.
    fn finish(&self) {
        if std::env::var_os("BUSSARD_SYNTHETIC_STREAMS_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// One synthetic product.
struct Product {
    name: String,
    archive: PathBuf,
    app: ApplicationProgram,
    mask: String,
    sim: PathBuf,
}

impl Product {
    /// A fresh work directory with a model pinning the product for 1.1.10.
    fn work(&self, root: &Path, test: &str) -> Result<Work<'_>, BoxError> {
        let dir = root.join(format!("{}-{test}", self.name));
        let _ = std::fs::remove_dir_all(&dir);
        let model = dir.join("model");
        std::fs::create_dir_all(model.join("products"))?;
        std::fs::create_dir_all(model.join("devices"))?;
        let name = format!("{}.knxprod", self.name);
        std::fs::copy(&self.archive, model.join("products").join(&name))?;
        let bytes = std::fs::read(&self.archive)?;
        let sha: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(
            model.join("bussard.lock"),
            format!(
                "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/{name}\"\n\
                 filename = \"{name}\"\nsize = {}\n\
                 origin = {{ kind = \"file\", path = \"{name}\" }}\napplications = [\"{}\"]\n\n\
                 [[device]]\naddress = \"{DEVICE}\"\napplication = \"{}\"\n\
                 product_sha256 = \"{sha}\"\nmask = \"{}\"\n",
                bytes.len(),
                self.app.id,
                self.app.id,
                self.mask
            ),
        )?;
        Ok(Work {
            product: self,
            dir: dir.clone(),
            model,
            secure: false,
        })
    }

    /// A fresh work directory for the Data Secure scenarios (issue #1054):
    /// the simulator starts the device `activated` under the synthetic tool key,
    /// and every device file marks it activated, every linked group address
    /// `secure`, with the key store holding the keys.
    fn secure_work(&self, root: &Path, test: &str) -> Result<Work<'_>, BoxError> {
        let mut work = self.work(root, &format!("{test}-secure"))?;
        work.secure = true;
        Ok(work)
    }
}

/// A recorded session: the capture and its normalized operations.
struct Recorded {
    pcap: PathBuf,
    ops: String,
}

/// A model directory and the scratch directory around it.
struct Work<'a> {
    product: &'a Product,
    /// Holds the model, the simulator configs and the captures.
    dir: PathBuf,
    model: PathBuf,
    /// The Data Secure scenario ([`Product::secure_work`]).
    secure: bool,
}

impl<'a> Work<'a> {
    /// Flashes `config` into a fresh device and returns the session.
    fn flash(&self, config: &Configuration) -> Result<Recorded, BoxError> {
        self.write_device(config)?;
        let ops = self.run(None, "flash", |port| {
            let out = self.bussard(port, &["flash", DEVICE, "--yes"])?;
            if out.contains("is Loaded on") {
                Ok(())
            } else {
                Err(format!("the flash did not report Loaded:\n{out}").into())
            }
        })?;
        Ok(Recorded {
            pcap: self.dir.join("flash.pcap"),
            ops,
        })
    }

    /// A copy of this work directory's model (after the flash: the lock and
    /// history the flash recorded) under `<dir>-<name>`.
    fn fork(&self, name: &str) -> Result<Work<'a>, BoxError> {
        let dir = self.dir.with_file_name(format!(
            "{}-{name}",
            self.dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let model = dir.join("model");
        copy_dir(&self.model, &model)?;
        Ok(Work {
            product: self.product,
            dir,
            model,
            secure: self.secure,
        })
    }

    /// Writes `config` as the device file and the group addresses.
    fn write_device(&self, config: &Configuration) -> Result<(), BoxError> {
        let mut device = config.device_toml();
        device.push_str(&knxnet_table(&self.product.app, &self.product.mask));
        let mut groups = config.groups_toml();
        if self.secure {
            device.push_str(SECURE_DEVICE_TABLE);
            groups = secure_groups(&groups);
            let keyring = write_key_store(&self.model, config)?;
            std::fs::write(self.dir.join("keys.knxkeys"), keyring)?;
        }
        std::fs::write(
            self.model.join("devices").join(format!("{DEVICE}.toml")),
            device,
        )?;
        std::fs::write(self.model.join("groups.toml"), groups)?;
        Ok(())
    }

    /// The environment of every bussard process of this work directory:
    /// [`BUSSARD_ENV`], plus the key store password in the Data Secure
    /// scenario.
    fn env(&self) -> Vec<(&'static str, &'static str)> {
        let mut env = BUSSARD_ENV.to_vec();
        if self.secure {
            env.push(("BUSSARD_KEYRING_PASSWORD", KEY_STORE_PASSWORD));
        }
        env
    }

    /// Runs `body` against a simulator that records `<name>.pcap` (after
    /// replaying `replay`, when given) and returns the normalized session.
    fn run(
        &self,
        replay: Option<&Path>,
        name: &str,
        body: impl FnOnce(u16) -> Result<(), BoxError>,
    ) -> Result<String, BoxError> {
        let sim = Sim::start(self, replay, name)?;
        std::fs::write(
            self.model.join("bussard.toml"),
            format!(
                "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:{}\"\n",
                sim.port
            ),
        )?;
        let result = body(sim.port);
        drop(sim);
        result.map_err(|e| format!("{} {name}: {e}", self.product.name))?;
        let keyring = self.secure.then(|| self.dir.join("keys.knxkeys"));
        normalized_ops(&self.dir.join(format!("{name}.pcap")), keyring.as_deref())
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>` and
    /// returns its output; a failed command is an error.
    fn bussard(&self, port: u16, args: &[&str]) -> Result<String, BoxError> {
        let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(args)
            .arg("--dir")
            .arg(&self.model)
            .args(["--gateway", &format!("127.0.0.1:{port}")])
            .envs(self.env())
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_FLASH_SYS7_LSM")
            .env_remove("BUSSARD_KEYRING")
            .stdin(Stdio::null())
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !out.status.success() {
            return Err(format!("`bussard {}` failed:\n{text}", args.join(" ")).into());
        }
        Ok(text)
    }

    /// The same write through both surfaces, each from the flashed state on
    /// its own simulator. The MCP side runs first: `knx_plan_device` says
    /// whether the change is a `flash` or an `apply`, and the CLI side runs
    /// `bussard plan --json` and then that command with `--yes`. A plan with
    /// nothing to write (`noop`) must be one on both surfaces, and the two
    /// plans' reads are compared. Returns the method and the two normalized
    /// sessions (CLI, MCP).
    fn compare(
        &self,
        flash: Option<&Path>,
        name: &str,
        config: &Configuration,
    ) -> Result<(String, String, String), BoxError> {
        let mcp_work = self.fork(&format!("{name}-mcp"))?;
        mcp_work.write_device(config)?;
        let mut method = String::new();
        let mcp_ops = mcp_work.run(flash, name, |port| {
            method = mcp_plan_and_apply(&mcp_work.model, port, &mcp_work.env())?;
            Ok(())
        })?;
        let cli_work = self.fork(&format!("{name}-cli"))?;
        cli_work.write_device(config)?;
        let cli_ops = cli_work.run(flash, name, |port| {
            let plan = cli_work.bussard(port, &["plan", DEVICE, "--json"])?;
            if method == "noop" {
                // Nothing to write: the CLI's plan must say so too.
                let json = plan.find('{').map(|at| &plan[at..]).unwrap_or_default();
                // The JSON is followed by the stderr notes.
                let plan: serde_json::Value = serde_json::Deserializer::from_str(json)
                    .into_iter()
                    .next()
                    .ok_or("`bussard plan --json` printed no JSON")??;
                if plan["noop"] != true {
                    return Err(format!("the MCP plan is a no-op, the CLI's is not: {plan}").into());
                }
                return Ok(());
            }
            cli_work
                .bussard(port, &[method.as_str(), DEVICE, "--yes"])
                .map(|_| ())
        })?;
        Ok((method, cli_ops, mcp_ops))
    }
}

/// `knx_plan_device` then `knx_apply_device` for 1.1.10 through `bussard mcp
/// --allow-programming`, waiting for the job; returns the plan's `method`
/// (`apply` or `flash`), or `noop` for a plan with nothing to write (no
/// apply then).
fn mcp_plan_and_apply(model: &Path, port: u16, env: &[(&str, &str)]) -> Result<String, BoxError> {
    let mut server = McpServer::start_without_keyring(
        model,
        port,
        env,
        &["--allow-programming", "--no-model-edits"],
    )
    .map_err(mcp_error)?;
    let plan = server
        .call_when_connected("knx_plan_device", json!({"address": DEVICE}), 100)
        .map_err(mcp_error)?;
    if plan["ok"] != true {
        return Err(format!("knx_plan_device refused: {plan}").into());
    }
    if plan["noop"] == true {
        return Ok("noop".to_string());
    }
    let method = plan["method"].as_str().unwrap_or_default().to_string();
    if method != "flash" && method != "apply" {
        return Err(format!("knx_plan_device planned method {method:?}: {plan}").into());
    }
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| format!("knx_plan_device returned no plan_digest: {plan}"))?;
    let mut result = server
        .call(
            "knx_apply_device",
            json!({"address": DEVICE, "plan_digest": digest}),
        )
        .map_err(mcp_error)?;
    let started = Instant::now();
    while result["started"] == true && result["done"] != true {
        if started.elapsed() > JOB_TIMEOUT {
            return Err(format!("knx_apply_device job did not end: {result}").into());
        }
        std::thread::sleep(Duration::from_millis(250));
        let job = result["job"].clone();
        let status = server
            .call("knx_apply_status", json!({"job": job}))
            .map_err(mcp_error)?;
        if status["done"] == true {
            result = status["result"].clone();
            break;
        }
    }
    if result["ok"] != true || result["verified"] != true {
        return Err(format!("knx_apply_device did not verify: {result}").into());
    }
    Ok(method)
}

/// The MCP client's error (`Send + Sync`) as this module's.
fn mcp_error(e: Box<dyn std::error::Error + Send + Sync>) -> BoxError {
    e.to_string().into()
}

/// A running knx-sim, killed on drop.
struct Sim {
    child: Child,
    port: u16,
}

impl Sim {
    /// Starts the simulator for `work`'s product with an unloaded 1.1.10,
    /// recording `<name>.pcap` in the work directory, after replaying the
    /// tool requests of `replay`.
    fn start(work: &Work<'_>, replay: Option<&Path>, name: &str) -> Result<Sim, BoxError> {
        let product = work.product;
        let port = std::net::UdpSocket::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        // Theben's 0701 family drives its load-state machines memory-mapped;
        // bussard picks that from the mask, and the sim must match.
        let lsm = if product.mask == "0701" {
            "memory"
        } else {
            "property"
        };
        let mut yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n  pcap: \"{name}.pcap\"\n\n\
             devices:\n  - address: \"{DEVICE}\"\n    knxprod: \"{}\"\n    \
             application: \"{}\"\n    initial_state: unloaded\n    lsm_access: {lsm}\n",
            product.archive.display(),
            product.app.id
        );
        if knxnet_tunnels(&product.app, &product.mask) > 0 {
            yaml.push_str("    knxnet:\n      tunnel_slots: 16\n");
        }
        if work.secure {
            // The `activated` start state (issue #1054).
            yaml.push_str(&activated_sim_block());
        }
        if let Some(replay) = replay {
            yaml.push_str(&format!("\nreplay:\n  - \"{}\"\n", replay.display()));
        }
        let config = work.dir.join(format!("sim-{name}.yaml"));
        std::fs::write(&config, yaml)?;
        let log = work.dir.join(format!("sim-{name}.log"));
        let child = Command::new(&product.sim)
            .arg(&config)
            .env("RUST_LOG", "knx_sim::run=info,warn")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log)?)
            .stderr(Stdio::from(std::fs::File::create(
                work.dir.join(format!("sim-{name}.err")),
            )?))
            .spawn()?;
        let mut sim = Sim { child, port };
        let started = Instant::now();
        loop {
            if std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("listening")
            {
                return Ok(sim);
            }
            if let Some(status) = sim.child.try_wait()? {
                let err = std::fs::read_to_string(work.dir.join(format!("sim-{name}.err")))
                    .unwrap_or_default();
                return Err(format!("knx-sim did not start ({status}): {err}").into());
            }
            if started.elapsed() > SIM_START_TIMEOUT {
                return Err("knx-sim did not listen within 60 s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Normalization and comparison
// ---------------------------------------------------------------------------

/// `knxtrace ops` of a capture for 1.1.10, without the header lines (the
/// capture path, the dropped counts) and the operation numbers, so a golden
/// diff shows only the operations that changed.
fn normalized_ops(pcap: &Path, keyring: Option<&Path>) -> Result<String, BoxError> {
    let mut command = Command::new("python3");
    command
        .arg(repo().join("tools/knxtrace/knxtrace.py"))
        .arg("ops")
        .arg(pcap)
        .args(["--device", DEVICE]);
    if let Some(keyring) = keyring {
        // Decrypts the secured frames, so the golden shows what they carry.
        command
            .arg("--keyring")
            .arg(keyring)
            .env("BUSSARD_KEYRING_PASSWORD", KEY_STORE_PASSWORD);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("python3 for knxtrace: {e}"))?;
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .ok_or("no stdout pipe")?
        .read_to_string(&mut stdout)?;
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .ok_or("no stderr pipe")?
        .read_to_string(&mut stderr)?;
    if !child.wait()?.success() {
        return Err(format!("knxtrace ops {} failed: {stderr}", pcap.display()).into());
    }
    let mut out = String::new();
    for line in stdout.lines() {
        if line.starts_with("normalized operation sequence") || line.starts_with("dropped:") {
            continue;
        }
        // `  12  mem-write …` -> `mem-write …`
        let trimmed = line.trim_start();
        let body = match trimmed.split_once("  ") {
            Some((n, rest)) if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() => rest,
            _ => line,
        };
        let body = secure_stable(body);
        if body.starts_with("secure-data S-A_Sync_Req") && out.lines().last() == Some(&body) {
            // A repeated Sync_Req: the device ignored the first within 1 s
            // of its last Sync_Res (KNX 3/3/7 §5.3.2), a matter of timing.
            continue;
        }
        out.push_str(&body);
        out.push('\n');
    }
    Ok(out.trim_start_matches('\n').to_string())
}

/// The device of `flash.txt`.
const FRESH: &str = "a fresh knx-sim device";
/// The device of `apply.txt` and `params.txt`.
const AFTER_FLASH: &str = "the state flash.txt left (knx-sim replays that session)";
/// The device of `flash-secure.txt` (issue #1054).
const ACTIVATED: &str = "a fresh knx-sim device, security `activated` under the synthetic tool \
                         key";
/// The device of `params-secure.txt` (issue #1054).
const AFTER_SECURE_FLASH: &str = "the state flash-secure.txt left (knx-sim replays that session)";

/// A normalized op without what differs from run to run under Data Secure:
/// the sending sequence of a secured frame (bussard seeds it from the clock)
/// and the hash of its encrypted part. The decrypted operation stays.
fn secure_stable(op: &str) -> String {
    if !op.starts_with("secure-data ") {
        return op.to_string();
    }
    op.split(' ')
        .filter(|t| !t.starts_with("seq=") && !t.starts_with("protected_sha="))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The committed form of a golden: a comment header naming the command, the
/// product, the device it met and the device file, then the operations.
fn golden_text(
    product: &Product,
    command: &str,
    device: &str,
    config: &Configuration,
    ops: &str,
) -> String {
    let mut text = format!(
        "# Golden request stream (epic #596), written by\n\
         # crates/bussard-cli/tests/it/synthetic_streams.rs; regenerate with\n\
         # BUSSARD_UPDATE_GOLDENS=1 (dev/testing.md).\n#\n\
         # command: bussard {command} {DEVICE} --yes\n\
         # product: {} ({})\n\
         # device:  {device}\n\
         # format:  tools/knxtrace/knxtrace.py ops, without the operation numbers\n\
         #          and the capture header\n#\n# devices/{DEVICE}.toml:\n",
        product.name, product.app.id
    );
    for line in config.device_toml().lines() {
        text.push_str(&format!("#   {line}\n").replace("#   \n", "#\n"));
    }
    text.push('\n');
    text.push_str(ops);
    text
}

/// The operations of a session that the CLI/MCP comparison keeps: every op
/// line but the session plumbing ([`PLUMBING`]), plus the memory image.
fn programming_ops(ops: &str) -> Vec<&str> {
    ops.lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !PLUMBING.iter().any(|p| l.contains(p)))
        .collect()
}

/// The op kinds that change the device: the first of them in a session
/// starts the write path the surfaces share.
const WRITE_KINDS: [&str; 7] = [
    "load-event ",
    "alloc-record ",
    "mem-write ",
    "prop-write ",
    "restart ",
    "ia-write ",
    "function-prop ",
];

/// `None` when the MCP session programs the device as the CLI session does,
/// else what differs. From the first write on (the write, its read-back and
/// the memory image) the kept operations must be identical. Before it, every
/// read the CLI makes (the identity gate, the plan's reads) must appear in
/// the MCP session in the same order; the MCP may read more there, because
/// `knx_apply_device` re-reads the device to check the plan digest.
fn compare_streams(cli: &str, mcp: &str) -> Option<String> {
    let (a, b) = (programming_ops(cli), programming_ops(mcp));
    let first_write = |ops: &[&str]| {
        ops.iter()
            .position(|l| WRITE_KINDS.iter().any(|k| l.starts_with(k)))
            .unwrap_or(ops.len())
    };
    let (a_pre, a_write) = a.split_at(first_write(&a));
    let (b_pre, b_write) = b.split_at(first_write(&b));
    if a_write != b_write {
        return Some(format!(
            "the write path differs (CLI -, MCP +):\n{}",
            line_diff(&a_write.join("\n"), &b_write.join("\n"))
        ));
    }
    let mut rest = b_pre.iter();
    let missing: Vec<&&str> = a_pre.iter().filter(|op| !rest.any(|m| m == *op)).collect();
    (!missing.is_empty()).then(|| {
        format!(
            "the MCP session skips reads the CLI makes before writing (the first is \
             {:?}):\nCLI:\n{}\nMCP:\n{}",
            missing.first(),
            a_pre.join("\n"),
            b_pre.join("\n")
        )
    })
}

/// `None` when the MCP session of an apply sends exactly the CLI's
/// requests, plumbing and pre-write reads included (issue #761), else the
/// diff. The plan-digest re-read of `knx_apply_device` is the read `bussard
/// apply` makes for its own plan, so nothing is left to excuse.
fn compare_apply(cli: &str, mcp: &str) -> Option<String> {
    (cli != mcp).then(|| {
        let (a, b) = (count_ops(cli), count_ops(mcp));
        format!(
            "the sessions differ ({a} operations on the CLI, {b} on the MCP server; CLI -, MCP \
             +):\n{}",
            line_diff(cli, mcp)
        )
    })
}

/// The number of operations in a normalized session.
fn count_ops(ops: &str) -> usize {
    ops.lines().filter(|l| !l.trim().is_empty()).count()
}

/// A short diff of two texts: the common head and tail are cut, the middle
/// is shown with `-` (expected) and `+` (actual), at most 40 lines each.
fn line_diff(expected: &str, actual: &str) -> String {
    let a: Vec<&str> = expected.lines().collect();
    let b: Vec<&str> = actual.lines().collect();
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let mut out = format!("@@ after line {head} @@\n");
    let minus = &a[head..a.len() - tail];
    let plus = &b[head..b.len() - tail];
    for line in minus.iter().take(40) {
        out.push_str(&format!("- {line}\n"));
    }
    if minus.len() > 40 {
        out.push_str(&format!("- … {} more\n", minus.len() - 40));
    }
    for line in plus.iter().take(40) {
        out.push_str(&format!("+ {line}\n"));
    }
    if plus.len() > 40 {
        out.push_str(&format!("+ … {} more\n", plus.len() - 40));
    }
    out
}

/// The parameter change of the issue #1054 scenarios: [`SEED_1054`]'s draw
/// of [`Configuration::parameter_change`] over `base`. A draw that changes
/// nothing is an error, so a golden never records an empty write.
fn parameter_change(product: &Product, base: &Configuration) -> Result<Configuration, BoxError> {
    let mut rng = SplitMix64::new(SEED_1054);
    let change = base.parameter_change(&product.app, &mut rng);
    if change.values == base.values {
        return Err(format!("{}: the parameter change changes nothing", product.name).into());
    }
    Ok(change)
}

/// A configuration that changes one enable switch of `base` so that a
/// com-object appears or disappears (or a System 7 allocation changes): the
/// change the MCP tier writes as a flash. Links on objects the change hides
/// are dropped. `None` when no shown switch
/// reshapes the table within a few draws.
fn reshaping_change(
    app: &ApplicationProgram,
    base: &Configuration,
    rng: &mut SplitMix64,
) -> Option<Configuration> {
    let memo = bussard_product::dynamic::DynamicMemo::new(app);
    let switches = switches(app);
    let config = evaluate_dynamic(app, &base.values);
    let mut refs: Vec<(String, String)> = visible_parameter_refs(app, &config)
        .into_iter()
        .filter(|v| {
            config
                .parameter_placements
                .get(v.index)
                .is_some_and(|p| p.shown)
        })
        .filter(|v| switches.contains(&v.param_ref_id))
        .map(|v| (v.ref_key, v.param_ref_id))
        .collect();
    refs.sort();
    for (key, param_ref) in refs {
        for _ in 0..8 {
            let Some(value) = draw_for(app, &base.values, &key, &param_ref, rng) else {
                break;
            };
            if base.values.get(&key) == Some(&value) {
                continue;
            }
            let mut values = base.values.clone();
            values.insert(key.clone(), value);
            // The test `knx_plan_device` itself applies (issues #303, #411):
            // a com-object appears or disappears, or a System 7 allocation
            // changes. A changed descriptor alone is an apply.
            let flashes = !bussard_download::group_object_change(
                app,
                &base.values,
                &values,
                &bussard_product::dynamic::DynamicMemo::new(app),
            )
            .is_empty()
                || bussard_download::allocation_change(app, &base.values, &values, &memo).is_some();
            if !flashes {
                continue;
            }
            let shown: Vec<u16> = object_shape(app, &values)
                .iter()
                .map(|(asap, _, _)| *asap)
                .collect();
            let mut out = base.clone();
            out.label = format!("{} + reshaping change", base.label);
            out.values = values;
            out.links.retain(|asap, _| shown.contains(asap));
            if out.links.is_empty() {
                // Both surfaces refuse to plan a device without links.
                out.add_links(app, rng, 1);
            }
            return Some(out);
        }
    }
    None
}

/// Copies a directory tree.
fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_programming_ops_drops_the_session_plumbing() {
        let ops = "connect T_Connect\nauthorize Authorize_Request key=FFFFFFFF(free-access)\n\
                   descriptor type0 type=0\nprop-read obj0/PID_MAX_APDU_LENGTH count=1 index=1\n\
                   prop-read obj3/PID_1 count=1 index=1\n\
                   prop-read obj4/PID_TABLE_REFERENCE count=1 index=1\n\
                   mem-write 0x6000 addr_int=24576 len=3 sha=28d21021 extended=False\n\
                   disconnect T_Disconnect\n";
        assert_eq!(
            programming_ops(ops),
            vec![
                "prop-read obj4/PID_TABLE_REFERENCE count=1 index=1",
                "mem-write 0x6000 addr_int=24576 len=3 sha=28d21021 extended=False",
            ]
        );
    }

    #[test]
    fn test_compare_streams_allows_extra_mcp_reads_before_the_write_only() {
        let cli = "prop-read obj4/PID_PROGRAM_VERSION count=1 index=1\n\
                   mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n\
                   mem-read 0x8000 addr_int=32768 count=2\n";
        let more_reads = "prop-read obj4/PID_PROGRAM_VERSION count=1 index=1\n\
                          mem-read 0xa000 addr_int=40960 count=2\n\
                          mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n\
                          mem-read 0x8000 addr_int=32768 count=2\n";
        assert_eq!(compare_streams(cli, more_reads), None);
        let skipped_gate = "mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n\
                            mem-read 0x8000 addr_int=32768 count=2\n";
        assert!(compare_streams(cli, skipped_gate).is_some());
        let no_readback = "prop-read obj4/PID_PROGRAM_VERSION count=1 index=1\n\
                           mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n";
        assert!(compare_streams(cli, no_readback).is_some());
    }

    #[test]
    fn test_compare_apply_refuses_a_rediscovery_before_the_write() -> TestResult {
        let cli = "connect T_Connect\ndescriptor type0 type=0\n\
                   prop-read obj4/PID_PROGRAM_VERSION count=1 index=1\n\
                   mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n";
        assert_eq!(compare_apply(cli, cli), None);
        let rediscovers = "connect T_Connect\ndescriptor type0 type=0\n\
                           prop-read obj4/PID_PROGRAM_VERSION count=1 index=1\n\
                           prop-read obj0/PID_1 count=1 index=1\n\
                           mem-write 0x8000 addr_int=32768 len=4 sha=e5e121e5 extended=False\n";
        let diff = compare_apply(cli, rediscovers).ok_or("a rediscovery must differ")?;
        assert!(diff.contains("+ prop-read obj0/PID_1"), "{diff}");
        Ok(())
    }

    #[test]
    fn test_secure_stable_drops_the_clock_seeded_sequence() {
        let op = "secure-data S-A_Sync_Req scf=0x92 tool_access=True seq=279317091657 \
                  protected_len=16 protected_sha=381ee6ce key=tool mac=ok";
        assert_eq!(
            secure_stable(op),
            "secure-data S-A_Sync_Req scf=0x92 tool_access=True protected_len=16 key=tool mac=ok"
        );
        let plain = "mem-write 0x6000 addr_int=24576 len=3 sha=88a32a5f extended=False";
        assert_eq!(secure_stable(plain), plain);
    }

    #[test]
    fn test_line_diff_shows_only_the_changed_middle() {
        let diff = line_diff("a\nb\nc\nd", "a\nx\nc\nd");
        assert_eq!(diff, "@@ after line 1 @@\n- b\n+ x\n");
    }
}
