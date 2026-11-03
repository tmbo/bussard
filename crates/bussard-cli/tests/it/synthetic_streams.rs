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
//! **CLI and MCP equivalence (step 8, the #314 class).** For every product,
//! the same write runs through both surfaces from the same flashed state, on
//! two simulators, and the two normalized streams are compared:
//!
//! - the apply: `bussard plan 1.1.10 --json` then `bussard apply 1.1.10
//!   --yes`, against `knx_plan_device` then `knx_apply_device`;
//! - the reshape, for a product with an enable switch that shows or hides a
//!   com-object: the MCP tier writes that as a flash (`method: flash`, issue
//!   #303), or as an apply that reloads the object table when the planner
//!   decides so; the CLI side runs `bussard plan` and then `bussard flash` or
//!   `bussard apply` as the MCP plan says.
//!
//! Before the first write the MCP session may read more than the CLI (its
//! `knx_apply_device` re-reads the device to check the plan digest), but
//! never skip a read the CLI makes (the identity gate, the plan's reads);
//! from the first write on (the write, the read-back and the memory image)
//! the two must be identical ([`compare_streams`]).
//!
//! The comparison drops the session plumbing whose count depends on how
//! often a surface opens a connection, not on what it writes or verifies:
//! `T_Connect`/`T_Disconnect`, the authorize, the device descriptor, the
//! maximum APDU length and the object-type (`PID_1`) discovery
//! ([`PLUMBING`]).
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

use bussard_prod::ApplicationProgram;
use bussard_prod::dynamic::{evaluate_dynamic, visible_parameter_refs};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::mcp_stdio_client::McpServer;
use crate::sim_catalog_loop::{
    Configuration, DEVICE, SIM_MASKS, SplitMix64, draw_for, knxnet_table, knxnet_tunnels,
    object_shape, read_synthetic_refusals, switches, synthetic_knxprods,
};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;

/// How many test functions split the catalogue, per test.
const SHARDS: usize = 4;

/// The seed of every product's configurations. Changing it rewrites every
/// golden.
const SEED: u64 = 596;

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

/// Whether the catalogue captured `product` with a run variant that writes
/// to a loaded device (`links`, `partial`): such a product gets an apply
/// golden too.
fn has_apply_variant(product: &str) -> bool {
    let dir = repo().join("captures/synthetic").join(product);
    ["links", "partial"]
        .iter()
        .any(|variant| dir.join(variant).is_dir())
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
        let mut expected = vec!["flash.txt".to_string()];
        if has_apply_variant(product) {
            expected.push("apply.txt".to_string());
        }
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
            golden_text(product, "flash", &base, &flash.ops),
        )];
        if has_apply_variant(&product.name) {
            let change = base.partial_change(&product.app, &mut rng);
            let cli = work.fork("apply")?;
            cli.write_device(&change)?;
            let run = cli.run(Some(&flash.pcap), "apply", |port| {
                cli.bussard(port, &["apply", DEVICE, "--yes"]).map(|_| ())
            })?;
            goldens.push(("apply.txt", golden_text(product, "apply", &change, &run)));
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
            let (method, cli, mcp) = work.compare(&flash.pcap, "apply", &change)?;
            if method != "apply" && method != "noop" {
                return Err(format!(
                    "{}: the partial change keeps the object table, yet the plan says \
                     {method:?}",
                    product.name
                )
                .into());
            }
            match compare_streams(&cli, &mcp) {
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
            let (method, cli, mcp) = work.compare(&flash.pcap, "reshape", &reshape)?;
            match compare_streams(&cli, &mcp) {
                None => checked.push(format!("reshape as {method} identical")),
                Some(diff) => {
                    divergences.push(format!("{} reshape as {method}:\n{diff}", product.name));
                }
            }
        } else {
            checked.push("reshape: no parameter shows or hides a com-object".to_string());
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
            let data = bussard_prod::read_knxprod(&archive)?;
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
        })
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
        })
    }

    /// Writes `config` as the device file and the group addresses.
    fn write_device(&self, config: &Configuration) -> Result<(), BoxError> {
        let mut device = config.device_toml();
        device.push_str(&knxnet_table(&self.product.app, &self.product.mask));
        std::fs::write(
            self.model.join("devices").join(format!("{DEVICE}.toml")),
            device,
        )?;
        std::fs::write(self.model.join("groups.toml"), config.groups_toml())?;
        Ok(())
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
        normalized_ops(&self.dir.join(format!("{name}.pcap")))
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>` and
    /// returns its output; a failed command is an error.
    fn bussard(&self, port: u16, args: &[&str]) -> Result<String, BoxError> {
        let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(args)
            .arg("--dir")
            .arg(&self.model)
            .args(["--gateway", &format!("127.0.0.1:{port}")])
            .envs(BUSSARD_ENV)
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
        flash: &Path,
        name: &str,
        config: &Configuration,
    ) -> Result<(String, String, String), BoxError> {
        let mcp_work = self.fork(&format!("{name}-mcp"))?;
        mcp_work.write_device(config)?;
        let mut method = String::new();
        let mcp_ops = mcp_work.run(Some(flash), name, |port| {
            method = mcp_plan_and_apply(&mcp_work.model, port)?;
            Ok(())
        })?;
        let cli_work = self.fork(&format!("{name}-cli"))?;
        cli_work.write_device(config)?;
        let cli_ops = cli_work.run(Some(flash), name, |port| {
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
fn mcp_plan_and_apply(model: &Path, port: u16) -> Result<String, BoxError> {
    let mut server = McpServer::start_without_keyring(
        model,
        port,
        &BUSSARD_ENV,
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
fn normalized_ops(pcap: &Path) -> Result<String, BoxError> {
    let mut child = Command::new("python3")
        .arg(repo().join("tools/knxtrace/knxtrace.py"))
        .arg("ops")
        .arg(pcap)
        .args(["--device", DEVICE])
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
        out.push_str(body);
        out.push('\n');
    }
    Ok(out.trim_start_matches('\n').to_string())
}

/// The committed form of a golden: a comment header naming the command, the
/// product and the device file, then the operations.
fn golden_text(product: &Product, command: &str, config: &Configuration, ops: &str) -> String {
    let device = if command == "flash" {
        "a fresh knx-sim device"
    } else {
        "the state flash.txt left (knx-sim replays that session)"
    };
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
    let memo = bussard_prod::dynamic::DynamicMemo::new(app);
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
            let flashes = !bussard_download::group_object_change(app, &base.values, &values)
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
    fn test_line_diff_shows_only_the_changed_middle() {
        let diff = line_diff("a\nb\nc\nd", "a\nx\nc\nd");
        assert_eq!(diff, "@@ after line 1 @@\n- b\n+ x\n");
    }
}
