//! The parameter-only download by the mask's `par` procedure through the
//! CLI and the MCP server (issue #1052), on the shape of the Hager
//! `M-0009_A-E802-13-7620`: a merged 07B0 program whose parameters all live
//! in properties, no `par` allocation, and a parameter reset
//! (`AppliesTo="full,par" EraseCode="5"`) before the writes. `apply`,
//! `knx_apply_device` and `restore --parameters` back up, write and read
//! back the same properties, the fixed object 9 PID 208 included, and say
//! that the parameters are reset first. bussard's own synthetic data (MIT).

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::mcp_stdio_client::McpServer;

use bussard_model::IndividualAddress;
use bussard_testkit::consts::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use serde_json::{Value, json};

/// `A_Restart` with the master-reset restart type, and its response.
const A_RESTART_MASTER_RESET: u16 = 0x381;
const A_RESTART_RESPONSE: u16 = 0x3A1;
/// `A_PropertyValue_Write` and its response.
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;

/// The E802-shaped synthetic program.
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard par procedure cli test app"
            LoadProcedureStyle="MergedProcedure" MinEtsVersion="5.0">
          <Static>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="dly" Text="Delay" ParameterType="M-00FA_A-0002_PT-0" Value="5"><Property ObjectIndex="10" PropertyId="52" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="lvl" Text="Level" ParameterType="M-00FA_A-0002_PT-0" Value="9"><Property ObjectIndex="10" PropertyId="52" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <LoadProcedures>
              <LoadProcedure MergeId="2" />
              <LoadProcedure MergeId="4">
                <LdCtrlMasterReset AppliesTo="full,grp" EraseCode="6" ChannelNumber="0" />
                <LdCtrlMasterReset AppliesTo="full,par" EraseCode="5" ChannelNumber="0" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="9" PropId="208" Count="2" Verify="false" InlineData="0102" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="9" PropId="208" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// The mock bus, the model directory and the product.
struct Bench {
    gw: MockGateway,
    port: u16,
    tmp: PathBuf,
    product: PathBuf,
    resets: Arc<Mutex<Vec<u8>>>,
    /// While set, the device acknowledges a write of object 9 PID 208 and
    /// keeps what it held (a write it does not take).
    drop_object_9: Arc<AtomicBool>,
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    /// Starts the bench.
    fn start(tag: &str) -> Result<Bench, BoxError> {
        let rt = tokio::runtime::Runtime::new()?;
        let resets = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&resets);
        let drop_object_9 = Arc::new(AtomicBool::new(false));
        let dropping = Arc::clone(&drop_object_9);
        let device = MockDevice::system_b(target()?)
            .with_object_types(&[
                OT_DEVICE,
                OT_ADDRESS_TABLE,
                OT_ASSOCIATION_TABLE,
                OT_GROUP_OBJECT_TABLE,
                OT_APPLICATION_PROGRAM,
                1000,
                1001,
                1002,
                1003,
                1004,
                1005,
            ])
            .with_writable_property(4, 13, 5, &[0; 5])
            .with_writable_property(9, 208, 1, &[0, 0])
            .with_writable_property(10, 52, 1, &[0, 0])
            .with_hook(move |_, apci, data| {
                if apci == A_PROPERTY_VALUE_WRITE
                    && dropping.load(Ordering::SeqCst)
                    && data.get(..2) == Some(&[9, 208][..])
                {
                    // Answered as taken, not stored.
                    return Some(Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, data.to_vec()));
                }
                if apci != A_RESTART_MASTER_RESET {
                    return None;
                }
                if let Ok(mut seen) = seen.lock() {
                    seen.extend(data.first());
                }
                Some(Reaction::Answer(A_RESTART_RESPONSE, vec![0, 0, 0]))
            });
        let gw = rt.block_on(
            MockGateway::builder()
                .keep_serving()
                .idle_timeout(Duration::from_secs(120))
                .device(device)
                .start(),
        )?;
        let port = gw.port();
        let tmp = std::env::temp_dir().join(format!("bussard-{tag}-{}-{port}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("prod").join("M-00FA"))?;
        std::fs::write(
            tmp.join("prod").join("M-00FA").join("M-00FA_A-0002.xml"),
            APP_XML,
        )?;
        let product = tmp.join("par-test.knxprod");
        // The `zip` CLI builds the synthetic product; without it the test
        // fails rather than pass without running.
        let status = Command::new("zip")
            .current_dir(tmp.join("prod"))
            .args(["-r", "-X", "-q"])
            .arg(&product)
            .arg("M-00FA")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("the `zip` CLI is needed to build the test product: {e}"))?;
        if !status.success() {
            return Err("`zip` failed to build the test product".into());
        }
        let bench = Bench {
            gw,
            port,
            tmp,
            product,
            resets,
            drop_object_9,
            _rt: rt,
        };
        bench.write_model("")?;
        Ok(bench)
    }

    fn model(&self) -> PathBuf {
        self.tmp.join("knx")
    }

    /// `bussard mcp --allow-programming` on the model, the shared client.
    fn mcp(&self) -> Result<McpServer, BoxError> {
        McpServer::start_without_keyring(
            &self.model(),
            self.port,
            &[
                ("BUSSARD_MGMT_TIMEOUT_MS", "300"),
                ("BUSSARD_ADDRESS_PROBE_MS", "200"),
                ("BUSSARD_FLASH_L4_TIMEOUT_MS", "300"),
                ("BUSSARD_FLASH_REBOOT_WAIT_MS", "50"),
            ],
            &["--allow-programming", "--no-model-edits"],
        )
    }

    /// The model with `params` as 1.1.4's `[parameters]`, the product pinned
    /// in `bussard.lock` (`restore` and the MCP server take no `--product`).
    fn write_model(&self, params: &str) -> TestResult {
        use sha2::Digest as _;
        let model = self.model();
        std::fs::create_dir_all(model.join("devices"))?;
        std::fs::create_dir_all(model.join("products"))?;
        std::fs::write(
            model.join("bussard.toml"),
            "[connection]\ntransport = \"tunnel\"\n",
        )?;
        let file = model.join("products").join("par-test.knxprod");
        std::fs::copy(&self.product, &file)?;
        let sha: String = sha2::Sha256::digest(std::fs::read(&file)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(
            model.join("bussard.lock"),
            format!(
                "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/par-test.knxprod\"\n\
                 filename = \"par-test.knxprod\"\norigin = {{ kind = \"file\", path = \"par-test.knxprod\" }}\n\
                 applications = [\"M-00FA_A-0002\"]\n\n[[device]]\naddress = \"1.1.4\"\n\
                 application = \"M-00FA_A-0002\"\nproduct_sha256 = \"{sha}\"\nmask = \"07B0\"\n"
            ),
        )?;
        let block = if params.is_empty() {
            String::new()
        } else {
            format!("\n[parameters]\n{params}")
        };
        std::fs::write(
            model.join("devices").join("1.1.4.toml"),
            format!("address = \"1.1.4\"\nname = \"Par test\"\n{block}\n"),
        )?;
        Ok(())
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>`.
    fn bussard(&self, args: &[&str]) -> Result<Output, BoxError> {
        let model = self.model();
        let gateway = format!("127.0.0.1:{}", self.port);
        let mut full: Vec<&str> = args.to_vec();
        full.extend_from_slice(&[
            "--dir",
            model.to_str().ok_or("path")?,
            "--gateway",
            &gateway,
        ]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .env("BUSSARD_FLASH_L4_TIMEOUT_MS", "300")
            .env("BUSSARD_FLASH_REBOOT_WAIT_MS", "50")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .args(&full)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    /// Runs `args` and fails unless it succeeds; returns stdout.
    fn ok(&self, args: &[&str]) -> Result<String, BoxError> {
        let out = self.bussard(args)?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if !out.status.success() {
            return Err(format!("{args:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}").into());
        }
        Ok(stdout)
    }

    fn property(&self, object: u8, pid: u8) -> Result<Option<Vec<u8>>, BoxError> {
        Ok(self
            .gw
            .with_device(target()?, |d| d.property(object, pid).map(<[u8]>::to_vec))?)
    }

    fn set_property(&self, object: u8, pid: u8, value: &[u8]) -> TestResult {
        self.gw.with_device(target()?, |d| {
            *d = d.clone().with_writable_property(object, pid, 1, value);
        })?;
        Ok(())
    }

    fn take_resets(&self) -> Result<Vec<u8>, BoxError> {
        let mut seen = self.resets.lock().map_err(|e| e.to_string())?;
        Ok(std::mem::take(&mut *seen))
    }

    /// The parameter backups, oldest first.
    fn backups(&self) -> Result<Vec<PathBuf>, BoxError> {
        let dir = self
            .model()
            .join("captures")
            .join("backups")
            .join("parameters");
        let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        out.sort();
        Ok(out)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.4".parse()?)
}

/// Whether the plan's notes say the parameters are reset first.
fn says_reset(notes: &Value) -> bool {
    notes.as_array().into_iter().flatten().any(|n| {
        n.as_str()
            .is_some_and(|n| n.contains("resets all its parameters"))
    })
}

#[test]
fn test_apply_mcp_apply_and_restore_run_the_par_procedure() -> TestResult {
    let bench = Bench::start("par-procedure")?;
    let product = bench.product.to_str().ok_or("path")?.to_string();
    bench.ok(&["flash", "1.1.4", "--product", &product, "--yes"])?;
    assert_eq!(bench.property(10, 52)?, Some(vec![5, 9]));
    assert_eq!(bench.take_resets()?, [6, 5]);
    // Something else changed object 9 since: the backup must hold that. A
    // fixed write that differs alone is no parameter change: the plan has
    // nothing to write.
    bench.set_property(9, 208, &[7, 7])?;
    let plan: Value = serde_json::from_str(&bench.ok(&["plan", "1.1.4", "--json"])?)?;
    assert_eq!(plan["changes"], json!([]), "{plan}");

    // `apply`: the plan says the parameters are reset first; the write
    // resets them (erase code 5 only) and writes every property.
    bench.write_model("\"lvl@P-1_R-2\" = \"20\"\n")?;
    let plan: Value = serde_json::from_str(&bench.ok(&["plan", "1.1.4", "--json"])?)?;
    assert!(says_reset(&plan["notes"]), "{plan}");
    let out = bench.ok(&["apply", "1.1.4", "--yes"])?;
    assert_eq!(bench.take_resets()?, [5], "{out}");
    assert_eq!(bench.property(10, 52)?, Some(vec![5, 20]));
    assert_eq!(bench.property(9, 208)?, Some(vec![1, 2]));
    // The backup holds every property the procedure writes, object 9's
    // fixed value included.
    let backups = bench.backups()?;
    // Kept aside: a later backup within the same second reuses its name.
    let first = bench.tmp.join("first-backup.json");
    std::fs::copy(backups.first().ok_or("no parameter backup")?, &first)?;
    let backup: Value = serde_json::from_str(&std::fs::read_to_string(&first)?)?;
    let props = backup["properties"].as_array().ok_or("no properties")?;
    assert!(
        props
            .iter()
            .any(|p| p["prop_id"] == 208 && p["bytes"] == "0707"),
        "{backup}"
    );
    assert!(
        props
            .iter()
            .any(|p| p["prop_id"] == 52 && p["bytes"] == "0509"),
        "{backup}"
    );

    // `knx_apply_device`: the same plan note, write and read-back.
    bench.write_model("\"lvl@P-1_R-2\" = \"21\"\n")?;
    {
        let mut server = bench.mcp()?;
        let plan =
            server.call_when_connected("knx_plan_device", json!({"address": "1.1.4"}), 50)?;
        assert!(says_reset(&plan["notes"]), "{plan}");
        // The approval question the assistant shows says it too (the one
        // question `apply` asks on the CLI).
        assert!(
            plan["question"]
                .as_str()
                .is_some_and(|q| q.contains("resets all its parameters")),
            "{plan}"
        );
        let digest = plan["plan_digest"]
            .as_str()
            .ok_or("no plan_digest")?
            .to_string();
        let applied = server.call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )?;
        assert_ne!(applied["refused"], true, "{applied}");
    }
    assert_eq!(bench.take_resets()?, [5]);
    assert_eq!(bench.property(10, 52)?, Some(vec![5, 21]));

    // `restore --parameters` of the first backup: the procedure resets the
    // parameters again and writes the backup's values, object 9 included.
    let restored = bench.ok(&[
        "restore",
        "--parameters",
        first.to_str().ok_or("path")?,
        "1.1.4",
        "--yes",
    ])?;
    assert!(restored.contains("resets all its parameters"), "{restored}");
    assert_eq!(bench.take_resets()?, [5], "{restored}");
    assert_eq!(bench.property(10, 52)?, Some(vec![5, 9]), "{restored}");
    assert_eq!(bench.property(9, 208)?, Some(vec![7, 7]));
    Ok(())
}

#[test]
fn test_restore_fails_when_a_property_write_is_dropped_after_the_reset() -> TestResult {
    // The restore runs the reset-first procedure; the device acknowledges the
    // write of object 9 and does not take it. The read-back of every
    // property finds it: the restore fails and says so.
    let bench = Bench::start("par-restore-drop")?;
    let product = bench.product.to_str().ok_or("path")?.to_string();
    bench.ok(&["flash", "1.1.4", "--product", &product, "--yes"])?;
    bench.set_property(9, 208, &[7, 7])?;
    bench.write_model("\"lvl@P-1_R-2\" = \"20\"\n")?;
    bench.ok(&["apply", "1.1.4", "--yes"])?;
    let first = bench.tmp.join("first-backup.json");
    std::fs::copy(bench.backups()?.first().ok_or("no backup")?, &first)?;
    bench.take_resets()?;
    bench.drop_object_9.store(true, Ordering::SeqCst);
    let out = bench.bussard(&[
        "restore",
        "--parameters",
        first.to_str().ok_or("path")?,
        "1.1.4",
        "--yes",
    ])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("PID 208"), "stderr:\n{stderr}");
    assert!(!stdout.contains("restored and verified"), "{stdout}");
    assert_eq!(bench.take_resets()?, [5]);
    Ok(())
}
