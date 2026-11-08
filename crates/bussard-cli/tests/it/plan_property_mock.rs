//! `bussard plan` on a device whose application has no group objects and a
//! property-only load procedure (issue #390, the Jung IPS 300 SREG): no links
//! is its correct state, so the empty-table guard does not fire, and the plan
//! reads the properties the procedure writes. An application with group
//! objects keeps the guard.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-0004_A-0016-10-TEST";

fn device_ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.200".parse()?)
}

/// The IPS 300 SREG's shape: two property-located parameters, a procedure of
/// compares and writes. `com_object` adds a group object to the program.
fn app_xml(com_object: bool) -> String {
    let objects = if com_object {
        r#"<ComObjectTable><ComObject Id="M-0004_A-0016-10-TEST_O-0" Number="0" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" /></ComObjectTable>"#
    } else {
        ""
    };
    format!(
        r#"<KNX xmlns="http://knx.org/xml/project/20"><ManufacturerData><Manufacturer RefId="M-0004"><ApplicationPrograms>
     <ApplicationProgram Id="{APP_ID}" ApplicationNumber="22" ApplicationVersion="16" MaskVersion="MV-0021" Name="IP" ProgramType="ApplicationProgram" LoadProcedureStyle="ProductProcedure">
      <Static>
       <ParameterTypes>
        <ParameterType Id="{APP_ID}_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
       </ParameterTypes>
       <Parameters>
        <Parameter Id="{APP_ID}_P-10" Name="timeout" ParameterType="{APP_ID}_PT-u8" Value="10">
         <Property ObjectType="11" PropertyId="204" Offset="0" BitOffset="0" />
        </Parameter>
        <Parameter Id="{APP_ID}_P-1" Name="rate" ParameterType="{APP_ID}_PT-u8" Value="50">
         <Property ObjectType="50001" PropertyId="211" Offset="0" BitOffset="0" />
        </Parameter>
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="{APP_ID}_P-10_R-10" RefId="{APP_ID}_P-10" />
        <ParameterRef Id="{APP_ID}_P-1_R-1" RefId="{APP_ID}_P-1" />
       </ParameterRefs>
       {objects}
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlCompareProp InlineData="0004" ObjType="0" PropId="12" />
         <LdCtrlWriteProp ObjType="11" PropId="204" Verify="true" />
         <LdCtrlWriteProp ObjType="50001" PropId="211" Verify="false" />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram>
    </ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
    )
}

struct Bench {
    gateway: MockGateway,
    dir: PathBuf,
    product: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    fn start(com_object: bool) -> Result<Bench, Box<dyn std::error::Error>> {
        Bench::start_with(com_object, false)
    }

    /// With `knxnet`, the device is also a KNX IP interface (a KNXnet/IP
    /// parameter object reached by type) and its file has a `[knxnet]` table
    /// (issue #391).
    fn start_with(com_object: bool, knxnet: bool) -> Result<Bench, Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        // The device holds the timeout your project asks for and another rate.
        let device = MockDevice::new(device_ia()?)
            .with_mask(0x0021)
            .with_manufacturer(0x0004)
            .with_property_ext(11, 204, 1, &[10])
            .with_property_ext(50001, 211, 1, &[5]);
        let device = if knxnet {
            let interface = MockKnxnet {
                tunnels: vec!["1.1.22".parse()?, "1.1.23".parse()?],
                friendly_name: "Bocklisch Alpha".to_string(),
                ..MockKnxnet::default()
            };
            device.with_knxnet_unlisted_writable(&interface, 8)
        } else {
            device
        };
        let gateway = rt.block_on(
            MockGateway::builder()
                .keep_serving()
                .idle_timeout(Duration::from_secs(60))
                .device(device)
                .start(),
        )?;
        let dir = std::env::temp_dir().join(format!(
            "bussard-plan-props-{}-{}",
            std::process::id(),
            gateway.port()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let product = dir.join("ips.knxprod");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&product)?);
        writer.start_file(
            format!("M-0004/{APP_ID}.xml"),
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.write_all(app_xml(com_object).as_bytes())?;
        writer.finish()?;
        write_model(&dir.join("knx"), knxnet)?;
        Ok(Bench {
            gateway,
            dir,
            product,
            _rt: rt,
        })
    }

    fn plan(&self, json: bool) -> Result<Output, Box<dyn std::error::Error>> {
        let model = self.dir.join("knx");
        let gateway = format!("127.0.0.1:{}", self.gateway.port());
        let product = self.product.to_str().ok_or("non-UTF-8 temp path")?;
        let mut args = vec!["plan", "1.1.200", "--product", product];
        if json {
            args.push("--json");
        }
        args.extend_from_slice(&[
            "--dir",
            model.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .env("BUSSARD_NO_DOTENV", "1")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A model whose device file has no links (and with `knxnet`, a `[knxnet]`
/// table whose friendly name differs from the device's).
fn write_model(dir: &Path, knxnet: bool) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[device]]\naddress = \"1.1.200\"\napplication = \"{APP_ID}\"\n\
             mask = \"0021\"\n"
        ),
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.200.toml"),
        if knxnet {
            "address = \"1.1.200\"\nname = \"KNX IP Interface\"\n\n[knxnet]\n\
             assignment = \"dhcp\"\nfriendly_name = \"Bocklisch Beta\"\n\
             tunnels = [\"1.1.22\", \"1.1.23\"]\n"
        } else {
            "address = \"1.1.200\"\nname = \"KNX IP Interface\"\n"
        },
    )?;
    Ok(())
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn test_plan_property_only_device_without_links_reads_its_properties() -> TestResult {
    let bench = Bench::start(false)?;
    let out = bench.plan(false)?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stderr.contains("empty table set"), "{stderr}");
    assert!(stdout.contains("property-only load procedure"), "{stdout}");
    assert!(
        stdout.contains("object type 11 PID 204: holds 0A, as your project asks"),
        "{stdout}"
    );
    assert!(
        stdout.contains("object type 50001 PID 211: holds 05, your project asks for 32"),
        "{stdout}"
    );
    assert!(stdout.contains("bussard flash 1.1.200"), "{stdout}");

    let out = bench.plan(true)?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let plan: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(plan["noop"], false);
    assert_eq!(plan["method"], "flash");
    assert_eq!(plan["property_procedure"].as_array().map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn test_plan_keeps_the_empty_table_guard_for_a_program_with_group_objects() -> TestResult {
    let bench = Bench::start(true)?;
    let out = bench.plan(false)?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refusing to plan an empty table set"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn test_plan_interface_with_a_property_procedure_shows_both() -> TestResult {
    // The real 1.1.200 (issue #391): a `[knxnet]` table and a property-only
    // load procedure, planned in one output.
    let bench = Bench::start_with(false, true)?;
    let out = bench.plan(false)?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("~ friendly name = \"Bocklisch Beta\", was \"Bocklisch Alpha\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("writes: KNXnet/IP parameter object (PID 76)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("object type 50001 PID 211: holds 05, your project asks for 32"),
        "{stdout}"
    );
    assert!(stdout.contains("bussard flash 1.1.200"), "{stdout}");
    assert!(stdout.contains("> bussard apply 1.1.200"), "{stdout}");

    let out = bench.plan(true)?;
    let (stdout, _) = text(&out);
    let plan: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(plan["noop"], false);
    assert_eq!(plan["changes"].as_array().map(Vec::len), Some(1));
    assert_eq!(plan["property_procedure"].as_array().map(Vec::len), Some(2));
    Ok(())
}
