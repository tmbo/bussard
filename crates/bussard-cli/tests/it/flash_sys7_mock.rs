//! Issue #314: `bussard flash` on a healthy System 7 device needs no
//! `--force`. System 7 has no readable application id, so the pre-flight
//! judges the device by its load-state machines and a sample of its code
//! (the verdict `knx_plan_device` decides on too): the product's code
//! proceeds, code that differs by one octet is refused with the segment
//! named. Issue #355: the sample covers the code alone, so a configuration
//! flashed over another one (the group-object descriptor table follows the
//! links) is the same application. Against an in-process mock KNXnet/IP
//! gateway on loopback; the `bussard` binary always runs with an explicit
//! loopback `--gateway`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::sys7::{
    SYS7_APP_ID, SYS7_APP_XML, SYS7_CODE, SYS7_CODE_BASE, SYS7_PARAM_BASE, system7_device,
};
use bussard_testkit::{MockDevice, MockGateway};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x58;

fn device_ia() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    Ok("1.1.7".parse()?)
}

/// A gateway serving the fixture device with `code`, a model and the
/// product archive in a fresh temporary directory. The runtime is returned
/// so it outlives the gateway.
struct Bench {
    gateway: MockGateway,
    dir: PathBuf,
    product: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    fn start(code: &[u8]) -> Result<Bench, Box<dyn std::error::Error>> {
        Bench::start_with(system7_device(device_ia()?, code), SYS7_APP_XML)
    }

    /// [`Bench::start`] with `device` on the bus and the application `xml`
    /// in the archive.
    fn start_with(device: MockDevice, xml: &str) -> Result<Bench, Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        let gateway = rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .keep_serving()
                .idle_timeout(Duration::from_secs(120))
                .device(device)
                .start(),
        )?;
        let dir = std::env::temp_dir().join(format!(
            "bussard-sys7-flash-{}-{}",
            std::process::id(),
            gateway.port()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let product = dir.join("sys7-test.knxprod");
        knxprod(&product, xml)?;
        write_model(&dir.join("knx"))?;
        Ok(Bench {
            gateway,
            dir,
            product,
            _rt: rt,
        })
    }

    /// Runs `bussard flash 1.1.7 --product <archive> --yes <extra> --dir
    /// <model> --gateway 127.0.0.1:<port>`.
    fn flash(&self, extra: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
        let model = self.dir.join("knx");
        let gateway = format!("127.0.0.1:{}", self.gateway.port());
        let product = self.product.to_str().ok_or("non-UTF-8 temp path")?;
        let mut args = vec!["flash", "1.1.7", "--product", product, "--yes"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&[
            "--dir",
            model.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .args(&args)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_FLASH_SYS7_LSM")
            .env("BUSSARD_FLASH_L4_TIMEOUT_MS", "300")
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

/// Packs the application `xml` into a `.knxprod`.
fn knxprod(path: &Path, xml: &str) -> TestResult {
    let mut writer = zip::ZipWriter::new(std::fs::File::create(path)?);
    writer.start_file(
        format!("M-00FA/{SYS7_APP_ID}.xml"),
        zip::write::SimpleFileOptions::default(),
    )?;
    writer.write_all(xml.as_bytes())?;
    writer.finish()?;
    Ok(())
}

/// The model: 1.1.7 runs the fixture application with object 2 on and one
/// link.
fn write_model(dir: &Path) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[device]]\naddress = \"1.1.7\"\napplication = \"{SYS7_APP_ID}\"\n\
             mask = \"0705\"\n"
        ),
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.7.toml"),
        "address = \"1.1.7\"\nname = \"Weather station\"\n\n[parameters]\n\
         \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"1\"\n\n[links]\n1.listen = [\"1/2/0\"]\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Switch\" },\n]\n",
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
fn test_flash_system7_same_application_proceeds_without_force() -> TestResult {
    let bench = Bench::start(&SYS7_CODE)?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("parameters match your project"), "{stdout}");
    // Issue #349: the read-back compared the links and the parameters.
    assert!(
        stdout.contains(
            "read back from 1.1.7 and compared with your project: 1 group address, 1 \
             association, 2 parameters"
        ),
        "{stdout}"
    );
    assert!(stderr.contains("already runs this application"), "{stderr}");
    assert!(stderr.contains("the code matches"), "{stderr}");
    assert!(!stderr.contains("could not identify"), "{stderr}");
    let (code, params) = bench.gateway.with_device(device_ia()?, |dev| {
        (
            dev.read_mem(SYS7_CODE_BASE, 4),
            dev.read_mem(SYS7_PARAM_BASE, 2),
        )
    })?;
    assert_eq!(code, SYS7_CODE);
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");
    Ok(())
}

#[test]
fn test_flash_system7_differing_code_is_refused_with_the_segment() -> TestResult {
    let mut code = SYS7_CODE;
    code[2] = 0xEE;
    let bench = Bench::start(&code)?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("REFUSING to flash 1.1.7"), "{stderr}");
    assert!(
        stderr.contains("M-00FA_A-0007_AS-4") && stderr.contains("offset 2"),
        "{stderr}"
    );
    assert!(stderr.contains("--force"), "{stderr}");
    assert!(!stderr.contains("could not identify"), "{stderr}");
    let writes = bench.gateway.with_device(device_ia()?, |dev| dev.writes)?;
    assert_eq!(writes, 0, "a refused flash writes nothing");

    // `--force` keeps its meaning: it replaces the other application.
    let out = bench.flash(&["--force"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let written = bench
        .gateway
        .with_device(device_ia()?, |dev| dev.read_mem(SYS7_CODE_BASE, 4))?;
    assert_eq!(written, SYS7_CODE);
    Ok(())
}

/// Issue #319: a device that reports every LSM Loaded but lost a parameter
/// octet (it reverts object 2's switch at the restart) fails the flash: the
/// read-back against the model names the parameter and the exit is non-zero.
/// The parameter segment carries a `<Mask>`, as the Meteodata's do, so no
/// spot check samples it.
#[test]
fn test_flash_system7_parameter_lost_on_the_device_fails_with_the_parameter() -> TestResult {
    let device = system7_device(device_ia()?, &SYS7_CODE).with_hook(|dev, apci, _| {
        if apci == bussard_testkit::consts::A_RESTART {
            dev.memory.insert(SYS7_PARAM_BASE + 1, 0x00);
        }
        None
    });
    let masked = SYS7_APP_XML.replace(
        r#"Address="17408"><Data>AAA=</Data>"#,
        r#"Address="17408"><Data>AAA=</Data><Mask>//8=</Mask>"#,
    );
    if masked == SYS7_APP_XML {
        return Err("the fixture's parameter segment moved".into());
    }
    let bench = Bench::start_with(device, &masked)?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("from your project after the write") && stderr.contains("obj2"),
        "the error names the parameter: {stderr}"
    );
    assert!(!stdout.contains("flash verified"), "{stdout}");
    Ok(())
}

/// Issue #349: a device that reports every LSM Loaded but lost its
/// association table at the restart fails the flash: the read-back names the
/// link and the table size, and the exit is non-zero.
#[test]
fn test_flash_system7_links_lost_on_the_device_fail_with_the_link() -> TestResult {
    let device = system7_device(device_ia()?, &SYS7_CODE).with_hook(|dev, apci, _| {
        if apci == bussard_testkit::consts::A_RESTART {
            dev.memory.insert(
                u32::from(bussard_download::SYS7_ASSOCIATION_TABLE_ADDR),
                0x00,
            );
        }
        None
    });
    let bench = Bench::start_with(device, SYS7_APP_XML)?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("object 1 -> 1/2/0") && stderr.contains("association table"),
        "the error names the link: {stderr}"
    );
    assert!(!stdout.contains("flash verified"), "{stdout}");
    Ok(())
}

/// Where the #355 fixture's group-object descriptor table (`AS-6`) sits.
const OBJECT_TABLE_BASE: u32 = 0x4700;

/// The fixture application with the group-object descriptor table in an
/// LSM 3 EEPROM segment and the RAM its pointers address, as the Theben
/// Meteodata 140 S and the MDT 0705 programs lay it out (issue #355): `[CNT=3]
/// [RAM flags 0x0700]` and three descriptors `[ptr][CONFIG 0xDF][TYPE 0]`.
/// The planner rewrites the CONFIG octets from the links, so they differ
/// between two configurations of the same application. `with_code` keeps the
/// code segment `AS-4`; without it the product has no code to sample.
fn object_table_app(with_code: bool) -> Result<String, Box<dyn std::error::Error>> {
    let segments = r#"<AbsoluteSegment Id="M-00FA_A-0007_AS-4" Size="4" Address="17920"><Data>CgsMDQ==</Data></AbsoluteSegment>"#;
    let ops = r#"<LdCtrlAbsSegment LsmIdx="3" Address="17920" Size="4" />"#;
    let table = "AwcABwHfAAcC3wAHA98A"; // 03 0700 0701DF00 0702DF00 0703DF00
    let code = if with_code {
        r#"<Data>CgsMDQ==</Data>"#
    } else {
        ""
    };
    let xml = SYS7_APP_XML
        .replace(
            segments,
            &format!(
                r#"<AbsoluteSegment Id="M-00FA_A-0007_AS-4" Size="4" Address="17920">{code}</AbsoluteSegment>
              <AbsoluteSegment Id="M-00FA_A-0007_AS-5" Size="64" Address="1792" />
              <AbsoluteSegment Id="M-00FA_A-0007_AS-6" Size="15" Address="18176"><Data>{table}</Data></AbsoluteSegment>"#
            ),
        )
        .replace(
            ops,
            r#"<LdCtrlAbsSegment LsmIdx="3" Address="1792" Size="64" MemType="2" />
                <LdCtrlAbsSegment LsmIdx="3" Address="17920" Size="4" />
                <LdCtrlAbsSegment LsmIdx="3" Address="18176" Size="15" />"#,
        );
    if !xml.contains("AS-6") || !xml.contains(r#"Address="18176" Size="15""#) {
        return Err("the fixture's code segment moved".into());
    }
    Ok(xml)
}

/// Rewrites the model's device file with `links` as its `[links]` body.
fn set_links(bench: &Bench, links: &str) -> TestResult {
    std::fs::write(
        bench.dir.join("knx").join("devices").join("1.1.7.toml"),
        format!(
            "address = \"1.1.7\"\nname = \"Weather station\"\n\n[parameters]\n\
             \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"1\"\n\n[links]\n{links}"
        ),
    )?;
    Ok(())
}

/// The CONFIG octet of descriptor `asap` in the device's object table.
fn object_config(bench: &Bench, asap: u32) -> Result<u8, Box<dyn std::error::Error>> {
    let config = bench.gateway.with_device(device_ia()?, |dev| {
        dev.read_mem(OBJECT_TABLE_BASE + 3 + 4 * asap + 2, 1)
    })?;
    config
        .first()
        .copied()
        .ok_or_else(|| "no CONFIG octet".into())
}

/// Issue #355: configuration A (object 1 linked), then configuration B (no
/// link) over it, without `--force`. The descriptor table's CONFIG octets
/// differ between the two, and the identity sample compares the code segment
/// alone, so B is accepted as the same application.
#[test]
fn test_flash_system7_configuration_over_another_proceeds_without_force() -> TestResult {
    let bench = Bench::start_with(
        system7_device(device_ia()?, &SYS7_CODE),
        &object_table_app(true)?,
    )?;
    // Configuration A goes on as the sim loop's first flash does.
    let out = bench.flash(&["--force"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let linked = object_config(&bench, 1)?;
    assert_eq!(
        linked & 0x04,
        0x04,
        "object 1 linked: C set ({linked:#04X})"
    );

    set_links(&bench, "")?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("already runs this application"), "{stderr}");
    assert!(
        stderr.contains("the code matches") && stderr.contains("1 segment(s) compared"),
        "only the code segment is sampled: {stderr}"
    );
    assert!(!stderr.contains("AS-6"), "{stderr}");
    let unlinked = object_config(&bench, 1)?;
    assert_eq!(
        unlinked & 0x04,
        0,
        "object 1 unlinked: C clear ({unlinked:#04X})"
    );
    Ok(())
}

/// Issue #355: a product whose segments hold tables and parameters only (the
/// Meteodata 140 S) has no code to sample; the gate judges it by its
/// load-state machines and says so.
#[test]
fn test_flash_system7_without_code_segment_falls_back_to_the_load_state() -> TestResult {
    let bench = Bench::start_with(
        system7_device(device_ia()?, &SYS7_CODE),
        &object_table_app(false)?,
    )?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    set_links(&bench, "")?;
    let out = bench.flash(&[])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("no code segment to sample")
            && stderr.contains("the load state alone identifies the application"),
        "{stderr}"
    );
    Ok(())
}
