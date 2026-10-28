//! `bussard apply --line` on a System 7 device (review of #433): the line walk
//! reads the device with its pinned product data, so a first link on an object
//! switches that object's communication flag on in the group-object table the
//! product declares, the write ends with the basic restart ETS sends, and the
//! walk reads the tables and flags back after it. Without product data the
//! newly linked object is named as unchecked instead of passing silently.
//! Against an in-process mock KNXnet/IP gateway on loopback.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::sys7::{
    SYS7_APP_ID, SYS7_APP_XML, SYS7_CODE, SYS7_PARAM_BASE, system7_device,
};
use bussard_testkit::{MockDevice, MockGateway};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x59;

/// Where the fixture product declares its group-object table: a segment of
/// its own, as the Ekinex EK-E72 does at `0x41D8`.
const OBJECT_TABLE: u32 = 0x4800;

/// The CONFIG octet of object 2's descriptor: `[CNT][RAM ptr:2]`, then
/// four-octet descriptors with CONFIG third.
const OBJECT_2_CONFIG: u32 = OBJECT_TABLE + 3 + 4 * 2 + 2;

/// The fixture application with its group-object table declared in segment
/// `AS-5` at [`OBJECT_TABLE`].
fn app_xml() -> String {
    SYS7_APP_XML
        .replace(
            "</Code>",
            "  <AbsoluteSegment Id=\"M-00FA_A-0007_AS-5\" Size=\"15\" Address=\"18432\" />\n            </Code>\n            <ComObjectTable CodeSegment=\"M-00FA_A-0007_AS-5\" Offset=\"0\" />",
        )
}

/// The fixture device with its group-object table at [`OBJECT_TABLE`]:
/// objects 0..=2, the communication flag on for the linked object 1 (DF) and
/// off for object 2 (DB).
fn device(address: IndividualAddress) -> MockDevice {
    system7_device(address, &SYS7_CODE)
        // Threshold 9 and object 2 shown, as the model has them: no
        // parameter write, so the restart counted is the table write's.
        .with_memory(SYS7_PARAM_BASE, &[9, 0x80])
        .with_memory(
            OBJECT_TABLE,
            &[
                0x03, 0x07, 0x00, // CNT + RAM-flags ptr
                0x07, 0x00, 0x13, 0x00, // object 0
                0x07, 0x01, 0xDF, 0x00, // object 1
                0x07, 0x02, 0xDB, 0x00, // object 2
            ],
        )
}

/// The lowercase hex SHA-256 of a file.
fn sha256_hex(path: &Path) -> TestResult<String> {
    use sha2::Digest as _;
    Ok(sha2::Sha256::digest(std::fs::read(path)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The model: 1.1.7 keeps object 1 on 1/2/0 and gives object 2 its first
/// link, 1/2/1. With `pin`, the fixture product is stored and pinned.
fn write_model(dir: &Path, pin: bool) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    let lock = if pin {
        let store = dir.join("products");
        std::fs::create_dir_all(&store)?;
        let file = store.join("sys7-test.knxprod");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&file)?);
        writer.start_file(
            format!("M-00FA/{SYS7_APP_ID}.xml"),
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.write_all(app_xml().as_bytes())?;
        writer.finish()?;
        let sha = sha256_hex(&file)?;
        format!(
            "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \
             \"products/sys7-test.knxprod\"\nfilename = \"sys7-test.knxprod\"\n\
             origin = {{ kind = \"file\", path = \"sys7-test.knxprod\" }}\n\
             applications = [\"{SYS7_APP_ID}\"]\n\n[[device]]\naddress = \"1.1.7\"\n\
             application = \"{SYS7_APP_ID}\"\nproduct_sha256 = \"{sha}\"\nmask = \"0705\"\n"
        )
    } else {
        "version = 3\n".to_string()
    };
    std::fs::write(dir.join("bussard.lock"), lock)?;
    std::fs::write(
        dir.join("devices").join("1.1.7.toml"),
        "address = \"1.1.7\"\nname = \"Weather station\"\n\n[parameters]\n\
         \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"1\"\n\n[links]\n\
         1.listen = [\"1/2/0\"]\n2.send = \"1/2/1\"\n",
    )?;
    Ok(())
}

/// A mock gateway with the fixture device and a fresh model directory.
struct Bench {
    gateway: MockGateway,
    dir: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    fn start(tag: &str, pin: bool) -> TestResult<Bench> {
        let rt = tokio::runtime::Runtime::new()?;
        let gateway = rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .keep_serving()
                .idle_timeout(Duration::from_secs(120))
                .device(device("1.1.7".parse()?))
                .start(),
        )?;
        let dir = std::env::temp_dir().join(format!(
            "bussard-line-sys7-{tag}-{}-{}",
            std::process::id(),
            gateway.port()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_model(&dir, pin)?;
        Ok(Bench {
            gateway,
            dir,
            _rt: rt,
        })
    }

    /// Runs `bussard <verb> --line 1.1 --yes --json --dir <model> --gateway …`.
    fn run(&self, verb: &str) -> TestResult<Output> {
        let gateway = format!("127.0.0.1:{}", self.gateway.port());
        let dir = self.dir.to_str().ok_or("non-UTF-8 temp path")?;
        let mut args = vec![verb, "--line", "1.1", "--json", "--dir", dir];
        if verb == "apply" {
            args.push("--yes");
        }
        args.extend(["--gateway", gateway.as_str()]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    /// Object 2's CONFIG octet and the restart count on the mock device.
    fn device_state(&self) -> TestResult<(Option<u8>, usize)> {
        let address: IndividualAddress = "1.1.7".parse()?;
        Ok(self.gateway.with_device(address, |dev| {
            (dev.memory.get(&OBJECT_2_CONFIG).copied(), dev.restarts)
        })?)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The JSON row of 1.1.7.
fn row(out: &Output) -> TestResult<serde_json::Value> {
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    json["devices"]
        .as_array()
        .and_then(|rows| rows.iter().find(|d| d["address"] == "1.1.7"))
        .cloned()
        .ok_or_else(|| format!("no row for 1.1.7 in {json}").into())
}

#[test]
fn test_apply_line_switches_the_communication_flag_on_a_first_link() -> TestResult {
    let bench = Bench::start("pinned", true)?;
    assert_eq!(bench.device_state()?, (Some(0xDB), 0));

    let out = bench.run("apply")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let applied = row(&out)?;
    assert_eq!(applied["status"], "applied", "{applied}\n{stderr}");
    // One new link and object 2's flag.
    assert_eq!(applied["changes"], 2, "{applied}");
    assert_eq!(
        bench.device_state()?,
        (Some(0xDF), 1),
        "object 2's C flag on, and one closing restart"
    );

    // The line is now in step, flags included.
    let again = bench.run("plan")?;
    assert_eq!(row(&again)?["status"], "unchanged", "{}", row(&again)?);
    Ok(())
}

#[test]
fn test_plan_line_names_an_unchecked_flag_without_product_data() -> TestResult {
    let bench = Bench::start("unpinned", false)?;
    let out = bench.run("plan")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(row(&out)?["status"], "changes", "{stderr}");
    assert!(
        stderr.contains("object(s) 2: newly linked, but the communication flag was not checked"),
        "{stderr}"
    );
    assert_eq!(
        bench.device_state()?,
        (Some(0xDB), 0),
        "a plan writes nothing"
    );
    Ok(())
}

#[test]
fn test_apply_restarts_a_system_7_device_and_reads_back_after_it() -> TestResult {
    let bench = Bench::start("single", true)?;
    let gateway = format!("127.0.0.1:{}", bench.gateway.port());
    let dir = bench.dir.to_str().ok_or("non-UTF-8 temp path")?;
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .args([
            "apply",
            "1.1.7",
            "--yes",
            "--dir",
            dir,
            "--gateway",
            &gateway,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("then a restart"),
        "the plan says so: {stdout}"
    );
    assert!(
        stdout.contains("restarted 1.1.7: it answered again after"),
        "{stdout}"
    );
    assert!(stdout.contains("read back from 1.1.7"), "{stdout}");
    assert_eq!(bench.device_state()?, (Some(0xDF), 1));
    Ok(())
}
