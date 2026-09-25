//! Device facts end to end (issue #209): `describe`, `reconstruct` and the
//! flash pre-flight against a 1.1.12-like mock device (System B, 11 interface
//! objects, about 90 property descriptions), in the clear and over KNX Data
//! Secure.
//!
//! The headline properties:
//!
//! - the first run stores the facts, a later run reuses them and prints the
//!   same report while sending a fraction of the requests;
//! - `--full`, `--refresh-facts`, a changed application id and a changed mask
//!   each read the device again;
//! - a device that refuses `PID_IO_LIST` or multi-element reads yields the
//!   same facts through the walk.
//!
//! `test_measure_*` (ignored) prints request counts and wall-clock with a
//! 200 ms answer delay per request; set `BUSSARD_BIN` to time another build.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_model::IndividualAddress;
use bussard_model::facts::{DeviceFactsRecord, ObjectTableSource, facts_path, load_facts};
use bussard_testkit::{MockDevice, MockGateway, MockPropertyDescription, TestResult};

const CHANNEL: u8 = 0x6C;

/// The synthetic tool key of the activated mock (no real key material).
const TOOL_KEY: [u8; 16] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
];

/// The 11 interface objects of a 1.1.12-like push-button module.
const TYPES: [u16; 11] = [
    OT_DEVICE,
    OT_ADDRESS_TABLE,
    OT_ASSOCIATION_TABLE,
    OT_APPLICATION_PROGRAM,
    4,
    6,
    OT_GROUP_OBJECT_TABLE,
    17,
    OT_APPLICATION_PROGRAM,
    8,
    19,
];

/// The application id on object 3 (M-00FA, application 2, version 1: the
/// synthetic app of the flash pre-flight measurement).
const APP_ID: [u8; 5] = [0x00, 0xFA, 0x00, 0x02, 0x01];

const PID_PROGRAM_VERSION: u8 = 13;
const PID_MAX_APDU_LENGTH: u8 = 56;
const A_PROPERTY_DESCRIPTION_READ: u16 = 0x3D8;
const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
const PID_OBJECT_TYPE: u8 = 1;

fn target() -> Result<IndividualAddress, Box<dyn std::error::Error + Send + Sync>> {
    Ok("1.1.12".parse()?)
}

/// Eight property descriptions per object (device object: its own set).
fn descriptions(object_index: u8) -> Vec<MockPropertyDescription> {
    let pids: &[u8] = if object_index == 0 {
        &[1, 11, 12, 13, 15, 54, 56, 71, 78]
    } else {
        &[1, 5, 7, 13, 23, 27, 51, 52]
    };
    pids.iter()
        .map(|&pid| MockPropertyDescription {
            pid,
            pdt: 0x04,
            writable: pid == 5 || pid == 54,
            max_elements: 1,
            read_level: 3,
            write_level: 1,
        })
        .collect()
}

/// The 1.1.12-like device: 11 objects, a small address and association
/// table, the application id, a max APDU of 233 and the descriptions.
fn device() -> Result<MockDevice, Box<dyn std::error::Error + Send + Sync>> {
    let mut dev = MockDevice::new(target()?)
        .with_object_types(&TYPES)
        .with_memory_write_policy(bussard_testkit::MemoryWritePolicy::WithinSegments)
        .with_table(1, &[0x00, 0x02, 0x0A, 0x00, 0x0A, 0x01])
        .with_table(
            2,
            &[0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02],
        )
        .with_go_count(2)
        .with_property(3, PID_PROGRAM_VERSION, 5, &APP_ID)
        .with_property(0, PID_MAX_APDU_LENGTH, 2, &233u16.to_be_bytes());
    for index in 0..TYPES.len() as u8 {
        dev = dev.with_property_descriptions(index, &descriptions(index));
    }
    // The synthetic app's parameter segment (flash pre-flight read-back).
    dev.segments.insert(3, (0x4006, 2));
    dev.load_states.extend([(1, 1), (2, 1), (3, 1)]);
    Ok(dev.with_memory(0x4000, &[0, 1, 2, 3, 4, 5, 7, 0]))
}

/// A mock line with one device and a scratch model directory.
struct Bench {
    gw: MockGateway,
    tmp: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    fn start(tag: &str, device: MockDevice) -> TestResult<Bench> {
        let rt = tokio::runtime::Runtime::new()?;
        let gw = rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .keep_serving()
                .idle_timeout(Duration::from_secs(300))
                .device(device)
                .start(),
        )?;
        let tmp = std::env::temp_dir().join(format!(
            "bussard-facts-{tag}-{}-{}",
            std::process::id(),
            gw.port()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let dir = tmp.join("knx");
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(
            dir.join("bussard.toml"),
            "[connection]\ntransport = \"tunnel\"\n",
        )?;
        std::fs::write(
            dir.join("bussard.lock"),
            "version = 2\n\n[[device]]\naddress = \"1.1.12\"\napplication = \"M-00FA_A-0002\"\nmask = \"07B0\"\n",
        )?;
        std::fs::write(
            dir.join("devices").join("1.1.12.toml"),
            "address = \"1.1.12\"\nname = \"Button\"\n\n[links]\n1.listen = [\"5/0/0\"]\n",
        )?;
        Ok(Bench { gw, tmp, _rt: rt })
    }

    fn dir(&self) -> PathBuf {
        self.tmp.join("knx")
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>` with the
    /// binary under test (or `$BUSSARD_BIN`).
    fn run(&self, args: &[&str]) -> TestResult<Output> {
        let dir = self.dir();
        let gateway = format!("127.0.0.1:{}", self.gw.port());
        let mut full: Vec<&str> = args.to_vec();
        full.extend_from_slice(&[
            "--dir",
            dir.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ]);
        let bin = std::env::var("BUSSARD_BIN")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_bussard").to_string());
        Ok(Command::new(bin)
            .args(&full)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    /// The device's request log so far, then cleared.
    fn take_requests(&self) -> TestResult<Vec<(u16, Vec<u8>)>> {
        Ok(self
            .gw
            .with_device(target()?, |d| std::mem::take(&mut d.requests))?)
    }

    fn facts(&self) -> TestResult<DeviceFactsRecord> {
        Ok(load_facts(&self.dir(), target()?)?.ok_or("no facts file written")?)
    }

    fn set_app_id(&self, app_id: &[u8; 5]) -> TestResult {
        self.gw.with_device(target()?, |d| {
            let changed = d.clone().with_property(3, PID_PROGRAM_VERSION, 5, app_id);
            *d = changed;
        })?;
        Ok(())
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn ok_stdout(out: &Output) -> TestResult<String> {
    let stdout = String::from_utf8(out.stdout.clone())?;
    if !out.status.success() {
        return Err(format!(
            "exit {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(stdout)
}

fn count(requests: &[(u16, Vec<u8>)], apci: u16) -> usize {
    requests.iter().filter(|(a, _)| *a == apci).count()
}

/// Plain `PID_OBJECT_TYPE` reads in a request log.
fn object_type_reads(requests: &[(u16, Vec<u8>)]) -> usize {
    requests
        .iter()
        .filter(|(a, d)| *a == A_PROPERTY_VALUE_READ && d.get(1) == Some(&PID_OBJECT_TYPE))
        .count()
}

/// The facts without the fields that legitimately differ between two reads.
fn comparable(mut record: DeviceFactsRecord) -> DeviceFactsRecord {
    record.read_at = String::new();
    record.object_table_source = ObjectTableSource::Walk;
    record
}

#[test]
fn test_describe_reuses_facts_with_identical_output() -> TestResult {
    let bench = Bench::start("describe", device()?)?;
    let cold = ok_stdout(&bench.run(&["describe", "1.1.12", "--json"])?)?;
    let cold_requests = bench.take_requests()?;
    let facts = bench.facts()?;
    assert_eq!(facts.object_table_source, ObjectTableSource::IoList);
    assert_eq!(facts.application_id.as_deref(), Some("00FA000201"));
    assert_eq!(facts.application_object, Some(3));
    assert_eq!(facts.max_apdu, Some(233));
    assert!(facts.has_properties());
    assert!(facts_path(&bench.dir(), target()?).is_file());

    let warm = ok_stdout(&bench.run(&["describe", "1.1.12", "--json"])?)?;
    let warm_requests = bench.take_requests()?;
    assert_eq!(
        warm, cold,
        "the report must not change when it comes from the facts"
    );
    assert_eq!(count(&warm_requests, A_PROPERTY_DESCRIPTION_READ), 0);
    assert_eq!(object_type_reads(&warm_requests), 0);
    // Descriptor, authorize and the application-id check only.
    assert!(
        warm_requests.len() <= 3,
        "warm describe sent {} requests: {warm_requests:?}",
        warm_requests.len()
    );
    assert!(count(&cold_requests, A_PROPERTY_DESCRIPTION_READ) >= 90);

    // The text report is the same too.
    let text_cold = ok_stdout(&bench.run(&["describe", "1.1.12", "--full"])?)?;
    let text_warm = ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    assert_eq!(text_warm, text_cold);
    Ok(())
}

#[test]
fn test_describe_full_walks_the_descriptions_again() -> TestResult {
    let bench = Bench::start("describe-full", device()?)?;
    let cold = ok_stdout(&bench.run(&["describe", "1.1.12", "--json"])?)?;
    bench.take_requests()?;
    let full = ok_stdout(&bench.run(&["describe", "1.1.12", "--json", "--full"])?)?;
    let requests = bench.take_requests()?;
    assert_eq!(full, cold);
    assert!(count(&requests, A_PROPERTY_DESCRIPTION_READ) >= 90);
    // The object table still comes from the facts.
    assert_eq!(object_type_reads(&requests), 0);
    Ok(())
}

#[test]
fn test_describe_refresh_facts_reads_everything_again() -> TestResult {
    let bench = Bench::start("describe-refresh", device()?)?;
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    bench.take_requests()?;
    ok_stdout(&bench.run(&["describe", "1.1.12", "--refresh-facts"])?)?;
    let requests = bench.take_requests()?;
    assert!(count(&requests, A_PROPERTY_DESCRIPTION_READ) >= 90);
    assert!(
        requests
            .iter()
            .any(|(a, d)| *a == A_PROPERTY_VALUE_READ && d.get(1) == Some(&71))
    );
    Ok(())
}

#[test]
fn test_describe_application_change_invalidates_facts() -> TestResult {
    let bench = Bench::start("describe-app", device()?)?;
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    let before = bench.facts()?;
    bench.set_app_id(&[0x00, 0xFA, 0x00, 0x03, 0x02])?;
    bench.take_requests()?;
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    let requests = bench.take_requests()?;
    let after = bench.facts()?;
    assert_eq!(before.application_id.as_deref(), Some("00FA000201"));
    assert_eq!(after.application_id.as_deref(), Some("00FA000302"));
    assert!(
        count(&requests, A_PROPERTY_DESCRIPTION_READ) >= 90,
        "stale facts must be re-read"
    );
    Ok(())
}

#[test]
fn test_describe_mask_change_invalidates_facts() -> TestResult {
    let bench = Bench::start("describe-mask", device()?)?;
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    bench.gw.with_device(target()?, |d| d.mask = 0x57B0)?;
    bench.take_requests()?;
    let out = ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    assert!(out.contains("mask 57B0"), "{out}");
    assert_eq!(bench.facts()?.mask, "57B0");
    assert!(count(&bench.take_requests()?, A_PROPERTY_DESCRIPTION_READ) >= 90);
    Ok(())
}

#[test]
fn test_describe_fast_and_slow_object_tables_yield_identical_facts() -> TestResult {
    let fast = Bench::start("describe-fast", device()?)?;
    let fast_out = ok_stdout(&fast.run(&["describe", "1.1.12", "--json"])?)?;
    let fast_facts = fast.facts()?;
    assert_eq!(fast_facts.object_table_source, ObjectTableSource::IoList);
    for (tag, slow_device) in [
        ("describe-no-io-list", device()?.without_io_list()),
        ("describe-single", device()?.with_single_element_reads()),
    ] {
        let slow = Bench::start(tag, slow_device)?;
        let slow_out = ok_stdout(&slow.run(&["describe", "1.1.12", "--json"])?)?;
        let slow_facts = slow.facts()?;
        assert_eq!(
            slow_facts.object_table_source,
            ObjectTableSource::Walk,
            "{tag}"
        );
        assert_eq!(
            slow_out, fast_out,
            "{tag}: the report must not depend on the path"
        );
        assert_eq!(
            comparable(slow_facts),
            comparable(fast_facts.clone()),
            "{tag}: the facts must not depend on the path"
        );
    }
    Ok(())
}

#[test]
fn test_describe_without_model_writes_no_facts() -> TestResult {
    let bench = Bench::start("describe-nomodel", device()?)?;
    // A directory that does not exist: no model, so nothing is created.
    let empty = bench.tmp.join("absent");
    let gateway = format!("127.0.0.1:{}", bench.gw.port());
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "describe",
            "1.1.12",
            "--dir",
            empty.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ])
        .stdin(Stdio::null())
        .output()?;
    ok_stdout(&out)?;
    assert!(!empty.exists());
    Ok(())
}

#[test]
fn test_describe_secure_reuses_facts() -> TestResult {
    let bench = Bench::start("describe-secure", device()?.with_data_secure(TOOL_KEY))?;
    let key: String = TOOL_KEY.iter().map(|b| format!("{b:02x}")).collect();
    let args = ["describe", "1.1.12", "--json", "--tool-key", key.as_str()];
    let cold = ok_stdout(&bench.run(&args)?)?;
    let cold_requests = bench.take_requests()?.len();
    let warm = ok_stdout(&bench.run(&args)?)?;
    let warm_requests = bench.take_requests()?.len();
    assert_eq!(warm, cold);
    assert_eq!(
        bench.facts()?.mask,
        "07B0",
        "the secured descriptor reports the real mask"
    );
    assert!(
        warm_requests * 10 < cold_requests,
        "{warm_requests} vs {cold_requests}"
    );
    // A plain run of the activated device sees mask FFFF: the facts are stale,
    // the walk is refused, and nothing is overwritten.
    let plain = bench.run(&["describe", "1.1.12"])?;
    assert!(!plain.status.success());
    assert_eq!(bench.facts()?.mask, "07B0");
    Ok(())
}

#[test]
fn test_reconstruct_reuses_facts_with_identical_output() -> TestResult {
    let bench = Bench::start("reconstruct", device()?)?;
    let cold = ok_stdout(&bench.run(&["reconstruct", "1.1.12", "--json"])?)?;
    let cold_requests = bench.take_requests()?;
    assert!(
        bench
            .facts()?
            .objects
            .iter()
            .all(|o| o.properties.is_none())
    );
    let warm = ok_stdout(&bench.run(&["reconstruct", "1.1.12", "--json"])?)?;
    let warm_requests = bench.take_requests()?;
    assert_eq!(warm, cold);
    assert_eq!(object_type_reads(&warm_requests), 0);
    assert!(warm_requests.len() < cold_requests.len());
    // A later describe walks the descriptions once, then reuses them.
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    assert!(count(&bench.take_requests()?, A_PROPERTY_DESCRIPTION_READ) >= 90);
    ok_stdout(&bench.run(&["describe", "1.1.12"])?)?;
    assert_eq!(
        count(&bench.take_requests()?, A_PROPERTY_DESCRIPTION_READ),
        0
    );
    Ok(())
}

#[test]
fn test_plan_uses_facts_and_ignores_a_corrupt_file() -> TestResult {
    let bench = Bench::start("plan", device()?)?;
    let cold = ok_stdout(&bench.run(&["plan", "1.1.12", "--json"])?)?;
    std::fs::write(
        facts_path(&bench.dir(), target()?),
        "device_facts = [\"not\", \"a\", \"table\"]\n",
    )?;
    bench.take_requests()?;
    let again = ok_stdout(&bench.run(&["plan", "1.1.12", "--json"])?)?;
    assert_eq!(again, cold, "a corrupt facts file only costs the fast path");
    assert!(object_type_reads(&bench.take_requests()?) > 0);
    // ... and is replaced by a valid one.
    assert_eq!(bench.facts()?.objects.len(), TYPES.len());
    Ok(())
}

const A_AUTHORIZE_REQUEST: u16 = 0x3D1;

/// [`device`] that acknowledges `A_Authorize_Request` and never answers it,
/// as 1.1.30, 1.1.39, 1.1.45, 1.1.51 and 1.1.202 do (speed deep dive
/// 2026-09-24): every session that asks waits out the 3 s response timeout.
fn unanswered_authorize_device() -> Result<MockDevice, Box<dyn std::error::Error + Send + Sync>> {
    Ok(device()?.with_hook(|_, apci, _| {
        (apci == A_AUTHORIZE_REQUEST).then_some(bussard_testkit::Reaction::Ack)
    }))
}

/// Issue #215: `apply` skips the authorize a device's facts record as never
/// answered, in its read phase and in its write phase; the write happens and
/// verifies as before.
#[test]
fn test_apply_skips_the_authorize_the_facts_record_as_unanswered() -> TestResult {
    let bench = Bench::start("apply-authorize", unanswered_authorize_device()?)?;
    // The first run learns the verdict (and pays the timeout once).
    ok_stdout(&bench.run(&["plan", "1.1.12", "--json"])?)?;
    assert_eq!(count(&bench.take_requests()?, A_AUTHORIZE_REQUEST), 1);
    assert_eq!(
        bench.facts()?.authorize,
        Some(bussard_model::facts::AuthorizeVerdict::Unsupported)
    );
    let started = Instant::now();
    let out = ok_stdout(&bench.run(&["apply", "1.1.12", "--yes"])?)?;
    let elapsed = started.elapsed();
    let requests = bench.take_requests()?;
    println!(
        "apply with a cached unanswered authorize: {} requests, {} authorize, {:.2} s",
        requests.len(),
        count(&requests, A_AUTHORIZE_REQUEST),
        elapsed.as_secs_f64()
    );
    assert!(out.contains("apply verified"), "{out}");
    assert_eq!(count(&requests, A_AUTHORIZE_REQUEST), 0, "{requests:x?}");
    Ok(())
}

/// Issue #215: `--refresh-facts` asks again, in both phases.
#[test]
fn test_apply_refresh_facts_presents_the_authorize_again() -> TestResult {
    let bench = Bench::start("apply-authorize-refresh", unanswered_authorize_device()?)?;
    ok_stdout(&bench.run(&["plan", "1.1.12", "--json"])?)?;
    bench.take_requests()?;
    ok_stdout(&bench.run(&["apply", "1.1.12", "--yes", "--refresh-facts"])?)?;
    // The read phase asks (refresh), and learns the verdict again; the write
    // phase of the same command then relies on it.
    assert_eq!(count(&bench.take_requests()?, A_AUTHORIZE_REQUEST), 1);
    Ok(())
}

/// Issue #215: a device that answers `A_Authorize` asking for a key is never
/// skipped: both phases present the key and the write refuses loudly.
#[test]
fn test_apply_never_skips_the_authorize_of_a_device_that_wants_a_key() -> TestResult {
    let bench = Bench::start("apply-authorize-keyed", device()?.with_authorize_level(2))?;
    ok_stdout(&bench.run(&["plan", "1.1.12", "--json"])?)?;
    assert_eq!(
        bench.facts()?.authorize,
        Some(bussard_model::facts::AuthorizeVerdict::Denied)
    );
    bench.take_requests()?;
    let out = bench.run(&["apply", "1.1.12", "--yes"])?;
    assert!(!out.status.success(), "a denied write session must fail");
    assert_eq!(count(&bench.take_requests()?, A_AUTHORIZE_REQUEST), 2);
    Ok(())
}

/// Issue #215: the flash pre-flight skips the authorize the facts record as
/// unanswered (the write phase already took the pre-flight's verdict).
#[test]
fn test_flash_preflight_skips_the_authorize_the_facts_record_as_unanswered() -> TestResult {
    let bench = Bench::start("flash-authorize", unanswered_authorize_device()?)?;
    let Some(product) = build_knxprod(&bench.tmp)? else {
        return Ok(());
    };
    let product = product.to_str().ok_or("non-UTF-8 temp path")?.to_string();
    // No --yes and no TTY: the pre-flight runs and stops at the confirmation.
    let args = ["flash", "1.1.12", "--product", product.as_str()];
    let _ = bench.run(&args)?;
    assert_eq!(count(&bench.take_requests()?, A_AUTHORIZE_REQUEST), 1);
    let _ = bench.run(&args)?;
    assert_eq!(count(&bench.take_requests()?, A_AUTHORIZE_REQUEST), 0);
    assert_eq!(bench.gw.with_device(target()?, |d| d.writes)?, 0);
    Ok(())
}

/// Issue #215: a cold `apply` (no facts yet) discovers the interface objects
/// once, in its read phase; the write phase's table discovery and read-back
/// use that table (the #209 seed), and a warm run reads none of it. The
/// deep dive of 2026-09-24 counted three walks per apply before #209.
#[test]
fn test_apply_discovers_the_objects_at_most_once() -> TestResult {
    // PID_IO_LIST confirms its list with three PID_OBJECT_TYPE reads (the last
    // object, the first application object, the index after the last); the
    // walk reads every index and the one after the last.
    for (tag, device, discovery_reads) in [
        ("apply-io-list", device()?, 3),
        ("apply-walk", device()?.without_io_list(), TYPES.len() + 1),
    ] {
        let bench = Bench::start(tag, device)?;
        let out = ok_stdout(&bench.run(&["apply", "1.1.12", "--yes"])?)?;
        assert!(out.contains("apply verified"), "{out}");
        let cold = bench.take_requests()?;
        // The tables match now: a no-op apply.
        ok_stdout(&bench.run(&["apply", "1.1.12", "--yes"])?)?;
        let warm = bench.take_requests()?;
        println!(
            "{tag}: cold {} requests, {} PID_OBJECT_TYPE, {} PID 56; no-op warm {} requests, \
             {} PID_OBJECT_TYPE, {} PID 56",
            cold.len(),
            object_type_reads(&cold),
            max_apdu_reads(&cold),
            warm.len(),
            object_type_reads(&warm),
            max_apdu_reads(&warm),
        );
        assert_eq!(object_type_reads(&cold), discovery_reads, "{tag}");
        assert_eq!(max_apdu_reads(&cold), 1, "{tag}");
        assert_eq!(
            (object_type_reads(&warm), max_apdu_reads(&warm)),
            (0, 0),
            "{tag}"
        );
    }
    Ok(())
}

/// `PID_MAX_APDU_LENGTH` reads in a request log.
fn max_apdu_reads(requests: &[(u16, Vec<u8>)]) -> usize {
    requests
        .iter()
        .filter(|(a, d)| {
            *a == A_PROPERTY_VALUE_READ
                && d.first() == Some(&0)
                && d.get(1) == Some(&PID_MAX_APDU_LENGTH)
        })
        .count()
}

/// Issue #215: on a device without `PID_MAX_APDU_LENGTH`, the flash
/// pre-flight reads it once (the facts' read and the pre-flight's own
/// negotiation used to read it twice).
#[test]
fn test_flash_preflight_reads_an_absent_max_apdu_once() -> TestResult {
    let device = device()?.with_hook(|_, apci, data| {
        (apci == A_PROPERTY_VALUE_READ
            && data.first() == Some(&0)
            && data.get(1) == Some(&PID_MAX_APDU_LENGTH))
        .then(|| {
            bussard_testkit::Reaction::Answer(
                0x3D6,
                bussard_testkit::device::prop_response(0, PID_MAX_APDU_LENGTH, 0, 1, &[]),
            )
        })
    });
    let bench = Bench::start("flash-max-apdu", device)?;
    let Some(product) = build_knxprod(&bench.tmp)? else {
        return Ok(());
    };
    let product = product.to_str().ok_or("non-UTF-8 temp path")?.to_string();
    let out = bench.run(&["flash", "1.1.12", "--product", product.as_str()])?;
    // Without a terminal and without --yes the flash stops at its prompt with
    // the one refusal text (issue #228), after the read-only pre-flight.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to flash 1.1.12 via 127.0.0.1:")
            && stderr.contains(
                "without a terminal to confirm on; pass --yes to confirm non-interactively"
            ),
        "{stderr}"
    );
    let requests = bench.take_requests()?;
    println!(
        "flash pre-flight PID_MAX_APDU_LENGTH reads: {}",
        max_apdu_reads(&requests)
    );
    assert_eq!(max_apdu_reads(&requests), 1);
    Ok(())
}

// --- Measurement (ignored; run with --ignored --nocapture) -----------------

/// One timed run: requests the device saw and the wall-clock.
fn timed(bench: &Bench, args: &[&str]) -> TestResult<(usize, Duration, bool)> {
    bench.take_requests()?;
    let started = Instant::now();
    let out = bench.run(args)?;
    let elapsed = started.elapsed();
    let requests = bench.take_requests()?.len();
    Ok((requests, elapsed, out.status.success()))
}

/// The 1.1.12-like Data Secure device answering every request after 200 ms
/// (the median per-request time of the speed deep dive, 2026-09-24).
fn measured_device() -> TestResult<MockDevice> {
    Ok(device()?
        .with_data_secure(TOOL_KEY)
        .with_response_delay(Duration::from_millis(200)))
}

#[test]
#[ignore = "measurement: 200 ms per request, about a minute"]
fn test_measure_describe_and_reconstruct() -> TestResult {
    let key: String = TOOL_KEY.iter().map(|b| format!("{b:02x}")).collect();
    for command in ["describe", "reconstruct"] {
        let bench = Bench::start(&format!("measure-{command}"), measured_device()?)?;
        let args = [
            command,
            "1.1.12",
            "--tool-key",
            key.as_str(),
            "--skip-address-check",
        ];
        let (n1, t1, ok1) = timed(&bench, &args)?;
        let (n2, t2, ok2) = timed(&bench, &args)?;
        println!(
            "MEASURE {command}: first run {n1} requests {:.2} s (ok {ok1}); second run {n2} \
             requests {:.2} s (ok {ok2})",
            t1.as_secs_f64(),
            t2.as_secs_f64()
        );
    }
    Ok(())
}

#[test]
#[ignore = "measurement: 200 ms per request; needs the `zip` CLI"]
fn test_measure_flash_preflight() -> TestResult {
    let bench = Bench::start("measure-flash", measured_device()?)?;
    let Some(product) = build_knxprod(&bench.tmp)? else {
        return Ok(());
    };
    let key: String = TOOL_KEY.iter().map(|b| format!("{b:02x}")).collect();
    let product = product.to_str().ok_or("non-UTF-8 temp path")?.to_string();
    // No --yes and no TTY: the flash runs its read-only pre-flight, prints the
    // plan and stops at the confirmation. Nothing is written.
    let args = [
        "flash",
        "1.1.12",
        "--product",
        product.as_str(),
        "--tool-key",
        key.as_str(),
        "--skip-address-check",
    ];
    let (n1, t1, _) = timed(&bench, &args)?;
    let (n2, t2, _) = timed(&bench, &args)?;
    let writes = bench.gw.with_device(target()?, |d| d.writes)?;
    println!(
        "MEASURE flash pre-flight: first run {n1} requests {:.2} s; second run {n2} requests \
         {:.2} s; writes {writes}",
        t1.as_secs_f64(),
        t2.as_secs_f64()
    );
    assert_eq!(writes, 0);
    Ok(())
}

/// The synthetic application of `flash_parameters_mock.rs` (bussard's own
/// work, MIT; no vendor data), zipped into `<dir>/facts-test.knxprod`. `None`
/// when the `zip` CLI is unavailable.
fn build_knxprod(dir: &Path) -> TestResult<Option<PathBuf>> {
    const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard facts test app" LoadProcedureStyle="ProductDefault">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;
    let src = dir.join("prod");
    std::fs::create_dir_all(src.join("M-00FA"))?;
    std::fs::write(src.join("M-00FA").join("M-00FA_A-0002.xml"), APP_XML)?;
    let archive = dir.join("facts-test.knxprod");
    let Ok(status) = Command::new("zip")
        .current_dir(&src)
        .args(["-r", "-X", "-q"])
        .arg(&archive)
        .arg("M-00FA")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    else {
        eprintln!("skipping: the `zip` CLI is unavailable to build the synthetic .knxprod");
        return Ok(None);
    };
    Ok(status.success().then_some(archive))
}

/// Pins `M-00FA_A-0002-01-ABCD` (application id `00FA000201`, the mock's
/// [`APP_ID`]) for 1.1.12 in a v2 lock (issue #228).
fn pin_application(bench: &Bench) -> TestResult {
    std::fs::write(
        bench.dir().join("bussard.lock"),
        "version = 2\n\n[[device]]\naddress = \"1.1.12\"\n\
         application = \"M-00FA_A-0002-01-ABCD\"\nmask = \"07B0\"\n",
    )?;
    Ok(())
}

#[test]
fn test_plan_reports_identity_match_and_drift_against_the_lock() -> TestResult {
    let bench = Bench::start("plan-identity", device()?)?;
    pin_application(&bench)?;
    let out = bench.run(&["plan", "1.1.12", "--json"])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(json["identity"]["verdict"], "match", "{json}");

    bench.set_app_id(&[0x00, 0xFA, 0x00, 0x02, 0x02])?;
    let out = bench.run(&["plan", "1.1.12", "--json"])?;
    assert!(out.status.success(), "plan never refuses on drift");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(json["identity"]["verdict"], "drift", "{json}");
    let out = bench.run(&["plan", "1.1.12"])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("drift from bussard.lock") && stdout.contains("bussard flash 1.1.12"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_apply_refuses_a_device_that_drifted_from_the_lock() -> TestResult {
    let bench = Bench::start("apply-drift", device()?)?;
    pin_application(&bench)?;
    bench.set_app_id(&[0x00, 0xFA, 0x00, 0x02, 0x02])?;
    bench.take_requests()?;
    let out = bench.run(&["apply", "1.1.12", "--yes"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "apply must refuse: {stderr}");
    assert!(
        stderr.contains("refusing to apply to 1.1.12")
            && stderr.contains("00FA000202")
            && stderr.contains("bussard flash 1.1.12"),
        "{stderr}"
    );
    let requests = bench.take_requests()?;
    let writes = requests
        .iter()
        .filter(|(apci, _)| *apci & 0x3C0 == 0x280 || *apci == 0x3D7)
        .count();
    assert_eq!(writes, 0, "nothing may be written to a drifted device");

    // The stored facts now say what the device runs: `audit` lists the drift
    // offline.
    let out = bench.run(&["audit", "--json"])?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let drift = json["products"]["application_drift"]
        .as_array()
        .ok_or("application_drift array")?;
    assert_eq!(drift.len(), 1, "{json}");
    Ok(())
}

/// The management commands that read a device, with their arguments: each
/// reads or refreshes the facts and prints the one identity line (issue
/// #228, item 5).
const IDENTITY_COMMANDS: &[&[&str]] = &[
    &["describe", "1.1.12"],
    &["reconstruct", "1.1.12"],
    &["plan", "1.1.12"],
    &["backup", "1.1.12"],
];

#[test]
fn test_identity_verdict_and_facts_across_the_management_commands() -> TestResult {
    let bench = Bench::start("verdict-table", device()?)?;
    pin_application(&bench)?;
    let facts_file = facts_path(&bench.dir(), target()?);

    for args in IDENTITY_COMMANDS {
        let _ = std::fs::remove_file(&facts_file);
        let out = bench.run(args)?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{args:?}: {said}");
        assert!(
            said.contains(
                "identity of 1.1.12: matches bussard.lock (application id 00FA000201, mask 07B0)"
            ),
            "{args:?}: {said}"
        );
        assert_eq!(
            bench.facts()?.application_id.as_deref(),
            Some("00FA000201"),
            "{args:?} writes the facts"
        );
    }

    // The device now runs another application: every command says so in the
    // same words and refreshes the facts it had.
    bench.set_app_id(&[0x00, 0xFA, 0x00, 0x02, 0x02])?;
    for args in IDENTITY_COMMANDS {
        pin_application(&bench)?;
        let out = bench.run(args)?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            said.contains(
                "identity of 1.1.12: drift from bussard.lock: the device reports application id \
                 00FA000202 but the lock pins 00FA000201"
            ),
            "{args:?}: {said}"
        );
        assert_eq!(
            bench.facts()?.application_id.as_deref(),
            Some("00FA000202"),
            "{args:?} refreshes the facts"
        );
    }

    // `scan` reads only the mask: its JSON row carries the verdict with the
    // application id the facts hold.
    let out = bench.run(&["scan", "1.1", "--from", "12", "--to", "12", "--json"])?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let row = &json["found"][0];
    assert_eq!(row["identity"]["verdict"], "drift", "{json}");
    assert_eq!(row["identity"]["device"]["application_id"], "00FA000202");
    Ok(())
}
