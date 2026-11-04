//! Issue #303: a parameter change that shows a com-object is planned by
//! `knx_plan_device` as `method: flash` and written by `knx_apply_device` as a
//! full application download, through the apply job, against an in-process
//! mock KNXnet/IP gateway on loopback. Never a real gateway.
//!
//! The device is a bussard-testkit `MockDevice` (System B, mask 07B0) running
//! a small synthetic application (bussard's own work, no vendor data): a
//! six-octet code segment and a two-octet parameter segment whose bit 1.0
//! shows com-object 2. A hook gives its application object the relative
//! segment allocation a real device does (each `LdCtrlRelSegment` gets a fresh
//! base, reported through `PID_TABLE_REFERENCE`); everything else is the
//! testkit's built-in device.

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_mgmt::apci::{A_PROPERTY_VALUE_RESPONSE, A_PROPERTY_VALUE_WRITE};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::consts::{
    LE_ADDITIONAL, LE_LOAD_COMPLETED, LE_START_LOADING, LE_UNLOAD, LS_LOADED, LS_UNLOADED,
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    PID_LOAD_STATE_CONTROL, PID_PROGRAM_VERSION, SUB_REL_SEGMENT,
};
use bussard_testkit::device::{decode_prop_header, prop_response};
use bussard_testkit::{MockDevice, MockGateway, Reaction};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use sha2::Digest as _;

pub(super) const CHANNEL: u8 = 0x56;

/// The application program object's index on the mock.
pub(super) const APP_OBJECT: u8 = 3;
/// Where the resident code and parameter segments sit.
const CODE_BASE: u32 = 0x5000;
const PARAM_BASE: u32 = 0x5006;
/// Where the mock allocates the segments a download asks for.
pub(super) const ALLOC_BASE: u32 = 0x6000;

/// The synthetic application (bussard's own work, MIT; no vendor data).
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard flash test app" LoadProcedureStyle="ProductDefault">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
              <ParameterType Id="M-00FA_A-0002_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
                <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0002_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" DatapointType="DPST-1-1" />
              <ComObject Id="M-00FA_A-0002_O-2" Number="2" Text="Alarm" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" DatapointType="DPST-1-5" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
              <ComObjectRef Id="M-00FA_A-0002_O-2_R-2" RefId="M-00FA_A-0002_O-2" />
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
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
                <choose ParamRefId="M-00FA_A-0002_P-1_R-2">
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0002_O-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

fn device_ia() -> anyhow::Result<IndividualAddress> {
    Ok("1.1.4".parse()?)
}

/// The device: runs the application with threshold 9 and object 2 off, and
/// the links the model asks for (object 1 listens on 1/2/0).
fn device() -> anyhow::Result<MockDevice> {
    device_running(Some([0x00, 0xFA, 0x00, 0x02, 0x01]), LS_LOADED)
}

/// The device with the links the model asks for, reporting `app_id` (none:
/// no `PID_PROGRAM_VERSION`) and its application object in `load_state`.
fn device_running(app_id: Option<[u8; 5]>, load_state: u8) -> anyhow::Result<MockDevice> {
    device_at(device_ia()?, app_id, load_state)
}

/// [`device_running`] at `address` (a replacement answers at another one
/// until it is assigned, issue #751).
pub(super) fn device_at(
    address: IndividualAddress,
    app_id: Option<[u8; 5]>,
    load_state: u8,
) -> anyhow::Result<MockDevice> {
    let ga: GroupAddress = "1/2/0".parse()?;
    let mut addresses = 1u16.to_be_bytes().to_vec();
    addresses.extend_from_slice(&ga.raw().to_be_bytes());
    let mut associations = 1u16.to_be_bytes().to_vec();
    associations.extend_from_slice(&1u16.to_be_bytes());
    associations.extend_from_slice(&1u16.to_be_bytes());
    let next_base = Arc::new(Mutex::new(ALLOC_BASE));
    let mut dev = MockDevice::new(address)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_table(1, &addresses)
        .with_table(2, &associations)
        .with_memory(CODE_BASE, &[0, 1, 2, 3, 4, 5])
        .with_memory(PARAM_BASE, &[9, 0x00])
        .with_hook(move |dev, apci, data| {
            // LdCtrlRelSegment on the application object: a fresh base for
            // each segment, as a real device allocates them.
            let (oi, pid, _, start) = decode_prop_header(data)?;
            let value = data.get(4..)?;
            if apci != A_PROPERTY_VALUE_WRITE
                || oi != APP_OBJECT
                || pid != PID_LOAD_STATE_CONTROL
                || value.first() != Some(&LE_ADDITIONAL)
                || value.get(1) != Some(&SUB_REL_SEGMENT)
            {
                return None;
            }
            let size = value
                .get(2..6)
                .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]))
                .unwrap_or(0);
            let mut next = next_base.lock().unwrap_or_else(|p| p.into_inner());
            dev.segments.insert(APP_OBJECT, (*next, size));
            *next += 0x100;
            dev.writes += 1;
            let state = dev.load_state(APP_OBJECT);
            Some(Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(APP_OBJECT, PID_LOAD_STATE_CONTROL, 1, start, &[state]),
            ))
        });
    // M-00FA, application 2, version 1 is the synthetic app's id.
    if let Some(id) = app_id {
        dev = dev.with_property(APP_OBJECT, PID_PROGRAM_VERSION, 5, &id);
    }
    dev.segments.insert(APP_OBJECT, (PARAM_BASE, 2));
    dev.load_states.insert(APP_OBJECT, load_state);
    Ok(dev)
}

/// Packs the synthetic application into a `.knxprod`.
fn knxprod(path: &Path) -> anyhow::Result<()> {
    let mut writer = zip::ZipWriter::new(std::fs::File::create(path)?);
    writer.start_file(
        "M-00FA/M-00FA_A-0002.xml",
        zip::write::SimpleFileOptions::default(),
    )?;
    writer.write_all(APP_XML.as_bytes())?;
    writer.finish()?;
    Ok(())
}

/// The model: 1.1.4 runs the app with object 2 on (the change), the archive
/// stored in `products/` and pinned in `bussard.lock`. Returns its SHA-256.
pub(super) fn write_model(dir: &Path) -> anyhow::Result<String> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join("products"))?;
    let archive = dir.join("products").join("flash-test.knxprod");
    knxprod(&archive)?;
    let sha: String = sha2::Sha256::digest(std::fs::read(&archive)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \
             \"products/flash-test.knxprod\"\nfilename = \"flash-test.knxprod\"\n\
             origin = {{ kind = \"file\", path = \"flash-test.knxprod\" }}\n\
             applications = [\"M-00FA_A-0002\"]\n\n[[device]]\naddress = \"1.1.4\"\n\
             application = \"M-00FA_A-0002\"\nproduct_sha256 = \"{sha}\"\nmask = \"07B0\"\n"
        ),
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Weather station\"\n\n[parameters]\n\
         \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"1\"\n\n[links]\n1.listen = [\"1/2/0\"]\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Switch\" },\n]\n",
    )?;
    Ok(sha)
}

pub(super) type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// Shrinks the management timeouts and the source-address probe for the mock
/// device on loopback, as the CLI mock-device tests do.
fn fast_mock_timeouts() {
    // SAFETY: nextest runs each test in its own process, and every test in
    // this binary sets the same values before the server starts; they are
    // read when a management connection or probe is set up.
    unsafe {
        std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
        std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
    }
}

/// A programming-tier server on `dir` against `gateway`, answering
/// `knx_apply_device` at once (reply wait zero) so the job runs under
/// `knx_apply_status`.
pub(super) async fn serve(
    dir: &Path,
    gateway: &MockGateway,
) -> anyhow::Result<(Client, tokio::task::JoinHandle<()>)> {
    fast_mock_timeouts();
    let connection = ConnectionConfig::tunnel(gateway.addr());
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: connection.clone(),
        passive: false,
        allow_writes: false,
        no_model_edits: true,
        capture_db: None,
        allow_programming: true,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(600),
        keyring: None,
        allow_home_assistant: false,
    };
    let state = bussard_mcp::build_state(&config)?;
    if let Some(tier) = state.programming.as_ref() {
        tier.set_reply_wait(Duration::ZERO);
    }
    let service = bussard_service::BusService::open(connection, config.write_policy())?;
    if !service.wait_connected(Duration::from_secs(5)).await {
        anyhow::bail!("the mock tunnel did not come up");
    }
    state.bus.wire(service);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Ok((().serve(client_io).await?, task))
}

/// Calls one tool and returns its structured result.
pub(super) async fn call(client: &Client, tool: &str, args: Value) -> anyhow::Result<Value> {
    let Value::Object(map) = args else {
        anyhow::bail!("tool arguments must be an object");
    };
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
    )
    .await??;
    res.structured_content
        .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
}

/// The load events written to the application object, in order.
pub(super) fn app_load_events(dev: &MockDevice) -> Vec<u8> {
    dev.requests
        .iter()
        .filter(|(apci, data)| {
            *apci == A_PROPERTY_VALUE_WRITE
                && data.first() == Some(&APP_OBJECT)
                && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
        })
        .filter_map(|(_, data)| data.get(4).copied())
        .collect()
}

#[tokio::test]
async fn test_knx_apply_device_flashes_a_parameter_that_shows_a_com_object() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device()?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    let sha = write_model(dir.path())?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    // The plan: a flash, with what it shows, why, the table sizes, the
    // offline time, the backup and the pinned archive.
    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["method"], "flash", "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    let flash = &plan["flash"];
    let shown = &flash["objects"]["shown"][0];
    assert_eq!(shown["number"], 2, "{flash}");
    assert_eq!(shown["text"], "Alarm", "{flash}");
    assert_eq!(shown["dpt"], "1.005", "{flash}");
    assert!(
        shown["because"][0]
            .as_str()
            .is_some_and(|b| b.contains("obj2") && b.contains("On")),
        "{flash}"
    );
    assert_eq!(flash["objects"]["hidden"], json!([]), "{flash}");
    assert_eq!(
        flash["tables"]["group_objects"],
        json!({"before": 1, "after": 2})
    );
    assert_eq!(flash["tables"]["address"], json!({"before": 1, "after": 1}));
    assert_eq!(
        flash["device_offline_seconds"],
        json!({"min": 30, "max": 50})
    );
    assert_eq!(flash["parameter_backup"]["taken_first"], true, "{flash}");
    assert_eq!(flash["product"]["product_sha256"], sha.as_str(), "{flash}");
    assert_eq!(flash["product"]["archive"], "products/flash-test.knxprod");
    // Issue #326: the links stay as they are, yet a full download writes
    // the image and the tables; neither text says "nothing".
    let text = plan["plan"].as_str().unwrap_or_default();
    assert!(!text.contains("nothing to do"), "{text}");
    assert!(
        text.contains("full download: writes full image (segment")
            && text.contains("tables rewritten (unchanged: 1 address, "),
        "{text}"
    );
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(!sentences.contains("writes: nothing"), "{sentences}");
    assert!(
        sentences.contains("writes: full image (segment"),
        "{sentences}"
    );
    assert!(
        plan["writes"]["full_image"]["segments"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
        "{plan}"
    );
    let question = plan["question"].as_str().unwrap_or_default();
    assert!(question.starts_with("flash 1.1.4 through"), "{question}");
    let next = plan["next_step"].as_str().unwrap_or_default();
    assert!(next.contains("explicit yes to flashing"), "{next}");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    let writes = gateway.with_device(device_ia()?, |dev| dev.writes)?;
    assert_eq!(writes, 0, "planning must not write");

    // The apply: the pre-flight answers, the download runs as the job.
    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    assert_eq!(started["refused"], Value::Null, "apply: {started}");
    let job = started["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {started}"))?
        .to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let done = loop {
        let status = call(&client, "knx_apply_status", json!({"job": job})).await?;
        if status["done"] == true {
            break status;
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("job {job} did not finish: {status}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(done["state"], "done", "{done}");
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["verified"], true, "{done}");
    assert_eq!(result["method"], "flash", "{done}");
    assert_eq!(result["parameters"]["written"], true, "{done}");
    // Issue #349: the flash's read-back compared the parameters; this
    // application's download loads no table object, so the tables it did
    // not write are not compared.
    let readback = &result["readback"];
    assert_eq!(readback["verified"], true, "{done}");
    assert_eq!(readback["compared"]["parameters"], 2, "{done}");
    assert!(readback["compared"]["addresses"].is_null(), "{done}");
    let backup = result["parameter_backup"].as_str().unwrap_or_default();
    assert!(Path::new(backup).is_file(), "parameter backup {backup}");

    // The mock saw the full download: unload, load, two segments, load
    // completed, the restart; the code and the model's parameters written.
    let (events, restarts, code, params) = gateway.with_device(device_ia()?, |dev| {
        (
            app_load_events(dev),
            dev.restarts,
            dev.read_mem(ALLOC_BASE, 6),
            dev.read_mem(ALLOC_BASE + 0x100, 2),
        )
    })?;
    assert_eq!(
        events,
        [
            LE_UNLOAD,
            LE_START_LOADING,
            LE_ADDITIONAL,
            LE_ADDITIONAL,
            LE_LOAD_COMPLETED
        ],
        "load events"
    );
    assert!(restarts >= 1, "the device restarts");
    assert_eq!(code, [0, 1, 2, 3, 4, 5]);
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");

    // The device now holds the model: nothing left to plan.
    let replan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert_eq!(replan["method"], "apply", "replan: {replan}");
    let last = call(&client, "knx_last_apply", json!({"address": "1.1.4"})).await?;
    assert_eq!(last["result"]["method"], "flash", "{last}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Polls a job until it is done and returns its status.
async fn finish(client: &Client, started: &Value) -> anyhow::Result<Value> {
    let job = started["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {started}"))?
        .to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let status = call(client, "knx_apply_status", json!({"job": job})).await?;
        if status["done"] == true {
            return Ok(status);
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("job {job} did not finish: {status}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Issue #750: a device with no application loaded gets the application
/// bussard.lock pins from the plan's one yes: the plan says it must be
/// loaded, the job downloads it with the model's parameters, reads it back
/// and says verified only when the device holds the model.
#[tokio::test]
async fn test_knx_apply_device_loads_the_application_into_a_fresh_device() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device_running(None, LS_UNLOADED)?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["method"], "flash", "plan: {plan}");
    let load = &plan["flash"]["load_application"];
    assert_eq!(load["application"], "M-00FA_A-0002", "{plan}");
    assert!(
        load["why"]
            .as_str()
            .is_some_and(|w| w.contains("no application program loaded")),
        "{plan}"
    );
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.starts_with("! 1.1.4 must have its application program loaded"),
        "{sentences}"
    );
    let question = plan["question"].as_str().unwrap_or_default();
    assert!(
        question.starts_with("load application M-00FA_A-0002 into 1.1.4"),
        "{question}"
    );
    let next = plan["next_step"].as_str().unwrap_or_default();
    assert!(next.contains("explicit yes to loading it"), "{next}");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    assert_eq!(gateway.with_device(device_ia()?, |dev| dev.writes)?, 0);

    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    let done = finish(&client, &started).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["verified"], true, "{done}");
    assert_eq!(result["load_application"]["loaded"], true, "{done}");
    assert_eq!(result["readback"]["verified"], true, "{done}");
    assert_eq!(result["readback"]["compared"]["parameters"], 2, "{done}");

    let (events, params) = gateway.with_device(device_ia()?, |dev| {
        (app_load_events(dev), dev.read_mem(ALLOC_BASE + 0x100, 2))
    })?;
    assert_eq!(events.first(), Some(&LE_UNLOAD), "load events {events:?}");
    assert_eq!(
        events.last(),
        Some(&LE_LOAD_COMPLETED),
        "load events {events:?}"
    );
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Issue #750: a device that runs another application gets the pinned one
/// from the plan's one yes; the plan names what it replaces.
#[tokio::test]
async fn test_knx_apply_device_loads_the_application_over_another_one() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device_running(
            Some([0x00, 0xFA, 0x00, 0x03, 0x01]),
            LS_LOADED,
        )?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["method"], "flash", "plan: {plan}");
    let replaces = plan["flash"]["load_application"]["replaces"]
        .as_str()
        .unwrap_or_default();
    assert!(replaces.contains("M-00FA A-0003 v1"), "{plan}");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    let done = finish(&client, &started).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["verified"], true, "{done}");
    assert_eq!(result["load_application"]["loaded"], true, "{done}");
    let params = gateway.with_device(device_ia()?, |dev| dev.read_mem(ALLOC_BASE + 0x100, 2))?;
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Writes the model of [`write_model`] with object 1 also listening on
/// 1/2/1, a link the device does not hold.
fn write_model_with_a_new_link(dir: &Path, obj2: &str) -> anyhow::Result<()> {
    write_model(dir)?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        format!(
            "address = \"1.1.4\"\nname = \"Weather station\"\n\n[parameters]\n\
             \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"{obj2}\"\n\n[links]\n\
             1.listen = [\"1/2/0\", \"1/2/1\"]\n"
        ),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Switch\" },\n  \
         { address = \"1/2/1\", name = \"Switch 2\" },\n]\n",
    )?;
    Ok(())
}

/// The address table the device holds after the job: count word, then
/// the group addresses.
fn address_table(gateway: &MockGateway) -> anyhow::Result<Vec<u8>> {
    let image = gateway.with_device(device_ia()?, |dev| dev.table_image(1))?;
    image.ok_or_else(|| anyhow::anyhow!("the mock holds no address table"))
}

/// The address table image of 1/2/0 and 1/2/1 (System B: the count word,
/// then the group addresses).
fn two_links() -> anyhow::Result<Vec<u8>> {
    let mut image = 2u16.to_be_bytes().to_vec();
    for ga in ["1/2/0", "1/2/1"] {
        image.extend_from_slice(&ga.parse::<GroupAddress>()?.raw().to_be_bytes());
    }
    Ok(image)
}

/// Issue #779: when the links change too and this application's download
/// writes no link table, the plan loads the application and then writes the
/// links, as `bussard replace` runs `flash` and then `apply`. One yes covers
/// both, each ends with its read-back, and the result is verified only when
/// the table write's read-back matches the model.
#[tokio::test]
async fn test_knx_apply_device_loads_the_application_then_writes_the_links() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device_running(None, LS_UNLOADED)?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model_with_a_new_link(dir.path(), "1")?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["method"], "flash", "plan: {plan}");
    assert_eq!(plan["flash"]["links_after_download"], true, "{plan}");
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.starts_with("! 1.1.4 must have its application program loaded")
            && sentences.contains("then writes the model's links"),
        "{sentences}"
    );
    let question = plan["question"].as_str().unwrap_or_default();
    assert!(
        question.starts_with("load application M-00FA_A-0002 into 1.1.4")
            && question.contains("then write its links"),
        "{question}"
    );
    let next = plan["next_step"].as_str().unwrap_or_default();
    assert!(
        next.contains("links are written by a table write"),
        "{next}"
    );
    let notes = plan["notes"].to_string();
    assert!(notes.contains("bussard apply 1.1.4"), "{notes}");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    assert_eq!(gateway.with_device(device_ia()?, |dev| dev.writes)?, 0);

    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    let done = finish(&client, &started).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["verified"], true, "{done}");
    assert_eq!(result["method"], "flash", "{done}");
    assert_eq!(result["load_application"]["loaded"], true, "{done}");
    // The download's read-back: the parameters, not the tables it did not
    // write.
    assert_eq!(result["readback"]["verified"], true, "{done}");
    assert_eq!(result["readback"]["compared"]["parameters"], 2, "{done}");
    // The table write after it, with its own read-back of the links.
    let links = &result["links"];
    assert_eq!(links["method"], "apply", "{done}");
    assert_eq!(links["ok"], true, "{done}");
    assert_eq!(links["verified"], true, "{done}");
    assert_eq!(links["readback"]["verified"], true, "{done}");
    assert_eq!(links["resulting_address_count"], 2, "{done}");

    let params = gateway.with_device(device_ia()?, |dev| dev.read_mem(ALLOC_BASE + 0x100, 2))?;
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");
    assert_eq!(address_table(&gateway)?, two_links()?);

    let replan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(replan["noop"], true, "replan: {replan}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Issue #779: a parameter that shows a com-object needs a full download
/// (issue #303); when the links change too, the same job writes them after
/// it.
#[tokio::test]
async fn test_knx_apply_device_flashes_then_writes_the_links() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device()?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model_with_a_new_link(dir.path(), "1")?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["method"], "flash", "plan: {plan}");
    assert!(plan["flash"]["load_application"].is_null(), "{plan}");
    assert_eq!(plan["flash"]["links_after_download"], true, "{plan}");
    let notes = plan["notes"].to_string();
    assert!(
        notes.contains("does not write the link tables") && notes.contains("bussard apply 1.1.4"),
        "{notes}"
    );
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    let done = finish(&client, &started).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["verified"], true, "{done}");
    assert_eq!(result["links"]["verified"], true, "{done}");
    assert_eq!(result["links"]["readback"]["verified"], true, "{done}");
    let params = gateway.with_device(device_ia()?, |dev| dev.read_mem(ALLOC_BASE + 0x100, 2))?;
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");
    assert_eq!(address_table(&gateway)?, two_links()?);

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Issue #779: the download verifies, but the device refuses the table
/// write after it. The result says the application is loaded and that the
/// links were not written: not verified.
#[tokio::test]
async fn test_knx_apply_device_load_whose_links_fail_is_not_verified() -> anyhow::Result<()> {
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .device(device_running(None, LS_UNLOADED)?.with_nak_writes_into(OT_ADDRESS_TABLE))
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model_with_a_new_link(dir.path(), "1")?;
    let (client, task) = serve(dir.path(), &gateway).await?;

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(plan["flash"]["links_after_download"], true, "{plan}");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
        .to_string();
    let started = call(
        &client,
        "knx_apply_device",
        json!({"address": "1.1.4", "plan_digest": digest}),
    )
    .await?;
    let done = finish(&client, &started).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], false, "{done}");
    assert_eq!(result["verified"], false, "{done}");
    assert_eq!(result["load_application"]["loaded"], true, "{done}");
    assert_eq!(result["links"]["verified"], false, "{done}");
    let reason = result["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("is loaded on 1.1.4 and verified, but its links were not written"),
        "{reason}"
    );
    assert!(result["recovery"].is_string(), "{done}");

    client.cancel().await?;
    task.abort();
    Ok(())
}
