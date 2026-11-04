//! Mock-gateway tests of `knx_add_device` (issue #749): the adopt flow from
//! chat, press the button, identify, the yes, the write and the read-back.
//!
//! The new device is a `bussard-testkit` [`MockDevice`] in programming mode at
//! 15.15.255 with a serial number, a manufacturer and an order number, on a
//! loopback [`MockGateway`] tunnel. The product data comes from a fabricated
//! `.knxprod` that a test pointer index serves over `file://`.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x56;

const SERIAL: [u8; 6] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];

const ORDER: &str = "MDT-BE-04001.02";

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-0083">
    <Hardware>
      <Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

// Two com-objects: a transmitting button (#0) and a write-only LED (#1).
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
  <ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster BE 04001" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-0" Number="0" Text="Taste 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" ReadFlag="Disabled" WriteFlag="Disabled" />
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-1" Number="1" Text="LED 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-1_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-1" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <Dynamic>
    <ChannelIndependentBlock>
     <ComObjectRefRef RefId="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" />
     <ComObjectRefRef RefId="M-0083_A-1234-11-ABCD-O000A_O-1_R-1" />
    </ChannelIndependentBlock>
   </Dynamic>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn ia(s: &str) -> anyhow::Result<IndividualAddress> {
    Ok(s.parse()?)
}

/// A factory-fresh device in programming mode at 15.15.255.
fn new_device() -> anyhow::Result<MockDevice> {
    Ok(MockDevice::new(ia("15.15.255")?)
        .with_programming(true)
        .with_serial(SERIAL)
        .with_manufacturer(0x0083)
        .with_order_info(ORDER.as_bytes()))
}

/// The model: one device on line 1.1, so the next free address is 1.1.1
/// and 1.1.7 is on a known line.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Rollladen Wohnzimmer\"\n",
    )?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    Ok(())
}

/// Packs the fabricated product into a `.knxprod` and writes a one-entry
/// pointer index serving it over `file://` for [`ORDER`]. Returns the index.
fn product_index(tmp: &Path) -> anyhow::Result<std::path::PathBuf> {
    use sha2::Digest as _;
    let knxprod = tmp.join("download.knxprod");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&knxprod)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        ("M-0083/M-0083_A-1234-11-ABCD-O000A.xml", APP_XML),
    ] {
        writer.start_file(name, zip::write::SimpleFileOptions::default())?;
        writer.write_all(body.as_bytes())?;
    }
    writer.finish()?;
    let bytes = std::fs::read(&knxprod)?;
    let sha: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let index = json!({"entries": [{
        "manufacturer": "MDT",
        "manufacturer_id": "M-0083",
        "order_numbers": [ORDER],
        "name": "Taster BE (test fixture)",
        "url": format!("file://{}", knxprod.display()),
        "sha256": sha,
        "size": bytes.len(),
        "filename": "fixture.knxprod",
        "redistributable": false,
    }]});
    let path = tmp.join("index.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&index)?)?;
    Ok(path)
}

/// One running server plus its mock line.
struct Harness {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
    gateway: MockGateway,
    dir: tempfile::TempDir,
}

impl Harness {
    /// Starts `devices` on a mock line and a programming-tier server, with
    /// the product index of [`product_index`].
    async fn start(devices: Vec<MockDevice>) -> anyhow::Result<Harness> {
        let dir = tempfile::tempdir()?;
        let model = dir.path().join("knx");
        write_model(&model)?;
        let index = product_index(dir.path())?;
        // SAFETY: nextest runs each test in its own process, and every test in
        // this module sets these before the server starts; they are read when
        // a management connection, a probe, a wait or the index is set up.
        unsafe {
            std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
            std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
            std::env::set_var(bussard_service::assign::WAIT_MS_ENV, "400");
            std::env::set_var(bussard_service::setup::products::PRODUCT_INDEX_ENV, &index);
        }
        let gateway = MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .devices(devices)
            .start()
            .await?;
        let connection = ConnectionConfig::tunnel(gateway.addr());
        let config = McpConfig {
            dir: model.clone(),
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
        let service = bussard_service::BusService::open(connection, config.write_policy())?;
        if !service.wait_connected(Duration::from_secs(5)).await {
            anyhow::bail!("the mock tunnel did not come up");
        }
        state.bus.wire(service);
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = bussard_mcp::server::BussardMcp::new(state);
        let server_task = tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        let client = ().serve(client_io).await?;
        Ok(Harness {
            client,
            server_task,
            gateway,
            dir,
        })
    }

    fn model(&self) -> std::path::PathBuf {
        self.dir.path().join("knx")
    }

    async fn call(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        let Value::Object(map) = args else {
            anyhow::bail!("tool arguments must be an object");
        };
        let res = tokio::time::timeout(
            Duration::from_secs(30),
            self.client
                .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
        )
        .await??;
        res.structured_content
            .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
    }

    /// Polls `knx_job_status` until `until` holds for the status.
    async fn poll(&self, job: &str, until: impl Fn(&Value) -> bool) -> anyhow::Result<Value> {
        for _ in 0..200 {
            let status = self.call("knx_job_status", json!({"job": job})).await?;
            if until(&status) {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::bail!("job {job} never reached the expected state")
    }

    /// Starts an add and polls until the device is identified.
    async fn identified(&self, args: Value) -> anyhow::Result<(String, Value)> {
        let first = self.call("knx_add_device", args).await?;
        assert_eq!(first["step"], "press_button", "{first}");
        assert!(
            first["question"]
                .as_str()
                .unwrap_or_default()
                .contains("programming button"),
            "{first}"
        );
        let job = first["job"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no job in {first}"))?
            .to_string();
        let status = self
            .poll(&job, |s| s["step"] == "identified" || s["done"] == true)
            .await?;
        Ok((job, status))
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        drop(self.gateway);
        Ok(())
    }
}

#[tokio::test]
async fn test_knx_add_device_identifies_then_assigns_downloads_and_verifies() -> anyhow::Result<()>
{
    let h = Harness::start(vec![new_device()?]).await?;
    let (job, status) = h.identified(json!({"address": "1.1.7"})).await?;
    assert_eq!(status["step"], "identified", "{status}");
    assert_eq!(status["done"], false, "{status}");
    assert_eq!(status["current_address"], "15.15.255", "{status}");
    assert_eq!(status["address"], "1.1.7", "{status}");
    assert_eq!(status["serial"], "00fa01020304", "{status}");
    assert_eq!(status["mask"], "07B0", "{status}");
    assert_eq!(status["order_number"], ORDER, "{status}");
    assert_eq!(status["download_needed"], true, "{status}");
    assert!(
        status["product_data"]
            .as_str()
            .unwrap_or_default()
            .starts_with("would download Taster BE (test fixture)"),
        "{status}"
    );
    assert!(
        status["question"]
            .as_str()
            .unwrap_or_default()
            .contains("Assign 1.1.7, download the product data"),
        "{status}"
    );
    let digest = status["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {status}"))?
        .to_string();
    // Identification wrote nothing: the device still answers at 15.15.255.
    assert!(h.gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());

    // `yes` never answers the download.
    let refused = h
        .call(
            "knx_add_device",
            json!({"job": job, "plan_digest": digest, "yes": true}),
        )
        .await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("download: true"),
        "{refused}"
    );
    // Neither does a yes without the digest of this job.
    let wrong = h
        .call(
            "knx_add_device",
            json!({"job": job, "plan_digest": "sha256:00", "yes": true, "download": true}),
        )
        .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");
    assert!(h.gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());

    let mut done = h
        .call(
            "knx_add_device",
            json!({"job": job, "plan_digest": digest, "yes": true, "download": true}),
        )
        .await?;
    if done["started"] == true {
        done = h.poll(&job, |s| s["done"] == true).await?["result"].clone();
    }
    assert_eq!(done["step"], "done", "{done}");
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(done["assigned"], true, "{done}");
    assert_eq!(done["verified"], true, "{done}");
    assert_eq!(done["address"], "1.1.7", "{done}");
    assert_eq!(done["from"], "15.15.255", "{done}");
    assert_eq!(done["readback"]["serial"], "00fa01020304", "{done}");
    assert_eq!(done["name"], "Taster BE 04001", "{done}");
    assert_eq!(done["product"]["com_objects"], 2, "{done}");
    assert_eq!(done["objects"][0]["object"], 0, "{done}");
    let summary = done["summary"].as_str().unwrap_or_default();
    assert!(
        summary.starts_with("Taster BE 04001 (1.1.7) now answers at 1.1.7 (was 15.15.255)"),
        "{summary}"
    );

    // The device took the address, and the model has it with its lock entry.
    assert!(h.gateway.with_device(ia("1.1.7")?, |_| ()).is_ok());
    let file = std::fs::read_to_string(h.model().join("devices").join("1.1.7.toml"))?;
    assert!(file.contains("Taster BE 04001"), "{file}");
    let lock = std::fs::read_to_string(h.model().join("bussard.lock"))?;
    assert!(lock.contains("M-0083_A-1234-11-ABCD-O000A"), "{lock}");
    assert!(
        lock.contains("00FA01020304") || lock.contains("00fa01020304"),
        "{lock}"
    );
    assert!(h.model().join("products").join("fixture.knxprod").is_file());

    // The job is done; a second yes is refused.
    let again = h
        .call(
            "knx_add_device",
            json!({"job": job, "plan_digest": digest, "yes": true, "download": true}),
        )
        .await?;
    assert_eq!(again["refused"], true, "{again}");
    h.stop().await
}

#[tokio::test]
async fn test_knx_add_device_without_a_device_in_programming_mode_ends_the_job()
-> anyhow::Result<()> {
    let h = Harness::start(vec![]).await?;
    let (_, status) = h.identified(json!({})).await?;
    assert_eq!(status["done"], true, "{status}");
    assert_eq!(status["result"]["ok"], false, "{status}");
    assert!(
        status["result"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("No device entered programming mode"),
        "{status}"
    );
    h.stop().await
}

#[tokio::test]
async fn test_knx_add_device_refuses_an_address_another_device_answers_at() -> anyhow::Result<()> {
    let occupant = MockDevice::new(ia("1.1.7")?);
    let h = Harness::start(vec![new_device()?, occupant]).await?;
    let (_, status) = h.identified(json!({"address": "1.1.7"})).await?;
    assert_eq!(status["done"], true, "{status}");
    let reason = status["result"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("1.1.7 is already in use"), "{reason}");
    assert!(reason.contains("Nothing was written"), "{reason}");
    // The new device was not re-addressed.
    assert!(h.gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());
    h.stop().await
}

#[tokio::test]
async fn test_knx_add_device_refuses_a_stale_plan_when_the_device_left_programming_mode()
-> anyhow::Result<()> {
    let h = Harness::start(vec![new_device()?]).await?;
    let (job, status) = h.identified(json!({})).await?;
    assert_eq!(status["step"], "identified", "{status}");
    assert_eq!(
        status["address"], "1.1.1",
        "the next free address: {status}"
    );
    let digest = status["plan_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    // The human pressed the button again: the device leaves programming mode.
    h.gateway
        .with_device(ia("15.15.255")?, |dev| dev.programming = false)?;
    let mut done = h
        .call(
            "knx_add_device",
            json!({"job": job, "plan_digest": digest, "yes": true, "download": true}),
        )
        .await?;
    if done["started"] == true {
        done = h.poll(&job, |s| s["done"] == true).await?["result"].clone();
    }
    assert_eq!(done["ok"], false, "{done}");
    assert!(
        done["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer the one device in programming mode"),
        "{done}"
    );
    assert!(h.gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());
    assert!(!h.model().join("devices").join("1.1.1.toml").exists());
    h.stop().await
}
