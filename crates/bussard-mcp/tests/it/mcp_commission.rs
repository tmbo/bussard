//! Mock-gateway tests of `knx_commission_line` (issue #753): the line walk
//! of `bussard commission` from chat. The plan, the one yes, then per device
//! the press of the button, the identification against the model's order
//! number and the address write with its read-back and label.
//!
//! The bench devices are `bussard-testkit` [`MockDevice`]s with a serial
//! number, a manufacturer and an order number, entering programming mode in
//! turn on a loopback [`MockGateway`] tunnel.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`.

use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x57;

const JAL: &str = "JAL-0810.03";
const AKK: &str = "AKK-0216.03";

fn ia(s: &str) -> anyhow::Result<IndividualAddress> {
    Ok(s.parse()?)
}

/// A device on the bench at `address` reporting `order`, its button pressed
/// or not.
fn bench(address: &str, order: &str, serial: u8, pressed: bool) -> anyhow::Result<MockDevice> {
    Ok(MockDevice::new(ia(address)?)
        .with_programming(pressed)
        .with_serial([0x00, 0x83, 0x00, 0x00, 0x00, serial])
        .with_manufacturer(0x0083)
        .with_order_info(order.as_bytes()))
}

/// Writes a model device file with a product and a place, plus its lock entry.
fn write_device(
    dir: &Path,
    address: &str,
    name: &str,
    order: &str,
    room: &str,
) -> anyhow::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join(format!("{address}.toml")),
        format!(
            "address = \"{address}\"\nname = \"{name}\"\nproduct = \"{order}\"\n\n\
             [location]\nfloor = \"Ground floor\"\nroom = \"{room}\"\n"
        ),
    )?;
    let lock = dir.join("bussard.lock");
    let fresh = !lock.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lock)?;
    if fresh {
        writeln!(file, "version = 3")?;
    }
    write!(
        file,
        "\n[[device]]\naddress = \"{address}\"\nproduct = \"{order}\"\nmanufacturer = \"MDT\"\n"
    )?;
    Ok(())
}

/// The model: a blind actuator at 1.1.7 and a switch actuator at 1.1.8.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    write_device(dir, "1.1.7", "Blind actuator", JAL, "Living room")?;
    write_device(dir, "1.1.8", "Switch actuator", AKK, "Kitchen")?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    Ok(())
}

/// One running server plus its mock line.
struct Harness {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
    gateway: MockGateway,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// Starts `devices` on a mock line and a programming-tier server over
    /// the model of [`write_model`].
    async fn start(devices: Vec<MockDevice>) -> anyhow::Result<Harness> {
        let dir = tempfile::tempdir()?;
        let model = dir.path().join("knx");
        write_model(&model)?;
        // SAFETY: nextest runs each test in its own process, and every test in
        // this module sets these before the server starts; they are read when
        // a management connection, a probe or a wait is set up.
        unsafe {
            std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
            std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
            std::env::set_var(bussard_service::scan::DISCOVERY_MS_ENV, "150");
            std::env::set_var(bussard_service::assign::WAIT_MS_ENV, "400");
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
            viz_listen: None,
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
            _dir: dir,
        })
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
        let mut last = Value::Null;
        for _ in 0..400 {
            let status = self.call("knx_job_status", json!({"job": job})).await?;
            if until(&status) {
                return Ok(status);
            }
            last = status;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        anyhow::bail!("job {job} never reached the expected state: {last}")
    }

    /// Asks for the plan of line 1.1, says yes, and returns the job.
    async fn start_run(&self) -> anyhow::Result<String> {
        let plan = self
            .call("knx_commission_line", json!({"line": "1.1"}))
            .await?;
        assert_eq!(plan["step"], "plan", "{plan}");
        assert_eq!(plan["total"], 2, "{plan}");
        assert!(
            plan["question"]
                .as_str()
                .unwrap_or_default()
                .contains("One yes covers every device"),
            "{plan}"
        );
        let digest = plan["plan_digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))?
            .to_string();
        let started = self
            .call(
                "knx_commission_line",
                json!({"line": "1.1", "plan_digest": digest, "yes": true}),
            )
            .await?;
        assert_eq!(started["started"], true, "{started}");
        Ok(started["job"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no job in {started}"))?
            .to_string())
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        drop(self.gateway);
        Ok(())
    }
}

/// Whether the job asks to press the button on device `position`.
fn asks_for(status: &Value, position: u64) -> bool {
    status["step"] == "press_button"
        && status["question"].is_string()
        && status["progress"]["device"]["position"] == position
}

#[tokio::test]
async fn test_knx_commission_line_assigns_each_device_in_turn_with_one_yes() -> anyhow::Result<()> {
    let h = Harness::start(vec![
        bench("15.15.250", JAL, 1, true)?,
        bench("15.15.251", AKK, 2, false)?,
    ])
    .await?;

    // A yes without this session's plan is refused, and nothing starts.
    let refused = h
        .call(
            "knx_commission_line",
            json!({"line": "1.1", "plan_digest": "sha256:00", "yes": true}),
        )
        .await?;
    assert_eq!(refused["refused"], true, "{refused}");

    let job = h.start_run().await?;
    // Device 1 is in programming mode already: the job identifies it, finds
    // the model's order number and assigns it without asking again. Then it
    // asks for device 2 by name, room and order number, and waits.
    let second = h
        .poll(&job, |s| asks_for(s, 2) || s["done"] == true)
        .await?;
    assert!(asks_for(&second, 2), "{second}");
    assert!(
        second["question"]
            .as_str()
            .unwrap_or_default()
            .contains("press the programming button on Switch actuator in Kitchen (AKK-0216.03)"),
        "{second}"
    );
    let first = &second["progress"]["devices"][0];
    assert_eq!(first["status"], "commissioned", "{second}");
    assert_eq!(first["step"], "assigned", "{second}");
    assert_eq!(first["identified"]["order_check"], "matches", "{second}");
    assert_eq!(first["identified"]["serial"], "008300000001", "{second}");
    assert_eq!(first["readback"]["verified"], true, "{second}");
    assert!(h.gateway.with_device(ia("1.1.7")?, |_| ()).is_ok());

    // Nobody pressed it within the wait: the job waits for the human's word.
    let waiting = h
        .poll(&job, |s| s["waiting"].is_object() || s["done"] == true)
        .await?;
    assert_eq!(waiting["step"], "press_button", "{waiting}");
    assert!(
        waiting["waiting"]["reason"]
            .as_str()
            .unwrap_or_default()
            .starts_with("No device entered programming mode"),
        "{waiting}"
    );
    // The human presses the button and says retry.
    h.gateway
        .with_device(ia("15.15.251")?, |dev| dev.programming = true)?;
    let resumed = h
        .call(
            "knx_commission_line",
            json!({"job": job, "answer": "retry"}),
        )
        .await?;
    assert_eq!(resumed["resumed"], true, "{resumed}");

    let done = h.poll(&job, |s| s["done"] == true).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], true, "{done}");
    assert_eq!(result["commissioned"], 2, "{done}");
    assert_eq!(
        result["labels"],
        json!([
            "1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room",
            "1.1.8  Switch actuator  MDT AKK-0216.03  Ground floor / Kitchen",
        ]),
        "{done}"
    );
    assert!(
        result["summary"]
            .as_str()
            .unwrap_or_default()
            .starts_with("Line 1.1: commissioned Blind actuator, Switch actuator"),
        "{done}"
    );
    assert!(h.gateway.with_device(ia("1.1.8")?, |_| ()).is_ok());
    // Neither device is left in programming mode.
    let devices = h.gateway.devices()?;
    assert!(devices.iter().all(|d| !d.programming), "{devices:?}");
    h.stop().await
}

#[tokio::test]
async fn test_knx_commission_line_pauses_on_a_mismatch_and_skips_on_the_humans_word()
-> anyhow::Result<()> {
    // The bench device is the SECOND model device's product, not the first's.
    let h = Harness::start(vec![bench("15.15.255", AKK, 9, true)?]).await?;
    let job = h.start_run().await?;
    let waiting = h
        .poll(&job, |s| s["waiting"].is_object() || s["done"] == true)
        .await?;
    assert_eq!(waiting["step"], "identified", "{waiting}");
    let reason = waiting["waiting"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(AKK) && reason.contains(JAL) && reason.contains("Nothing was written"),
        "{reason}"
    );
    assert_eq!(waiting["waiting"]["identified"]["order_check"], "refused");
    assert!(
        waiting["question"]
            .as_str()
            .unwrap_or_default()
            .contains("Say retry"),
        "{waiting}"
    );
    // Nothing was written: the device still answers at its factory address.
    assert!(h.gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());

    // `assign` is not an answer to a mismatch.
    let wrong = h
        .call(
            "knx_commission_line",
            json!({"job": job, "answer": "assign"}),
        )
        .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");

    let skipped = h
        .call("knx_commission_line", json!({"job": job, "answer": "skip"}))
        .await?;
    assert_eq!(skipped["resumed"], true, "{skipped}");
    // The run goes on: the pressed device is the switch actuator's product.
    let done = h.poll(&job, |s| s["done"] == true).await?;
    let result = &done["result"];
    assert_eq!(result["ok"], false, "one device was skipped: {done}");
    assert_eq!(result["failed"], 1, "{done}");
    assert_eq!(result["commissioned"], 1, "{done}");
    assert_eq!(result["devices"][0]["status"], "failed", "{done}");
    assert!(
        result["devices"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .starts_with("skipped on the human's word"),
        "{done}"
    );
    assert_eq!(
        result["labels"],
        json!(["1.1.8  Switch actuator  MDT AKK-0216.03  Ground floor / Kitchen"]),
        "{done}"
    );
    assert!(h.gateway.with_device(ia("1.1.8")?, |_| ()).is_ok());
    h.stop().await
}

#[tokio::test]
async fn test_knx_commission_line_skips_a_present_device_and_stops_on_the_humans_word()
-> anyhow::Result<()> {
    // The blind actuator answers at its address already; nothing is pressed.
    let h = Harness::start(vec![bench("1.1.7", JAL, 3, false)?]).await?;
    let job = h.start_run().await?;
    let asking = h
        .poll(&job, |s| asks_for(s, 2) || s["done"] == true)
        .await?;
    assert!(asks_for(&asking, 2), "{asking}");
    assert_eq!(
        asking["progress"]["devices"][0]["status"], "present",
        "{asking}"
    );

    // Stop: at once while the job waits for the button, or, when the wait
    // ran out first and the job waits for the human's word, with the answer.
    let stopping = h
        .call("knx_commission_line", json!({"job": job, "answer": "stop"}))
        .await?;
    let done = if stopping["stopping"] == true {
        h.poll(&job, |s| s["done"] == true).await?["result"].clone()
    } else {
        stopping
    };
    let result = &done;
    assert_eq!(result["stopped"], true, "{done}");
    assert_eq!(result["ok"], false, "{done}");
    assert_eq!(result["present"], 1, "{done}");
    assert_eq!(
        result["not_reached"][0]["name"], "Switch actuator",
        "{done}"
    );
    assert_eq!(result["labels"], json!([]), "{done}");
    h.stop().await
}
