//! `knx_audit` over an in-process MCP client (issue #93).
//!
//! Covers the static report, the live report against a mock KNXnet/IP
//! interface on 127.0.0.1 that advertises its tunnelling slots, and the
//! refusal of `live: true` in passive mode.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_mcp::{BussardMcp, SharedState};
use bussard_model::schema::{BussardConfig, Group, Groups, Link, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_testkit::MockGateway;
use bussard_testkit::wire::description_response_body;
use bussard_transport::TransportKind;
use bussard_transport::knxnet::ServiceType;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A model with one wired GA and one sender-only GA (a finding).
fn model() -> Result<Model, Box<dyn std::error::Error>> {
    let ga = |s: &str| s.parse::<GroupAddress>();
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("1/0/1")?,
        Group {
            name: "Wired".to_string(),
            dpt: Some("1.001".parse()?),
            description: None,
            protected: false,
            secure: false,
        },
    );
    groups.insert(
        ga("1/0/2")?,
        Group {
            name: "Sender only".to_string(),
            dpt: None,
            description: None,
            protected: true,
            secure: false,
        },
    );
    let mut links = BTreeMap::new();
    links.insert(
        "1.1.1".parse::<IndividualAddress>()?,
        vec![
            Link {
                object: 1,
                name: None,
                send: Some(ga("1/0/1")?),
                listen: vec![],
            },
            Link {
                object: 2,
                name: None,
                send: Some(ga("1/0/2")?),
                listen: vec![],
            },
        ],
    );
    links.insert(
        "1.1.2".parse::<IndividualAddress>()?,
        vec![Link {
            object: 1,
            name: None,
            send: None,
            listen: vec![ga("1/0/1")?],
        }],
    );
    Ok(Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: Some("Audit".to_string()),
            imported_from: Some("audit.knxproj".to_string()),
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices: BTreeMap::new(),
    })
}

fn server(
    passive: bool,
    gateway: Option<SocketAddrV4>,
) -> Result<BussardMcp, Box<dyn std::error::Error>> {
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new("knx".into(), model()?),
        dir: "knx".into(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel).with_gateway(gateway),
        passive,
        allow_writes: false,
        no_model_edits: false,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
        keyring: None,
    });
    Ok(BussardMcp::new(state))
}

/// Calls `knx_audit` with `args` and returns the structured result, or the
/// error message when the call is refused.
async fn call_audit(
    server: BussardMcp,
    args: Value,
) -> Result<Result<Value, String>, Box<dyn std::error::Error>> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    let Value::Object(map) = args else {
        return Err("arguments must be an object".into());
    };
    let result = client
        .call_tool(CallToolRequestParams::new("knx_audit").with_arguments(map))
        .await;
    let out = match result {
        Ok(res) => Ok(res.structured_content.ok_or("no structured content")?),
        Err(err) => Err(err.to_string()),
    };
    client.cancel().await?;
    server_task.abort();
    Ok(out)
}

#[tokio::test]
async fn test_knx_audit_static_report() -> TestResult {
    let report = call_audit(server(false, None)?, json!({})).await??;
    assert_eq!(report["format_version"], 1);
    assert!(report["live"].is_null());
    let model = &report["model"];
    assert_eq!(model["project"], "Audit");
    assert_eq!(model["imported_from"], "audit.knxproj");
    assert_eq!(model["findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(model["findings"][0]["type"], "ga-no-listener");
    assert_eq!(model["findings"][0]["ga"], "1/0/2");
    assert_eq!(model["protected_group_addresses"], json!(["1/0/2"]));
    assert_eq!(model["group_addresses_without_dpt"], json!(["1/0/2"]));
    assert_eq!(report["secure"]["keyring_checked"], false);
    Ok(())
}

#[tokio::test]
async fn test_knx_audit_live_refused_in_passive_mode() -> TestResult {
    let result = call_audit(server(true, None)?, json!({ "live": true })).await?;
    let err = result.err().ok_or("live must be refused in passive mode")?;
    assert!(err.contains("passive"), "{err}");
    // The static audit still works in passive mode.
    let report = call_audit(server(true, None)?, json!({ "live": false })).await??;
    assert!(report["live"].is_null());
    Ok(())
}

#[tokio::test]
async fn test_knx_audit_live_reports_tunnel_slots() -> TestResult {
    // An interface with two tunnelling slots, one in use.
    let gw = MockGateway::builder()
        .description(description_response_body("Mock Gate", 2, 1))
        .start()
        .await?;

    let report = call_audit(server(false, Some(gw.addr()))?, json!({ "live": true })).await??;

    // The live audit may only ever ask the interface to describe itself.
    let services = gw.stats().services;
    assert!(!services.is_empty(), "the live audit sent nothing");
    assert!(
        services
            .iter()
            .all(|s| *s == ServiceType::DescriptionRequest),
        "only DESCRIPTION_REQUEST is allowed, got {services:?}"
    );

    let gateway = &report["live"]["gateway"];
    assert_eq!(gateway["name"], "Mock Gate");
    assert_eq!(gateway["tunnels"], 2);
    assert_eq!(gateway["tunnels_in_use"], 1);
    assert!(report["live"]["scan"].is_null());
    assert_eq!(report["live"]["traffic"]["telegrams"], 0);
    Ok(())
}

/// `live.secure` (issue #203): the model's Data Secure devices are probed; a
/// device answering the plain descriptor read with mask FFFF is reported as
/// activated with plain reads refused (no keyring on this server), a plain
/// device with a security block as not activated.
#[tokio::test]
async fn test_knx_audit_live_probes_secure_devices() -> TestResult {
    let dir = std::env::temp_dir().join(format!("bussard-mcp-audit-secure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "connection:\n  transport: tunnel\n",
    )?;
    std::fs::write(dir.join("groups.toml"), "groups: {}\n")?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    for (addr, activated) in [("1.1.12", true), ("1.1.13", false)] {
        std::fs::write(
            dir.join("devices").join(format!("{addr}.yaml")),
            format!(
                "address: {addr}\nname: Dev {addr}\nsecurity:\n  secure_capable: true\n  \
                 activated: {activated}\n"
            ),
        )?;
    }
    let model = Model::load(&dir)?;
    let _ = std::fs::remove_dir_all(&dir);

    let gw = MockGateway::builder()
        .keep_serving()
        .description(description_response_body("Mock Gate", 2, 0))
        .device(bussard_testkit::MockDevice::new("1.1.12".parse()?).with_data_secure([0x24; 16]))
        .device(bussard_testkit::MockDevice::new("1.1.13".parse()?))
        .start()
        .await?;
    let config = bussard_transport::ConnectionConfig::tunnel(gw.addr());
    let (handle, _task) = bussard_bus::Bus::connect(config.clone());
    let service = bussard_service::BusService::from_handle(
        config,
        handle.clone(),
        bussard_service::WritePolicy::ReadOnly,
    )?;
    if !handle
        .wait_connected(std::time::Duration::from_secs(5))
        .await
    {
        return Err("the mock bus did not connect".into());
    }
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new("knx".into(), model),
        dir: "knx".into(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::with_service(TransportKind::Tunnel, service).with_gateway(Some(gw.addr())),
        passive: false,
        allow_writes: false,
        no_model_edits: false,
        read_limiter: ReadLimiter::new(
            std::time::Duration::from_millis(1),
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
        keyring: None,
    });
    let report = call_audit(BussardMcp::new(state), json!({ "live": true })).await??;
    let _ = handle.close().await;

    let secure = &report["live"]["secure"];
    let row = |addr: &str| -> Result<Value, Box<dyn std::error::Error>> {
        Ok(secure["devices"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["address"] == addr))
            .ok_or(format!("{addr} in live.secure: {secure}"))?
            .clone())
    };
    let d12 = row("1.1.12")?;
    assert_eq!(d12["status"], "plain_reads_refused", "{secure}");
    assert_eq!(d12["activated"], true);
    assert_eq!(d12["plain_reads_refused"], true);
    assert_eq!(d12["reachable_secured"], Value::Null);
    assert_eq!(d12["in_keyring"], Value::Null);
    let d13 = row("1.1.13")?;
    assert_eq!(d13["status"], "plain", "{secure}");
    assert_eq!(d13["activated"], false);
    assert_eq!(d13["mask"], "07B0");
    Ok(())
}
