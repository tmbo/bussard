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
use bussard_transport::TransportKind;
use bussard_transport::knxnet::{self, ServiceType};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
use tokio::net::UdpSocket;

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

/// A device-info DIB plus a tunnelling-info DIB with two slots, one in use.
fn description_body() -> Vec<u8> {
    let mut body = vec![0u8; 54];
    body[0] = 54;
    body[1] = 0x01;
    body[2] = 0x02;
    body[4..6].copy_from_slice(&0x1000u16.to_be_bytes());
    body[24..33].copy_from_slice(b"Mock Gate");
    body.extend_from_slice(&[12, 0x07, 0x00, 0xF8]);
    body.extend_from_slice(&[0x10, 0xF1, 0x00, 0x06]); // in use
    body.extend_from_slice(&[0x10, 0xF2, 0x00, 0x07]); // free
    body
}

#[tokio::test]
async fn test_knx_audit_live_reports_tunnel_slots() -> TestResult {
    let gw = UdpSocket::bind("127.0.0.1:0").await?;
    let std::net::SocketAddr::V4(addr) = gw.local_addr()? else {
        return Err("expected an IPv4 mock".into());
    };
    let mock = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = gw.recv_from(&mut buf).await {
            let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                continue;
            };
            // The live audit may only ever ask the interface to describe itself.
            assert_eq!(parsed.service, ServiceType::DescriptionRequest);
            let reply = knxnet::frame(ServiceType::DescriptionResponse, &description_body());
            let _ = gw.send_to(&reply, peer).await;
        }
    });

    let report = call_audit(server(false, Some(addr))?, json!({ "live": true })).await??;
    mock.abort();

    let gateway = &report["live"]["gateway"];
    assert_eq!(gateway["name"], "Mock Gate");
    assert_eq!(gateway["tunnels"], 2);
    assert_eq!(gateway["tunnels_in_use"], 1);
    assert!(report["live"]["scan"].is_null());
    assert_eq!(report["live"]["traffic"]["telegrams"], 0);
    Ok(())
}
