//! In-process tests of the learn and acceptance-test MCP tools (issues #95 and
//! #101): `knx_infer_group` over a hand-fed telegram ring, and the tier and
//! protected-GA rules of `knx_run_tests`. No bus is wired, so nothing here can
//! transmit.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::schema::{
    BussardConfig, Channel, ComObject, Device, Group, Groups, Link, Links, Location,
};
use bussard_model::{Flags, LoadedDevice, Model};
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;

type R = Result<(), Box<dyn std::error::Error>>;

/// A model with one kitchen switch actuator whose com object 3 sends 1/0/1, and
/// a protected wind alarm.
fn model() -> Result<Model, Box<dyn std::error::Error>> {
    let mut groups = BTreeMap::new();
    groups.insert(
        "3/1/0".parse()?,
        Group {
            name: "Wind alarm".to_string(),
            dpt: Some("1.005".parse()?),
            protected: true,
            ..Default::default()
        },
    );
    let mut channels = BTreeMap::new();
    channels.insert(
        "A".to_string(),
        Channel {
            name: "Ceiling light".to_string(),
            key: None,
            number: None,
            text: None,
        },
    );
    let mut com_objects = BTreeMap::new();
    com_objects.insert(
        3u16,
        ComObject {
            dpt: Some("1.001".parse()?),
            size: None,
            flags: Flags::COMMUNICATION | Flags::TRANSMIT,
            reference: None,
            channel: Some("A".to_string()),
            secure: false,
            function: None,
            key: None,
            text: None,
        },
    );
    let device = Device {
        address: "1.1.30".parse()?,
        name: "Schaltaktor".to_string(),
        description: None,
        location: Some(Location {
            floor: None,
            room: Some("Kitchen".to_string()),
        }),
        product: None,
        channels,
        parameters: BTreeMap::new(),
        module_bases: BTreeMap::new(),
        com_objects,
        security: None,
        replaced: None,
        application_override: None,
        lock: Default::default(),
    };
    let mut devices = BTreeMap::new();
    devices.insert(
        device.address,
        LoadedDevice {
            device,
            file_stem: "1.1.30-schaltaktor".to_string(),
        },
    );
    let mut links = BTreeMap::new();
    links.insert(
        "1.1.30".parse()?,
        vec![Link {
            object: 3,
            name: Some("Schalten".to_string()),
            send: Some("1/0/1".parse()?),
            listen: vec![],
        }],
    );
    Ok(Model {
        config: BussardConfig::default(),
        groups: Groups {
            groups,
            ..Default::default()
        },
        links: Links { links },
        devices,
    })
}

fn server(
    dir: &Path,
    passive: bool,
    allow_writes: bool,
) -> Result<BussardMcp, Box<dyn std::error::Error>> {
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model()?),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive,
        allow_writes,
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

async fn connect(
    server: BussardMcp,
) -> Result<
    (
        rmcp::service::RunningService<rmcp::RoleClient, ()>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    let (server_io, client_io) = tokio::io::duplex(8 * 1024);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

/// Pushes a group write from `src` to `dest` carrying `payload` into the ring.
fn push(server: &BussardMcp, dest: &str, src: &str, payload: &[u8]) -> R {
    let frame = bussard_transport::TimestampedFrame {
        received_at: SystemTime::now(),
        frame: bussard_transport::cemi::CemiFrame::group_write_packed(
            dest.parse()?,
            src.parse()?,
            payload,
        ),
    };
    let model = server.state().model.current();
    let decoded = bussard_monitor::DecodedTelegram::from_frame(&frame, Some(&model));
    server.state().ring.push(decoded);
    Ok(())
}

#[tokio::test]
async fn test_knx_infer_group_uses_the_ring_and_the_model() -> R {
    let dir = tempfile::tempdir()?;
    // Passive mode: the tool must be available there, since it transmits nothing.
    let server = server(dir.path(), true, false)?;
    push(&server, "1/0/1", "1.1.30", &[1])?;
    push(&server, "1/0/1", "1.1.30", &[0])?;
    let (client, task) = connect(server).await?;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("1/0/1"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_infer_group").with_arguments(args))
        .await?;
    let out = res.structured_content.ok_or("structured result")?;

    assert_eq!(out["observations"], 2, "{out}");
    assert_eq!(out["sender"]["address"], "1.1.30", "{out}");
    assert_eq!(out["sender"]["name"], "Schaltaktor", "{out}");
    assert_eq!(out["com_object"]["index"], 3, "{out}");
    assert_eq!(out["com_object"]["declared_dpt"], "1.001", "{out}");
    assert_eq!(out["channel"]["name"], "Ceiling light", "{out}");
    // The declared DPT leads with high confidence.
    assert_eq!(out["candidates"][0]["dpt"], "1.001", "{out}");
    assert_eq!(out["candidates"][0]["confidence"], "high", "{out}");
    assert_eq!(
        out["proposed_name"], "Kitchen ceiling light, schalten",
        "{out}"
    );
    let next = out["next_step"].as_str().ok_or("next_step")?;
    assert!(next.contains("knx_set_group") && next.contains("knx_add_link"));

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_infer_group_explicit_payload_never_claims_high() -> R {
    let dir = tempfile::tempdir()?;
    let (client, task) = connect(server(dir.path(), false, false)?).await?;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("2/0/0"));
    args.insert("payload_hex".to_string(), serde_json::json!("32"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_infer_group").with_arguments(args))
        .await?;
    let out = res.structured_content.ok_or("structured result")?;
    assert_eq!(out["candidates"][0]["dpt"], "5.001", "{out}");
    let candidates = out["candidates"].as_array().ok_or("candidates")?;
    assert!(
        candidates.iter().all(|c| c["confidence"] != "high"),
        "shape alone is never certain: {out}"
    );
    assert!(out["sender"].is_null(), "{out}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_run_tests_names_protected_tests_it_refuses() -> R {
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("tests.toml"),
        // The file opts in, but MCP never honours the opt-in.
        "allow_protected = true\n\n\
         [[tests]]\n\
         name = \"Wind alarm\"\n\
         write = { ga = \"3/1/0\", value = \"alarm\" }\n\
         expect = { ga = \"3/1/1\" }\n",
    )?;
    let (client, task) = connect(server(dir.path(), false, true)?).await?;

    let res = client
        .call_tool(CallToolRequestParams::new("knx_run_tests"))
        .await?;
    let out = res.structured_content.ok_or("structured result")?;
    // No bus is wired here, so nothing ran; the refusal is still named.
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(out["refused_protected"][0], "Wind alarm", "{out}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_run_tests_absent_without_allow_writes() -> R {
    let dir = tempfile::tempdir()?;
    let (client, task) = connect(server(dir.path(), false, false)?).await?;
    let tools = client.list_all_tools().await?;
    assert!(tools.iter().all(|t| t.name != "knx_run_tests"));
    assert!(tools.iter().any(|t| t.name == "knx_infer_group"));
    client.cancel().await?;
    task.abort();
    Ok(())
}
