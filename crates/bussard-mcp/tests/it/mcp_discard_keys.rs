//! Issue #336: `knx_discard_edits` on a group address whose Data Secure
//! state the session flipped restores the key store like `knx_undo` does.
//! A group key switched off and then discarded is back in `bussard.keys`,
//! byte-identical to the pre-edit copy. Files only: no bus is wired.

use std::path::Path;
use std::sync::Arc;

use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::{GroupAddress, Model};
use bussard_project::KeyStore;
use bussard_secure::Key16;
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

/// The key store's made-up password.
const PASSWORD: &str = "synthetic-store-password";
/// The SYNTHETIC group key of 1/0/4.
const GROUP_KEY: [u8; 16] = [0x42; 16];

/// A model where 1/0/4 runs secured, linked to object 12 of the
/// Secure-capable 1.1.5, and a key store holding its group key.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/4\", name = \"Kitchen light\", dpt = \"1.001\", \
         secure = true },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Actuator\"\n\n[security]\nactivated = true\n\n\
         [links]\n12.listen = [\"1/0/4\"]\n",
    )?;
    let mut store = KeyStore::new("Synthetic");
    store
        .group_keys
        .insert("1/0/4".parse()?, Key16::new(GROUP_KEY));
    store.save(dir, PASSWORD)?;
    Ok(())
}

fn server_over(dir: &Path) -> anyhow::Result<BussardMcp> {
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
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
        home_assistant: None,
    });
    Ok(BussardMcp::new(state))
}

/// Calls one tool and returns its structured result.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &'static str,
    args: Value,
) -> anyhow::Result<Value> {
    let Value::Object(map) = args else {
        anyhow::bail!("tool arguments must be an object");
    };
    client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await?
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
}

/// The group key the store in `dir` holds for `ga`.
fn stored_key(dir: &Path, ga: GroupAddress) -> anyhow::Result<Option<Key16>> {
    let store =
        KeyStore::load(dir, PASSWORD)?.ok_or_else(|| anyhow::anyhow!("the key store is gone"))?;
    Ok(store.group_key(ga).cloned())
}

#[tokio::test]
async fn test_knx_discard_edits_restores_the_group_key_like_undo() -> anyhow::Result<()> {
    bussard_model::dotenv::install(vec![(
        bussard_service::secure::KEYRING_PASSWORD_ENV.to_string(),
        PASSWORD.to_string(),
    )]);
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let ga: GroupAddress = "1/0/4".parse()?;
    let before = std::fs::read(KeyStore::path(dir.path()))?;

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = server_over(dir.path())?;
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;

    // Switch Data Secure off: the key leaves the store.
    let off = call(
        &client,
        "knx_set_group",
        json!({"ga": "1/0/4", "secure": false}),
    )
    .await?;
    assert_eq!(off["ok"], true, "{off}");
    assert!(stored_key(dir.path(), ga)?.is_none(), "{off}");

    // Discard the group's edits: the flag and the key come back.
    let discarded = call(&client, "knx_discard_edits", json!({"group": "1/0/4"})).await?;
    assert_eq!(discarded["ok"], true, "{discarded}");
    assert_eq!(discarded["key_store"]["ok"], true, "{discarded}");
    assert!(
        Model::load(dir.path())?
            .groups
            .groups
            .get(&ga)
            .is_some_and(|g| g.secure),
        "the model marks 1/0/4 secure again"
    );
    assert!(
        stored_key(dir.path(), ga)? == Some(Key16::new(GROUP_KEY)),
        "the store holds the pre-edit group key again"
    );
    let after = KeyStore::load(dir.path(), PASSWORD)?.ok_or_else(|| anyhow::anyhow!("no store"))?;
    let original = KeyStore::parse(&String::from_utf8(before)?, PASSWORD)?;
    assert_eq!(after.group_keys.len(), original.group_keys.len());

    // Undo of the discard takes the key away again.
    let undone = call(&client, "knx_undo", json!({})).await?;
    assert_eq!(undone["ok"], true, "{undone}");
    assert!(stored_key(dir.path(), ga)?.is_none(), "{undone}");

    client.cancel().await?;
    task.abort();
    Ok(())
}
