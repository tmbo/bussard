//! `knx_import_file` and `knx_export` (issues #743, #744) over an in-process
//! duplex transport against a model in a temporary directory. Files only: no
//! bus is wired, so no gateway is contacted.

use std::path::Path;
use std::sync::Arc;

use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_project::KeyStore;
use bussard_secure::Key16;
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

/// The keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-password-7f3a";
/// The SYNTHETIC group key of 1/0/4.
const GROUP_KEY: [u8; 16] = [0x42; 16];

/// A small model: two group addresses and one device linking them.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("bussard.toml"), "")?;
    std::fs::write(
        dir.join("groups.toml"),
        "project = \"Demo\"\ngroups = [\n  { address = \"1/0/1\", name = \"Kitchen light\", \
         dpt = \"1.001\" },\n  { address = \"1/0/4\", name = \"Hall light\", dpt = \"1.001\", \
         secure = true },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Actuator\"\n\n[links]\n12.listen = [\"1/0/1\"]\n",
    )?;
    Ok(())
}

/// The server over the model in `dir`.
fn server_over(dir: &Path, no_model_edits: bool) -> anyhow::Result<BussardMcp> {
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
        allow_writes: false,
        no_model_edits,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
        keyring: None,
        home_assistant: None,
        jobs: Default::default(),
    });
    Ok(BussardMcp::new(state))
}

/// A connected client and the server task.
async fn connect(
    server: BussardMcp,
) -> anyhow::Result<(RunningService<RoleClient, ()>, tokio::task::JoinHandle<()>)> {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

/// Calls one tool and returns its structured result.
async fn call(
    client: &RunningService<RoleClient, ()>,
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

/// Asserts that `text` carries neither the password nor the group key in
/// any of the spellings a keyring or a debug print would use.
fn assert_no_secret(what: &str, text: &str) {
    let hex_lower: String = GROUP_KEY.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex_lower.to_uppercase();
    // Base64 of sixteen 0x42 bytes; a byte list as Debug prints it.
    let base64 = "QkJCQkJCQkJCQkJCQkJCQg";
    let bytes = "66, 66, 66, 66";
    for secret in [PASSWORD, &hex_lower, &hex_upper, base64, bytes] {
        assert!(!text.contains(secret), "{what} leaks {secret:?}: {text}");
    }
}

/// Writes a `.knxkeys` holding the group key of 1/0/4 under [`PASSWORD`].
fn write_keyring(path: &Path) -> anyhow::Result<()> {
    let mut store = KeyStore::new("Demo");
    store
        .group_keys
        .insert("1/0/4".parse()?, Key16::new(GROUP_KEY));
    let export = store.export_knxkeys(PASSWORD)?;
    std::fs::write(path, export.xml)?;
    Ok(())
}

#[tokio::test]
async fn test_knx_export_writes_each_form() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir)?;
    let (client, task) = connect(server_over(&dir, true)?).await?;

    let bundle_path = tmp.path().join("handover.bussard");
    let bundle = call(
        &client,
        "knx_export",
        json!({"what": "bundle", "out": bundle_path}),
    )
    .await?;
    assert_eq!(bundle["ok"], true, "{bundle}");
    assert!(bundle_path.is_file(), "{bundle}");
    assert!(
        bundle["summary"]
            .as_str()
            .is_some_and(|s| s.starts_with("Wrote the bundle") && s.contains("2 group address")),
        "{bundle}"
    );

    // The alias writes the same form.
    let alias_path = tmp.path().join("alias.bussard");
    let alias = call(&client, "knx_export_bundle", json!({"path": alias_path})).await?;
    assert_eq!(alias["ok"], true, "{alias}");
    assert!(
        alias_path.is_file() && alias["manifest"].is_object(),
        "{alias}"
    );

    let csv = tmp.path().join("groups.csv");
    let groups = call(&client, "knx_export", json!({"what": "groups", "out": csv})).await?;
    assert_eq!(groups["ok"], true, "{groups}");
    assert_eq!(groups["count"], 2, "{groups}");
    assert!(std::fs::read_to_string(&csv)?.contains("Kitchen light"));

    let xml = tmp.path().join("groups.xml");
    let groups = call(
        &client,
        "knx_export",
        json!({"what": "groups", "out": xml, "format": "ets-xml"}),
    )
    .await?;
    assert_eq!(groups["format"], "ETS XML", "{groups}");
    assert!(std::fs::read_to_string(&xml)?.contains("GroupAddress"));

    let docs = tmp.path().join("docs");
    let doc = call(&client, "knx_export", json!({"what": "doc", "out": docs})).await?;
    assert_eq!(doc["ok"], true, "{doc}");
    let files = doc["files"].as_array().map_or(0, Vec::len);
    assert!(files > 0, "{doc}");
    assert!(docs.is_dir());

    let missing = call(&client, "knx_export", json!({"what": "groups"})).await?;
    assert_eq!(missing["refused"], true, "{missing}");
    let unknown = call(&client, "knx_export", json!({"what": "everything"})).await?;
    assert_eq!(unknown["refused"], true, "{unknown}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_import_file_keyring_never_returns_key_material() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir)?;
    let keyring = tmp.path().join("export.knxkeys");
    write_keyring(&keyring)?;
    let (client, task) = connect(server_over(&dir, false)?).await?;

    let imported = call(
        &client,
        "knx_import_file",
        json!({"path": keyring, "password": PASSWORD}),
    )
    .await?;
    assert_eq!(imported["ok"], true, "{imported}");
    assert_eq!(imported["kind"], "keyring", "{imported}");
    assert!(
        imported["summary"]
            .as_str()
            .is_some_and(|s| s.contains("1 group key(s) added")),
        "{imported}"
    );
    assert_no_secret("the import result", &imported.to_string());
    let store =
        KeyStore::load(&dir, PASSWORD)?.ok_or_else(|| anyhow::anyhow!("no key store written"))?;
    assert!(store.group_key("1/0/4".parse()?).is_some());

    // A wrong password is refused without echoing either password.
    let wrong = call(
        &client,
        "knx_import_file",
        json!({"path": keyring, "password": "not-the-password-91c2"}),
    )
    .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");
    assert!(
        !wrong.to_string().contains("not-the-password-91c2"),
        "{wrong}"
    );
    assert_no_secret("the refusal", &wrong.to_string());

    // The export reads its file back and reports addresses and counts only.
    let out = tmp.path().join("handover.knxkeys");
    let exported = call(
        &client,
        "knx_export",
        json!({"what": "keyring", "out": out, "password": PASSWORD}),
    )
    .await?;
    assert_eq!(exported["ok"], true, "{exported}");
    assert_eq!(exported["verified"], true, "{exported}");
    assert_eq!(exported["group_addresses"], json!(["1/0/4"]), "{exported}");
    assert_no_secret("the export result", &exported.to_string());

    // A second export onto the same file needs force.
    let again = call(
        &client,
        "knx_export",
        json!({"what": "keyring", "out": out, "password": PASSWORD}),
    )
    .await?;
    assert_eq!(again["refused"], true, "{again}");
    assert!(
        again["reason"]
            .as_str()
            .is_some_and(|r| r.contains("force: true")),
        "{again}"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_import_file_bundle_keeps_hand_edits_until_theirs() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir)?;
    let bundle = tmp.path().join("integrator.bussard");
    bussard_service::files::export::bundle(&dir, Some(&bundle), false)?;
    // The owner renames 1/0/1 by hand after the integrator's export.
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    std::fs::write(
        dir.join("groups.toml"),
        groups.replace("Kitchen light", "Kitchen ceiling"),
    )?;
    let (client, task) = connect(server_over(&dir, false)?).await?;

    let kept = call(&client, "knx_import_file", json!({"path": bundle})).await?;
    assert_eq!(kept["ok"], true, "{kept}");
    assert_eq!(kept["kind"], "bundle", "{kept}");
    assert_eq!(kept["kept"], 1, "{kept}");
    assert!(
        kept["summary"]
            .as_str()
            .is_some_and(|s| s.contains("theirs: true")),
        "{kept}"
    );
    let name = |dir: &Path| -> anyhow::Result<String> {
        Ok(Model::load(dir)?
            .groups
            .groups
            .get(&"1/0/1".parse()?)
            .map(|g| g.name.clone())
            .unwrap_or_default())
    };
    assert_eq!(name(&dir)?, "Kitchen ceiling");

    let taken = call(
        &client,
        "knx_import_file",
        json!({"path": bundle, "theirs": true}),
    )
    .await?;
    assert_eq!(taken["ok"], true, "{taken}");
    assert_eq!(name(&dir)?, "Kitchen light", "{taken}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_import_file_order_number_needs_download_consent() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir)?;
    let (client, task) = connect(server_over(&dir, false)?).await?;

    // An order number the committed index knows: without `download: true`
    // nothing is fetched and the result says what would be.
    let refused = call(
        &client,
        "knx_import_file",
        json!({"order_number": "AKK-01UP.03", "yes": true}),
    )
    .await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|r| r.contains("download: true")),
        "{refused}"
    );
    assert!(
        refused["sentences"].to_string().contains("AKK-01UP.03"),
        "{refused}"
    );
    assert!(!dir.join("products").exists(), "nothing was downloaded");

    let unknown = call(&client, "knx_import_file", json!({"path": "notes.txt"})).await?;
    assert_eq!(unknown["refused"], true, "{unknown}");
    let neither = call(&client, "knx_import_file", json!({})).await?;
    assert_eq!(neither["refused"], true, "{neither}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_import_file_is_withheld_by_no_model_edits() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir)?;
    let (client, task) = connect(server_over(&dir, true)?).await?;
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.iter().any(|n| n == "knx_import_file"), "{names:?}");
    assert!(names.iter().any(|n| n == "knx_export"), "{names:?}");
    client.cancel().await?;
    task.abort();
    Ok(())
}
