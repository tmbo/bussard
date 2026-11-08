//! Issue #818: the ETS project password from bussard's password form.
//!
//! A protected `.knxproj` and no password on the server: a client with
//! URL-mode elicitation (a fake chat app whose human types into the page)
//! gets the password form's URL, the human posts a wrong and then the right
//! password, bussard stores it as `BUSSARD_PROJECT_PASSWORD` in the `.env`
//! next to the model directory and runs the import. Without URL-mode
//! elicitation the tools refuse as before. No tool result carries the
//! password or the form's URL. Mock gateway on 127.0.0.1 only.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_mcp::SharedState;
use bussard_mcp::onboarding::Onboarding;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_testkit::MockGateway;
use bussard_transport::{ConnectionConfig, TransportKind};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientInfo, ElicitRequestParams,
    ElicitResult, ElicitationAction, ElicitationCapability, FormElicitationCapability,
    Implementation, InputRequest, ProtocolVersion, RequestMetaObject, UrlElicitationCapability,
};
use rmcp::service::RequestContext;
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};
use zip::write::{FileOptions, SimpleFileOptions};
use zip::{AesMode, ZipWriter};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

/// The project password of the synthetic export; a space so it
/// is written quoted.
const PASSWORD: &str = "s3cret pw-818";
/// A wrong password the human types first.
const WRONG: &str = "not-the-password-818";

/// The chat app with its human: declares URL elicitation (or not), records
/// the URLs it shows and, on accept, types `passwords` into the page one
/// after the other, recording each page it gets back.
#[derive(Clone)]
struct Human {
    url_mode: bool,
    passwords: Vec<&'static str>,
    shown: Arc<Mutex<Vec<String>>>,
    pages: Arc<Mutex<Vec<String>>>,
}

impl Human {
    fn new(url_mode: bool, passwords: Vec<&'static str>) -> Self {
        Self {
            url_mode,
            passwords,
            shown: Arc::default(),
            pages: Arc::default(),
        }
    }

    fn shown(&self) -> Vec<String> {
        self.shown.lock().map(|s| s.clone()).unwrap_or_default()
    }

    fn pages(&self) -> Vec<String> {
        self.pages.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn capabilities(&self) -> ClientCapabilities {
        let mut elicitation =
            ElicitationCapability::new().with_form(FormElicitationCapability::new());
        if self.url_mode {
            elicitation = elicitation.with_url(UrlElicitationCapability::new());
        }
        let mut capabilities = ClientCapabilities::default();
        capabilities.elicitation = Some(elicitation);
        capabilities
    }

    /// Records the URL, accepts, and types the passwords into the page on
    /// another thread (each post waits for the import).
    fn answer(&self, request: ElicitRequestParams) -> ElicitResult {
        if let ElicitRequestParams::UrlElicitationParams { url, .. } = request {
            if let Ok(mut shown) = self.shown.lock() {
                shown.push(url.clone());
            }
            let (passwords, pages) = (self.passwords.clone(), Arc::clone(&self.pages));
            std::thread::spawn(move || {
                // The page answers a GET before anything is posted.
                let _ = ureq::get(&url).call();
                for password in passwords {
                    let page = ureq::post(&url)
                        .set(
                            "Origin",
                            url.trim_end_matches('/')
                                .rsplit_once('/')
                                .map_or("", |(o, _)| o),
                        )
                        .timeout(Duration::from_secs(60))
                        .send_form(&[("password", password)])
                        .map_err(|e| e.to_string())
                        .and_then(|r| r.into_string().map_err(|e| e.to_string()))
                        .unwrap_or_else(|e| format!("post failed: {e}"));
                    if let Ok(mut pages) = pages.lock() {
                        pages.push(page);
                    }
                }
            });
        }
        ElicitResult::new(ElicitationAction::Accept)
    }
}

impl ClientHandler for Human {
    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        Ok(self.answer(request))
    }

    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            self.capabilities(),
            Implementation::new("fake-chat", "0.0.0"),
        )
    }
}

type Client = rmcp::service::RunningService<RoleClient, Human>;

/// A minimal ETS 6 project export protected with [`PASSWORD`]: one group
/// address 1/0/1.
fn protected_knxproj(path: &Path) -> Result<(), BoxError> {
    let derived = bussard_product::derive_zip_password(PASSWORD);
    let project = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21">
  <Project Id="P-0001">
    <Installations><Installation>
      <GroupAddresses><GroupRanges>
        <GroupRange Id="P-0001_GR-1" Name="Ground floor" RangeStart="2048">
          <GroupRange Id="P-0001_GR-2" Name="Lighting" RangeStart="2048">
            <GroupAddress Id="P-0001_GA-10" Address="2049" Name="Living room light" DatapointType="DPST-1-1"/>
          </GroupRange>
        </GroupRange>
      </GroupRanges></GroupAddresses>
    </Installation></Installations>
  </Project>
</KNX>"#;
    let info = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21">
  <Project Id="P-0001">
    <ProjectInformation Name="Synthetic Home" GroupAddressStyle="ThreeLevel"/>
  </Project>
</KNX>"#;
    let master = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21">
  <MasterData><Manufacturers><Manufacturer Id="M-0001" Name="Test"/></Manufacturers></MasterData>
</KNX>"#;
    let mut inner = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut inner));
        for (name, body) in [("0.xml", project), ("project.xml", info)] {
            let options: FileOptions<'_, '_, ()> =
                FileOptions::default().with_aes_encryption(AesMode::Aes256, &derived);
            zip.start_file(name, options)?;
            zip.write_all(body.as_bytes())?;
        }
        zip.finish()?;
    }
    let mut outer = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut outer));
        zip.start_file("knx_master.xml", SimpleFileOptions::default())?;
        zip.write_all(master.as_bytes())?;
        zip.start_file("P-0001.zip", SimpleFileOptions::default())?;
        zip.write_all(&inner)?;
        zip.finish()?;
    }
    std::fs::write(path, outer)?;
    Ok(())
}

/// The onboarding server on `knx` (missing), bussard on the mock gateway.
async fn start_setup(
    knx: &Path,
    gateway: std::net::SocketAddrV4,
    human: Human,
) -> Result<Client, BoxError> {
    let config = McpConfig {
        dir: knx.to_path_buf(),
        connection: ConnectionConfig::tunnel(gateway),
        passive: true,
        viz_listen: None,
        allow_writes: false,
        no_model_edits: false,
        capture_db: None,
        allow_programming: false,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(60),
        keyring: None,
        allow_home_assistant: false,
    };
    let server = BussardMcp::onboarding(Onboarding {
        config,
        resolve: Arc::new(move |_model: &Model| {
            Ok(bussard_mcp::onboarding::ResolvedConnection {
                connection: ConnectionConfig::tunnel(gateway),
                keyring: None,
                tunnel_note: None,
            })
        }),
        default_gateway: Some(gateway.to_string()),
        routing: false,
    })?;
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Ok(human.serve(client_io).await?)
}

/// The full server on the model in `dir`, no bus.
async fn start_full(dir: &Path, human: Human) -> Result<Client, BoxError> {
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
        viz: Default::default(),
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
        jobs: Default::default(),
    });
    let server = BussardMcp::new(state);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Ok(human.serve(client_io).await?)
}

/// The whole result of one call, as text, and its structured content.
async fn call(
    client: &Client,
    tool: &'static str,
    args: Value,
) -> Result<(Value, String), BoxError> {
    let Value::Object(map) = args else {
        return Err("tool arguments must be an object".into());
    };
    let result = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await?;
    let text = serde_json::to_string(&result)?;
    let value = result
        .structured_content
        .ok_or_else(|| format!("{tool} returned no structured content"))?;
    Ok((value, text))
}

/// A scratch root that is the working directory too, so the `.env` lookup
/// never reaches the crate's own directory.
fn scratch() -> Result<(tempfile::TempDir, PathBuf), BoxError> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().canonicalize()?;
    // nextest runs each test in its own process.
    std::env::set_current_dir(&root)?;
    Ok((tmp, root))
}

fn assert_no_secret(text: &str, human: &Human) {
    for secret in [PASSWORD, WRONG] {
        assert!(!text.contains(secret), "a result holds a password: {text}");
    }
    for url in human.shown() {
        assert!(
            !text.contains(&url),
            "a result holds the form's URL: {text}"
        );
        let token = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        assert!(
            !text.contains(token),
            "a result holds the form's token: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_setup_password_form_stores_env_and_imports() -> TestResult {
    let (_tmp, root) = scratch()?;
    let knx = root.join("knx");
    protected_knxproj(&root.join("home.knxproj"))?;
    let gw = MockGateway::builder()
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .start()
        .await?;
    let human = Human::new(true, vec![WRONG, PASSWORD]);
    let client = start_setup(&knx, gw.addr(), human.clone()).await?;
    let (result, text) = call(
        &client,
        "knx_setup",
        json!({"gateway": gw.addr().to_string(), "project_file": root.join("home.knxproj")}),
    )
    .await?;
    assert_eq!(result["done"], true, "{result}");
    assert_eq!(
        result["password"],
        bussard_mcp::password_form::FROM_FORM,
        "{result}"
    );
    assert_eq!(human.shown().len(), 1, "one form");
    assert!(human.shown()[0].starts_with("http://127.0.0.1:"));
    let pages = human.pages();
    assert_eq!(pages.len(), 2, "{pages:?}");
    assert!(
        pages[0].contains("does not open the project"),
        "{}",
        pages[0]
    );
    assert!(pages[1].contains("stored it in"), "{}", pages[1]);
    for page in &pages {
        assert!(!page.contains(PASSWORD) && !page.contains(WRONG), "{page}");
    }

    let env = root.join(".env");
    assert_eq!(
        std::fs::read_to_string(&env)?,
        format!("BUSSARD_PROJECT_PASSWORD='{PASSWORD}'\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&env)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }
    assert_eq!(
        bussard_model::dotenv::var("BUSSARD_PROJECT_PASSWORD")?,
        PASSWORD,
        "this process reads the stored password too"
    );
    let model = Model::load(&knx)?;
    assert!(
        model.groups.groups.contains_key(&"1/0/1".parse()?),
        "imported"
    );
    assert_no_secret(&text, &human);
    client.cancel().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_setup_without_url_elicitation_refuses() -> TestResult {
    let (_tmp, root) = scratch()?;
    let knx = root.join("knx");
    protected_knxproj(&root.join("home.knxproj"))?;
    let gw = MockGateway::builder().start().await?;
    let human = Human::new(false, vec![PASSWORD]);
    let client = start_setup(&knx, gw.addr(), human.clone()).await?;
    let (result, text) = call(
        &client,
        "knx_setup",
        json!({"gateway": gw.addr().to_string(), "project_file": root.join("home.knxproj")}),
    )
    .await?;
    assert_eq!(result["done"], false, "{result}");
    let error = result["error"].as_str().ok_or("no error")?;
    assert!(
        error.contains("put BUSSARD_PROJECT_PASSWORD=<password> in the .env"),
        "{error}"
    );
    assert!(human.shown().is_empty(), "no form was shown");
    assert!(!root.join(".env").exists(), "no .env written");
    assert!(!knx.join("bussard.toml").exists(), "nothing written");
    assert_no_secret(&text, &human);
    client.cancel().await?;
    Ok(())
}

/// A model directory with no devices and no groups.
fn write_model(dir: &Path) -> Result<(), BoxError> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("bussard.toml"), "")?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    Ok(())
}

/// The `_meta` of a request from a client speaking protocol 2026-07-28.
fn meta_2026(human: &Human) -> RequestMetaObject {
    let mut meta = RequestMetaObject::default();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_info(Implementation::new("fake-chat", "0.0.0"));
    meta.set_client_capabilities(human.capabilities());
    meta
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_import_file_password_form_multi_round_trip_replaces_env_line() -> TestResult {
    let (_tmp, root) = scratch()?;
    let knx = root.join("knx");
    write_model(&knx)?;
    let project = root.join("home.knxproj");
    protected_knxproj(&project)?;
    let env = root.join(".env");
    std::fs::write(
        &env,
        "# mine\nBUSSARD_PROJECT_PASSWORD=old\nBUSSARD_GATEWAY=127.0.0.1:3671\n",
    )?;
    let human = Human::new(true, vec![PASSWORD]);
    let client = start_full(&knx, human.clone()).await?;
    let mut args = serde_json::Map::new();
    args.insert("path".to_string(), json!(project));
    let mut params = CallToolRequestParams::new("knx_import_file").with_arguments(args.clone());
    params.meta = Some(meta_2026(&human));
    let first = client.call_tool_once(params).await?;
    let CallToolResponse::InputRequired(input) = first else {
        return Err(format!("expected input_required, got {first:?}").into());
    };
    assert!(
        human.shown().is_empty(),
        "the server sent no request itself"
    );
    let state = input.request_state.clone().ok_or("no request state")?;
    let mut responses = rmcp::model::InputResponses::new();
    for (key, request) in input.input_requests.clone().ok_or("no input requests")? {
        let InputRequest::Elicitation(request) = request else {
            return Err("not an elicitation".into());
        };
        responses.insert(key, serde_json::to_value(human.answer(request.params))?);
    }
    let mut params = CallToolRequestParams::new("knx_import_file")
        .with_arguments(args)
        .with_input_responses(responses)
        .with_request_state(state.clone());
    params.meta = Some(meta_2026(&human));
    let second = client.call_tool_once(params).await?;
    let CallToolResponse::Complete(result) = second else {
        return Err(format!("expected a result, got {second:?}").into());
    };
    // The InputRequiredResult carries the URL to the client, never to the
    // assistant; only its request state comes back in the next call.
    let text = format!(
        "{} {}",
        serde_json::to_string(&result)?,
        serde_json::to_string(&input.request_state)?
    );
    let value = result.structured_content.ok_or("no structured content")?;
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(
        value["password"],
        bussard_mcp::password_form::FROM_FORM,
        "{value}"
    );
    assert_eq!(
        std::fs::read_to_string(&env)?,
        format!("# mine\nBUSSARD_PROJECT_PASSWORD='{PASSWORD}'\nBUSSARD_GATEWAY=127.0.0.1:3671\n")
    );
    let model = Model::load(&knx)?;
    assert!(
        model.groups.groups.contains_key(&"1/0/1".parse()?),
        "imported"
    );
    assert_no_secret(&text, &human);

    // The form was single use: the same request state opens nothing.
    let mut params = CallToolRequestParams::new("knx_import_file").with_request_state(state);
    params.meta = Some(meta_2026(&human));
    let CallToolResponse::Complete(stale) = client.call_tool_once(params).await? else {
        return Err("expected a result".into());
    };
    let stale = stale.structured_content.ok_or("no structured content")?;
    assert_eq!(stale["done"], false, "{stale}");
    client.cancel().await?;
    Ok(())
}

#[test]
fn test_password_debug_output_is_redacted() {
    let request = bussard_service::setup::SetupRequest {
        password: Some(PASSWORD.to_string()),
        ..Default::default()
    };
    let args: bussard_mcp::onboarding::SetupArgs =
        serde_json::from_value(json!({"password": PASSWORD})).unwrap_or_default();
    let import: bussard_mcp::tools_files::ImportFileArgs =
        serde_json::from_value(json!({"path": "x.knxproj", "password": PASSWORD}))
            .unwrap_or_default();
    let (reply, _verdict) = tokio::sync::oneshot::channel();
    let submission = bussard_viz::password_page::Submission {
        password: bussard_secure::Password::new(PASSWORD),
        reply,
    };
    for text in [
        format!("{request:?}"),
        format!("{args:?}"),
        format!("{import:?}"),
        format!("{submission:?}"),
    ] {
        assert!(!text.contains(PASSWORD), "{text}");
    }
    assert!(format!("{args:?}").contains("<redacted>"));
}
