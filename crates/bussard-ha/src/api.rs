//! A small client for the Home Assistant REST API (issue #280).
//!
//! Only what the MCP server's Home Assistant tier needs: the status reads
//! (`GET /api/`, `/api/config`, `/api/states`, the config entries) and one
//! service call, `knx.reload`. The client is blocking ([`ureq`]); async
//! callers run it on a blocking thread.
//!
//! The token is held in the client and sent as a bearer header, which
//! [`ureq`] redacts from its own logs. It never appears in an error, a
//! `Debug` rendering or a status: every error message is built here and
//! scrubbed of the token before it is returned.

use std::collections::BTreeMap;
use std::time::Duration;

use bussard_model::schema::HomeAssistantConfig;
use serde::Serialize;
use serde_json::Value;

/// How long one request may take before it counts as unreachable.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The entity domains the KNX integration's YAML can produce.
pub const KNX_DOMAINS: [&str; 6] = [
    "switch",
    "light",
    "cover",
    "climate",
    "sensor",
    "binary_sensor",
];

/// An error talking to Home Assistant. No variant carries the token.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The token's environment variable is unset or empty.
    #[error(
        "the Home Assistant token is not set: export {var} or put it in the model's .env \
         (a .env supplies only BUSSARD_* names)"
    )]
    MissingToken {
        /// The variable name (never its value).
        var: String,
    },
    /// The configured URL is not `http://` or `https://`.
    #[error("home_assistant.url must start with http:// or https://, got {url}")]
    BadUrl {
        /// The configured URL.
        url: String,
    },
    /// Home Assistant rejected the token.
    #[error("Home Assistant rejected the token on {path} (HTTP {status}); check {var}")]
    Unauthorized {
        /// The request path.
        path: String,
        /// 401 or 403.
        status: u16,
        /// The token variable name.
        var: String,
    },
    /// Any other HTTP error status.
    #[error("Home Assistant answered {path} with HTTP {status}")]
    Status {
        /// The request path.
        path: String,
        /// The status code.
        status: u16,
    },
    /// The request did not complete (connection refused, DNS, timeout, TLS).
    #[error("Home Assistant is not reachable at {url}: {message}")]
    Transport {
        /// The base URL.
        url: String,
        /// What failed, scrubbed of the token.
        message: String,
    },
    /// The body was not the JSON expected.
    #[error("Home Assistant answered {path} with a body bussard cannot read: {message}")]
    Decode {
        /// The request path.
        path: String,
        /// What was wrong.
        message: String,
    },
}

/// A Home Assistant REST API client.
pub struct HaClient {
    base: String,
    token: String,
    token_env: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HaClient")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .field("token_env", &self.token_env)
            .finish()
    }
}

impl HaClient {
    /// A client for `config`, with the token read from `config.token_env`
    /// through [`bussard_model::dotenv::var`] (the process environment, then
    /// the installed `.env` values).
    ///
    /// # Errors
    ///
    /// [`ApiError::MissingToken`] when the variable is unset or empty,
    /// [`ApiError::BadUrl`] for a URL that is not HTTP(S).
    pub fn from_config(config: &HomeAssistantConfig) -> Result<Self, ApiError> {
        let token = bussard_model::dotenv::var(&config.token_env)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ApiError::MissingToken {
                var: config.token_env.clone(),
            })?;
        Self::new(&config.url, token, &config.token_env)
    }

    /// A client for `url` with `token`; `token_env` names where the token
    /// came from, for error messages.
    ///
    /// # Errors
    ///
    /// [`ApiError::BadUrl`] for a URL that is not HTTP(S).
    pub fn new(url: &str, token: String, token_env: &str) -> Result<Self, ApiError> {
        let base = url.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(ApiError::BadUrl {
                url: url.to_string(),
            });
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(REQUEST_TIMEOUT)
            .redirects(0)
            .build();
        Ok(HaClient {
            base,
            token,
            token_env: token_env.to_string(),
            agent,
        })
    }

    /// The base URL, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `GET path`, decoded as JSON.
    ///
    /// # Errors
    ///
    /// Any [`ApiError`] but the token and URL ones.
    pub fn get_json(&self, path: &str) -> Result<Value, ApiError> {
        let request = self
            .agent
            .get(&format!("{}{path}", self.base))
            .set("Authorization", &format!("Bearer {}", self.token));
        self.finish(path, request.call())
    }

    /// `POST path` with a JSON `body`, decoded as JSON.
    ///
    /// # Errors
    ///
    /// Any [`ApiError`] but the token and URL ones.
    pub fn post_json(&self, path: &str, body: &Value) -> Result<Value, ApiError> {
        let request = self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json");
        self.finish(path, request.send_string(&body.to_string()))
    }

    /// Calls the `knx.reload` service: Home Assistant re-reads the KNX YAML.
    ///
    /// # Errors
    ///
    /// Any [`ApiError`] but the token and URL ones.
    pub fn reload_knx(&self) -> Result<(), ApiError> {
        self.post_json(
            "/api/services/knx/reload",
            &Value::Object(Default::default()),
        )
        .map(|_| ())
    }

    /// Reads what the REST API tells about Home Assistant and its KNX
    /// integration. Never fails: what could not be read is `None` or listed
    /// in [`HaStatus::errors`].
    pub fn status(&self) -> HaStatus {
        let mut status = HaStatus {
            url: self.base.clone(),
            reachable: false,
            authorized: false,
            version: None,
            location_name: None,
            knx_loaded: None,
            knx_entries: None,
            entity_counts: BTreeMap::new(),
            total_entities: None,
            entities: Vec::new(),
            errors: Vec::new(),
        };
        match self.get_json("/api/") {
            Ok(_) => {
                status.reachable = true;
                status.authorized = true;
            }
            Err(err) => {
                status.reachable = !matches!(err, ApiError::Transport { .. });
                status.errors.push(err.to_string());
                return status;
            }
        }
        match self.get_json("/api/config") {
            Ok(config) => {
                status.version = config["version"].as_str().map(str::to_string);
                status.location_name = config["location_name"].as_str().map(str::to_string);
                status.knx_loaded = config["components"]
                    .as_array()
                    .map(|list| list.iter().any(|c| c.as_str() == Some("knx")));
            }
            Err(err) => status.errors.push(err.to_string()),
        }
        match self.get_json("/api/config/config_entries/entry") {
            Ok(entries) => {
                status.knx_entries = entries.as_array().map(|list| {
                    list.iter()
                        .filter(|e| e["domain"].as_str() == Some("knx"))
                        .map(|e| KnxEntry {
                            title: e["title"].as_str().unwrap_or_default().to_string(),
                            state: e["state"].as_str().unwrap_or_default().to_string(),
                        })
                        .collect()
                });
            }
            // An older Home Assistant or a non-admin token: say so, go on.
            Err(err) => status.errors.push(err.to_string()),
        }
        match self.get_json("/api/states") {
            Ok(states) => {
                let list = states.as_array().cloned().unwrap_or_default();
                status.total_entities = Some(list.len());
                for state in &list {
                    let Some(entity_id) = state["entity_id"].as_str() else {
                        continue;
                    };
                    let domain = entity_id.split('.').next().unwrap_or_default();
                    if !KNX_DOMAINS.contains(&domain) {
                        continue;
                    }
                    *status.entity_counts.entry(domain.to_string()).or_insert(0) += 1;
                    status.entities.push(HaEntity {
                        entity_id: entity_id.to_string(),
                        domain: domain.to_string(),
                        friendly_name: state["attributes"]["friendly_name"]
                            .as_str()
                            .map(str::to_string),
                    });
                }
            }
            Err(err) => status.errors.push(err.to_string()),
        }
        status
    }

    /// Turns a ureq result into JSON or an [`ApiError`] without the token.
    fn finish(
        &self,
        path: &str,
        result: Result<ureq::Response, ureq::Error>,
    ) -> Result<Value, ApiError> {
        match result {
            Ok(response) => {
                let text = response.into_string().map_err(|e| ApiError::Decode {
                    path: path.to_string(),
                    message: self.scrub(&e.to_string()),
                })?;
                if text.trim().is_empty() {
                    return Ok(Value::Null);
                }
                serde_json::from_str(&text).map_err(|e| ApiError::Decode {
                    path: path.to_string(),
                    message: self.scrub(&e.to_string()),
                })
            }
            Err(ureq::Error::Status(status @ (401 | 403), _)) => Err(ApiError::Unauthorized {
                path: path.to_string(),
                status,
                var: self.token_env.clone(),
            }),
            Err(ureq::Error::Status(status, _)) => Err(ApiError::Status {
                path: path.to_string(),
                status,
            }),
            Err(ureq::Error::Transport(transport)) => {
                let message = match transport.message() {
                    Some(detail) => format!("{}: {detail}", transport.kind()),
                    None => transport.kind().to_string(),
                };
                Err(ApiError::Transport {
                    url: self.base.clone(),
                    message: self.scrub(&message),
                })
            }
        }
    }

    /// `text` with every occurrence of the token replaced.
    fn scrub(&self, text: &str) -> String {
        if self.token.is_empty() {
            text.to_string()
        } else {
            text.replace(&self.token, "<redacted>")
        }
    }
}

/// One KNX config entry of Home Assistant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KnxEntry {
    /// The entry title.
    pub title: String,
    /// The entry state, e.g. `loaded`.
    pub state: String,
}

/// One entity of a KNX-capable domain, from `/api/states`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaEntity {
    /// The entity id, e.g. `light.kueche`.
    pub entity_id: String,
    /// The domain, e.g. `light`.
    pub domain: String,
    /// The friendly name, which for a YAML KNX entity is its `name`.
    pub friendly_name: Option<String>,
}

/// What the REST API tells about Home Assistant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaStatus {
    /// The base URL.
    pub url: String,
    /// Whether Home Assistant answered at all.
    pub reachable: bool,
    /// Whether it accepted the token.
    pub authorized: bool,
    /// The Home Assistant version.
    pub version: Option<String>,
    /// The installation's location name.
    pub location_name: Option<String>,
    /// Whether `knx` is among the loaded components (`None`: unknown).
    pub knx_loaded: Option<bool>,
    /// The KNX config entries (`None`: the endpoint could not be read).
    pub knx_entries: Option<Vec<KnxEntry>>,
    /// Entities per KNX-capable domain (of any integration).
    pub entity_counts: BTreeMap<String, usize>,
    /// All entities, of any domain.
    pub total_entities: Option<usize>,
    /// The entities of KNX-capable domains, for matching against the YAML.
    #[serde(skip)]
    pub entities: Vec<HaEntity>,
    /// What could not be read, one line each.
    pub errors: Vec<String>,
}

impl HaStatus {
    /// Whether Home Assistant runs an entity of `platform` named `name`.
    pub fn runs(&self, platform: &str, name: &str) -> bool {
        self.entities
            .iter()
            .any(|e| e.domain == platform && e.friendly_name.as_deref() == Some(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_testkit::{MockHaConfig, MockHomeAssistant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TOKEN: &str = "test-token-3f9a";

    #[test]
    fn test_status_reads_the_mock() -> TestResult {
        let mock = MockHomeAssistant::start(
            MockHaConfig::new(TOKEN)
                .with_entities(&[("light.kueche", "Küche"), ("sun.sun", "Sun")]),
        )?;
        let client = HaClient::new(&mock.url(), TOKEN.to_string(), "BUSSARD_HA_TOKEN")?;
        let status = client.status();
        assert!(status.reachable && status.authorized, "{status:?}");
        assert_eq!(status.version.as_deref(), Some("2026.9.2"));
        assert_eq!(status.knx_loaded, Some(true));
        assert_eq!(status.knx_entries.as_ref().map(Vec::len), Some(1));
        assert_eq!(status.entity_counts.get("light"), Some(&1));
        assert_eq!(status.total_entities, Some(2));
        assert!(status.runs("light", "Küche"));
        assert!(status.errors.is_empty(), "{:?}", status.errors);
        Ok(())
    }

    #[test]
    fn test_status_wrong_token_is_unauthorized_without_the_token() -> TestResult {
        let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
        let wrong = "wrong-token-77c1";
        let client = HaClient::new(&mock.url(), wrong.to_string(), "BUSSARD_HA_TOKEN")?;
        let status = client.status();
        assert!(status.reachable && !status.authorized);
        let rendered = format!("{status:?} {client:?}");
        assert!(!rendered.contains(wrong), "{rendered}");
        assert!(
            status.errors[0].contains("rejected the token"),
            "{status:?}"
        );
        Ok(())
    }

    #[test]
    fn test_status_unreachable() -> TestResult {
        // Port 9 (discard) on loopback: nothing listens.
        let client = HaClient::new("http://127.0.0.1:9", TOKEN.to_string(), "X")?;
        let status = client.status();
        assert!(!status.reachable);
        assert!(status.errors[0].contains("not reachable"), "{status:?}");
        Ok(())
    }

    #[test]
    fn test_reload_knx_calls_the_service() -> TestResult {
        let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
        let client = HaClient::new(&mock.url(), TOKEN.to_string(), "BUSSARD_HA_TOKEN")?;
        client.reload_knx()?;
        assert_eq!(mock.reloads(), 1);
        Ok(())
    }

    #[test]
    fn test_new_refuses_a_non_http_url() {
        assert!(matches!(
            HaClient::new("ftp://x", TOKEN.to_string(), "X"),
            Err(ApiError::BadUrl { .. })
        ));
    }
}
