//! The relay side of an enrolment session: the [`Relay`] trait and its
//! outbound HTTP client [`HttpRelay`] (the relay API of
//! `dev/enroll-protocol.md`).
//!
//! bussard only ever calls out: it creates the session, long-polls `up`,
//! posts `down` and deletes the session. The phone-side endpoints are the
//! page's business.

use std::time::Duration;

use serde::Deserialize;

use super::{EnrollSession, Envelope, MAX_ENVELOPE_BYTES};

/// Connect timeout of every relay request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout beyond the long-poll wait.
const READ_SLACK: Duration = Duration::from_secs(15);

/// One message read from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    /// Its sequence number in its direction (from 1).
    pub seq: u64,
    /// The envelope, or `None` when the body is not one (anyone may post).
    pub envelope: Option<Envelope>,
}

/// The answer to a long poll.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelayPoll {
    /// The messages after the requested sequence number.
    pub messages: Vec<RelayMessage>,
    /// Whether the session was deleted.
    pub closed: bool,
}

/// Errors talking to a relay. None carries the owner token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    /// The relay does not know the session (expired or never created).
    #[error("the relay does not know this enrolment session (it expired, or was closed)")]
    NotFound,
    /// The relay already has a session with this id.
    #[error("the relay already has this enrolment session")]
    Exists,
    /// A limit was hit (messages per direction, envelope size).
    #[error("the relay refused: a session limit was reached (HTTP 429)")]
    Limit,
    /// Another HTTP status.
    #[error("the relay answered HTTP {status} to {what}")]
    Status {
        /// The request.
        what: &'static str,
        /// The HTTP status.
        status: u16,
    },
    /// The relay could not be reached.
    #[error("cannot reach the relay at {url}: {message}")]
    Transport {
        /// The relay base URL.
        url: String,
        /// What failed.
        message: String,
    },
    /// The relay's answer was not the documented JSON.
    #[error("the relay's answer to {what} is not the documented JSON")]
    Decode {
        /// The request.
        what: &'static str,
    },
    /// The relay URL is not `https://`, or `http://` on a loopback host.
    #[error(
        "the relay URL {0} must be https:// (plain http:// only on localhost, 127.0.0.0/8 or [::1])"
    )]
    BadUrl(String),
    /// An envelope is larger than the protocol allows.
    #[error("an envelope exceeds {MAX_ENVELOPE_BYTES} bytes")]
    TooLarge,
}

/// The relay operations bussard needs for one session.
pub trait Relay {
    /// Create the session (`PUT /v1/sessions/{sid}`).
    ///
    /// # Errors
    ///
    /// A [`RelayError`] when the relay refuses or cannot be reached.
    fn create(&self) -> Result<(), RelayError>;

    /// Long-poll `up` for messages after `after`, waiting up to `wait_secs`.
    ///
    /// # Errors
    ///
    /// [`RelayError::NotFound`] once the session expired; another
    /// [`RelayError`] when the relay refuses or cannot be reached.
    fn poll_up(&self, after: u64, wait_secs: u64) -> Result<RelayPoll, RelayError>;

    /// Post an envelope `down`; returns its sequence number.
    ///
    /// # Errors
    ///
    /// A [`RelayError`] when the relay refuses or cannot be reached.
    fn post_down(&self, envelope: &Envelope) -> Result<u64, RelayError>;

    /// Delete the session.
    ///
    /// # Errors
    ///
    /// A [`RelayError`] when the relay refuses or cannot be reached.
    fn delete(&self) -> Result<(), RelayError>;
}

/// The relay API over HTTP(S), outbound only (`ureq`, rustls).
pub struct HttpRelay {
    base: String,
    session_url: String,
    bearer: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HttpRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRelay")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct PollBody {
    messages: Vec<PollMessage>,
    #[serde(default)]
    closed: bool,
}

#[derive(Deserialize)]
struct PollMessage {
    seq: u64,
    body: serde_json::Value,
}

#[derive(Deserialize)]
struct SeqBody {
    seq: u64,
}

impl HttpRelay {
    /// The client for `session` on the relay at `base` (e.g.
    /// `https://relay.example`; a trailing slash is ignored).
    ///
    /// # Errors
    ///
    /// [`RelayError::BadUrl`] when `base` is not `https://`, or `http://`
    /// on a loopback host (finding F9: a plain-http relay on the network
    /// would expose the owner token and the session's timing).
    pub fn new(base: &str, session: &EnrollSession) -> Result<Self, RelayError> {
        let base = base.trim().trim_end_matches('/').to_string();
        let allowed = if base.starts_with("https://") {
            true
        } else if let Some(rest) = base.strip_prefix("http://") {
            is_loopback_authority(rest.split('/').next().unwrap_or_default())
        } else {
            false
        };
        if !allowed {
            return Err(RelayError::BadUrl(base));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .redirects(0)
            .build();
        Ok(HttpRelay {
            session_url: format!("{base}/v1/sessions/{}", session.session_id()),
            bearer: format!("Bearer {}", session.owner_token()),
            base,
            agent,
        })
    }

    /// The relay base URL, without a trailing slash.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    fn request(&self, method: &str, path: &str, read_timeout: Duration) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{path}", self.session_url))
            .timeout(CONNECT_TIMEOUT + read_timeout)
            .set("Authorization", &self.bearer)
    }

    fn finish(
        &self,
        what: &'static str,
        result: Result<ureq::Response, ureq::Error>,
    ) -> Result<String, RelayError> {
        match result {
            Ok(response) => response
                .into_string()
                .map_err(|_| RelayError::Decode { what }),
            Err(ureq::Error::Status(404, _)) => Err(RelayError::NotFound),
            Err(ureq::Error::Status(409, _)) => Err(RelayError::Exists),
            Err(ureq::Error::Status(429, _)) => Err(RelayError::Limit),
            Err(ureq::Error::Status(status, _)) => Err(RelayError::Status { what, status }),
            Err(ureq::Error::Transport(transport)) => Err(RelayError::Transport {
                url: self.base.clone(),
                message: match transport.message() {
                    Some(detail) => format!("{}: {detail}", transport.kind()),
                    None => transport.kind().to_string(),
                },
            }),
        }
    }
}

/// Whether a URL authority (`host[:port]`, no user info) names a loopback
/// host: `localhost`, an address in `127.0.0.0/8`, or `[::1]`.
fn is_loopback_authority(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, _)) => host,
            None => return false,
        },
        None => authority.split(':').next().unwrap_or_default(),
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

impl Relay for HttpRelay {
    fn create(&self) -> Result<(), RelayError> {
        let result = self
            .request("PUT", "", Duration::ZERO)
            .set("Content-Type", "application/json")
            .send_string("{}");
        self.finish("create the session", result).map(|_| ())
    }

    fn poll_up(&self, after: u64, wait_secs: u64) -> Result<RelayPoll, RelayError> {
        let what = "poll up";
        let wait = Duration::from_secs(wait_secs);
        let result = self
            .request(
                "GET",
                &format!("/up?after={after}&wait={wait_secs}"),
                wait + READ_SLACK,
            )
            .call();
        let text = self.finish(what, result)?;
        let body: PollBody =
            serde_json::from_str(&text).map_err(|_| RelayError::Decode { what })?;
        Ok(RelayPoll {
            messages: body
                .messages
                .into_iter()
                .map(|m| RelayMessage {
                    seq: m.seq,
                    envelope: serde_json::from_value(m.body).ok(),
                })
                .collect(),
            closed: body.closed,
        })
    }

    fn post_down(&self, envelope: &Envelope) -> Result<u64, RelayError> {
        let what = "post down";
        let body = serde_json::to_string(envelope).map_err(|_| RelayError::Decode { what })?;
        if body.len() > MAX_ENVELOPE_BYTES {
            return Err(RelayError::TooLarge);
        }
        let result = self
            .request("POST", "/down", Duration::ZERO)
            .set("Content-Type", "application/json")
            .send_string(&body);
        let text = self.finish(what, result)?;
        let seq: SeqBody = serde_json::from_str(&text).map_err(|_| RelayError::Decode { what })?;
        Ok(seq.seq)
    }

    fn delete(&self) -> Result<(), RelayError> {
        let result = self.request("DELETE", "", Duration::ZERO).call();
        self.finish("delete the session", result).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_relay_new_rejects_non_http() -> Result<(), Box<dyn std::error::Error>> {
        let session = EnrollSession::new()?;
        assert_eq!(
            HttpRelay::new("ftp://relay", &session).map(|_| ()),
            Err(RelayError::BadUrl("ftp://relay".to_string()))
        );
        let relay = HttpRelay::new("https://relay.example/", &session)?;
        assert_eq!(relay.base(), "https://relay.example");
        assert!(!format!("{relay:?}").contains("Bearer"));
        Ok(())
    }

    #[test]
    fn test_http_relay_new_allows_plain_http_only_on_loopback()
    -> Result<(), Box<dyn std::error::Error>> {
        let session = EnrollSession::new()?;
        for ok in [
            "http://127.0.0.1:8123",
            "http://127.1.2.3/",
            "http://localhost:9",
            "http://LOCALHOST",
            "http://[::1]:8123",
        ] {
            assert!(HttpRelay::new(ok, &session).is_ok(), "{ok}");
        }
        for bad in [
            "http://relay.example",
            "http://192.168.1.10:8123",
            "http://localhost.example",
            "http://127.0.0.1@relay.example",
            "http://[::2]:1",
            "http://[::1",
        ] {
            assert!(
                matches!(HttpRelay::new(bad, &session), Err(RelayError::BadUrl(_))),
                "{bad}"
            );
        }
        Ok(())
    }
}
