//! The KNXnet/IP Secure idle-timeout probe (issue #197).
//!
//! The KNX specification lets an interface drop a secure session that has
//! been idle for its session timeout (60 s in the specification); bussard's
//! keepalive interval (30 s) is INFERRED from that. [`probe_secure_idle`]
//! measures the real value read-only: it opens a secure session (no tunnel,
//! no CONNECT, so no slot and no bus traffic), sends nothing for the idle
//! period while it watches for the interface ending the session, then sends
//! one wrapped CONNECTIONSTATE_REQUEST for a channel it does not hold. A live
//! session answers that (with `E_CONNECTION_ID`); a dropped one answers
//! nothing, a plain SESSION_STATUS, or closes the TCP connection.

use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::time::{self, Instant};

use crate::config::{CONNECT_TIMEOUT, ConnectionConfig, SecureTransport};
use crate::error::{Result, TransportError};
use crate::knxnet::{self, ServiceType};
use crate::secure::{SecureLink, UserKeys};
use crate::tunnel::{Plan, open_secure, plan_connection};

/// How long the probe after the idle period waits for an answer.
const PROBE_ANSWER_TIMEOUT: Duration = Duration::from_secs(3);

/// The channel id the liveness probe names: one the client never holds, so
/// the interface answers `E_CONNECTION_ID` and nothing else changes.
const PROBE_CHANNEL: u8 = 0xFF;

/// What [`probe_secure_idle`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureIdleOutcome {
    /// The session survived the idle period: the probe was answered.
    Alive {
        /// How long the answer took.
        answered_in: Duration,
    },
    /// The interface ended the session (a SESSION_STATUS, or a closed TCP
    /// connection) `after` this long without traffic from the client.
    Dropped {
        /// Time since the session was authenticated (the client sent nothing
        /// in between, except the probe if the drop came after it).
        after: Duration,
        /// What ended it.
        reason: String,
    },
    /// The probe after the idle period got no answer: the interface forgot
    /// the session silently (typical over UDP).
    Silent,
}

/// The report of one idle probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureIdleReport {
    /// The gateway probed.
    pub gateway: SocketAddrV4,
    /// The tunnelling user the session authenticated as.
    pub user_id: u8,
    /// The carrier the session ran over.
    pub transport: SecureTransport,
    /// The idle period requested.
    pub idle: Duration,
    /// What happened.
    pub outcome: SecureIdleOutcome,
}

/// Opens a KNXnet/IP Secure session to the gateway in `config`, stays idle
/// (no keepalive, no heartbeat, no tunnel) for `idle`, and reports whether
/// the interface dropped the session. Read-only: no CONNECT, nothing reaches
/// the bus.
///
/// # Errors
///
/// [`TransportError::SecureNotSelected`] when `config` selects no secure
/// session for the gateway, and every handshake error of a secure tunnel
/// (refused password, unverified interface, unreachable gateway).
pub async fn probe_secure_idle(
    config: &ConnectionConfig,
    idle: Duration,
) -> Result<SecureIdleReport> {
    let gateway = config.gateway.ok_or(TransportError::InvalidField {
        field: "tunnel gateway (none configured)",
        value: 0,
    })?;
    let (user, probed) = match plan_connection(config, gateway).await? {
        Plan::Secure { user, probed } => (user, probed),
        Plan::Plain { keyring_note, .. } => {
            return Err(TransportError::SecureNotSelected {
                gateway,
                reason: keyring_note.unwrap_or_else(|| {
                    format!(
                        "no tunnelling credentials were given, or the interface does not \
                         advertise KNXnet/IP Secure ({})",
                        crate::guidance::tunnel_credentials_hint()
                    )
                }),
            });
        }
    };
    let keys = UserKeys::derive(&user);
    let requested = config
        .secure
        .as_ref()
        .map(|s| s.transport)
        .unwrap_or_default();
    let mut link = open_secure(
        gateway,
        config.local_interface,
        &keys,
        requested,
        probed.as_deref(),
        CONNECT_TIMEOUT,
    )
    .await?;
    let transport = link.transport();
    let started = Instant::now();
    tracing::info!(
        user = keys.user_id,
        "KNXnet/IP Secure session with {gateway} over {transport} authenticated; idle for {} s",
        idle.as_secs()
    );
    let outcome = watch(&mut link, started, idle).await;
    link.close().await;
    Ok(SecureIdleReport {
        gateway,
        user_id: keys.user_id,
        transport,
        idle,
        outcome,
    })
}

/// The idle watch and the probe after it.
async fn watch(link: &mut SecureLink, started: Instant, idle: Duration) -> SecureIdleOutcome {
    let mut buf = [0u8; 1024];
    // Idle: read whatever arrives until the period ends.
    let idle_end = started + idle;
    loop {
        match time::timeout_at(idle_end, link.recv(&mut buf)).await {
            Err(_) => break,
            Ok(Ok(_)) => continue, // an unsolicited frame; the session lives
            Ok(Err(err)) => {
                return SecureIdleOutcome::Dropped {
                    after: started.elapsed(),
                    reason: drop_reason(&err),
                };
            }
        }
    }
    // Probe: one wrapped CONNECTIONSTATE_REQUEST for a channel we do not hold.
    let request = knxnet::connectionstate_request(PROBE_CHANNEL, link.hpai());
    let sent = Instant::now();
    if let Err(err) = link.send(&request).await {
        return SecureIdleOutcome::Dropped {
            after: started.elapsed(),
            reason: drop_reason(&err),
        };
    }
    let deadline = sent + PROBE_ANSWER_TIMEOUT;
    loop {
        match time::timeout_at(deadline, link.recv(&mut buf)).await {
            Err(_) => return SecureIdleOutcome::Silent,
            Ok(Ok(n)) => {
                if knxnet::parse(&buf[..n])
                    .is_ok_and(|p| p.service == ServiceType::ConnectionstateResponse)
                {
                    return SecureIdleOutcome::Alive {
                        answered_in: sent.elapsed(),
                    };
                }
            }
            Ok(Err(err)) => {
                return SecureIdleOutcome::Dropped {
                    after: started.elapsed(),
                    reason: drop_reason(&err),
                };
            }
        }
    }
}

/// A short description of what ended the session.
fn drop_reason(err: &TransportError) -> String {
    match err {
        TransportError::SecureSessionEnded(status) => format!("SESSION_STATUS {status}"),
        TransportError::Io { source, .. } if source.kind() == std::io::ErrorKind::UnexpectedEof => {
            "the interface closed the TCP connection".to_string()
        }
        other => other.to_string(),
    }
}
