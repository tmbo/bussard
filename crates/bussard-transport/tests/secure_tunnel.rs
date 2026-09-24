//! KNXnet/IP Secure tunnelling (issue #71 Phase B) and the secure-only refusal
//! (issue #182) against the loopback [`MockSecureGateway`].
//!
//! The mock refuses a plain UDP CONNECT with `0x22` and advertises the
//! secured-families DIB, as the Jung interface did in the issue #90 S4
//! capture; over TCP it runs the session handshake and wrapped tunnelling.

use std::time::Duration;

use bussard_secure::{Key16, Password, salt};
use bussard_testkit::secure_gateway::SECURE_GATEWAY_IA;
use bussard_testkit::{MockSecureGateway, TestResult, ga, ia};
use bussard_transport::cemi::{CemiFrame, MessageCode};
use bussard_transport::{
    BusConnection, ConnectionConfig, LinkState, SecureIdleOutcome, SecureSource, SecureTransport,
    SecureTunnelConfig, SecureUser, Transport, TransportError, TunnelReconnect, probe_secure_idle,
};

const DEVICE_AUTH: &str = "device-auth-code";
const USER2_KEY: &str = "tunnel-user-2";
const USER3_KEY: &str = "tunnel-user-3";
const TUNNEL_22: u16 = 0x1116;
const TUNNEL_23: u16 = 0x1117;

fn user(user_id: u8, password: &str, tunnel_ia: u16, host: Option<u16>) -> SecureUser {
    SecureUser {
        user_id,
        password: Password::new(password),
        device_authentication_code: Some(Password::new(DEVICE_AUTH)),
        tunnel_ia: Some(tunnel_ia),
        host_ia: host,
    }
}

/// The key the mock checks: PBKDF2 of the password with `salt`.
fn key(password: &str, salt: &[u8]) -> Key16 {
    Password::new(password).derive(salt)
}

fn user_key(password: &str) -> Key16 {
    key(password, salt::USER_PASSWORD)
}

fn device_key() -> Key16 {
    key(DEVICE_AUTH, salt::DEVICE_AUTHENTICATION_CODE)
}

async fn gateway() -> TestResult<MockSecureGateway> {
    Ok(MockSecureGateway::builder()
        .device_auth(device_key())
        .user(2, user_key(USER2_KEY), TUNNEL_22)
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .start()
        .await?)
}

fn config(gw: &MockSecureGateway, secure: Option<SecureTunnelConfig>) -> ConnectionConfig {
    ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(TunnelReconnect::disabled())
        .with_secure(secure)
}

/// Receives frames until an `L_Data.con` arrives.
async fn expect_con(conn: &mut Transport) -> TestResult<CemiFrame> {
    let wait = async {
        loop {
            let stamped = conn.recv().await?;
            if stamped.frame.message_code == MessageCode::LDataCon {
                return Ok::<CemiFrame, TransportError>(stamped.frame);
            }
        }
    };
    Ok(tokio::time::timeout(Duration::from_secs(3), wait).await??)
}

#[tokio::test]
async fn test_secure_tunnel_explicit_user_connects_sends_and_closes() -> TestResult {
    let gw = gateway().await?;
    let secure = SecureTunnelConfig::new(
        vec![user(3, USER3_KEY, TUNNEL_23, None)],
        SecureSource::Explicit,
    );
    let mut conn = Transport::connect(&config(&gw, Some(secure))).await?;
    // The interface assigns the authenticated user's tunnel address.
    assert_eq!(conn.assigned_individual_address(), Some(TUNNEL_23));

    let frame = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.23")?, &[1]);
    conn.send(frame.clone()).await?;
    let con = expect_con(&mut conn).await?;
    assert_eq!(con.destination, frame.destination);
    conn.close().await?;

    // Give the mock a moment to read the close.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stats = gw.stats()?;
    assert_eq!(stats.sessions, 1);
    assert_eq!(stats.users, vec![3]);
    assert_eq!(stats.connects, 1);
    assert_eq!(stats.requests, vec![frame]);
    assert_eq!(stats.client_acks, 0, "no TUNNELING_ACK over TCP");
    assert_eq!(stats.disconnects, 1);
    assert_eq!(stats.closes, 1, "the session is closed with STATUS_CLOSE");
    assert_eq!(
        stats.plain_refusals, 0,
        "explicit credentials never try plain"
    );
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_keyring_picks_the_user_of_this_interface() -> TestResult {
    let gw = gateway().await?;
    let secure = SecureTunnelConfig::new(
        vec![
            // Another interface's user: never chosen.
            user(7, "other-interface", 0x1201, Some(0x1200)),
            user(2, USER2_KEY, TUNNEL_22, Some(SECURE_GATEWAY_IA)),
            user(3, USER3_KEY, TUNNEL_23, Some(SECURE_GATEWAY_IA)),
        ],
        SecureSource::Keyring,
    );
    let conn = Transport::connect(&config(&gw, Some(secure))).await?;
    assert_eq!(conn.assigned_individual_address(), Some(TUNNEL_22));
    conn.close().await?;
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![2]);
    assert!(stats.extended_searches >= 1, "the probe ran");
    Ok(())
}

#[tokio::test]
async fn test_secure_only_interface_without_credentials_fails_fast() -> TestResult {
    let gw = gateway().await?;
    let started = std::time::Instant::now();
    let err = match Transport::connect(&config(&gw, None)).await {
        Ok(_) => return Err("a plain connect to a secure-only interface must fail".into()),
        Err(err) => err,
    };
    assert!(
        matches!(err, TransportError::SecureRequired { .. }),
        "got {err:?}"
    );
    assert!(err.is_fatal());
    let msg = err.to_string();
    assert!(msg.contains("requires KNXnet/IP Secure"), "{msg}");
    assert!(msg.contains("--keyring"), "{msg}");
    assert!(started.elapsed() < Duration::from_secs(5), "no retries");
    assert_eq!(gw.stats()?.plain_refusals, 1);
    Ok(())
}

#[tokio::test]
async fn test_keyring_without_a_user_for_this_interface_names_it() -> TestResult {
    let gw = gateway().await?;
    let secure = SecureTunnelConfig::new(
        vec![user(7, "other-interface", 0x1201, Some(0x1200))],
        SecureSource::Keyring,
    );
    let err = match Transport::connect(&config(&gw, Some(secure))).await {
        Ok(_) => return Err("must refuse".into()),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("the keyring has no tunnelling user for interface 1.1.200"),
        "{msg}"
    );
    Ok(())
}

#[tokio::test]
async fn test_wrong_password_is_a_fatal_auth_failure() -> TestResult {
    let gw = gateway().await?;
    let secure = SecureTunnelConfig::new(
        vec![user(3, "wrong-password", TUNNEL_23, None)],
        SecureSource::Explicit,
    );
    let err = match Transport::connect(&config(&gw, Some(secure))).await {
        Ok(_) => return Err("a wrong password must fail".into()),
        Err(err) => err,
    };
    assert!(
        matches!(err, TransportError::SecureAuthFailed { user_id: 3, .. }),
        "got {err:?}"
    );
    assert!(err.is_fatal());
    assert_eq!(gw.stats()?.auth_failures, 1);
    Ok(())
}

#[tokio::test]
async fn test_wrong_device_authentication_code_refuses_the_interface() -> TestResult {
    let gw = gateway().await?;
    let mut bad = user(3, USER3_KEY, TUNNEL_23, None);
    bad.device_authentication_code = Some(Password::new("not-the-code"));
    let secure = SecureTunnelConfig::new(vec![bad], SecureSource::Explicit);
    let err = match Transport::connect(&config(&gw, Some(secure))).await {
        Ok(_) => return Err("an unverified interface must be refused".into()),
        Err(err) => err,
    };
    assert!(
        matches!(err, TransportError::SecureServerUnverified { .. }),
        "got {err:?}"
    );
    // The client never authenticated to an interface it could not verify.
    assert_eq!(gw.stats()?.sessions, 0);
    assert_eq!(gw.stats()?.auth_failures, 0);
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_reestablishes_a_new_session_after_link_loss() -> TestResult {
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .drop_after_requests(1)
        .start()
        .await?;
    let secure = SecureTunnelConfig::new(
        vec![user(3, USER3_KEY, TUNNEL_23, None)],
        SecureSource::Explicit,
    );
    let cfg = ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(TunnelReconnect::with_budget(Duration::from_secs(10)))
        .with_secure(Some(secure));
    let mut conn = Transport::connect(&cfg).await?;
    let mut link = conn.link_state().ok_or("a tunnel has a link state")?;

    conn.send(CemiFrame::group_write_packed(
        ga("1/2/3")?,
        ia("1.1.23")?,
        &[1],
    ))
    .await?;
    // The mock closes the TCP connection after that frame; the tunnel sees
    // the EOF, re-opens a secure session and CONNECTs again.
    let wait = async {
        loop {
            link.changed().await?;
            if matches!(*link.borrow(), LinkState::Up { .. }) {
                return Ok::<(), tokio::sync::watch::error::RecvError>(());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(8), wait).await??;

    let second = CemiFrame::group_write_packed(ga("1/2/4")?, ia("1.1.23")?, &[0]);
    conn.send(second.clone()).await?;
    let _ = expect_con(&mut conn).await;
    conn.close().await?;
    let stats = gw.stats()?;
    assert_eq!(stats.sessions, 2, "a second secure session");
    assert_eq!(stats.connects, 2);
    assert_eq!(stats.requests.last(), Some(&second));
    Ok(())
}

/// A secure tunnel to `gw` with a 10 s re-establish budget and `deadline` as
/// its TCP read deadline.
fn stall_config(gw: &MockSecureGateway, deadline: Duration) -> ConnectionConfig {
    let secure = SecureTunnelConfig::new(
        vec![user(3, USER3_KEY, TUNNEL_23, None)],
        SecureSource::Explicit,
    );
    ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(
            TunnelReconnect::with_budget(Duration::from_secs(10)).with_tcp_read_deadline(deadline),
        )
        .with_secure(Some(secure))
}

/// Waits until the link state reports `Reconnecting`.
async fn until_reconnecting(link: &mut tokio::sync::watch::Receiver<LinkState>) -> TestResult {
    loop {
        link.changed().await?;
        if matches!(*link.borrow(), LinkState::Reconnecting) {
            return Ok(());
        }
    }
}

#[tokio::test]
async fn test_secure_tunnel_read_deadline_detects_a_silent_link() -> TestResult {
    // Issue #192: a pulled cable on a TCP tunnel is silence, not a socket
    // error, until the kernel gives up (~37 s). With a 300 ms read deadline
    // the idle link is probed with a CONNECTIONSTATE_REQUEST; the stalled
    // interface answers nothing, so the loss is detected within the deadline
    // plus the probe wait and a new secure session is opened.
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .stall_after_requests(1)
        .start()
        .await?;
    let deadline = Duration::from_millis(300);
    let mut conn = Transport::connect(&stall_config(&gw, deadline)).await?;
    let mut link = conn.link_state().ok_or("a tunnel has a link state")?;

    conn.send(CemiFrame::group_write_packed(
        ga("1/2/3")?,
        ia("1.1.23")?,
        &[1],
    ))
    .await?;
    let _ = expect_con(&mut conn).await?;
    let stalled_at = std::time::Instant::now();
    // The loss must be noticed within the deadline plus the probe wait (with
    // slack for a loaded CI machine), far below the kernel's TCP timeout.
    tokio::time::timeout(Duration::from_secs(3), until_reconnecting(&mut link)).await??;
    let detected = stalled_at.elapsed();
    assert!(
        detected >= deadline,
        "no probe before the deadline expired (detected after {detected:?})"
    );
    let wait_up = async {
        loop {
            link.changed().await?;
            if matches!(*link.borrow(), LinkState::Up { .. }) {
                return Ok::<(), tokio::sync::watch::error::RecvError>(());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(8), wait_up).await??;

    let second = CemiFrame::group_write_packed(ga("1/2/4")?, ia("1.1.23")?, &[0]);
    conn.send(second.clone()).await?;
    let _ = expect_con(&mut conn).await?;
    conn.close().await?;
    let stats = gw.stats()?;
    assert_eq!(
        stats.sessions, 2,
        "the lost link got a second secure session"
    );
    assert!(
        stats.stalled_frames >= 1,
        "the liveness probe went into the stalled connection"
    );
    assert_eq!(stats.requests.last(), Some(&second));
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_read_deadline_keeps_a_healthy_idle_link() -> TestResult {
    // An idle but healthy link answers every probe: it stays up on its one
    // session, and the probes are the only traffic.
    let gw = gateway().await?;
    let mut conn = Transport::connect(&stall_config(&gw, Duration::from_millis(200))).await?;
    let link = conn.link_state().ok_or("a tunnel has a link state")?;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(*link.borrow(), LinkState::Up { .. }));
    conn.send(CemiFrame::group_write_packed(
        ga("1/2/3")?,
        ia("1.1.23")?,
        &[1],
    ))
    .await?;
    let _ = expect_con(&mut conn).await?;
    conn.close().await?;
    let stats = gw.stats()?;
    assert_eq!(stats.sessions, 1, "no re-establish on a healthy link");
    assert!(
        stats.heartbeats >= 3,
        "the idle link was probed every 200 ms (got {})",
        stats.heartbeats
    );
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_without_read_deadline_does_not_probe() -> TestResult {
    // The control: with the check off (`Duration::ZERO`) a stalled link is not
    // noticed within the same window, which is the ~37 s blind spot of #192.
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .stall_after_requests(1)
        .start()
        .await?;
    let mut conn = Transport::connect(&stall_config(&gw, Duration::ZERO)).await?;
    let mut link = conn.link_state().ok_or("a tunnel has a link state")?;
    conn.send(CemiFrame::group_write_packed(
        ga("1/2/3")?,
        ia("1.1.23")?,
        &[1],
    ))
    .await?;
    let _ = expect_con(&mut conn).await?;
    let noticed = tokio::time::timeout(Duration::from_millis(1500), until_reconnecting(&mut link))
        .await
        .is_ok();
    assert!(!noticed, "without a read deadline nothing probes the link");
    assert_eq!(gw.stats()?.heartbeats, 0);
    Ok(())
}

// --- KNXnet/IP Secure over UDP, keepalive, idle probe (issue #197) ---------

/// Explicit user 3 over `transport`, with the TCP read deadline off so the
/// only idle traffic is what the test is about.
fn explicit(gw: &MockSecureGateway, transport: SecureTransport) -> ConnectionConfig {
    let secure = SecureTunnelConfig::new(
        vec![user(3, USER3_KEY, TUNNEL_23, None)],
        SecureSource::Explicit,
    )
    .with_transport(transport);
    ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(TunnelReconnect::disabled().with_tcp_read_deadline(Duration::ZERO))
        .with_secure(Some(secure))
}

/// A mock that also serves secure sessions over UDP.
async fn udp_gateway() -> TestResult<MockSecureGateway> {
    Ok(MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .udp_sessions()
        .start()
        .await?)
}

#[tokio::test]
async fn test_secure_tunnel_over_udp_acks_inside_the_wrappers() -> TestResult {
    let gw = udp_gateway().await?;
    let mut conn = Transport::connect(&explicit(&gw, SecureTransport::Udp)).await?;
    assert_eq!(conn.assigned_individual_address(), Some(TUNNEL_23));

    let frame = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.23")?, &[1]);
    conn.send(frame.clone()).await?;
    let con = expect_con(&mut conn).await?;
    assert_eq!(con.destination, frame.destination);
    conn.close().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = gw.stats()?;
    assert_eq!(stats.udp_sessions, 1, "the session ran over UDP");
    assert_eq!(stats.sessions, 1);
    assert_eq!(stats.connects, 1);
    assert_eq!(stats.requests, vec![frame]);
    // The client acknowledged the gateway's L_Data.con: TUNNELING_ACK is back
    // in the loop over UDP (and the send itself waited for the gateway's).
    assert!(stats.client_acks >= 1, "no TUNNELING_ACK from the client");
    assert_eq!(stats.disconnects, 1);
    assert_eq!(stats.closes, 1);
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_auto_falls_back_to_udp_when_tcp_is_refused() -> TestResult {
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .udp_sessions()
        .without_tcp()
        .start()
        .await?;
    let mut conn = Transport::connect(&explicit(&gw, SecureTransport::Auto)).await?;
    let frame = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.23")?, &[0]);
    conn.send(frame.clone()).await?;
    let _ = expect_con(&mut conn).await?;
    conn.close().await?;
    let stats = gw.stats()?;
    assert_eq!(stats.udp_sessions, 1, "fell back to UDP");
    assert!(
        stats.extended_searches >= 1,
        "the fallback checked that the interface advertises Secure"
    );
    assert_eq!(stats.requests, vec![frame]);
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_keyring_falls_back_to_udp_when_tcp_is_refused() -> TestResult {
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(2, user_key(USER2_KEY), TUNNEL_22)
        .udp_sessions()
        .without_tcp()
        .start()
        .await?;
    let secure = SecureTunnelConfig::new(
        vec![user(2, USER2_KEY, TUNNEL_22, Some(SECURE_GATEWAY_IA))],
        SecureSource::Keyring,
    );
    let conn = Transport::connect(&config(&gw, Some(secure))).await?;
    assert_eq!(conn.assigned_individual_address(), Some(TUNNEL_22));
    conn.close().await?;
    assert_eq!(gw.stats()?.udp_sessions, 1);
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_tcp_only_does_not_fall_back() -> TestResult {
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .udp_sessions()
        .without_tcp()
        .start()
        .await?;
    let err = match Transport::connect(&explicit(&gw, SecureTransport::Tcp)).await {
        Ok(_) => return Err("--secure-transport tcp must not use UDP".into()),
        Err(err) => err,
    };
    assert!(matches!(err, TransportError::Io { .. }), "got {err:?}");
    assert_eq!(gw.stats()?.udp_sessions, 0);
    Ok(())
}

#[tokio::test]
async fn test_secure_tunnel_keepalive_interval_is_configurable() -> TestResult {
    let gw = gateway().await?;
    let fast = explicit(&gw, SecureTransport::Tcp);
    let fast = fast.clone().with_secure(
        fast.secure
            .map(|s| s.with_keepalive(Duration::from_millis(150))),
    );
    let conn = Transport::connect(&fast).await?;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    conn.close().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let keepalives = gw.stats()?.keepalives;
    assert!(keepalives >= 4, "150 ms keepalive sent only {keepalives}");

    // Zero turns it off.
    let gw = gateway().await?;
    let off = explicit(&gw, SecureTransport::Tcp);
    let off = off
        .clone()
        .with_secure(off.secure.map(|s| s.with_keepalive(Duration::ZERO)));
    let conn = Transport::connect(&off).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    conn.close().await?;
    assert_eq!(gw.stats()?.keepalives, 0);
    Ok(())
}

#[tokio::test]
async fn test_probe_secure_idle_reports_a_live_session() -> TestResult {
    let gw = udp_gateway().await?;
    for transport in [SecureTransport::Tcp, SecureTransport::Udp] {
        let report =
            probe_secure_idle(&explicit(&gw, transport), Duration::from_millis(300)).await?;
        assert_eq!(report.transport, transport);
        assert_eq!(report.user_id, 3);
        assert!(
            matches!(report.outcome, SecureIdleOutcome::Alive { .. }),
            "{transport}: {:?}",
            report.outcome
        );
    }
    let stats = gw.stats()?;
    assert_eq!(stats.connects, 0, "the probe never opens a tunnel");
    assert_eq!(stats.keepalives, 0, "nor sends a keepalive");
    assert!(stats.requests.is_empty(), "nothing reaches the bus");
    Ok(())
}

#[tokio::test]
async fn test_probe_secure_idle_detects_the_session_timeout() -> TestResult {
    let gw = MockSecureGateway::builder()
        .device_auth(device_key())
        .user(3, user_key(USER3_KEY), TUNNEL_23)
        .udp_sessions()
        .session_timeout(Duration::from_millis(300))
        .start()
        .await?;
    // TCP: the interface announces the timeout and closes.
    let report =
        probe_secure_idle(&explicit(&gw, SecureTransport::Tcp), Duration::from_secs(1)).await?;
    match report.outcome {
        SecureIdleOutcome::Dropped { after, reason } => {
            assert!(
                after >= Duration::from_millis(300),
                "dropped after {after:?}"
            );
            assert!(after < Duration::from_secs(1), "dropped after {after:?}");
            assert!(reason.contains("SESSION_STATUS"), "{reason}");
        }
        other => return Err(format!("expected a drop over TCP, got {other:?}").into()),
    }
    // UDP: the interface forgets the session; the probe goes unanswered.
    let report =
        probe_secure_idle(&explicit(&gw, SecureTransport::Udp), Duration::from_secs(1)).await?;
    assert_eq!(report.outcome, SecureIdleOutcome::Silent);
    assert_eq!(gw.stats()?.timeouts, 2);
    Ok(())
}

#[tokio::test]
async fn test_probe_secure_idle_without_credentials_is_refused() -> TestResult {
    let gw = gateway().await?;
    let err = match probe_secure_idle(&config(&gw, None), Duration::from_millis(10)).await {
        Ok(r) => return Err(format!("no credentials must be refused, got {r:?}").into()),
        Err(err) => err,
    };
    assert!(
        matches!(err, TransportError::SecureNotSelected { .. }),
        "got {err:?}"
    );
    Ok(())
}
