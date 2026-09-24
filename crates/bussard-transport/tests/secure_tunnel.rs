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
    BusConnection, ConnectionConfig, LinkState, SecureSource, SecureTunnelConfig, SecureUser,
    Transport, TransportError, TunnelReconnect,
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
    let secure = SecureTunnelConfig {
        users: vec![user(3, USER3_KEY, TUNNEL_23, None)],
        source: SecureSource::Explicit,
    };
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
    let secure = SecureTunnelConfig {
        users: vec![
            // Another interface's user: never chosen.
            user(7, "other-interface", 0x1201, Some(0x1200)),
            user(2, USER2_KEY, TUNNEL_22, Some(SECURE_GATEWAY_IA)),
            user(3, USER3_KEY, TUNNEL_23, Some(SECURE_GATEWAY_IA)),
        ],
        source: SecureSource::Keyring,
    };
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
    let secure = SecureTunnelConfig {
        users: vec![user(7, "other-interface", 0x1201, Some(0x1200))],
        source: SecureSource::Keyring,
    };
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
    let secure = SecureTunnelConfig {
        users: vec![user(3, "wrong-password", TUNNEL_23, None)],
        source: SecureSource::Explicit,
    };
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
    let secure = SecureTunnelConfig {
        users: vec![bad],
        source: SecureSource::Explicit,
    };
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
    let secure = SecureTunnelConfig {
        users: vec![user(3, USER3_KEY, TUNNEL_23, None)],
        source: SecureSource::Explicit,
    };
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
