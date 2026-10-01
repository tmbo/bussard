//! Reconnect hygiene of the bus actor against the mock KNXnet/IP Secure
//! interface (issue #287).
//!
//! - After the interface closes the TCP side and opens it again, the bus
//!   reconnects within one backoff, over a new socket and a new session.
//! - [`BusHandle::reconnect`] connects at once, with the backoff reset.
//! - Two buses whose key store lists the same first user both come up on an
//!   interface that holds one session per user.

use std::time::{Duration, Instant};

use bussard_bus::{Bus, BusHandle, BusState};
use bussard_secure::{Key16, Password, salt};
use bussard_testkit::secure_gateway::SECURE_GATEWAY_IA;
use bussard_testkit::{MockSecureGateway, TestResult};
use bussard_transport::{
    ConnectionConfig, SecureSource, SecureTunnelConfig, SecureUser, TunnelReconnect,
};

const DEVICE_AUTH: &str = "device-auth-code";
const USER2_KEY: &str = "tunnel-user-2";
const USER3_KEY: &str = "tunnel-user-3";
const TUNNEL_22: u16 = 0x1116;
const TUNNEL_23: u16 = 0x1117;

/// What a connect attempt may take on the slowest CI runner on top of the
/// backoff it waits out: a refused loopback connect takes about 2 s on
/// Windows (it retries the SYN), and an attempt makes up to two of them.
const SLACK: Duration = Duration::from_secs(10);

fn key(password: &str, salt: &[u8]) -> Key16 {
    Password::new(password).derive(salt)
}

fn user(user_id: u8, password: &str, tunnel_ia: u16) -> SecureUser {
    SecureUser {
        user_id,
        password: Password::new(password),
        device_authentication_code: Some(Password::new(DEVICE_AUTH)),
        tunnel_ia: Some(tunnel_ia),
        host_ia: Some(SECURE_GATEWAY_IA),
    }
}

async fn gateway(one_session_per_user: bool) -> TestResult<MockSecureGateway> {
    let mut builder = MockSecureGateway::builder()
        .device_auth(key(DEVICE_AUTH, salt::DEVICE_AUTHENTICATION_CODE))
        .user(2, key(USER2_KEY, salt::USER_PASSWORD), TUNNEL_22)
        .user(3, key(USER3_KEY, salt::USER_PASSWORD), TUNNEL_23);
    if one_session_per_user {
        builder = builder.one_session_per_user();
    }
    Ok(builder.start().await?)
}

/// Keyring users 2 and 3, the tunnel's own re-establish off so every loss
/// reaches the actor's reconnect loop.
fn config(gw: &MockSecureGateway, lock_dir: Option<&std::path::Path>) -> ConnectionConfig {
    let mut secure = SecureTunnelConfig::new(
        vec![user(2, USER2_KEY, TUNNEL_22), user(3, USER3_KEY, TUNNEL_23)],
        SecureSource::Keyring,
    );
    if let Some(dir) = lock_dir {
        secure = secure.with_user_lock_dir(dir);
    }
    ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(TunnelReconnect::disabled())
        .with_secure(Some(secure))
}

/// Polls `handle` until `done` holds, up to `limit`.
async fn until(handle: &BusHandle, limit: Duration, done: impl Fn(&BusHandle) -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done(handle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done(handle)
}

#[tokio::test]
async fn test_bus_reconnects_within_one_backoff_after_the_listener_returns() -> TestResult {
    let gw = gateway(false).await?;
    let (handle, _task) = Bus::connect(config(&gw, None));
    assert!(handle.wait_connected(Duration::from_secs(5)).await);
    assert_eq!(handle.diagnostics().tunnel_user, Some(2));
    let before = gw.stats()?;

    // The interface goes away: listener closed, the session's socket closed.
    gw.close_tcp()?;
    assert!(
        until(&handle, Duration::from_secs(30), |h| h
            .diagnostics()
            .attempts
            >= 1)
        .await,
        "a connect attempt failed while the TCP side was closed"
    );
    let down = handle.diagnostics();
    assert_ne!(handle.status(), BusState::Connected);
    assert!(down.last_error.is_some() && down.last_error_at.is_some());
    // A refused TCP connect on an interface whose UDP still advertises Secure
    // is fatal at startup, but this bus connected before: it keeps trying.
    assert_ne!(handle.status(), BusState::Closed, "{down:?}");
    let backoff = down.retry_in.ok_or("waiting for the next attempt")?;

    gw.reopen_tcp().await?;
    let reopened = Instant::now();
    assert!(
        handle.wait_connected(backoff + SLACK).await,
        "connected within one backoff ({backoff:?}) of the listener's return"
    );
    assert!(reopened.elapsed() <= backoff + SLACK);

    let after = gw.stats()?;
    assert!(
        after.tcp_connections > before.tcp_connections,
        "a new socket, not the closed one"
    );
    assert_eq!(after.sessions, before.sessions + 1, "a new secure session");
    let up = handle.diagnostics();
    assert_eq!(up.attempts, 0, "the attempt count resets on connect");
    assert!(up.connected_since.is_some());
    assert!(up.last_error.is_some(), "the last error stays as history");
    handle.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_reconnect_connects_now_with_the_backoff_reset() -> TestResult {
    let gw = gateway(false).await?;
    let (handle, _task) = Bus::connect(config(&gw, None));
    assert!(handle.wait_connected(Duration::from_secs(5)).await);

    // While connected: a clean close, then a fresh session.
    handle.reconnect().await?;
    assert_eq!(handle.status(), BusState::Connected);
    let stats = gw.stats()?;
    assert_eq!(stats.sessions, 2, "{stats:?}");
    assert!(stats.disconnects >= 1, "the old tunnel was disconnected");

    // While down with a grown backoff: the next attempt is now, not later.
    gw.close_tcp()?;
    assert!(
        until(&handle, Duration::from_secs(45), |h| h
            .diagnostics()
            .attempts
            >= 2)
        .await,
        "two failed attempts"
    );
    let waiting = handle
        .diagnostics()
        .retry_in
        .ok_or("waiting for the next attempt")?;
    assert!(
        waiting > Duration::from_secs(1),
        "the backoff grew: {waiting:?}"
    );
    gw.reopen_tcp().await?;
    let asked = Instant::now();
    tokio::time::timeout(Duration::from_secs(20), handle.reconnect()).await??;
    assert_eq!(handle.status(), BusState::Connected);
    assert!(
        asked.elapsed() < waiting,
        "reconnected in {:?}, before the backoff ({waiting:?}) ran out",
        asked.elapsed()
    );
    handle.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_two_buses_with_the_same_first_user_both_come_up() -> TestResult {
    // The interface holds one session per user. Without lock files the second
    // bus collides on user 2 and rotates to user 3.
    let gw = gateway(true).await?;
    let (a, _ta) = Bus::connect(config(&gw, None));
    assert!(a.wait_connected(Duration::from_secs(5)).await);
    let (b, _tb) = Bus::connect(config(&gw, None));
    assert!(b.wait_connected(Duration::from_secs(5)).await);
    assert_eq!(a.diagnostics().tunnel_user, Some(2));
    assert_eq!(b.diagnostics().tunnel_user, Some(3));
    assert_eq!(gw.stats()?.user_conflicts, 1);
    a.close().await?;
    b.close().await?;

    // With lock files the second bus never asks for the held user.
    let dir = std::env::temp_dir().join(format!("bussard-bus-users-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let gw = gateway(true).await?;
    let (a, _ta) = Bus::connect(config(&gw, Some(&dir)));
    assert!(a.wait_connected(Duration::from_secs(5)).await);
    let (b, _tb) = Bus::connect(config(&gw, Some(&dir)));
    assert!(b.wait_connected(Duration::from_secs(5)).await);
    assert_eq!(a.diagnostics().tunnel_user, Some(2));
    assert_eq!(b.diagnostics().tunnel_user, Some(3));
    assert_eq!(gw.stats()?.user_conflicts, 0);
    a.close().await?;
    b.close().await?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
