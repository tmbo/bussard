//! Issue #575 against the testkit device: the transport connection timeout
//! (03_03_04 §5, E16) and `E_SUCCESS_WITH_CRC` on an extended memory write
//! (03_03_07 §3.4.9.2.1).
//!
//! The device runs a shortened connection timeout
//! ([`MockDevice::with_connection_timeout`]) and the client is told the same
//! value, so the idle paths run in a few hundred milliseconds. Every gateway
//! binds 127.0.0.1.

use std::time::Duration;

use bussard_mgmt::{
    Layer4Connection, MgmtError, SecureLayer, SyncRetry, Timeouts, WriteError,
    read_device_descriptor,
};
use bussard_model::IndividualAddress;
use bussard_secure::{DataSecureSession, Key16};
use bussard_testkit::consts::{A_AUTHORIZE_REQUEST, A_MEMORY_EXTENDED_WRITE};
use bussard_testkit::{BoxError, ExtWriteConfirmation, MockDevice, MockGateway, TestResult};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

/// The device's (and the client's) connection timeout in these tests.
const IDLE: Duration = Duration::from_millis(150);

/// Starts a gateway with `device` on the line.
async fn start(device: MockDevice) -> Result<MockGateway, bussard_testkit::MockError> {
    MockGateway::builder()
        .idle_timeout(Duration::from_secs(5))
        .device(device)
        .start()
        .await
}

/// The client's transport control frames of one kind.
fn count(sent: &[CemiFrame], want: fn(TpciKind) -> bool) -> usize {
    sent.iter()
        .filter(|f| f.group_destination().is_none() && want(tpci::classify(f.tpci_octet())))
        .count()
}

#[tokio::test]
async fn test_send_data_reconnects_after_the_connection_timeout() -> TestResult {
    let target: IndividualAddress = "1.1.7".parse()?;
    let device = MockDevice::new(target)
        .with_authorize_level(1)
        .with_connection_timeout(IDLE);
    let gw = start(device).await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    l4.set_connection_timeout(IDLE);
    l4.authorize_or_fail(0x1122_3344).await?;
    assert_eq!(read_device_descriptor(&mut l4).await?, 0x07B0);

    // Idle past the device's timeout: the next request reconnects first.
    tokio::time::sleep(IDLE * 2).await;
    assert!(l4.idle_beyond_connection_timeout());
    assert_eq!(read_device_descriptor(&mut l4).await?, 0x07B0);
    assert_eq!(l4.idle_reconnects(), 1);
    let _ = l4.disconnect().await;

    let sent = gw.sent()?;
    assert_eq!(count(&sent, |k| matches!(k, TpciKind::Connect)), 2);
    assert_eq!(
        count(&sent, |k| matches!(k, TpciKind::Disconnect)),
        2,
        "one before the reconnect, one at the end"
    );
    let (timed_out, authorizes) = gw.with_device(target, |d| {
        (
            d.timed_out_requests,
            d.requests
                .iter()
                .filter(|(apci, _)| *apci == A_AUTHORIZE_REQUEST)
                .count(),
        )
    })?;
    assert_eq!(timed_out, 0, "no request met the closed connection");
    assert_eq!(
        authorizes, 2,
        "the key is presented again on the new connection"
    );
    Ok(())
}

#[tokio::test]
async fn test_idle_connection_without_reconnect_meets_t_disconnect() -> TestResult {
    // The device side of the timeout: a client that assumes the standard 6 s
    // sends into the closed connection and gets the device's T_Disconnect
    // (CLOSED, A10), the failure the reconnect avoids.
    let target: IndividualAddress = "1.1.7".parse()?;
    let gw = start(MockDevice::new(target).with_connection_timeout(IDLE)).await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    assert_eq!(read_device_descriptor(&mut l4).await?, 0x07B0);
    tokio::time::sleep(IDLE * 2).await;
    let Err(err) = read_device_descriptor(&mut l4).await else {
        return Err("the device closed the connection".into());
    };
    assert!(!err.to_string().is_empty());
    assert_eq!(l4.idle_reconnects(), 0);
    assert_eq!(gw.with_device(target, |d| d.timed_out_requests)?, 1);
    Ok(())
}

#[tokio::test]
async fn test_sync_backoff_stays_inside_the_connection_timeout() -> TestResult {
    // A Data Secure device whose security layer drops the first two
    // S-A_Sync_Reqs (just restarted, issue #166) and closes a connection
    // idle for IDLE. The retry policy asks for a 1 s backoff, longer than
    // IDLE: the sync loop bounds it by the connection timeout less the
    // response timeout, so the third attempt reaches the device on the
    // same connection, without a reconnect and without meeting CLOSED.
    const TOOL_KEY: [u8; 16] = [0x5A; 16];
    let target: IndividualAddress = "1.1.12".parse()?;
    let device = MockDevice::system_b(target)
        .with_data_secure(TOOL_KEY)
        .with_dropped_sync_requests(2)
        .with_connection_timeout(IDLE * 2);
    let gw = start(device).await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let timeouts = Timeouts {
        ack_timeout: Duration::from_millis(200),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(100),
        absent_on_negative_confirmation: false,
    };
    let mut l4 = Layer4Connection::connect_with_secure(
        &mut bus,
        target,
        "0.0.255".parse()?,
        timeouts,
        SecureLayer::activated(DataSecureSession::new(Key16::new(TOOL_KEY))),
    )
    .await?;
    l4.set_connection_timeout(IDLE * 2);
    l4.set_sync_retry(SyncRetry {
        attempts: 3,
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(2),
    });
    let started = std::time::Instant::now();
    assert_eq!(read_device_descriptor(&mut l4).await?, 0x07B0);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the backoff was bounded: {:?}",
        started.elapsed()
    );
    assert_eq!(l4.idle_reconnects(), 0);
    let _ = l4.disconnect().await;
    let (dropped_left, timed_out) =
        gw.with_device(target, |d| (d.drop_sync_requests, d.timed_out_requests))?;
    assert_eq!(dropped_left, 0, "both dropped Sync_Reqs were sent");
    assert_eq!(timed_out, 0);
    Ok(())
}

#[test]
fn test_after_restart_sync_window_and_backoff_bound() {
    // Issue #575: no pause between two attempts outlasts the device's
    // connection timeout, and the window the device gets to bring its
    // security layer up is not shorter than the 30 s of the old schedule.
    let policy = SyncRetry::after_restart();
    assert!(
        bussard_mgmt::connection::RESPONSE_TIMEOUT + bussard_mgmt::MAX_SYNC_BACKOFF
            < bussard_mgmt::CONNECTION_TIMEOUT
    );
    if std::env::var_os(bussard_mgmt::MGMT_TIMEOUT_MS_ENV).is_none() {
        let mut window = bussard_mgmt::connection::RESPONSE_TIMEOUT * policy.attempts;
        let mut backoff = policy.initial_backoff;
        for _ in 1..policy.attempts {
            window += backoff;
            backoff = (backoff * 2).min(policy.max_backoff);
        }
        assert!(window >= Duration::from_secs(30), "{window:?}");
        assert!(policy.max_backoff <= bussard_mgmt::MAX_SYNC_BACKOFF);
    }
}

/// Writes 40 octets above 0xFFFF (the extended service) to a device that
/// confirms as `confirmation` says; the outer error is the test rig's.
async fn extended_write(
    confirmation: ExtWriteConfirmation,
) -> Result<Result<(), WriteError>, BoxError> {
    let target = IndividualAddress::from_raw(0x1104);
    let device = MockDevice::new(target).with_ext_write_confirmation(confirmation);
    let gw = start(device).await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 =
        Layer4Connection::connect(&mut bus, target, IndividualAddress::from_raw(0x00FF)).await?;
    let data: Vec<u8> = (0..40u8).collect();
    let result = bussard_mgmt::write_memory_chunked(&mut l4, 0x01_6000, &data, |_| {}).await;
    let _ = l4.disconnect().await;
    let writes = gw.with_device(target, |d| {
        d.requests
            .iter()
            .filter(|(apci, _)| *apci == A_MEMORY_EXTENDED_WRITE)
            .count()
    })?;
    if writes == 0 {
        return Err("no A_MemoryExtended_Write went out".into());
    }
    Ok(result)
}

#[tokio::test]
async fn test_extended_write_accepts_success_with_crc() -> TestResult {
    extended_write(ExtWriteConfirmation::SuccessWithCrc).await??;
    extended_write(ExtWriteConfirmation::Success).await??;
    Ok(())
}

#[tokio::test]
async fn test_extended_write_refuses_a_crc_that_does_not_match() -> TestResult {
    let Err(err) = extended_write(ExtWriteConfirmation::SuccessWithWrongCrc).await? else {
        return Err("a wrong CRC fails the write".into());
    };
    assert!(
        matches!(err, WriteError::Mgmt(MgmtError::MemoryWriteCrc { .. })),
        "got {err:?}"
    );
    Ok(())
}
