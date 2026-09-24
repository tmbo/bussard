//! L4 transport tests: NDT sequencing and the per-connection exchange budget.

use super::*;

#[test]
fn test_l4_duplicate_ndt_is_reacked_not_reprocessed() -> Result<(), Box<dyn std::error::Error>> {
    // A retransmit of the last-accepted NDT (its T_ACK was lost) must be
    // re-acknowledged with the SAME sequence but NOT reprocessed. We use an
    // authorize at seq 0 (auth -> level 0), then replay the identical seq-0
    // frame: the replay must produce a bare T_ACK(0), not a second authorize
    // response, and must not advance rx_seq.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    assert_eq!(dev.rx_seq, 0);
    let auth = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    let r = dev.handle_cemi(&auth)?;
    assert_eq!(
        r.responses.len(),
        1,
        "authorize answers with a response NDT"
    );
    assert_eq!(dev.rx_seq, 1, "rx_seq advanced past the accepted frame");

    // Replay the exact same seq-0 frame (a retransmit).
    let replay = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    let r2 = dev.handle_cemi(&replay)?;
    assert_eq!(r2.responses.len(), 1, "duplicate is re-acknowledged");
    // The re-ACK is a bare transport T_ACK(0), not an application response.
    assert_eq!(r2.responses[0].tpdu, vec![Tpci::ack_byte(0)]);
    assert_eq!(dev.rx_seq, 1, "duplicate must not advance rx_seq");
    Ok(())
}

#[test]
fn test_l4_out_of_sequence_ndt_is_dropped() -> Result<(), Box<dyn std::error::Error>> {
    // An NDT with an unexpected sequence (neither the expected one nor the
    // last-accepted duplicate) is ignored entirely: no response at all, and
    // rx_seq does not move. This is how a real device behaves, so a bussard
    // L4 desync reproduces here rather than being silently tolerated.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    // Expected seq is 0; send seq 5 (off-window).
    let stray = data_seq(&dev, 5, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    let r = dev.handle_cemi(&stray)?;
    assert!(
        r.responses.is_empty(),
        "out-of-sequence NDT draws no response"
    );
    assert_eq!(dev.rx_seq, 0, "rx_seq unchanged by an ignored frame");
    assert_eq!(
        dev.access_level, 15,
        "the stray authorize was not processed"
    );
    Ok(())
}

#[test]
fn test_l4_sequence_advances_across_a_wrap() -> Result<(), Box<dyn std::error::Error>> {
    // Drive 18 accepted device-descriptor reads so the receive sequence wraps
    // past 15 back through 0 and 1. Each read is at the expected sequence
    // (data() threads dev.rx_seq), so every one must be accepted and answered,
    // and rx_seq must land at 18 mod 16 = 2.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    for i in 0..18u16 {
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(
            r.responses.len(),
            1,
            "descriptor read {i} must be accepted and answered"
        );
    }
    assert_eq!(dev.rx_seq, 2, "18 accepted NDTs wrap rx_seq to 2");
    Ok(())
}

#[test]
fn test_l4_exchange_budget_drops_connection_after_budget() -> Result<(), Box<dyn std::error::Error>>
{
    // A device with a per-connection exchange budget drops the connection —
    // stops answering — once that many numbered exchanges have been accepted on
    // one connection, modelling a real connection-oriented device's
    // per-connection resource limit (KNX Virtual drops at ~35). Set a low
    // budget (3) and drive descriptor reads: the first 3 are answered, the 4th
    // and beyond draw no response and the device is no longer connected.
    let Some(dev) = da_tp_device()? else {
        return Ok(());
    };
    let mut dev = dev.with_l4_exchange_budget(Some(3));
    connect(&mut dev)?;
    for i in 0..3u16 {
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(
            r.responses.len(),
            1,
            "exchange {i} is within budget and must be answered"
        );
    }
    // The 4th exchange exceeds the budget: the device drops the connection.
    let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
    assert!(
        r.responses.is_empty(),
        "the over-budget exchange must draw no response (connection dropped)"
    );
    assert!(
        !dev.connected,
        "exceeding the budget drops the L4 connection"
    );
    Ok(())
}

#[test]
fn test_l4_exchange_budget_resets_on_reconnect() -> Result<(), Box<dyn std::error::Error>> {
    // The per-connection budget is per CONNECTION: a fresh T_Connect resets it,
    // so a tool that reconnects before exhausting the budget keeps being
    // served. Drive the budget to exhaustion, then reconnect and confirm the
    // device answers again — the persistent object state is unchanged.
    let Some(dev) = da_tp_device()? else {
        return Ok(());
    };
    let mut dev = dev.with_l4_exchange_budget(Some(2));
    connect(&mut dev)?;
    for _ in 0..2u16 {
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(r.responses.len(), 1);
    }
    // Over budget: dropped.
    assert!(
        dev.handle_cemi(&data(&dev, 0x300, &[]))?
            .responses
            .is_empty()
    );
    // Reconnect: a fresh window resets the budget and the device serves again.
    connect(&mut dev)?;
    let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
    assert_eq!(
        r.responses.len(),
        1,
        "a fresh connection resets the budget and the device answers again"
    );
    Ok(())
}

#[test]
fn test_l4_exchange_budget_unlimited_by_default() -> Result<(), Box<dyn std::error::Error>> {
    // The default budget is unlimited: without `with_l4_exchange_budget`, a
    // long run of exchanges on one connection is served in full (existing tests
    // and captures are unaffected).
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    for i in 0..40u16 {
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(
            r.responses.len(),
            1,
            "exchange {i} must be answered under the default unlimited budget"
        );
    }
    assert!(dev.connected, "the connection stays up under no budget");
    Ok(())
}
