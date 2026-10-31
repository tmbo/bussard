//! Issue #479: a load-state machine may answer a load event with the
//! intermediate states `Unloading` (4) and `LoadCompleting` (5) before it
//! settles (KNX 3/5/1 §4.23.2.3.1). The client re-reads the state until it
//! settles and fails with a clear timeout when it does not, on the System B
//! property form ([`load::write_load_control_with_poll`]) and on both System 7
//! forms ([`LsmAccess::drive_with_poll`]: property 0705, memory-mapped 0701).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bussard_mgmt::load::{self, IntermediatePoll, LoadControl, LoadState};
use bussard_mgmt::{Layer4Connection, LsmAccess, WriteError};
use bussard_model::IndividualAddress;
use bussard_testkit::consts::{
    A_MEMORY_READ, A_MEMORY_RESPONSE, A_PROPERTY_VALUE_READ, APCI_SELECTOR, PID_LOAD_STATE_CONTROL,
};
use bussard_testkit::sys7::{SYS7_CODE, system7_device};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// A short timing for the tests: the logic is the same as
/// [`IntermediatePoll::STANDARD`], only faster.
const FAST: IntermediatePoll = IntermediatePoll {
    period: Duration::from_millis(50),
    max_wait: Duration::from_millis(400),
};

/// The memory-mapped LSM status base of the 0701 form (`0xB6EA`).
const STATUS_ADDR: u16 = 0xB6EA;

/// The device, its gateway, an open tunnel and the counted PID 5 reads.
async fn connect(
    device: MockDevice,
) -> Result<(MockGateway, Transport, IndividualAddress), BoxError> {
    let target = device.address;
    let gw = MockGateway::builder()
        .idle_timeout(Duration::from_secs(60))
        .device(device)
        .start()
        .await?;
    let bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    Ok((gw, bus, target))
}

/// The `PID_LOAD_STATE_CONTROL` reads the device saw.
fn pid5_reads(gw: &MockGateway, target: IndividualAddress) -> Result<usize, BoxError> {
    let requests = gw.with_device(target, |d| d.requests.clone())?;
    Ok(requests
        .iter()
        .filter(|(apci, data)| {
            *apci == A_PROPERTY_VALUE_READ && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
        })
        .count())
}

#[tokio::test]
async fn test_write_load_control_with_poll_reads_through_load_completing() -> TestResult {
    let device = MockDevice::system_b("1.1.4".parse()?).with_intermediate_load_states(3);
    let (gw, mut bus, target) = connect(device).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let opened =
        load::write_load_control_with_poll(&mut l4, 1, LoadControl::StartLoading, FAST).await?;
    assert_eq!(opened, LoadState::Loading);
    // The answer and two reads report LoadCompleting, the third read Loaded.
    let done =
        load::write_load_control_with_poll(&mut l4, 1, LoadControl::LoadCompleted, FAST).await?;
    assert_eq!(done, LoadState::Loaded);
    // Unload of the loaded object: Unloading three times, then Unloaded.
    let gone = load::write_load_control_with_poll(&mut l4, 1, LoadControl::Unload, FAST).await?;
    assert_eq!(gone, LoadState::Unloaded);
    let _ = l4.disconnect().await;
    // Per event: two reads still intermediate, the third settled.
    assert_eq!(
        pid5_reads(&gw, target)?,
        6,
        "three re-reads per intermediate event"
    );
    Ok(())
}

#[tokio::test]
async fn test_write_load_control_with_poll_times_out_on_load_completing() -> TestResult {
    let device = MockDevice::system_b("1.1.4".parse()?).with_intermediate_load_states(u32::MAX);
    let (_gw, mut bus, target) = connect(device).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    load::write_load_control_with_poll(&mut l4, 1, LoadControl::StartLoading, FAST).await?;
    let err = load::write_load_control_with_poll(&mut l4, 1, LoadControl::LoadCompleted, FAST)
        .await
        .err()
        .ok_or("a machine that never settles must time out")?;
    let _ = l4.disconnect().await;
    match &err {
        WriteError::LoadStateTimeout {
            object_index,
            control,
            last,
            waited,
            ..
        } => {
            assert_eq!(*object_index, 1);
            assert_eq!(*control, LoadControl::LoadCompleted);
            assert_eq!(*last, LoadState::LoadCompleting);
            assert!(*waited >= FAST.max_wait, "waited {waited:?}");
        }
        other => return Err(format!("expected LoadStateTimeout, got {other:?}").into()),
    }
    assert!(
        err.to_string().contains("still reports LoadCompleting"),
        "{err}"
    );
    Ok(())
}

#[tokio::test]
async fn test_write_load_control_pauses_the_standard_period() -> TestResult {
    let device = MockDevice::system_b("1.1.4".parse()?).with_intermediate_load_states(1);
    let (gw, mut bus, target) = connect(device).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    load::write_load_control(&mut l4, 1, LoadControl::StartLoading).await?;
    let started = Instant::now();
    let done = load::write_load_control(&mut l4, 1, LoadControl::LoadCompleted).await?;
    let elapsed = started.elapsed();
    let _ = l4.disconnect().await;
    assert_eq!(done, LoadState::Loaded);
    // One re-read, after the 3 s of KNX 3/5/1 §4.23.2.4.1.
    assert_eq!(pid5_reads(&gw, target)?, 1);
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(10),
        "took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_drive_with_poll_property_reads_through_both_states() -> TestResult {
    // The 0705 form: a System 7 device whose LSMs start Loaded.
    let device = system7_device("1.1.7".parse()?, &SYS7_CODE).with_intermediate_load_states(2);
    let (gw, mut bus, target) = connect(device).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let lsm = LsmAccess::Property;
    let unloaded = lsm
        .drive_with_poll(&mut l4, 3, LoadControl::Unload, FAST)
        .await?;
    assert_eq!(unloaded, LoadState::Unloaded);
    lsm.drive_with_poll(&mut l4, 3, LoadControl::StartLoading, FAST)
        .await?;
    let loaded = lsm
        .drive_with_poll(&mut l4, 3, LoadControl::LoadCompleted, FAST)
        .await?;
    assert_eq!(loaded, LoadState::Loaded);
    let _ = l4.disconnect().await;
    // Per event: one read still intermediate, the second settled.
    assert_eq!(
        pid5_reads(&gw, target)?,
        4,
        "two re-reads per intermediate event"
    );
    Ok(())
}

#[tokio::test]
async fn test_drive_with_poll_property_times_out_on_unloading() -> TestResult {
    let device =
        system7_device("1.1.7".parse()?, &SYS7_CODE).with_intermediate_load_states(u32::MAX);
    let (_gw, mut bus, target) = connect(device).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let result = LsmAccess::Property
        .drive_with_poll(&mut l4, 1, LoadControl::Unload, FAST)
        .await;
    let _ = l4.disconnect().await;
    match result {
        Err(WriteError::LoadStateTimeout { last, control, .. }) => {
            assert_eq!(last, LoadState::Unloading);
            assert_eq!(control, LoadControl::Unload);
            Ok(())
        }
        other => Err(format!("expected LoadStateTimeout, got {other:?}").into()),
    }
}

/// A 0701-form device: the records land in plain memory at `0x0104`, and the
/// status octet of every LSM at `0xB6EA + lsm - 1` reads `LoadCompleting`
/// while `completing` is above zero (one used per read), then `Loaded`.
fn memory_mapped_device(completing: Arc<AtomicU32>) -> Result<MockDevice, BoxError> {
    Ok(MockDevice::new("1.1.8".parse()?)
        .with_mask(0x0701)
        .with_hook(move |_, apci, data| {
            if apci & APCI_SELECTOR != A_MEMORY_READ {
                return None;
            }
            let addr = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            if !(STATUS_ADDR..STATUS_ADDR + 4).contains(&addr) {
                return None;
            }
            let left = completing.load(Ordering::SeqCst);
            let state = if left > 0 {
                completing.store(left.saturating_sub(1), Ordering::SeqCst);
                5
            } else {
                1
            };
            let mut answer = addr.to_be_bytes().to_vec();
            answer.push(state);
            Some(Reaction::Answer(A_MEMORY_RESPONSE | 1, answer))
        }))
}

const MEMORY_MAPPED: LsmAccess = LsmAccess::MemoryMapped {
    control_addr: 0x0104,
    status_addr: STATUS_ADDR,
};

#[tokio::test]
async fn test_drive_with_poll_memory_mapped_reads_through_load_completing() -> TestResult {
    let completing = Arc::new(AtomicU32::new(3));
    let (_gw, mut bus, target) = connect(memory_mapped_device(Arc::clone(&completing))?).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let loaded = MEMORY_MAPPED
        .drive_with_poll(&mut l4, 3, LoadControl::LoadCompleted, FAST)
        .await?;
    let _ = l4.disconnect().await;
    assert_eq!(loaded, LoadState::Loaded);
    assert_eq!(
        completing.load(Ordering::SeqCst),
        0,
        "every report was read"
    );
    Ok(())
}

#[tokio::test]
async fn test_drive_with_poll_memory_mapped_times_out_on_load_completing() -> TestResult {
    let completing = Arc::new(AtomicU32::new(u32::MAX));
    let (_gw, mut bus, target) = connect(memory_mapped_device(completing)?).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let result = MEMORY_MAPPED
        .drive_with_poll(&mut l4, 3, LoadControl::LoadCompleted, FAST)
        .await;
    let _ = l4.disconnect().await;
    match result {
        Err(WriteError::LoadStateTimeout {
            object_index, last, ..
        }) => {
            assert_eq!(object_index, 3);
            assert_eq!(last, LoadState::LoadCompleting);
            Ok(())
        }
        other => Err(format!("expected LoadStateTimeout, got {other:?}").into()),
    }
}
