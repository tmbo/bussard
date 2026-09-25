//! Issue #211: a load-control write is confirmed by the load state the device
//! echoes in its `A_PropertyValue_Response`, as ETS does, and the separate
//! `PID_LOAD_STATE_CONTROL` read is only the fallback for a device that
//! answers without the expected state octet.
//!
//! Every test runs the same sequence (`Unload`, `StartLoading`, a relative
//! segment allocation, `LoadCompleted`) against a testkit System B device and
//! counts the requests it sees. The fast path and each fallback must end in
//! the same load states and the same device-placed segment address.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::Layer4Connection;
use bussard_mgmt::load::{self, LoadControl, LoadState};
use bussard_mgmt::{SegmentAllocation, WriteError};
use bussard_model::IndividualAddress;
use bussard_testkit::consts::{
    A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_RESPONSE, A_PROPERTY_VALUE_WRITE,
    PID_LOAD_STATE_CONTROL,
};
use bussard_testkit::device::{decode_prop_header, prop_response, segment_base_for};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// The table object the sequence drives (the address table of
/// [`MockDevice::system_b`]).
const OBJ: u8 = 1;

/// How the device answers a `PID_LOAD_STATE_CONTROL` write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// The resulting state as one octet (every 07B0 and 0705 device in the
    /// ETS captures).
    State,
    /// Count 1 but no data octet.
    Empty,
    /// The 10-octet event echoed back instead of the state.
    EchoEvent,
    /// The resulting state, except `Loaded` after `StartLoading` (KNX Virtual,
    /// issue #47).
    SnapToLoaded,
}

/// What one run of the sequence observed.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    states: Vec<LoadState>,
    segment: SegmentAllocation,
    /// `PID_LOAD_STATE_CONTROL` reads the device saw.
    pid5_reads: usize,
    /// Every request the device saw.
    requests: usize,
}

fn device(target: IndividualAddress, answer: Answer) -> MockDevice {
    MockDevice::system_b(target).with_hook(move |dev, apci, data| {
        if apci != A_PROPERTY_VALUE_WRITE || answer == Answer::State {
            return None;
        }
        let (oi, pid, _, start) = decode_prop_header(data)?;
        if pid != PID_LOAD_STATE_CONTROL {
            return None;
        }
        let value = data.get(4..).unwrap_or_default();
        // The KNX load-state machine, as the testkit's built-in handler runs
        // it; only the answer differs.
        let state = match value.first() {
            Some(1) if answer == Answer::SnapToLoaded => 1,
            Some(1) => 2,
            Some(2) => 1,
            Some(4) => 0,
            Some(3) if value.get(1) == Some(&0x0B) => {
                let size = u32::from_be_bytes([
                    *value.get(2)?,
                    *value.get(3)?,
                    *value.get(4)?,
                    *value.get(5)?,
                ]);
                dev.segments.insert(oi, (segment_base_for(oi), size));
                dev.load_state(oi)
            }
            _ => dev.load_state(oi),
        };
        dev.load_states.insert(oi, state);
        let reply = match answer {
            Answer::Empty => Vec::new(),
            Answer::EchoEvent => value.to_vec(),
            Answer::State | Answer::SnapToLoaded => vec![state],
        };
        Some(Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, 1, start, &reply),
        ))
    })
}

async fn open(gw: &MockGateway) -> Result<Transport, BoxError> {
    let addr: SocketAddrV4 = gw.addr();
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// Runs `Unload`, `StartLoading`, a 64-octet allocation and `LoadCompleted`.
async fn run_sequence(answer: Answer) -> Result<Run, BoxError> {
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let gw = MockGateway::builder()
        .idle_timeout(Duration::from_secs(5))
        .device(device(target, answer))
        .start()
        .await?;
    let mut bus = open(&gw).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut states = Vec::new();
    states.push(load::write_load_control(&mut l4, OBJ, LoadControl::Unload).await?);
    states.push(load::write_load_control(&mut l4, OBJ, LoadControl::StartLoading).await?);
    let segment = load::allocate_segment(&mut l4, OBJ, 64, Some(0)).await?;
    states.push(load::write_load_control(&mut l4, OBJ, LoadControl::LoadCompleted).await?);
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target, |d| d.requests.clone())?;
    let pid5_reads = requests
        .iter()
        .filter(|(apci, data)| {
            *apci == A_PROPERTY_VALUE_READ && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
        })
        .count();
    Ok(Run {
        states,
        segment,
        pid5_reads,
        requests: requests.len(),
    })
}

#[tokio::test]
async fn test_write_load_control_trusts_the_echoed_state() -> TestResult {
    let run = run_sequence(Answer::State).await?;
    assert_eq!(
        run.states,
        [LoadState::Unloaded, LoadState::Loading, LoadState::Loaded]
    );
    assert_eq!(run.pid5_reads, 0, "no PID 5 read-back, as ETS");
    // Unload 1, StartLoading 1, allocation 2 (the record and the PID 7 read),
    // LoadCompleted 1. Before issue #211: 2 / 2 / 4 / 2.
    assert_eq!(run.requests, 5);
    Ok(())
}

#[tokio::test]
async fn test_write_load_control_reads_back_without_a_state_octet() -> TestResult {
    let fast = run_sequence(Answer::State).await?;
    let run = run_sequence(Answer::Empty).await?;
    assert_eq!(run.states, fast.states, "same states as the fast path");
    assert_eq!(run.segment, fast.segment, "same segment as the fast path");
    assert_eq!(run.pid5_reads, 4, "every event falls back to the read");
    assert_eq!(run.requests, 9);
    Ok(())
}

#[tokio::test]
async fn test_write_load_control_reads_back_an_echoed_event() -> TestResult {
    let fast = run_sequence(Answer::State).await?;
    let run = run_sequence(Answer::EchoEvent).await?;
    assert_eq!(run.states, fast.states);
    assert_eq!(run.segment, fast.segment);
    assert_eq!(run.pid5_reads, 4);
    Ok(())
}

#[tokio::test]
async fn test_write_load_control_reads_back_an_unexpected_state() -> TestResult {
    // KNX Virtual answers StartLoading with Loaded (#47): not the state ETS
    // continues on, so it is read back; Loaded still opens the object.
    let run = run_sequence(Answer::SnapToLoaded).await?;
    assert_eq!(
        run.states,
        [LoadState::Unloaded, LoadState::Loaded, LoadState::Loaded]
    );
    // StartLoading reads back; the allocation answers Loaded and reads back.
    assert_eq!(run.pid5_reads, 2);
    Ok(())
}

#[tokio::test]
async fn test_allocate_segment_error_answer_is_confirmed_by_a_read() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    // The device refuses the allocation: it answers Error and stays there.
    let dev = MockDevice::system_b(target).with_hook(|dev, apci, data| {
        let (oi, pid, _, start) = decode_prop_header(data)?;
        if apci != A_PROPERTY_VALUE_WRITE
            || pid != PID_LOAD_STATE_CONTROL
            || data.get(4) != Some(&3)
        {
            return None;
        }
        dev.load_states.insert(oi, 3);
        Some(Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, 1, start, &[3]),
        ))
    });
    let gw = MockGateway::builder()
        .idle_timeout(Duration::from_secs(5))
        .device(dev)
        .start()
        .await?;
    let mut bus = open(&gw).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    load::write_load_control(&mut l4, OBJ, LoadControl::StartLoading).await?;
    let err = load::allocate_segment(&mut l4, OBJ, 0xFFFF_FFF0, None)
        .await
        .err()
        .ok_or("the refused allocation must fail")?;
    let _ = l4.disconnect().await;
    assert!(
        matches!(
            err,
            WriteError::LoadError {
                object_index: OBJ,
                ..
            }
        ),
        "a refused allocation is a load error: {err:?}"
    );
    let reads = gw.with_device(target, |d| {
        d.requests
            .iter()
            .filter(|(apci, data)| {
                *apci == A_PROPERTY_VALUE_READ && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
            })
            .count()
    })?;
    assert_eq!(reads, 1, "the Error answer is confirmed by one read");
    Ok(())
}
