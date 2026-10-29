//! Issue #472: memory above `0xFFFF` of an application without extended
//! memory services goes over `A_UserMemory_Read`/`_Write` (03_03_07
//! §3.5.6.2, §3.5.6.3), against the testkit device that leaves the extended
//! services unanswered.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::{
    Layer4Connection, read_memory_range, write_memory_chunked, write_memory_echoed,
};
use bussard_model::IndividualAddress;
use bussard_testkit::consts::{A_MEMORY_WRITE, A_USER_MEMORY_READ, A_USER_MEMORY_WRITE};
use bussard_testkit::{BoxError, MockDevice, MockGateway, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// What one write-then-read run left behind.
struct Run {
    read_back: Vec<u8>,
    stored: Vec<u8>,
    requests: Vec<(u16, Vec<u8>)>,
}

async fn run(addr: u32, data: &[u8], echo: bool) -> Result<Run, BoxError> {
    let target: IndividualAddress = "1.1.4".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut device = MockDevice::new(target).without_extended_memory();
    if !echo {
        device = device.without_memory_write_echo();
    }
    let gw = MockGateway::builder()
        .idle_timeout(Duration::from_secs(5))
        .device(device)
        .start()
        .await?;
    let gw_addr: SocketAddrV4 = gw.addr();
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw_addr)).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.set_user_memory_above_64k(true);
    if echo {
        write_memory_echoed(&mut l4, addr, data, |_| {}).await?;
    } else {
        write_memory_chunked(&mut l4, addr, data, |_| {}).await?;
    }
    let read_back = read_memory_range(&mut l4, addr, data.len()).await?;
    let _ = l4.disconnect().await;
    let (stored, requests) = gw.with_device(target, |d| {
        let stored = (0..data.len() as u32)
            .map(|i| d.memory.get(&(addr + i)).copied().unwrap_or(0))
            .collect::<Vec<u8>>();
        (stored, d.requests.clone())
    })?;
    Ok(Run {
        read_back,
        stored,
        requests,
    })
}

fn ramp(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7)).collect()
}

#[tokio::test]
async fn test_write_memory_chunked_user_memory_above_64k() -> TestResult {
    let data = ramp(25);
    let run = run(0x01_0010, &data, false).await?;
    assert_eq!(run.stored, data);
    assert_eq!(run.read_back, data);
    let writes: Vec<&Vec<u8>> = run
        .requests
        .iter()
        .filter(|(apci, _)| *apci == A_USER_MEMORY_WRITE)
        .map(|(_, d)| d)
        .collect();
    // No negotiated APDU: 10 octets per request (the standard frame), and
    // the first carries extension 1, count 10, address 0x0010.
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0].get(..3), Some(&[0x1A, 0x00, 0x10][..]));
    assert!(
        run.requests
            .iter()
            .any(|(apci, _)| *apci == A_USER_MEMORY_READ)
    );
    Ok(())
}

#[tokio::test]
async fn test_write_memory_echoed_compares_the_user_memory_echo() -> TestResult {
    let data = ramp(12);
    let run = run(0x02_FFF8, &data, true).await?;
    assert_eq!(run.stored, data);
    assert_eq!(run.read_back, data);
    Ok(())
}

#[tokio::test]
async fn test_user_memory_flag_keeps_the_plain_service_below_64k() -> TestResult {
    let data = ramp(8);
    let run = run(0x4000, &data, false).await?;
    assert_eq!(run.stored, data);
    assert!(
        run.requests
            .iter()
            .all(|(apci, _)| *apci != A_USER_MEMORY_WRITE)
    );
    assert!(
        run.requests
            .iter()
            .any(|(apci, _)| apci & 0x3C0 == A_MEMORY_WRITE)
    );
    Ok(())
}
