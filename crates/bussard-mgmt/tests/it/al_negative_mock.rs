//! The defined negative answers of the application layer, read as what they
//! are (issue #509): an `A_Memory_Response` with number 0 (03_03_07 §3.5.3,
//! §3.5.4), the extended-memory return codes (§3.4.9), the descriptor type
//! 3Fh (§3.4.2.1) and an authorize level between maximum and minimum
//! (§3.5.7).

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::load::WriteError;
use bussard_mgmt::{
    AuthorizeOutcome, Layer4Connection, MgmtError, read_device_descriptor, read_memory,
    read_memory_range, write_memory,
};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockError, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x15;

async fn start_mock(device: MockDevice) -> Result<MockGateway, MockError> {
    MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .device(device)
        .start()
        .await
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// A device at 1.1.7 that answers every request with `reaction(apci, data)`.
fn device<F>(reaction: F) -> Result<MockDevice, BoxError>
where
    F: Fn(u16, &[u8]) -> Reaction + Send + Sync + 'static,
{
    Ok(
        MockDevice::new("1.1.7".parse()?)
            .with_hook(move |_, apci, data| Some(reaction(apci, data))),
    )
}

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.7".parse()?)
}

fn source() -> Result<IndividualAddress, BoxError> {
    Ok("0.0.255".parse()?)
}

#[tokio::test]
async fn test_memory_response_number_zero_is_a_refusal() -> TestResult {
    // §3.5.3: protected memory answers with number 0 and no data.
    let gw = start_mock(device(|apci_val, data| {
        if apci_val & apci::APCI_SELECTOR_MASK == apci::A_MEMORY_READ {
            Reaction::Answer(apci::A_MEMORY_RESPONSE, data[..2].to_vec())
        } else {
            Reaction::Ack
        }
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    // The single-telegram read keeps returning the empty answer.
    assert!(read_memory(&mut l4, 0x4000, 4).await?.is_empty());
    let Err(err) = read_memory_range(&mut l4, 0x4000, 4).await else {
        return Err("a refused read cannot fill the range".into());
    };
    assert!(
        matches!(
            err,
            WriteError::Mgmt(MgmtError::MemoryRefused {
                op: "read",
                addr: 0x4000,
                count: 4,
                ..
            })
        ),
        "got {err:?}"
    );
    assert!(err.to_string().contains("number 0"), "{err}");
    l4.disconnect().await?;
    Ok(())
}

#[tokio::test]
async fn test_extended_read_return_code_is_named() -> TestResult {
    // §3.4.9.1.1: E_ACCESS_DENIED (FCh), no data.
    let gw = start_mock(device(|apci_val, data| {
        if apci_val == apci::A_MEMORY_EXTENDED_READ {
            let mut payload = vec![0xFC];
            payload.extend_from_slice(&data[1..4]);
            Reaction::Answer(apci::A_MEMORY_EXTENDED_READ_RESPONSE, payload)
        } else {
            Reaction::Ack
        }
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    let Err(err) = read_memory(&mut l4, 0x01_6000, 4).await else {
        return Err("access denied".into());
    };
    assert!(
        matches!(
            err,
            WriteError::Mgmt(MgmtError::MemoryReturnCode {
                code: 0xFC,
                name: "E_ACCESS_DENIED",
                ..
            })
        ),
        "got {err:?}"
    );
    l4.disconnect().await?;
    Ok(())
}

#[tokio::test]
async fn test_extended_write_return_code_is_not_a_verify_mismatch() -> TestResult {
    // §3.4.9.2.1: E_LENGTH_EXCEEDS_MAX_APDU_LENGTH (F4h) is a sizing problem.
    let gw = start_mock(device(|apci_val, data| {
        if apci_val == apci::A_MEMORY_EXTENDED_WRITE {
            let mut payload = vec![0xF4];
            payload.extend_from_slice(&data[1..4]);
            Reaction::Answer(apci::A_MEMORY_EXTENDED_WRITE_RESPONSE, payload)
        } else {
            Reaction::Ack
        }
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    let Err(err) = write_memory(&mut l4, 0x01_6000, &[1, 2, 3]).await else {
        return Err("the write is refused".into());
    };
    assert!(
        matches!(
            err,
            WriteError::Mgmt(MgmtError::MemoryReturnCode {
                code: 0xF4,
                name: "E_LENGTH_EXCEEDS_MAX_APDU_LENGTH",
                ..
            })
        ),
        "got {err:?}"
    );
    l4.disconnect().await?;
    Ok(())
}

#[tokio::test]
async fn test_descriptor_type_3f_is_unsupported() -> TestResult {
    // §3.4.2.1: type 3Fh, no data: the type is not supported.
    let gw = start_mock(device(|_, _| {
        Reaction::Answer(apci::A_DEVICE_DESCRIPTOR_RESPONSE | 0x3F, Vec::new())
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    let Err(err) = read_device_descriptor(&mut l4).await else {
        return Err("type 0 is not supported".into());
    };
    assert!(
        matches!(
            err,
            MgmtError::DescriptorTypeUnsupported { requested: 0, .. }
        ),
        "got {err:?}"
    );
    l4.disconnect().await?;
    Ok(())
}

#[tokio::test]
async fn test_descriptor_of_another_type_is_not_read_as_type_0() -> TestResult {
    // §3.4.2.1: a device without type 0 answers with its lowest supported
    // type; its value is not a mask version.
    let gw = start_mock(device(|_, _| {
        Reaction::Answer(
            apci::A_DEVICE_DESCRIPTOR_RESPONSE | 0x02,
            vec![0x00, 0x83, 0x01],
        )
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    let Err(err) = read_device_descriptor(&mut l4).await else {
        return Err("a type-2 answer is not a mask".into());
    };
    assert!(
        matches!(err, MgmtError::MalformedResponse { .. }),
        "got {err:?}"
    );
    assert!(err.to_string().contains("descriptor type 2"), "{err}");
    l4.disconnect().await?;
    Ok(())
}

#[tokio::test]
async fn test_authorize_level_between_maximum_and_minimum_is_granted() -> TestResult {
    // §3.5.7: the free key maps to the highest unprotected level, here 2.
    let gw = start_mock(device(|apci_val, _| {
        if apci_val == apci::A_AUTHORIZE_REQUEST {
            Reaction::Answer(apci::A_AUTHORIZE_RESPONSE, vec![0x02])
        } else {
            Reaction::Ack
        }
    })?)
    .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, source()?).await?;
    let outcome = l4.authorize_or_fail(0xFFFF_FFFF).await?;
    assert_eq!(outcome, AuthorizeOutcome::Granted { level: 2 });
    assert_eq!(outcome.level(), Some(2));
    assert!(outcome.grants(2));
    assert!(
        !outcome.grants(1),
        "level 2 does not allow a level-1 access"
    );
    l4.disconnect().await?;
    Ok(())
}
