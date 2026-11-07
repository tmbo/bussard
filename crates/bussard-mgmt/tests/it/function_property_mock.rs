//! `A_FunctionPropertyCommand` (issue #946) against the testkit mock device:
//! the call goes out as object index, PID and input, and only a state
//! response with return code 00h for the same object and PID is a success
//! (KNX 3/3/7 §3.4.7.3).

use std::time::Duration;

use bussard_mgmt::function_property::{
    A_FUNCTION_PROPERTY_COMMAND, A_FUNCTION_PROPERTY_STATE_RESPONSE, function_property_command,
};
use bussard_mgmt::{Layer4Connection, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x33;

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.1".parse()?)
}

/// Calls object 5 PID 52 with `04` on a device that answers the command
/// with `answer` (`None`: acknowledges and stays silent); returns the result
/// and the commands the device saw.
async fn call(answer: Option<Vec<u8>>) -> Result<(Result<(), MgmtError>, Vec<Vec<u8>>), BoxError> {
    let device = MockDevice::new(target()?).with_hook(move |_, apci, _| {
        (apci == A_FUNCTION_PROPERTY_COMMAND).then(|| match &answer {
            Some(payload) => Reaction::Answer(A_FUNCTION_PROPERTY_STATE_RESPONSE, payload.clone()),
            None => Reaction::Ack,
        })
    });
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(10))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let timeouts = Timeouts {
        response_timeout: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let mut l4 =
        Layer4Connection::connect(&mut bus, target()?, "0.0.255".parse()?, timeouts.into()).await?;
    let result = function_property_command(&mut l4, 5, 52, &[0x04])
        .await
        .map(|_| ());
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target()?, |d| d.requests.clone())?;
    let commands = requests
        .into_iter()
        .filter(|(apci, _)| *apci == A_FUNCTION_PROPERTY_COMMAND)
        .map(|(_, data)| data)
        .collect();
    Ok((result, commands))
}

#[tokio::test]
async fn test_function_property_command_return_code_zero_succeeds() -> TestResult {
    // The capture's exchange: `05 34 04`, answered `05 34 00`.
    let (result, commands) = call(Some(vec![0x05, 0x34, 0x00])).await?;
    result?;
    assert_eq!(commands, vec![vec![0x05, 0x34, 0x04]]);
    Ok(())
}

#[tokio::test]
async fn test_function_property_command_nonzero_return_code_fails() -> TestResult {
    let (result, _) = call(Some(vec![0x05, 0x34, 0x01])).await?;
    assert!(
        matches!(
            result,
            Err(MgmtError::ServiceRejected {
                return_code: Some(1),
                ..
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_function_property_command_without_return_code_fails() -> TestResult {
    // Not a function property: the answer carries no return code (§3.4.7.3).
    let (result, _) = call(Some(vec![0x05, 0x34])).await?;
    assert!(
        matches!(
            result,
            Err(MgmtError::ServiceRejected {
                return_code: None,
                ..
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_function_property_command_other_property_fails() -> TestResult {
    let (result, _) = call(Some(vec![0x05, 0x35, 0x00])).await?;
    assert!(
        matches!(result, Err(MgmtError::MalformedResponse { .. })),
        "{result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_function_property_command_no_answer_fails() -> TestResult {
    let (result, _) = call(None).await?;
    assert!(result.is_err(), "an unanswered call is not a success");
    Ok(())
}
