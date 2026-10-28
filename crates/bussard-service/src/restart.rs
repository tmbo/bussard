//! Restarting one device: the write behind `bussard restart`.
//!
//! A restart re-runs the device's application, as a power cycle of that one
//! device would: parameters, tables and the individual address stay. A device
//! may transmit its status objects as it starts, so a restart can act on the
//! bus like a bus-voltage return does.
//!
//! ETS's "Restart device" sends one of two forms, chosen from the product data
//! by [`bussard_download::restart_form`] (the rule the flash uses for the
//! restart that ends a download, issue #452); [`restart_choice`] applies it to
//! a model device:
//!
//! - **Confirmed** (a secure-capable System B application): `A_Restart` master
//!   reset, erase code 1, channel 0. The device answers `A_Restart_Response`.
//!   [`restart_device`] counts the restart as confirmed only on error code 0;
//!   no answer, or another error code, is an error. It then waits the process
//!   time the device reported, as the flash does, and checks the device comes
//!   back.
//! - **Basic** (every other application, and a device without product data): a
//!   bare `A_Restart`, which a device never answers and may not even
//!   acknowledge. bussard can only say the restart was sent and that the
//!   device answered again afterwards; [`RestartOutcome::confirmed`] stays
//!   false and the surfaces say so.
//!
//! Either way [`restart_device`] reads the device's mask first and, after the
//! restart, reconnects until the device answers its descriptor read again with
//! the same mask. A device that stays silent, or comes back as another mask,
//! is an error.
//!
//! A Data Secure device (one whose [`L4Options::tool_key`] is set) gets both
//! the descriptor reads and the restart inside the secured session, as every
//! other management write: ETS's restart of the activated 1.1.12 is a
//! secured confirmed restart (36-octet request, 37-octet answer, capture
//! `restart-1-1-12-secure.pcapng`).

use std::path::Path;
use std::time::{Duration, Instant};

use bussard_download::{RestartForm, restart_form};
use bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART;
use bussard_mgmt::load::WriteError;
use bussard_model::{IndividualAddress, Model};

use crate::params::{MissingProduct, Selection, resolve_product};
use crate::{BusService, L4Options, ServiceError};

/// How long [`restart_device`] waits for the device to come back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartWait {
    /// The pause after the restart (after the reported process time, for the
    /// confirmed form) before the first reconnect, so the probe does not reach
    /// a device that has not dropped the old connection yet.
    pub settle: Duration,
    /// The pause between two reconnect attempts.
    pub retry: Duration,
    /// How long after the restart the device may take to answer.
    pub timeout: Duration,
}

impl Default for RestartWait {
    /// Two seconds to settle, a retry every second, thirty seconds in all: a
    /// TP1 device answers within a few seconds of its restart.
    fn default() -> Self {
        RestartWait {
            settle: Duration::from_secs(2),
            retry: Duration::from_secs(1),
            timeout: Duration::from_secs(30),
        }
    }
}

/// The restart form for one device and why it was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartChoice {
    /// The form [`restart_device`] sends.
    pub form: RestartForm,
    /// Why: the application and whether it is secure-capable, or why there
    /// was no product data to decide with.
    pub why: String,
}

/// The restart form ETS uses for `target`, from the product data the lock
/// pins for it in the model at `dir` ([`bussard_download::restart_form`]).
/// Without product data the form is basic, which every device accepts, and
/// `why` says what was missing.
pub fn restart_choice(
    dir: &Path,
    model: Option<&Model>,
    target: IndividualAddress,
) -> RestartChoice {
    let basic = |why: String| RestartChoice {
        form: RestartForm::Basic,
        why,
    };
    let lookup = match resolve_product(
        dir,
        Selection::default(),
        model,
        target,
        MissingProduct::Warn,
        None,
    ) {
        Ok(lookup) => lookup,
        Err(err) => return basic(format!("no product data to decide with: {err}")),
    };
    let Some(source) = lookup.source else {
        return basic(match lookup.warning {
            Some(warning) => format!("no product data to decide with: {warning}"),
            None => format!("bussard.lock pins no product data for {target}"),
        });
    };
    let Some(app) = source.app() else {
        return basic(format!(
            "the pinned product data does not carry application {}",
            source.app_id
        ));
    };
    let form = restart_form(app);
    let why = match form {
        RestartForm::Confirmed => format!(
            "{} is a secure-capable System B application (IsSecureEnabled)",
            app.id
        ),
        RestartForm::Basic => format!("{} is not a secure-capable System B application", app.id),
    };
    RestartChoice { form, why }
}

/// A restart the device answered again after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartOutcome {
    /// The form that was sent.
    pub form: RestartForm,
    /// Whether the device confirmed the restart itself: an
    /// `A_Restart_Response` with error code 0. Always false for the basic
    /// form, which a device never answers.
    pub confirmed: bool,
    /// The process time the device reported in its `A_Restart_Response`
    /// (confirmed form only), as bussard waited it.
    pub process_time: Option<Duration>,
    /// The device's mask, read before the restart and again after it.
    pub mask: u16,
    /// How long after the restart the device answered again.
    pub answered_after: Duration,
}

/// Restarting a device failed.
#[derive(Debug, thiserror::Error)]
pub enum RestartError {
    /// The device could not be reached before the restart, or the restart
    /// could not be sent.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// The confirmed restart was sent, but the device did not answer it with
    /// an `A_Restart_Response`.
    #[error(
        "{address} did not answer the confirmed restart with an A_Restart_Response, so the \
         restart is not confirmed (the device may or may not have restarted): {last}"
    )]
    NotConfirmed {
        /// The device.
        address: IndividualAddress,
        /// What the request ended with.
        last: String,
    },
    /// The device answered the confirmed restart with a non-zero error code.
    #[error("{address} refused the restart: {source}")]
    Refused {
        /// The device.
        address: IndividualAddress,
        /// The device's error code.
        error_code: u8,
        /// The refusal, with the error code's meaning.
        source: WriteError,
    },
    /// The restart was sent, but the device did not answer again in time.
    #[error(
        "{address} did not answer within {}s of the restart (last error: {last})",
        .timeout.as_secs()
    )]
    NoAnswer {
        /// The device.
        address: IndividualAddress,
        /// How long bussard waited.
        timeout: Duration,
        /// The last reconnect's error.
        last: String,
    },
    /// The device answered again, but with another mask.
    #[error("{address} answered with mask {after:04X} after the restart, {before:04X} before it")]
    MaskChanged {
        /// The device.
        address: IndividualAddress,
        /// The mask before the restart.
        before: u16,
        /// The mask after it.
        after: u16,
    },
}

/// Restarts `target` in `form` and waits until it answers again (see the
/// module docs).
///
/// # Errors
///
/// [`RestartError::Service`] when the device cannot be reached or the restart
/// cannot be sent, [`RestartError::NotConfirmed`] or
/// [`RestartError::Refused`] when a confirmed restart is not answered with
/// error code 0, [`RestartError::NoAnswer`] when the device does not come
/// back within `wait.timeout`, [`RestartError::MaskChanged`] when it comes
/// back as another mask.
pub async fn restart_device(
    service: &BusService,
    target: IndividualAddress,
    options: &L4Options,
    form: RestartForm,
    wait: RestartWait,
) -> Result<RestartOutcome, RestartError> {
    let (before, answer) = service
        .with_device(target, options, async |dev| {
            let mask = dev.device_descriptor().await?;
            let answer = match form {
                RestartForm::Confirmed => Some(
                    bussard_mgmt::master_reset(dev.l4_mut(), ERASE_CODE_CONFIRMED_RESTART, 0).await,
                ),
                RestartForm::Basic => {
                    dev.restart().await?;
                    None
                }
            };
            Ok::<_, ServiceError>((mask, answer))
        })
        .await?;
    let started = Instant::now();
    let process_time = match answer {
        None => None,
        Some(Ok(response)) => Some(bussard_mgmt::restart_process_wait(&response)),
        Some(Err(err @ WriteError::RestartRefused { error_code, .. })) => {
            return Err(RestartError::Refused {
                address: target,
                error_code,
                source: err,
            });
        }
        Some(Err(err)) => {
            return Err(RestartError::NotConfirmed {
                address: target,
                last: err.to_string(),
            });
        }
    };
    // Wait the process time the device asked for, as the flash does
    // (`restart_process_wait`, capped at a minute), before the reconnects.
    if let Some(process_time) = process_time {
        tokio::time::sleep(process_time).await;
    }
    wait_until_back(service, target, options, before, wait).await?;
    Ok(RestartOutcome {
        form,
        confirmed: process_time.is_some(),
        process_time,
        mask: before,
        answered_after: started.elapsed(),
    })
}

/// Waits for `target` to answer its descriptor read again after a restart
/// another write sent (the basic restart that ends a System 7 table apply),
/// reconnecting as [`restart_device`] does, and checks it comes back as
/// `mask`. Returns how long after the call it answered.
pub async fn wait_until_back(
    service: &BusService,
    target: IndividualAddress,
    options: &L4Options,
    mask: u16,
    wait: RestartWait,
) -> Result<Duration, RestartError> {
    let started = Instant::now();
    let after = wait_for_answer(target, wait, move || async move {
        service
            .with_device(target, options, async |dev| {
                Ok::<u16, ServiceError>(dev.device_descriptor().await?)
            })
            .await
            .map_err(|err| err.to_string())
    })
    .await?;
    if after != mask {
        return Err(RestartError::MaskChanged {
            address: target,
            before: mask,
            after,
        });
    }
    Ok(started.elapsed())
}

/// Runs `probe` after `wait.settle`, then every `wait.retry`, until it answers
/// or `wait.timeout` has passed since the call.
///
/// `probe` is a plain closure returning a future, not an `AsyncFnMut`: an
/// async closure's future is not provably `Send` here, and the MCP server runs
/// this inside a spawned job.
async fn wait_for_answer<F, Fut>(
    target: IndividualAddress,
    wait: RestartWait,
    mut probe: F,
) -> Result<u16, RestartError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<u16, String>>,
{
    let deadline = Instant::now() + wait.timeout;
    tokio::time::sleep(wait.settle).await;
    loop {
        match probe().await {
            Ok(mask) => return Ok(mask),
            Err(last) if Instant::now() + wait.retry >= deadline => {
                return Err(RestartError::NoAnswer {
                    address: target,
                    timeout: wait.timeout,
                    last,
                });
            }
            Err(err) => {
                tracing::debug!("{target} not back yet after the restart: {err}");
                tokio::time::sleep(wait.retry).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bussard_mgmt::apci::{A_RESTART_MASTER_RESET, A_RESTART_RESPONSE};
    use bussard_testkit::device::Reaction;
    use bussard_testkit::{MockDevice, MockGateway};
    use bussard_transport::ConnectionConfig;

    use crate::{SourcePolicy, WritePolicy};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn quick() -> RestartWait {
        RestartWait {
            settle: Duration::from_millis(1),
            retry: Duration::from_millis(1),
            timeout: Duration::from_millis(200),
        }
    }

    /// How a mock device answers a confirmed (master reset) restart.
    #[derive(Clone, Copy)]
    enum Answer {
        /// `A_Restart_Response` with this error code and a zero process time.
        Response(u8),
        /// A `T_ACK` and nothing else.
        Silent,
    }

    /// A System B device at 1.1.39 that answers a master reset as `answer`
    /// says and counts the master resets it sees (the mock counts basic
    /// restarts itself). `tool_key` makes it a Data Secure device.
    fn device(
        answer: Answer,
        resets: Arc<AtomicUsize>,
        tool_key: Option<[u8; 16]>,
    ) -> TestResult<MockDevice> {
        let mut device = MockDevice::new("1.1.39".parse()?)
            .with_mask(0x07B0)
            .with_hook(move |_, apci, data| {
                if apci != A_RESTART_MASTER_RESET || data != [ERASE_CODE_CONFIRMED_RESTART, 0] {
                    return None;
                }
                resets.fetch_add(1, Ordering::SeqCst);
                Some(match answer {
                    Answer::Response(code) => {
                        Reaction::Answer(A_RESTART_RESPONSE, vec![code, 0, 0])
                    }
                    Answer::Silent => Reaction::Ack,
                })
            });
        if let Some(key) = tool_key {
            device = device.with_data_secure(key);
        }
        Ok(device)
    }

    /// Restarts 1.1.39 on a loopback mock gateway holding `device`, in
    /// `form`; returns the result, the master resets and the basic restarts
    /// the device saw, and how many requests reached it secured.
    async fn restart_on(
        device: MockDevice,
        resets: Arc<AtomicUsize>,
        form: RestartForm,
        tool_key: Option<[u8; 16]>,
    ) -> TestResult<(Result<RestartOutcome, RestartError>, usize, usize, usize)> {
        let gw = MockGateway::builder().device(device).start().await?;
        let service = BusService::open(
            ConnectionConfig::tunnel(gw.addr()),
            WritePolicy::transmit(false),
        )?;
        service.wait_connected(Duration::from_secs(5)).await;
        let options = L4Options {
            source: SourcePolicy::Check { skip: true },
            tool_key: tool_key.map(bussard_secure::Key16::new),
            timeouts: bussard_mgmt::Timeouts {
                ack_timeout: Duration::from_millis(300),
                response_timeout: Duration::from_millis(300),
                ..bussard_mgmt::Timeouts::default()
            },
            ..L4Options::default()
        };
        let result = restart_device(&service, "1.1.39".parse()?, &options, form, quick()).await;
        service.close().await;
        let (basic, secured) = gw
            .devices()?
            .first()
            .map(|d| (d.restarts, d.secured_requests))
            .unwrap_or_default();
        Ok((result, resets.load(Ordering::SeqCst), basic, secured))
    }

    #[tokio::test]
    async fn test_restart_device_confirmed_answered_is_confirmed() -> TestResult {
        let resets = Arc::new(AtomicUsize::new(0));
        let dev = device(Answer::Response(0), resets.clone(), None)?;
        let (result, master, basic, _) =
            restart_on(dev, resets, RestartForm::Confirmed, None).await?;
        let outcome = result?;
        assert!(outcome.confirmed);
        assert_eq!(outcome.form, RestartForm::Confirmed);
        assert_eq!(outcome.process_time, Some(Duration::ZERO));
        assert_eq!(outcome.mask, 0x07B0);
        assert_eq!(
            (master, basic),
            (1, 0),
            "one master reset, no bare A_Restart"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_restart_device_confirmed_unanswered_is_an_error() -> TestResult {
        let resets = Arc::new(AtomicUsize::new(0));
        let dev = device(Answer::Silent, resets.clone(), None)?;
        let (result, master, _, _) = restart_on(dev, resets, RestartForm::Confirmed, None).await?;
        let err = result
            .err()
            .ok_or("an unanswered confirmed restart is an error")?;
        assert!(matches!(err, RestartError::NotConfirmed { .. }), "{err}");
        assert!(master >= 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_restart_device_confirmed_error_code_is_an_error() -> TestResult {
        let resets = Arc::new(AtomicUsize::new(0));
        let dev = device(Answer::Response(0x01), resets.clone(), None)?;
        let (result, _, _, _) = restart_on(dev, resets, RestartForm::Confirmed, None).await?;
        let err = result.err().ok_or("a refused restart is an error")?;
        assert!(
            matches!(
                err,
                RestartError::Refused {
                    error_code: 0x01,
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("access denied"), "{err}");
        Ok(())
    }

    #[tokio::test]
    async fn test_restart_device_basic_is_sent_but_unconfirmed() -> TestResult {
        let resets = Arc::new(AtomicUsize::new(0));
        let dev = device(Answer::Response(0), resets.clone(), None)?;
        let (result, master, basic, _) = restart_on(dev, resets, RestartForm::Basic, None).await?;
        let outcome = result?;
        assert!(!outcome.confirmed, "a bare A_Restart is never confirmed");
        assert_eq!(outcome.form, RestartForm::Basic);
        assert_eq!(outcome.process_time, None);
        assert_eq!(
            (master, basic),
            (0, 1),
            "one bare A_Restart, no master reset"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_restart_device_confirmed_over_data_secure() -> TestResult {
        // 1.1.12: an activated Data Secure device gets the confirmed restart
        // inside the secured session; the mock unwraps it before the hook and
        // seals the A_Restart_Response.
        let key = [0x5A; 16];
        let resets = Arc::new(AtomicUsize::new(0));
        let dev = device(Answer::Response(0), resets.clone(), Some(key))?;
        let (result, master, _, secured) =
            restart_on(dev, resets, RestartForm::Confirmed, Some(key)).await?;
        let outcome = result?;
        assert!(outcome.confirmed);
        assert_eq!(master, 1);
        // The mock refuses a plain request to an activated device, so the
        // descriptor reads and the restart all went in A_SecureData.
        assert!(secured >= 3, "secured requests: {secured}");
        Ok(())
    }

    #[test]
    fn test_restart_choice_without_product_data_is_basic() -> TestResult {
        let dir =
            std::env::temp_dir().join(format!("bussard-restart-choice-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let choice = restart_choice(&dir, None, "1.1.45".parse()?);
        std::fs::remove_dir_all(&dir)?;
        assert_eq!(choice.form, RestartForm::Basic);
        assert!(choice.why.contains("no product data"), "{}", choice.why);
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_answer_retries_until_the_device_is_back()
    -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.39".parse()?;
        let mut calls = 0;
        let mask = wait_for_answer(target, quick(), || {
            calls += 1;
            let answer = if calls < 3 {
                Err("no response".to_string())
            } else {
                Ok(0x0705)
            };
            async move { answer }
        })
        .await?;
        assert_eq!(mask, 0x0705);
        assert_eq!(calls, 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_answer_gives_up_at_the_timeout() -> Result<(), Box<dyn std::error::Error>>
    {
        let target: IndividualAddress = "1.1.39".parse()?;
        let err = wait_for_answer(target, quick(), || async { Err("no response".to_string()) })
            .await
            .err()
            .ok_or("a device that never answers is an error")?;
        assert!(
            matches!(&err, RestartError::NoAnswer { last, .. } if last == "no response"),
            "{err}"
        );
        Ok(())
    }
}
