//! URL-mode elicitation (#798), shared by the pairing page of
//! `knx_enroll_certificates` ([`crate::tools_enroll`]) and the project
//! password form ([`crate::password_form`]) (issue #911).
//!
//! A page bussard serves on 127.0.0.1 reaches the human as the URL of an
//! elicitation, never through the assistant. Two transports (MCP
//! 2026-07-28, client features): from protocol 2026-07-28 the tool answers
//! with an `InputRequiredResult` holding the `elicitation/create` request
//! and the client calls the tool again with the human's answer (multi
//! round-trip, SEP-2322); before it, the server sends `elicitation/create`
//! to the client while the call runs.

use std::sync::{Mutex, MutexGuard};

use rmcp::RoleServer;
use rmcp::model::{
    CallToolResponse, ElicitRequest, ElicitRequestParams, ElicitResult, ElicitationAction,
    InputRequest, InputRequests, InputRequiredResult, InputResponses, ProtocolVersion,
};
use rmcp::service::RequestContext;

/// A lock that survives a panicked holder: the data is a page handle or a
/// report.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether the client of this call declared URL-mode elicitation: only then
/// can a link reach the human without passing through the assistant.
pub fn shows_urls(context: &RequestContext<RoleServer>) -> bool {
    context
        .client_capabilities()
        .and_then(|caps| caps.elicitation)
        .is_some_and(|elicitation| elicitation.url.is_some())
}

/// A fresh random elicitation id, the handle a multi round-trip call names
/// its page by.
///
/// # Errors
///
/// The random source failed.
pub fn new_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("drawing a random id: {e}"))?;
    Ok(bussard_model::text::hex(&bytes))
}

/// What became of an elicitation.
#[derive(Debug)]
pub enum Shown {
    /// The client asks the human and calls the tool again: answer the call
    /// with this `InputRequiredResult`.
    Pending(CallToolResponse),
    /// The human answered while the call ran.
    Answered(ElicitationAction),
    /// The client did not show the page (logged, never returned: a
    /// client's error text could echo the URL).
    Failed,
}

/// Shows the URL of `params` to the human by the transport of `context`'s
/// protocol: `key` names the request in `inputRequests`, `state` is the
/// `requestState` the client's second round carries.
pub async fn show(
    context: &RequestContext<RoleServer>,
    key: &str,
    state: String,
    params: ElicitRequestParams,
) -> Shown {
    if context
        .protocol_version()
        .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
    {
        let mut requests = InputRequests::new();
        requests.insert(
            key.to_owned(),
            InputRequest::Elicitation(ElicitRequest::new(params)),
        );
        return Shown::Pending(InputRequiredResult::new(Some(requests), Some(state)).into());
    }
    match context.peer.create_elicitation(params).await {
        Ok(result) => Shown::Answered(result.action),
        Err(err) => {
            tracing::warn!(%err, "the client did not show a page by elicitation");
            Shown::Failed
        }
    }
}

/// The human's answer under `key` in the second round of a multi
/// round-trip call; no answer counts as dismissed.
pub fn answer(responses: Option<&InputResponses>, key: &str) -> ElicitationAction {
    responses
        .and_then(|responses| responses.get(key).cloned())
        .and_then(|value| serde_json::from_value::<ElicitResult>(value).ok())
        .map_or(ElicitationAction::Cancel, |answer| answer.action)
}
