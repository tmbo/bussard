//! The API error type and its HTTP mapping.
//!
//! [`ApiError`] is the single error surface for the JSON API handlers. Each
//! variant maps to a fixed HTTP status and serializes to the contract's error
//! body `{"error":{"code","message"}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// An API error, mapped to an HTTP status and a stable `code` string.
///
/// The status codes match the `/api/group-write` contract: `400` for a bad
/// group address or value, `403` for a protected GA written without `force`,
/// `422` when no DPT can be resolved (and, for `/api/reload`, when the model on
/// disk is broken), and `503` when the bus is unavailable.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// A malformed group address or an un-encodable value (400).
    #[error("{0}")]
    BadRequest(String),

    /// A write to a `protected` GA without `force` (403).
    #[error("{0}")]
    Protected(String),

    /// The request was refused by the browser guard: a `Host` this server does
    /// not answer to, or a cross-origin state-changing request (403). See
    /// [`crate::guard`].
    #[error("{0}")]
    Forbidden(String),

    /// A group write while the server runs without `--allow-writes` (403).
    #[error("{0}")]
    WritesDisabled(String),

    /// No DPT could be resolved for the write (422).
    #[error("{0}")]
    NoDpt(String),

    /// A reload found a broken model on disk (422). The old model is kept.
    #[error("{0}")]
    ModelInvalid(String),

    /// The bus is not connected, so the write could not be sent (503).
    #[error("{0}")]
    BusUnavailable(String),

    /// An unexpected internal failure (500).
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    /// The HTTP status this error maps to.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Protected(_) => StatusCode::FORBIDDEN,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::WritesDisabled(_) => StatusCode::FORBIDDEN,
            ApiError::NoDpt(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::ModelInvalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::BusUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The stable machine-readable code string for this error.
    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Protected(_) => "protected",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::WritesDisabled(_) => "writes_disabled",
            ApiError::NoDpt(_) => "no_dpt",
            ApiError::ModelInvalid(_) => "model_invalid",
            ApiError::BusUnavailable(_) => "bus_unavailable",
            ApiError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {
                "code": self.code(),
                "message": self.to_string(),
            }
        });
        (self.status(), Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(
            ApiError::BadRequest("x".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Protected("x".into()).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::NoDpt("x".into()).status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::ModelInvalid("x".into()).status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::BusUnavailable("x".into()).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::Internal("x".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_api_error_forbidden_variants() {
        assert_eq!(
            ApiError::Forbidden("x".into()).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(ApiError::Forbidden("x".into()).code(), "forbidden");
        assert_eq!(
            ApiError::WritesDisabled("x".into()).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::WritesDisabled("x".into()).code(),
            "writes_disabled"
        );
    }

    #[test]
    fn test_api_error_codes() {
        assert_eq!(ApiError::BadRequest("x".into()).code(), "bad_request");
        assert_eq!(ApiError::Protected("x".into()).code(), "protected");
        assert_eq!(ApiError::NoDpt("x".into()).code(), "no_dpt");
        assert_eq!(ApiError::ModelInvalid("x".into()).code(), "model_invalid");
        assert_eq!(
            ApiError::BusUnavailable("x".into()).code(),
            "bus_unavailable"
        );
    }
}
