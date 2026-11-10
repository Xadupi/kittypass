use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Erreurs de l'API. Les messages sont volontairement génériques : aucune
/// trace interne, aucun indice sur l'existence d'un compte.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(&'static str),
    /// Identifiant, mot de passe ou code 2FA faux, compte désactivé ou
    /// verrouillé : toujours la même réponse.
    InvalidCredentials,
    TotpRequired,
    Unauthorized,
    Forbidden(&'static str),
    NotFound,
    Conflict(&'static str),
    VersionConflict { current: i64 },
    PreconditionRequired,
    TooManyRequests,
    Internal,
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("base de données : {e}");
        Self::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::BadRequest(d) => (StatusCode::BAD_REQUEST, json!({"error": "bad_request", "detail": d})),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, json!({"error": "invalid_credentials"})),
            Self::TotpRequired => (StatusCode::UNAUTHORIZED, json!({"error": "totp_required"})),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"})),
            Self::Forbidden(d) => (StatusCode::FORBIDDEN, json!({"error": d})),
            Self::NotFound => (StatusCode::NOT_FOUND, json!({"error": "not_found"})),
            Self::Conflict(d) => (StatusCode::CONFLICT, json!({"error": d})),
            Self::VersionConflict { current } => {
                (StatusCode::CONFLICT, json!({"error": "version_conflict", "current_version": current}))
            }
            Self::PreconditionRequired => {
                (StatusCode::PRECONDITION_REQUIRED, json!({"error": "if_match_required"}))
            }
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, json!({"error": "too_many_requests"})),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "internal"})),
        };
        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
