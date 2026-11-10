//! Activation et désactivation de la 2FA (TOTP + codes de secours).

use axum::{Json, http::StatusCode};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{AuthUser, ClientIp, State, unb64};
use crate::{
    crypto::{ct_eq, random_bytes, token_hash},
    db::audit,
    error::{ApiError, ApiResult},
    totp,
};

const RECOVERY_CODES: usize = 10;

#[derive(Serialize)]
pub struct SetupResp {
    secret: String,
    otpauth_uri: String,
}

/// Prépare un secret TOTP (pas encore actif tant qu'un code n'a pas été validé).
pub async fn setup(axum::extract::State(state): State, user: AuthUser) -> ApiResult<Json<SetupResp>> {
    let conn = state.db();
    let (username, enabled): (String, bool) = conn.query_row(
        "SELECT username, totp_secret IS NOT NULL FROM users WHERE id = ?1",
        [&user.user_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if enabled {
        return Err(ApiError::Conflict("2fa_already_enabled"));
    }
    let secret = random_bytes::<20>();
    conn.execute(
        "UPDATE users SET totp_pending = ?1 WHERE id = ?2",
        params![state.keys.seal(&user.user_id, &secret), user.user_id],
    )?;
    Ok(Json(SetupResp { secret: totp::base32(&secret), otpauth_uri: totp::otpauth_uri(&secret, &username) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableReq {
    code: String,
}

#[derive(Serialize)]
pub struct EnableResp {
    recovery_codes: Vec<String>,
}

/// Code de secours de 80 bits, au format `XXXX-XXXX-XXXX-XXXX`.
fn new_recovery_code() -> String {
    let raw = totp::base32(&random_bytes::<10>());
    raw.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join("-")
}

pub async fn enable(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    Json(req): Json<EnableReq>,
) -> ApiResult<Json<EnableResp>> {
    if !state.limiter.allow(&format!("2fa-enable:{}", user.user_id), 10, 300, state.now()) {
        return Err(ApiError::TooManyRequests);
    }
    let now = state.now();
    let mut conn = state.db();
    let pending: Option<Vec<u8>> = conn
        .query_row(
            "SELECT totp_pending FROM users WHERE id = ?1 AND totp_secret IS NULL",
            [&user.user_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let sealed = pending.ok_or(ApiError::Conflict("2fa_setup_required"))?;
    let secret = state.keys.open(&user.user_id, &sealed).ok_or(ApiError::Internal)?;
    let step = totp::verify(&secret, &req.code, now, None).ok_or(ApiError::BadRequest("code invalide"))?;

    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ?1 WHERE id = ?2",
        params![step, user.user_id],
    )?;
    tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [&user.user_id])?;
    for c in &codes {
        let norm = super::auth::normalize_recovery_code(c).ok_or(ApiError::Internal)?;
        tx.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
            params![user.user_id, token_hash(&norm)],
        )?;
    }
    // Les autres appareils doivent se reconnecter avec la 2FA.
    tx.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND id != ?2",
        params![user.user_id, user.session_id],
    )?;
    tx.execute("DELETE FROM trusted_devices WHERE user_id = ?1", [&user.user_id])?;
    tx.commit()?;
    audit(&conn, now, Some(&user.user_id), "2fa_enabled", &ip.to_string());
    Ok(Json(EnableResp { recovery_codes: codes }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableReq {
    auth_key: String,
    code: String,
}

/// Désactiver la 2FA exige le mot de passe ET un code valide : un jeton volé
/// ne suffit pas.
pub async fn disable(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    Json(req): Json<DisableReq>,
) -> ApiResult<StatusCode> {
    if !state.limiter.allow(&format!("2fa-disable:{}", user.user_id), 5, 300, state.now()) {
        return Err(ApiError::TooManyRequests);
    }
    if state.config.require_2fa {
        return Err(ApiError::Forbidden("2fa_required_by_server"));
    }
    let auth_key = unb64(&req.auth_key, 32, 32)?;
    let now = state.now();
    let conn = state.db();
    let (salt, hash, sealed, last): (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<i64>) = conn.query_row(
        "SELECT auth_salt, auth_hash, totp_secret, totp_last_step FROM users WHERE id = ?1",
        [&user.user_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let sealed = sealed.ok_or(ApiError::Conflict("2fa_not_enabled"))?;
    let secret = state.keys.open(&user.user_id, &sealed).ok_or(ApiError::Internal)?;
    let pw_ok = ct_eq(&state.keys.auth_hash(&salt, &auth_key), &hash);
    let code_ok = totp::verify(&secret, &req.code, now, last).is_some();
    if !(pw_ok && code_ok) {
        audit(&conn, now, Some(&user.user_id), "2fa_disable_denied", &ip.to_string());
        return Err(ApiError::InvalidCredentials);
    }
    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?1",
        [&user.user_id],
    )?;
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [&user.user_id])?;
    conn.execute("DELETE FROM trusted_devices WHERE user_id = ?1", [&user.user_id])?;
    audit(&conn, now, Some(&user.user_id), "2fa_disabled", &ip.to_string());
    Ok(StatusCode::NO_CONTENT)
}
