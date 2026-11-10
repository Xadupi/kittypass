use axum::Json;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{AuthUser, ClientIp, State};
use crate::{
    AppState,
    crypto::{random_token, token_hash},
    db::audit,
    error::{ApiError, ApiResult},
};

pub const DEFAULT_INVITE_HOURS: i64 = 72;

/// Crée une invitation et renvoie le code en clair (seule l'empreinte est
/// stockée). Utilisé par l'API admin et par la ligne de commande.
pub fn new_invite(conn: &rusqlite::Connection, state: &AppState, is_admin: bool, hours: i64) -> rusqlite::Result<String> {
    let code = random_token();
    conn.execute(
        "INSERT INTO invites (code_hash, is_admin, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash(&code), is_admin, state.now() + hours * 3600],
    )?;
    Ok(code)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteReq {
    #[serde(default)]
    admin: bool,
    hours: Option<i64>,
}

#[derive(Serialize)]
pub struct InviteResp {
    code: String,
    expires_in_hours: i64,
}

pub async fn create_invite(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    Json(req): Json<InviteReq>,
) -> ApiResult<Json<InviteResp>> {
    if !user.is_admin {
        return Err(ApiError::Forbidden("admin_required"));
    }
    // Un compte admin doit avoir la 2FA pour inviter d'autres admins.
    if req.admin && !user.has_2fa {
        return Err(ApiError::Forbidden("2fa_setup_required"));
    }
    let hours = req.hours.unwrap_or(DEFAULT_INVITE_HOURS);
    if !(1..=24 * 30).contains(&hours) {
        return Err(ApiError::BadRequest("durée invalide"));
    }
    let conn = state.db();
    let code = new_invite(&conn, &state, req.admin, hours)?;
    audit(&conn, state.now(), Some(&user.user_id), if req.admin { "invite_admin" } else { "invite" }, &ip.to_string());
    Ok(Json(InviteResp { code, expires_in_hours: hours }))
}

#[derive(Serialize)]
pub struct UserOut {
    username: String,
    is_admin: bool,
    totp_enabled: bool,
    disabled: bool,
    created_at: i64,
    current: bool,
}

/// Liste des comptes (admins seulement).
pub async fn list_users(axum::extract::State(state): State, user: AuthUser) -> ApiResult<Json<Vec<UserOut>>> {
    if !user.is_admin {
        return Err(ApiError::Forbidden("admin_required"));
    }
    let conn = state.db();
    let mut stmt = conn.prepare(
        "SELECT id, username, is_admin, totp_secret IS NOT NULL, disabled, created_at FROM users ORDER BY username",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(UserOut {
                current: r.get::<_, String>(0)? == user.user_id,
                username: r.get(1)?,
                is_admin: r.get(2)?,
                totp_enabled: r.get(3)?,
                disabled: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableReq {
    disabled: bool,
}

/// Désactive (sessions fermées, connexion refusée) ou réactive un compte.
/// Un admin ne peut pas se désactiver lui-même.
pub async fn set_user_disabled(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    axum::extract::Path(username): axum::extract::Path<String>,
    Json(req): Json<DisableReq>,
) -> ApiResult<axum::http::StatusCode> {
    if !user.is_admin {
        return Err(ApiError::Forbidden("admin_required"));
    }
    let username = super::normalize_username(&username)?;
    let conn = state.db();
    let target: String = conn
        .query_row("SELECT id FROM users WHERE username = ?1", [&username], |r| r.get(0))
        .optional()?
        .ok_or(ApiError::NotFound)?;
    if target == user.user_id {
        return Err(ApiError::BadRequest("impossible de désactiver son propre compte"));
    }
    conn.execute("UPDATE users SET disabled = ?1 WHERE id = ?2", params![req.disabled, target])?;
    if req.disabled {
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [&target])?;
        conn.execute("DELETE FROM trusted_devices WHERE user_id = ?1", [&target])?;
    }
    let event = if req.disabled { "admin_disable_user" } else { "admin_enable_user" };
    audit(&conn, state.now(), Some(&user.user_id), event, &ip.to_string());
    Ok(axum::http::StatusCode::NO_CONTENT)
}
