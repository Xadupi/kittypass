//! Comptes, connexion, jetons, sessions.

use axum::{Json, extract::Path, http::StatusCode};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use kittypass_core::account::KdfParams;

use super::{AuthUser, ClientIp, State, TokenPair, rate_key, b64, clean_label, issue_tokens, normalize_username, unb64};
use crate::{
    crypto::{ct_eq, random_bytes, random_token, token_hash},
    db::audit,
    error::{ApiError, ApiResult},
    totp,
};

/// Longueur imposée du sel de compte : identique au sel factice du pré-login,
/// sinon la longueur trahirait l'existence du compte.
const ACCOUNT_SALT_LEN: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfIn {
    salt: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Serialize)]
pub struct KdfOut {
    salt: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Les paramètres sont imposés (valeurs par défaut) : des paramètres propres à
/// chaque compte permettraient de distinguer un vrai compte d'un faux au
/// pré-login.
fn parse_kdf(k: &KdfIn) -> ApiResult<Vec<u8>> {
    let params = KdfParams { memory_kib: k.memory_kib, iterations: k.iterations, parallelism: k.parallelism };
    if params != KdfParams::DEFAULT {
        return Err(ApiError::BadRequest("paramètres KDF non pris en charge"));
    }
    unb64(&k.salt, ACCOUNT_SALT_LEN, ACCOUNT_SALT_LEN)
}

fn too_many(state: &crate::AppState, key: String, limit: u32, window: i64) -> ApiResult<()> {
    if state.limiter.allow(&key, limit, window, state.now()) { Ok(()) } else { Err(ApiError::TooManyRequests) }
}

// ---------- Pré-login ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginReq {
    username: String,
}

pub async fn prelogin(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    Json(req): Json<PreloginReq>,
) -> ApiResult<Json<KdfOut>> {
    too_many(&state, format!("prelogin:{}", rate_key(ip)), 60, 60)?;
    let username = normalize_username(&req.username)?;
    let found = state
        .db()
        .query_row(
            "SELECT kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism FROM users WHERE username = ?1",
            [&username],
            |r| {
                Ok(KdfOut {
                    salt: b64(&r.get::<_, Vec<u8>>(0)?),
                    memory_kib: r.get(1)?,
                    iterations: r.get(2)?,
                    parallelism: r.get(3)?,
                })
            },
        )
        .optional()?;
    let d = KdfParams::DEFAULT;
    Ok(Json(found.unwrap_or_else(|| KdfOut {
        salt: b64(&state.keys.fake_salt(&username)),
        memory_kib: d.memory_kib,
        iterations: d.iterations,
        parallelism: d.parallelism,
    })))
}

// ---------- Inscription (sur invitation) ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterReq {
    invite: String,
    username: String,
    kdf: KdfIn,
    auth_key: String,
}

pub async fn register(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterReq>,
) -> ApiResult<StatusCode> {
    too_many(&state, format!("register:{}", rate_key(ip)), 10, 3600)?;
    let now = state.now();
    let username = normalize_username(&req.username)?;
    let kdf_salt = parse_kdf(&req.kdf)?;
    let auth_key = unb64(&req.auth_key, 32, 32)?;
    if req.invite.is_empty() || req.invite.len() > 128 {
        return Err(ApiError::Forbidden("invalid_invite"));
    }
    let auth_salt = random_bytes::<16>();
    let auth_hash = state.keys.auth_hash(&auth_salt, &auth_key);
    let id = uuid::Uuid::new_v4().to_string();
    let invite_hash = token_hash(&req.invite);

    let mut conn = state.db();
    // Transaction « immédiate » : deux inscriptions simultanées avec la même
    // invitation ne peuvent pas réussir toutes les deux.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let is_admin: Option<bool> = tx
        .query_row(
            "SELECT is_admin FROM invites WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?2",
            params![invite_hash, now],
            |r| r.get(0),
        )
        .optional()?;
    let Some(is_admin) = is_admin else {
        drop(tx);
        audit(&conn, now, None, "register_bad_invite", &ip.to_string());
        return Err(ApiError::Forbidden("invalid_invite"));
    };
    let taken: bool =
        tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)", [&username], |r| r.get(0))?;
    if taken {
        return Err(ApiError::Conflict("username_taken"));
    }
    let d = KdfParams::DEFAULT;
    tx.execute(
        "INSERT INTO users (id, username, is_admin, kdf_salt, kdf_memory_kib, kdf_iterations,
                            kdf_parallelism, auth_salt, auth_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![id, username, is_admin, kdf_salt, d.memory_kib, d.iterations, d.parallelism,
                auth_salt.as_slice(), auth_hash.as_slice(), now],
    )?;
    tx.execute("UPDATE invites SET used_by = ?1 WHERE code_hash = ?2", params![id, invite_hash])?;
    tx.commit()?;
    audit(&conn, now, Some(&id), "register", &ip.to_string());
    Ok(StatusCode::CREATED)
}

// ---------- Connexion ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginReq {
    username: String,
    auth_key: String,
    totp: Option<String>,
    recovery_code: Option<String>,
    device: String,
    /// Jeton d'appareil de confiance, à la place du code 2FA.
    device_token: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResp {
    #[serde(flatten)]
    tokens: TokenPair,
    must_setup_2fa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_token: Option<String>,
}

struct LoginRow {
    id: String,
    auth_salt: Vec<u8>,
    auth_hash: Vec<u8>,
    totp_secret: Option<Vec<u8>>,
    totp_last_step: Option<i64>,
    failed_logins: i64,
    locked_until: i64,
    disabled: bool,
}

/// Verrouillage progressif après 5 échecs : 30 s, 60 s, 120 s… jusqu'à 15 min.
fn register_failure(conn: &Connection, user_id: &str, failed_before: i64, now: i64) -> ApiResult<()> {
    let n = failed_before + 1;
    let locked_until = if n >= 5 { now + (30i64 << (n - 5).min(5)).min(900) } else { 0 };
    conn.execute(
        "UPDATE users SET failed_logins = ?1, locked_until = ?2 WHERE id = ?3",
        params![n, locked_until, user_id],
    )?;
    Ok(())
}

pub fn normalize_recovery_code(c: &str) -> Option<String> {
    let s: String = c.chars().filter(|c| !matches!(c, '-' | ' ')).collect::<String>().to_ascii_uppercase();
    (s.len() == 16 && s.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(s)
}

pub async fn login(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginReq>,
) -> ApiResult<Json<LoginResp>> {
    let ip_s = ip.to_string();
    too_many(&state, format!("login-ip:{}", rate_key(ip)), 30, 60)?;
    let username = normalize_username(&req.username).map_err(|_| ApiError::InvalidCredentials)?;
    // Même limite pour un compte existant ou non : pas d'énumération possible.
    too_many(&state, format!("login-user:{username}"), 10, 60)?;
    let device = clean_label(&req.device, 64)?;
    let auth_key = unb64(&req.auth_key, 32, 32).map_err(|_| ApiError::InvalidCredentials)?;
    let now = state.now();
    let conn = state.db();

    let user = conn
        .query_row(
            "SELECT id, auth_salt, auth_hash, totp_secret, totp_last_step, failed_logins, locked_until, disabled
             FROM users WHERE username = ?1",
            [&username],
            |r| {
                Ok(LoginRow {
                    id: r.get(0)?,
                    auth_salt: r.get(1)?,
                    auth_hash: r.get(2)?,
                    totp_secret: r.get(3)?,
                    totp_last_step: r.get(4)?,
                    failed_logins: r.get(5)?,
                    locked_until: r.get(6)?,
                    disabled: r.get(7)?,
                })
            },
        )
        .optional()?;
    let Some(u) = user else {
        // Même travail que pour un vrai compte : temps de réponse identique.
        let _ = state.keys.auth_hash(&[0u8; 16], &auth_key);
        audit(&conn, now, None, "login_unknown_user", &ip_s);
        return Err(ApiError::InvalidCredentials);
    };
    if u.disabled || u.locked_until > now {
        audit(&conn, now, Some(&u.id), "login_blocked", &ip_s);
        return Err(ApiError::InvalidCredentials);
    }
    if !ct_eq(&state.keys.auth_hash(&u.auth_salt, &auth_key), &u.auth_hash) {
        register_failure(&conn, &u.id, u.failed_logins, now)?;
        audit(&conn, now, Some(&u.id), "login_bad_password", &ip_s);
        return Err(ApiError::InvalidCredentials);
    }

    if let Some(sealed) = &u.totp_secret {
        let secret = state.keys.open(&u.id, sealed).ok_or(ApiError::Internal)?;
        match (&req.totp, &req.recovery_code) {
            (Some(code), _) => match totp::verify(&secret, code, now, u.totp_last_step) {
                Some(step) => {
                    conn.execute("UPDATE users SET totp_last_step = ?1 WHERE id = ?2", params![step, u.id])?;
                }
                None => {
                    register_failure(&conn, &u.id, u.failed_logins, now)?;
                    audit(&conn, now, Some(&u.id), "login_bad_totp", &ip_s);
                    return Err(ApiError::InvalidCredentials);
                }
            },
            (None, Some(code)) => {
                let used = match normalize_recovery_code(code) {
                    Some(c) => conn.execute(
                        "DELETE FROM recovery_codes WHERE user_id = ?1 AND code_hash = ?2",
                        params![u.id, token_hash(&c)],
                    )?,
                    None => 0,
                };
                if used != 1 {
                    register_failure(&conn, &u.id, u.failed_logins, now)?;
                    audit(&conn, now, Some(&u.id), "login_bad_recovery_code", &ip_s);
                    return Err(ApiError::InvalidCredentials);
                }
                audit(&conn, now, Some(&u.id), "recovery_code_used", &ip_s);
            }
            (None, None) => {
                // Appareil déjà validé par la 2FA : le jeton remplace le code.
                // Usage unique : il est remplacé par un nouveau plus bas.
                let trusted = match req.device_token.as_deref().filter(|t| t.len() <= 128) {
                    Some(t) => conn.execute(
                        "DELETE FROM trusted_devices WHERE hash = ?1 AND user_id = ?2 AND last_used > ?3",
                        params![token_hash(t), u.id, now - crate::db::TRUST_TTL],
                    )?,
                    None => 0,
                };
                if trusted != 1 {
                    return Err(ApiError::TotpRequired);
                }
                audit(&conn, now, Some(&u.id), "login_trusted_device", &ip_s);
            }
        }
    }

    conn.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?1", [&u.id])?;
    let session_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO sessions (id, user_id, device, created_at, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)",
        params![session_id, u.id, device, now],
    )?;
    let tokens = issue_tokens(&conn, &state, &session_id)?;
    let device_token = if u.totp_secret.is_some() {
        let t = random_token();
        conn.execute(
            "INSERT INTO trusted_devices (hash, user_id, session_id, created_at, last_used) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![token_hash(&t), u.id, session_id, now],
        )?;
        Some(t)
    } else {
        None
    };
    audit(&conn, now, Some(&u.id), "login", &ip_s);
    Ok(Json(LoginResp { tokens, must_setup_2fa: state.config.require_2fa && u.totp_secret.is_none(), device_token }))
}

// ---------- Jetons ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshReq {
    refresh_token: String,
}

/// Rotation : chaque jeton de rafraîchissement ne sert qu'une fois. S'il est
/// présenté une seconde fois, il a été volé (ou copié) : toute la session est
/// révoquée, chez le voleur comme chez la victime.
pub async fn refresh(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    Json(req): Json<RefreshReq>,
) -> ApiResult<Json<TokenPair>> {
    too_many(&state, format!("refresh:{}", rate_key(ip)), 60, 60)?;
    if req.refresh_token.len() > 128 {
        return Err(ApiError::Unauthorized);
    }
    let now = state.now();
    let hash = token_hash(&req.refresh_token);
    let conn = state.db();
    let row: Option<(String, i64, bool, String, bool)> = conn
        .query_row(
            "SELECT t.session_id, t.expires_at, t.used, s.user_id, u.disabled
             FROM tokens t JOIN sessions s ON s.id = t.session_id JOIN users u ON u.id = s.user_id
             WHERE t.hash = ?1 AND t.kind = 'refresh'",
            [&hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (session_id, expires_at, used, user_id, disabled) = row.ok_or(ApiError::Unauthorized)?;
    if used {
        conn.execute("DELETE FROM sessions WHERE id = ?1", [&session_id])?;
        conn.execute("DELETE FROM trusted_devices WHERE session_id = ?1", [&session_id])?;
        audit(&conn, now, Some(&user_id), "refresh_token_reuse", &ip.to_string());
        return Err(ApiError::Unauthorized);
    }
    if expires_at <= now || disabled {
        return Err(ApiError::Unauthorized);
    }
    if conn.execute("UPDATE tokens SET used = 1 WHERE hash = ?1 AND used = 0", [&hash])? != 1 {
        return Err(ApiError::Unauthorized);
    }
    Ok(Json(issue_tokens(&conn, &state, &session_id)?))
}

pub async fn logout(axum::extract::State(state): State, user: AuthUser) -> ApiResult<StatusCode> {
    let conn = state.db();
    conn.execute("DELETE FROM sessions WHERE id = ?1", [&user.session_id])?;
    conn.execute("DELETE FROM trusted_devices WHERE session_id = ?1", [&user.session_id])?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Compte ----------

#[derive(Serialize)]
pub struct AccountOut {
    username: String,
    totp_enabled: bool,
    /// Le serveur impose la 2FA : elle ne peut pas être désactivée.
    require_2fa: bool,
    is_admin: bool,
}

/// Résumé du compte connecté, pour l'écran « Compte » des clients.
pub async fn account(axum::extract::State(state): State, user: AuthUser) -> ApiResult<Json<AccountOut>> {
    let username: String =
        state.db().query_row("SELECT username FROM users WHERE id = ?1", [&user.user_id], |r| r.get(0))?;
    Ok(Json(AccountOut { username, totp_enabled: user.has_2fa, require_2fa: state.config.require_2fa, is_admin: user.is_admin }))
}

// ---------- Sessions ----------

#[derive(Serialize)]
pub struct SessionOut {
    id: String,
    device: String,
    created_at: i64,
    last_seen: i64,
    current: bool,
}

pub async fn list_sessions(
    axum::extract::State(state): State,
    user: AuthUser,
) -> ApiResult<Json<Vec<SessionOut>>> {
    let conn = state.db();
    let mut stmt = conn.prepare(
        "SELECT id, device, created_at, last_seen FROM sessions WHERE user_id = ?1 ORDER BY last_seen DESC",
    )?;
    let rows = stmt
        .query_map([&user.user_id], |r| {
            let id: String = r.get(0)?;
            Ok(SessionOut {
                current: id == user.session_id,
                id,
                device: r.get(1)?,
                created_at: r.get(2)?,
                last_seen: r.get(3)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(rows))
}

pub async fn revoke_session(
    axum::extract::State(state): State,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    // Le filtre sur user_id empêche de révoquer la session d'un autre compte.
    let conn = state.db();
    let n = conn.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![id, user.user_id])?;
    conn.execute("DELETE FROM trusted_devices WHERE session_id = ?1 AND user_id = ?2", params![id, user.user_id])?;
    if n == 0 { Err(ApiError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}

// ---------- Mot de passe ----------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordReq {
    current_auth_key: String,
    kdf: KdfIn,
    new_auth_key: String,
}

/// Change la clé d'authentification. Toutes les autres sessions sont fermées.
/// (Le client doit aussi rechiffrer et renvoyer ses coffres.)
pub async fn change_password(
    axum::extract::State(state): State,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    Json(req): Json<ChangePasswordReq>,
) -> ApiResult<StatusCode> {
    too_many(&state, format!("password:{}", user.user_id), 5, 3600)?;
    let current = unb64(&req.current_auth_key, 32, 32)?;
    let new_key = unb64(&req.new_auth_key, 32, 32)?;
    let kdf_salt = parse_kdf(&req.kdf)?;
    let now = state.now();
    let conn = state.db();
    let (salt, hash): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT auth_salt, auth_hash FROM users WHERE id = ?1",
        [&user.user_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !ct_eq(&state.keys.auth_hash(&salt, &current), &hash) {
        audit(&conn, now, Some(&user.user_id), "password_change_bad_current", &ip.to_string());
        return Err(ApiError::InvalidCredentials);
    }
    let new_salt = random_bytes::<16>();
    conn.execute(
        "UPDATE users SET kdf_salt = ?1, auth_salt = ?2, auth_hash = ?3 WHERE id = ?4",
        params![kdf_salt, new_salt.as_slice(), state.keys.auth_hash(&new_salt, &new_key).as_slice(), user.user_id],
    )?;
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND id != ?2",
        params![user.user_id, user.session_id],
    )?;
    conn.execute(
        "DELETE FROM trusted_devices WHERE user_id = ?1 AND session_id != ?2",
        params![user.user_id, user.session_id],
    )?;
    audit(&conn, now, Some(&user.user_id), "password_changed", &ip.to_string());
    Ok(StatusCode::NO_CONTENT)
}
