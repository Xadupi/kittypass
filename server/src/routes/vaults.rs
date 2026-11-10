//! Stockage versionné des fichiers KDBX chiffrés.
//!
//! Concurrence optimiste : chaque envoi précise la version sur laquelle il se
//! base (`If-Match`). Si un autre appareil a écrit entre temps, le serveur
//! répond 409 et le client fusionne avant de renvoyer.

use axum::{
    Json,
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use kittypass_core::header::{self as kdbx_header, OpenLimits};

use super::{AuthUser, State, clean_label};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};

#[derive(Serialize)]
pub struct VaultOut {
    id: String,
    name: String,
    version: i64,
    updated_at: i64,
}

/// Les identifiants sont des UUID : on refuse tout le reste avant la base.
fn parse_id(id: &str) -> ApiResult<String> {
    uuid::Uuid::parse_str(id).map(|u| u.to_string()).map_err(|_| ApiError::NotFound)
}

/// Version courante d'un coffre **appartenant** à l'utilisateur, sinon 404
/// (même réponse pour « n'existe pas » et « appartient à quelqu'un d'autre »).
fn owned_version(conn: &rusqlite::Connection, id: &str, user: &AuthUser) -> ApiResult<i64> {
    conn.query_row(
        "SELECT version FROM vaults WHERE id = ?1 AND owner_id = ?2",
        params![id, user.user_id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

pub async fn list(axum::extract::State(state): State, user: AuthUser) -> ApiResult<Json<Vec<VaultOut>>> {
    user.require_full_access(&state)?;
    let conn = state.db();
    let mut stmt = conn.prepare(
        "SELECT id, name, version, updated_at FROM vaults WHERE owner_id = ?1 ORDER BY name",
    )?;
    let rows = stmt
        .query_map([&user.user_id], |r| {
            Ok(VaultOut { id: r.get(0)?, name: r.get(1)?, version: r.get(2)?, updated_at: r.get(3)? })
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    name: String,
}

pub async fn create(
    axum::extract::State(state): State,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<(StatusCode, Json<VaultOut>)> {
    user.require_full_access(&state)?;
    let name = clean_label(&req.name, 64)?;
    let now = state.now();
    let mut conn = state.db();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM vaults WHERE owner_id = ?1", [&user.user_id], |r| r.get(0))?;
    if count >= state.config.max_vaults_per_user {
        return Err(ApiError::Forbidden("vault_limit_reached"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO vaults (id, owner_id, name, version, updated_at) VALUES (?1, ?2, ?3, 0, ?4)",
        params![id, user.user_id, name, now],
    )?;
    tx.commit()?;
    Ok((StatusCode::CREATED, Json(VaultOut { id, name, version: 0, updated_at: now })))
}

fn kdbx_response(version: i64, data: Vec<u8>) -> Response {
    (
        [
            (header::ETAG, format!("\"{version}\"")),
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
        ],
        data,
    )
        .into_response()
}

pub async fn download(
    axum::extract::State(state): State,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    user.require_full_access(&state)?;
    let id = parse_id(&id)?;
    let conn = state.db();
    let version = owned_version(&conn, &id, &user)?;
    if version == 0 {
        return Ok((StatusCode::NO_CONTENT, [(header::ETAG, "\"0\"")]).into_response());
    }
    let data: Vec<u8> = conn.query_row(
        "SELECT data FROM vault_versions WHERE vault_id = ?1 AND version = ?2",
        params![id, version],
        |r| r.get(0),
    )?;
    Ok(kdbx_response(version, data))
}

/// Lit `If-Match: "N"` (ou `N`). Obligatoire : sans lui, un client pourrait
/// écraser à l'aveugle les modifications d'un autre appareil.
fn if_match(headers: &HeaderMap) -> ApiResult<i64> {
    let v = headers
        .get(header::IF_MATCH)
        .ok_or(ApiError::PreconditionRequired)?
        .to_str()
        .map_err(|_| ApiError::BadRequest("If-Match invalide"))?;
    v.trim()
        .trim_matches('"')
        .parse::<i64>()
        .ok()
        .filter(|n| *n >= 0)
        .ok_or(ApiError::BadRequest("If-Match invalide"))
}

/// Le serveur ne peut pas déchiffrer le fichier, mais il vérifie que c'est un
/// KDBX 4 aux paramètres raisonnables : un appareil compromis ne peut pas
/// déposer un fichier piégé qui bloquerait les autres appareils.
fn validate_kdbx(state: &AppState, data: &[u8]) -> ApiResult<()> {
    let limits = OpenLimits { max_file_bytes: state.config.max_vault_bytes, ..Default::default() };
    match kdbx_header::check(data, &limits) {
        Ok(info) if info.major == 4 => Ok(()),
        _ => Err(ApiError::BadRequest("fichier KDBX 4 invalide")),
    }
}

#[derive(Serialize)]
pub struct UploadResp {
    version: i64,
}

pub async fn upload(
    axum::extract::State(state): State,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<UploadResp>> {
    user.require_full_access(&state)?;
    let id = parse_id(&id)?;
    let expected = if_match(&headers)?;
    validate_kdbx(&state, &body)?;
    let now = state.now();
    let mut conn = state.db();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = owned_version(&tx, &id, &user)?;
    if current != expected {
        return Err(ApiError::VersionConflict { current });
    }
    let next = current + 1;
    tx.execute(
        "UPDATE vaults SET version = ?1, updated_at = ?2 WHERE id = ?3 AND owner_id = ?4 AND version = ?5",
        params![next, now, id, user.user_id, current],
    )?;
    tx.execute(
        "INSERT INTO vault_versions (vault_id, version, data, created_at, session_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, next, body.as_ref(), now, user.session_id],
    )?;
    tx.execute(
        "DELETE FROM vault_versions WHERE vault_id = ?1 AND version <= ?2",
        params![id, next - state.config.versions_kept],
    )?;
    // Quota du compte, versions gardées comprises : un compte ne peut pas
    // remplir le disque du serveur (20 coffres × 50 versions × 64 Mio sinon).
    let used: i64 = tx.query_row(
        "SELECT COALESCE(SUM(length(vv.data)), 0) FROM vault_versions vv
         JOIN vaults v ON v.id = vv.vault_id WHERE v.owner_id = ?1",
        [&user.user_id],
        |r| r.get(0),
    )?;
    if used > state.config.max_user_bytes {
        return Err(ApiError::Forbidden("storage_quota_exceeded"));
    }
    tx.commit()?;
    Ok(Json(UploadResp { version: next }))
}

pub async fn remove(
    axum::extract::State(state): State,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_full_access(&state)?;
    let id = parse_id(&id)?;
    let n = state
        .db()
        .execute("DELETE FROM vaults WHERE id = ?1 AND owner_id = ?2", params![id, user.user_id])?;
    if n == 0 { Err(ApiError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}

#[derive(Serialize)]
pub struct VersionOut {
    version: i64,
    created_at: i64,
    size: i64,
}

pub async fn versions(
    axum::extract::State(state): State,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<VersionOut>>> {
    user.require_full_access(&state)?;
    let id = parse_id(&id)?;
    let conn = state.db();
    owned_version(&conn, &id, &user)?;
    let mut stmt = conn.prepare(
        "SELECT version, created_at, length(data) FROM vault_versions WHERE vault_id = ?1 ORDER BY version DESC",
    )?;
    let rows = stmt
        .query_map([&id], |r| Ok(VersionOut { version: r.get(0)?, created_at: r.get(1)?, size: r.get(2)? }))?
        .collect::<Result<_, _>>()?;
    Ok(Json(rows))
}

pub async fn download_version(
    axum::extract::State(state): State,
    user: AuthUser,
    Path((id, version)): Path<(String, i64)>,
) -> ApiResult<Response> {
    user.require_full_access(&state)?;
    let id = parse_id(&id)?;
    let conn = state.db();
    owned_version(&conn, &id, &user)?;
    let data: Vec<u8> = conn
        .query_row(
            "SELECT data FROM vault_versions WHERE vault_id = ?1 AND version = ?2",
            params![id, version],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
    Ok(kdbx_response(version, data))
}
