mod admin;
mod auth;
mod twofa;
mod vaults;

pub use admin::new_invite;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts},
    http::{HeaderValue, header, request::Parts},
    middleware,
    response::Response,
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::{
    AppState,
    crypto::{random_token, token_hash},
    error::{ApiError, ApiResult},
};

pub type State = axum::extract::State<Arc<AppState>>;

/// Taille maximale des requêtes JSON.
const JSON_LIMIT: usize = 16 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    let vault_limit = state.config.max_vault_bytes;
    let api = Router::new()
        .route("/prelogin", post(auth::prelogin))
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/token/refresh", post(auth::refresh))
        .route("/logout", post(auth::logout))
        .route("/account", get(auth::account))
        .route("/account/password", post(auth::change_password))
        .route("/sessions", get(auth::list_sessions))
        .route("/sessions/{id}", delete(auth::revoke_session))
        .route("/2fa/setup", post(twofa::setup))
        .route("/2fa/enable", post(twofa::enable))
        .route("/2fa/disable", post(twofa::disable))
        .route("/admin/invites", post(admin::create_invite))
        .route("/admin/users", get(admin::list_users))
        .route("/admin/users/{username}/disabled", post(admin::set_user_disabled))
        .route("/vaults", get(vaults::list).post(vaults::create))
        .route(
            "/vaults/{id}",
            get(vaults::download)
                .put(vaults::upload)
                .delete(vaults::remove)
                .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(vault_limit))
                // Au plus 8 transferts de coffre à la fois (jusqu'à 64 Mio
                // chacun en mémoire) : pas d'épuisement de la RAM.
                .layer::<_, std::convert::Infallible>(tower::limit::ConcurrencyLimitLayer::new(8)),
        )
        .route("/vaults/{id}/versions", get(vaults::versions))
        .route("/vaults/{id}/versions/{version}", get(vaults::download_version))
        .layer(DefaultBodyLimit::max(JSON_LIMIT));

    Router::new()
        .nest("/api/v1", api)
        .route("/health", get(|| async { "ok" }))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, header::CACHE_CONTROL, "no-store");
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::CONTENT_SECURITY_POLICY, "default-src 'none'; frame-ancestors 'none'");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains");
    res
}

// ---------- Extracteurs ----------

/// Adresse du client. `X-Forwarded-For` n'est lu que si la connexion vient
/// d'un proxy de confiance.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<Arc<AppState>> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> ApiResult<Self> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        if !state.config.trusted_proxies.contains(&peer) {
            return Ok(Self(peer));
        }
        // Le proxy ajoute l'adresse réelle en dernier : seule cette valeur est
        // fiable, les précédentes viennent du client.
        let forwarded = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|s| s.trim().parse().ok());
        Ok(Self(forwarded.unwrap_or(peer)))
    }
}

/// Clé de limitation de débit pour une adresse. En IPv6, un abonné reçoit au
/// moins un /64 : compter adresse par adresse lui donnerait des milliards
/// d'essais. On compte donc par /64 (et les adresses IPv4 mappées en IPv4).
pub fn rate_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Utilisateur authentifié par un jeton d'accès valide.
pub struct AuthUser {
    pub user_id: String,
    pub session_id: String,
    pub is_admin: bool,
    pub has_2fa: bool,
}

impl AuthUser {
    /// Bloque l'accès aux coffres tant qu'un compte doit configurer sa 2FA.
    pub fn require_full_access(&self, state: &AppState) -> ApiResult<()> {
        if state.config.require_2fa && !self.has_2fa {
            return Err(ApiError::Forbidden("2fa_setup_required"));
        }
        Ok(())
    }
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> ApiResult<Self> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| t.len() <= 128)
            .ok_or(ApiError::Unauthorized)?;
        let now = state.now();
        let conn = state.db();
        let user = conn
            .query_row(
                "SELECT s.user_id, s.id, u.is_admin, u.totp_secret IS NOT NULL
                 FROM tokens t
                 JOIN sessions s ON s.id = t.session_id
                 JOIN users u ON u.id = s.user_id
                 WHERE t.hash = ?1 AND t.kind = 'access' AND t.expires_at > ?2 AND u.disabled = 0",
                params![token_hash(token), now],
                |r| {
                    Ok(AuthUser {
                        user_id: r.get(0)?,
                        session_id: r.get(1)?,
                        is_admin: r.get(2)?,
                        has_2fa: r.get(3)?,
                    })
                },
            )
            .optional()?
            .ok_or(ApiError::Unauthorized)?;
        conn.execute("UPDATE sessions SET last_seen = ?1 WHERE id = ?2", params![now, user.session_id])?;
        Ok(user)
    }
}

// ---------- Utilitaires ----------

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(s: &str, min: usize, max: usize) -> ApiResult<Vec<u8>> {
    if s.len() > max.div_ceil(3) * 4 + 4 {
        return Err(ApiError::BadRequest("base64 trop long"));
    }
    let v = STANDARD.decode(s).map_err(|_| ApiError::BadRequest("base64 invalide"))?;
    if !(min..=max).contains(&v.len()) {
        return Err(ApiError::BadRequest("longueur invalide"));
    }
    Ok(v)
}

/// Identifiants : minuscules ASCII, chiffres, `.`, `_`, `-`, 3 à 32 caractères.
/// L'ASCII seul exclut les homoglyphes Unicode (« аdmin » cyrillique).
pub fn normalize_username(u: &str) -> ApiResult<String> {
    let u = u.trim().to_ascii_lowercase();
    let ok = (3..=32).contains(&u.len())
        && u.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if ok { Ok(u) } else { Err(ApiError::BadRequest("identifiant invalide")) }
}

/// Caractères invisibles ou de contrôle bidirectionnel (catégorie Cf), utilisés
/// pour déguiser un texte (« exe.gpj » affiché « jpg.exe »).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

/// Texte libre court (noms d'appareil, de coffre) sans caractères de contrôle.
pub fn clean_label(s: &str, max: usize) -> ApiResult<String> {
    let s = s.trim();
    if s.is_empty()
        || s.chars().count() > max
        || s.chars().any(|c| c.is_control() || is_invisible(c))
    {
        return Err(ApiError::BadRequest("libellé invalide"));
    }
    Ok(s.to_owned())
}

#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub fn issue_tokens(conn: &Connection, state: &AppState, session_id: &str) -> ApiResult<TokenPair> {
    let now = state.now();
    let access = random_token();
    let refresh = random_token();
    let mut stmt =
        conn.prepare("INSERT INTO tokens (hash, session_id, kind, expires_at) VALUES (?1, ?2, ?3, ?4)")?;
    stmt.execute(params![token_hash(&access), session_id, "access", now + state.config.access_ttl])?;
    stmt.execute(params![token_hash(&refresh), session_id, "refresh", now + state.config.refresh_ttl])?;
    Ok(TokenPair { access_token: access, refresh_token: refresh, expires_in: state.config.access_ttl })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert_eq!(normalize_username("  Alice.B ").unwrap(), "alice.b");
        for bad in ["ab", "a b", "аdmin", "admin\0", "x".repeat(33).as_str(), "admin'--", "../x", "é_t_é"] {
            assert!(normalize_username(bad).is_err(), "{bad:?} accepté");
        }
    }

    #[test]
    fn base64_bounds() {
        assert_eq!(unb64(&b64(&[1; 32]), 32, 32).unwrap(), vec![1; 32]);
        assert!(unb64(&b64(&[1; 31]), 32, 32).is_err());
        assert!(unb64("%%%", 0, 10).is_err());
        assert!(unb64(&"A".repeat(10_000), 0, 64).is_err());
    }

    #[test]
    fn labels() {
        assert!(clean_label("", 10).is_err());
        assert!(clean_label("a\nb", 10).is_err());
        assert!(clean_label("\u{202e}gpj.exe", 64).is_err(), "override bidirectionnel accepté");
        assert_eq!(clean_label(" Pixel 8 ", 64).unwrap(), "Pixel 8");
    }
}
