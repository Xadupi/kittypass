//! Client HTTP de l'API KittyPass (fonctionnalité `client`).

use std::sync::Mutex;

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    account::{KdfParams, derive_auth_key, new_account_salt},
    sync::{PushOutcome, Remote},
};

/// Jetons de session. Le jeton de rafraîchissement est un secret long terme :
/// l'application doit le ranger dans le trousseau du système, jamais en clair.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tokens(<masqués>)")
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub device: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub current: bool,
}

/// Résumé du compte connecté.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub username: String,
    pub totp_enabled: bool,
    /// Le serveur impose la 2FA : elle ne peut pas être désactivée.
    pub require_2fa: bool,
    /// Peut créer des invitations et gérer les comptes.
    #[serde(default)]
    pub is_admin: bool,
}

/// Compte du serveur, vu par un admin.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserInfo {
    pub username: String,
    pub is_admin: bool,
    pub totp_enabled: bool,
    pub disabled: bool,
    pub created_at: i64,
    /// Le compte de l'admin qui fait la demande.
    pub current: bool,
}

/// Invitation créée : code à transmettre à la personne (une seule fois).
#[derive(Debug, Clone, Deserialize)]
pub struct Invite {
    pub code: Zeroizing<String>,
    pub expires_in_hours: i64,
}

/// Version passée d'un coffre gardée par le serveur.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: i64,
    pub created_at: i64,
    pub size: i64,
}

/// 2FA en cours de configuration : secret à saisir ou lien à scanner.
pub struct TotpSetup {
    pub secret: Zeroizing<String>,
    pub otpauth_uri: Zeroizing<String>,
}

pub struct Client {
    base: Url,
    http: reqwest::Client,
    tokens: Mutex<Option<Tokens>>,
    /// Jeton « appareil de confiance » : remplace le code 2FA aux connexions
    /// suivantes sur cet appareil (renouvelé à chaque connexion).
    device_token: Mutex<Option<String>>,
}

/// N'accepte que HTTPS, sauf vers la machine locale (développement) : en HTTP
/// clair, la clé d'authentification et les jetons circuleraient en clair.
pub fn validate_server_url(url: &str) -> Result<Url> {
    let u = Url::parse(url.trim()).map_err(|_| Error::InsecureUrl)?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let ok_scheme = u.scheme() == "https" || (u.scheme() == "http" && local);
    // Pas d'identifiants dans l'URL, pas de requête ni de fragment.
    if !ok_scheme || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return Err(Error::InsecureUrl);
    }
    let mut u = u;
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u)
}

fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn map_status(status: StatusCode, body: &[u8]) -> Error {
    let detail = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["detail"].as_str().map(str::to_owned));
    if status == StatusCode::BAD_REQUEST && detail.as_deref() == Some("code invalide") {
        return Error::InvalidTotp;
    }
    match (status, error_code(body).as_str()) {
        (StatusCode::UNAUTHORIZED, "totp_required") => Error::TotpRequired,
        (StatusCode::UNAUTHORIZED, "invalid_credentials") => Error::InvalidCredentials,
        (StatusCode::UNAUTHORIZED, _) => Error::SessionExpired,
        (StatusCode::TOO_MANY_REQUESTS, _) => Error::RateLimited,
        (StatusCode::FORBIDDEN, "invalid_invite") => Error::InvalidInvite,
        (StatusCode::FORBIDDEN, "admin_required") => Error::InvalidArgument("réservé aux administrateurs"),
        (StatusCode::FORBIDDEN, "2fa_setup_required") => {
            Error::InvalidArgument("activez d'abord la 2FA sur votre compte")
        }
        (StatusCode::CONFLICT, "username_taken") => Error::UsernameTaken,
        (StatusCode::FORBIDDEN, "2fa_required_by_server") => Error::InvalidArgument("la 2FA est imposée par le serveur"),
        (s, _) => Error::Server(s.as_u16()),
    }
}

/// Android : le vérificateur du système demande une initialisation Java ;
/// on utilise à la place les autorités de confiance de Mozilla (webpki).
#[cfg(target_os = "android")]
pub fn android_roots(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    b.tls_certs_only(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok()))
}
#[cfg(not(target_os = "android"))]
pub fn android_roots(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    b
}

impl Client {
    pub fn new(server_url: &str) -> Result<Self> {
        let base = validate_server_url(server_url)?;
        let http = reqwest::Client::builder()
            .https_only(base.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .user_agent(concat!("kittypass/", env!("CARGO_PKG_VERSION")));
        let http = android_roots(http)
            .build()
            .map_err(|_| Error::Network)?;
        Ok(Self { base, http, tokens: Mutex::new(None), device_token: Mutex::new(None) })
    }

    pub fn set_tokens(&self, tokens: Option<Tokens>) {
        *self.tokens.lock().unwrap_or_else(|e| e.into_inner()) = tokens;
    }

    pub fn set_device_token(&self, token: Option<String>) {
        *self.device_token.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }

    pub fn device_token(&self) -> Option<String> {
        self.device_token.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn tokens(&self) -> Option<Tokens> {
        self.tokens.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base.join(path).map_err(|_| Error::InvalidArgument("chemin"))
    }

    async fn post_json(&self, path: &str, body: &Value, auth: bool) -> Result<(StatusCode, Vec<u8>)> {
        let mut req = self.http.post(self.url(path)?).json(body);
        if auth {
            req = req.bearer_auth(self.tokens().ok_or(Error::SessionExpired)?.access_token);
        }
        let res = req.send().await.map_err(|_| Error::Network)?;
        let status = res.status();
        Ok((status, res.bytes().await.map_err(|_| Error::Network)?.to_vec()))
    }

    async fn prelogin(&self, username: &str) -> Result<(Vec<u8>, KdfParams)> {
        let (s, b) = self.post_json("api/v1/prelogin", &json!({"username": username}), false).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        let v: Value = serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))?;
        let salt = STANDARD
            .decode(v["salt"].as_str().unwrap_or_default())
            .map_err(|_| Error::Server(s.as_u16()))?;
        let num = |k: &str| v[k].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or(Error::Server(s.as_u16()));
        let params = KdfParams { memory_kib: num("memory_kib")?, iterations: num("iterations")?, parallelism: num("parallelism")? };
        // derive_auth_key valide ensuite les paramètres : un serveur malveillant
        // ne peut pas imposer une dérivation faible.
        Ok((salt, params))
    }

    pub async fn register(&self, invite: &str, username: &str, password: &str) -> Result<()> {
        let salt = new_account_salt()?;
        let key = derive_auth_key(password, &salt, &KdfParams::DEFAULT)?;
        let d = KdfParams::DEFAULT;
        let body = json!({
            "invite": invite,
            "username": username,
            "kdf": {"salt": STANDARD.encode(salt), "memory_kib": d.memory_kib, "iterations": d.iterations, "parallelism": d.parallelism},
            "auth_key": STANDARD.encode(key.as_bytes()),
        });
        let (s, b) = self.post_json("api/v1/register", &body, false).await?;
        if s == StatusCode::CREATED { Ok(()) } else { Err(map_status(s, &b)) }
    }

    /// Connexion. Renvoie `Error::TotpRequired` si un code 2FA est nécessaire.
    /// Le second booléen indique que le serveur exige la configuration de la 2FA.
    pub async fn login(&self, username: &str, password: &str, totp: Option<&str>, device: &str) -> Result<bool> {
        let (salt, params) = self.prelogin(username).await?;
        let key = derive_auth_key(password, &salt, &params)?;
        let mut body = json!({"username": username, "auth_key": STANDARD.encode(key.as_bytes()), "device": device});
        if let Some(code) = totp {
            let code = code.trim();
            // Code TOTP à 6 chiffres, sinon on le traite comme un code de secours.
            body[if code.len() == 6 { "totp" } else { "recovery_code" }] = json!(code);
        } else if let Some(t) = self.device_token() {
            body["device_token"] = json!(t);
        }
        let (s, b) = self.post_json("api/v1/login", &body, false).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        let v: Value = serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))?;
        let tokens: Tokens = serde_json::from_value(v.clone()).map_err(|_| Error::Server(s.as_u16()))?;
        self.set_tokens(Some(tokens));
        if let Some(t) = v["device_token"].as_str() {
            self.set_device_token(Some(t.to_owned()));
        }
        Ok(v["must_setup_2fa"].as_bool().unwrap_or(false))
    }

    pub async fn refresh(&self) -> Result<()> {
        let t = self.tokens().ok_or(Error::SessionExpired)?;
        let (s, b) = self.post_json("api/v1/token/refresh", &json!({"refresh_token": t.refresh_token}), false).await?;
        if !s.is_success() {
            self.set_tokens(None);
            return Err(map_status(s, &b));
        }
        let tokens: Tokens = serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))?;
        self.set_tokens(Some(tokens));
        Ok(())
    }

    pub async fn logout(&self) -> Result<()> {
        let r = self.post_json("api/v1/logout", &json!({}), true).await;
        self.set_tokens(None);
        r.map(|_| ())
    }

    /// Requête authentifiée ; si le jeton d'accès a expiré, rafraîchit une
    /// fois puis réessaie.
    async fn authed(
        &self,
        build: impl Fn(&str) -> Result<reqwest::RequestBuilder>,
    ) -> Result<(StatusCode, header::HeaderMap, Vec<u8>)> {
        for attempt in 0..2 {
            let token = self.tokens().ok_or(Error::SessionExpired)?.access_token;
            let res = build(&token)?.send().await.map_err(|_| Error::Network)?;
            let status = res.status();
            if status == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.refresh().await?;
                continue;
            }
            let headers = res.headers().clone();
            let body = res.bytes().await.map_err(|_| Error::Network)?.to_vec();
            return Ok((status, headers, body));
        }
        Err(Error::SessionExpired)
    }

    pub async fn list_vaults(&self) -> Result<Vec<VaultInfo>> {
        let url = self.url("api/v1/vaults")?;
        let (s, _, b) = self.authed(|t| Ok(self.http.get(url.clone()).bearer_auth(t))).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))
    }

    pub async fn create_vault(&self, name: &str) -> Result<VaultInfo> {
        let url = self.url("api/v1/vaults")?;
        let body = json!({"name": name});
        let (s, _, b) = self.authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await?;
        if s != StatusCode::CREATED {
            return Err(map_status(s, &b));
        }
        serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let url = self.url("api/v1/sessions")?;
        let (s, _, b) = self.authed(|t| Ok(self.http.get(url.clone()).bearer_auth(t))).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))
    }

    /// Accès au coffre `vault_id` pour l'algorithme de synchronisation.
    pub fn remote<'a>(&'a self, vault_id: &str) -> Result<HttpRemote<'a>> {
        let id = uuid::Uuid::parse_str(vault_id).map_err(|_| Error::InvalidId)?;
        Ok(HttpRemote { client: self, url: self.url(&format!("api/v1/vaults/{id}"))? })
    }

    /// Requête authentifiée sans corps de réponse attendu (204).
    async fn send_authed(&self, build: impl Fn(&str) -> Result<reqwest::RequestBuilder>) -> Result<()> {
        let (s, _, b) = self.authed(build).await?;
        if s.is_success() { Ok(()) } else { Err(map_status(s, &b)) }
    }

    /// GET authentifié renvoyant du JSON.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path)?;
        let (s, _, b) = self.authed(|t| Ok(self.http.get(url.clone()).bearer_auth(t))).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))
    }

    pub async fn account(&self) -> Result<AccountInfo> {
        self.get_json("api/v1/account").await
    }

    /// Crée une invitation (admins). `admin` : le futur compte sera admin.
    pub async fn create_invite(&self, admin: bool, hours: i64) -> Result<Invite> {
        let url = self.url("api/v1/admin/invites")?;
        let body = json!({"admin": admin, "hours": hours});
        let (s, _, b) = self.authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await?;
        let b = Zeroizing::new(b);
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))
    }

    /// Comptes du serveur (admins).
    pub async fn list_users(&self) -> Result<Vec<UserInfo>> {
        self.get_json("api/v1/admin/users").await
    }

    /// Désactive ou réactive un compte (admins).
    pub async fn set_user_disabled(&self, username: &str, disabled: bool) -> Result<()> {
        let ok = (3..=32).contains(&username.len())
            && username.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if !ok {
            return Err(Error::InvalidArgument("identifiant invalide"));
        }
        let url = self.url(&format!("api/v1/admin/users/{username}/disabled"))?;
        let body = json!({"disabled": disabled});
        self.send_authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await
    }

    /// Révoque une session (un autre appareil) : ses jetons ne valent plus rien.
    pub async fn revoke_session(&self, id: &str) -> Result<()> {
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::InvalidId)?;
        let url = self.url(&format!("api/v1/sessions/{id}"))?;
        self.send_authed(|t| Ok(self.http.delete(url.clone()).bearer_auth(t))).await
    }

    /// Change la clé d'authentification du compte (nouveau sel, paramètres
    /// actuels par défaut). Le serveur ferme toutes les autres sessions.
    /// Le coffre doit ensuite être re-chiffré et renvoyé par l'appelant.
    pub async fn change_password(&self, username: &str, current: &str, new: &str) -> Result<()> {
        let (salt, params) = self.prelogin(username).await?;
        let current_key = derive_auth_key(current, &salt, &params)?;
        let new_salt = new_account_salt()?;
        let d = KdfParams::DEFAULT;
        let new_key = derive_auth_key(new, &new_salt, &d)?;
        let body = json!({
            "current_auth_key": STANDARD.encode(current_key.as_bytes()),
            "kdf": {"salt": STANDARD.encode(new_salt), "memory_kib": d.memory_kib, "iterations": d.iterations, "parallelism": d.parallelism},
            "new_auth_key": STANDARD.encode(new_key.as_bytes()),
        });
        let url = self.url("api/v1/account/password")?;
        self.send_authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await
    }

    /// Versions passées du coffre, de la plus récente à la plus ancienne.
    pub async fn list_versions(&self, vault_id: &str) -> Result<Vec<VersionInfo>> {
        let id = uuid::Uuid::parse_str(vault_id).map_err(|_| Error::InvalidId)?;
        self.get_json(&format!("api/v1/vaults/{id}/versions")).await
    }

    /// Contenu (chiffré) d'une version passée du coffre.
    pub async fn download_version(&self, vault_id: &str, version: i64) -> Result<Vec<u8>> {
        let id = uuid::Uuid::parse_str(vault_id).map_err(|_| Error::InvalidId)?;
        if version < 0 {
            return Err(Error::InvalidArgument("version"));
        }
        let url = self.url(&format!("api/v1/vaults/{id}/versions/{version}"))?;
        let (s, _, b) = self.authed(|t| Ok(self.http.get(url.clone()).bearer_auth(t))).await?;
        if s == StatusCode::OK { Ok(b) } else { Err(map_status(s, &b)) }
    }

    /// Prépare la 2FA : secret à saisir ou lien `otpauth://` à scanner.
    pub async fn setup_2fa(&self) -> Result<TotpSetup> {
        let url = self.url("api/v1/2fa/setup")?;
        let (s, _, b) = self.authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&json!({})))).await?;
        let b = Zeroizing::new(b);
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        let v: Value = serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))?;
        let field = |k: &str| v[k].as_str().map(|x| Zeroizing::new(x.to_owned())).ok_or(Error::Server(s.as_u16()));
        Ok(TotpSetup { secret: field("secret")?, otpauth_uri: field("otpauth_uri")? })
    }

    /// Désactive la 2FA : mot de passe du compte et code actuel exigés.
    pub async fn disable_2fa(&self, username: &str, password: &str, code: &str) -> Result<()> {
        let (salt, params) = self.prelogin(username).await?;
        let key = derive_auth_key(password, &salt, &params)?;
        let body = json!({"auth_key": STANDARD.encode(key.as_bytes()), "code": code.trim()});
        let url = self.url("api/v1/2fa/disable")?;
        self.send_authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await
    }

    /// Active la 2FA et renvoie les codes de secours (à afficher une seule fois).
    pub async fn enable_2fa(&self, code: &str) -> Result<Vec<Zeroizing<String>>> {
        let url = self.url("api/v1/2fa/enable")?;
        let body = json!({"code": code.trim()});
        let (s, _, b) = self.authed(|t| Ok(self.http.post(url.clone()).bearer_auth(t).json(&body))).await?;
        if !s.is_success() {
            return Err(map_status(s, &b));
        }
        let v: Value = serde_json::from_slice(&b).map_err(|_| Error::Server(s.as_u16()))?;
        Ok(v["recovery_codes"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| c.as_str().map(|s| Zeroizing::new(s.to_owned()))).collect())
            .unwrap_or_default())
    }
}

pub struct HttpRemote<'a> {
    client: &'a Client,
    url: Url,
}

impl Remote for HttpRemote<'_> {
    async fn fetch(&self) -> Result<(i64, Option<Vec<u8>>)> {
        let c = self.client;
        let (s, h, b) = c.authed(|t| Ok(c.http.get(self.url.clone()).bearer_auth(t))).await?;
        let version = h
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim_matches('"').parse::<i64>().ok())
            .filter(|v| *v >= 0);
        match (s, version) {
            (StatusCode::NO_CONTENT, Some(v)) => Ok((v, None)),
            (StatusCode::OK, Some(v)) => Ok((v, Some(b))),
            _ => Err(map_status(s, &b)),
        }
    }

    async fn push(&self, expected: i64, data: Vec<u8>) -> Result<PushOutcome> {
        let c = self.client;
        let (s, _, b) = c
            .authed(|t| {
                Ok(c.http
                    .put(self.url.clone())
                    .bearer_auth(t)
                    .header(header::IF_MATCH, format!("\"{expected}\""))
                    .body(data.clone()))
            })
            .await?;
        match s {
            StatusCode::OK => {
                let v: Value = serde_json::from_slice(&b).map_err(|_| Error::Server(200))?;
                v["version"].as_i64().map(PushOutcome::Stored).ok_or(Error::Server(200))
            }
            StatusCode::CONFLICT => Ok(PushOutcome::Conflict),
            _ => Err(map_status(s, &b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_except_localhost() {
        for ok in ["https://coffre.example.org", "https://x.org:8443/vs", "http://localhost:8080", "http://127.0.0.1:1"] {
            assert!(validate_server_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://coffre.example.org",
            "http://192.168.1.10",
            "http://localhost.evil.org",
            "ftp://x.org",
            "file:///etc/passwd",
            "https://user:pass@x.org",
            "https://x.org/?a=1",
            "https://x.org/#f",
            "javascript:alert(1)",
            "",
        ] {
            assert!(validate_server_url(bad).is_err(), "{bad} accepté");
        }
    }

    #[test]
    fn base_path_is_kept() {
        let c = Client::new("https://x.org/kittypass").unwrap();
        assert_eq!(c.url("api/v1/login").unwrap().as_str(), "https://x.org/kittypass/api/v1/login");
    }

    #[test]
    fn remote_rejects_path_injection() {
        let c = Client::new("https://x.org").unwrap();
        assert!(c.remote("../admin").is_err());
        assert!(c.remote("x/../../y").is_err());
    }

    #[test]
    fn tokens_debug_hidden() {
        let t = Tokens { access_token: "AAA".into(), refresh_token: "BBB".into() };
        assert!(!format!("{t:?}").contains("AAA"));
    }
}
