//! Compte sur le serveur : mot de passe maître, 2FA, appareils connectés,
//! versions du coffre ; et délai de verrouillage automatique (local).
//!
//! Le mot de passe maître est aussi celui du compte : le changer modifie la
//! clé d'authentification sur le serveur ET re-chiffre le coffre.

use std::{path::Path, time::Duration};

use kittypass_core::{
    Error as CoreError,
    client::{AccountInfo, Client, UserInfo, VersionInfo},
    sync::sync,
    vault::{MasterKey, Vault, import},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Invitation à transmettre (code affiché une seule fois).
#[derive(Debug, Clone, Serialize)]
pub struct InviteView {
    pub code: Zeroizing<String>,
    pub expires_in_hours: i64,
    pub admin: bool,
    pub server_url: String,
}

use crate::{App, AppError, AppResult, ImportView, SyncOutcome, keyfile::read_key_file, storage};

const LOCK_FILE: &str = "lock.json";
/// Délai par défaut, comme avant qu'il soit réglable.
pub const DEFAULT_AUTO_LOCK_SECS: u64 = 5 * 60;
const MIN_AUTO_LOCK_SECS: u64 = 30;
const MAX_AUTO_LOCK_SECS: u64 = 24 * 3600;

/// Verrouillage automatique après inactivité, réglé sur cet appareil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockConfig {
    /// Secondes d'inactivité avant verrouillage ; `None` : jamais.
    pub auto_lock_secs: Option<u64>,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self { auto_lock_secs: Some(DEFAULT_AUTO_LOCK_SECS) }
    }
}

impl LockConfig {
    fn checked(self) -> AppResult<Self> {
        match self.auto_lock_secs {
            Some(s) if !(MIN_AUTO_LOCK_SECS..=MAX_AUTO_LOCK_SECS).contains(&s) => {
                Err(CoreError::InvalidArgument("délai de verrouillage : entre 30 secondes et 24 heures").into())
            }
            _ => Ok(self),
        }
    }

    pub(crate) fn duration(self) -> Option<Duration> {
        self.auto_lock_secs.map(Duration::from_secs)
    }

    /// Réglage enregistré ; un fichier absent, illisible ou hors limites
    /// donne la valeur par défaut (jamais « jamais » par accident).
    pub(crate) fn load(dir: &Path) -> Self {
        storage::read_json::<Self>(&dir.join(LOCK_FILE)).ok().flatten().and_then(|c| c.checked().ok()).unwrap_or_default()
    }
}

/// Appareil connecté au compte.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub id: String,
    pub device: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub current: bool,
}

/// 2FA en cours de configuration : le secret, le lien et son QR code
/// (`size` × `size` modules, ligne par ligne, vrai = noir).
#[derive(Serialize)]
pub struct TotpSetupView {
    pub secret: Zeroizing<String>,
    pub uri: Zeroizing<String>,
    pub qr_size: usize,
    pub qr: Vec<bool>,
}

/// Récupération d'une version passée du coffre dans un nouveau groupe.
#[derive(Deserialize)]
pub struct RestoreRequest {
    pub version: i64,
    /// Groupe sous lequel créer le groupe de la version.
    pub parent: String,
    pub name: String,
    /// Si la version date d'avant un changement de mot de passe ou de fichier
    /// clé : l'ancienne clé. Sinon, la clé actuelle du coffre est utilisée.
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub key_file: Option<std::path::PathBuf>,
}

fn qr(text: &str) -> AppResult<(usize, Vec<bool>)> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| CoreError::InvalidArgument("QR code"))?;
    let modules = code.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect();
    Ok((code.width(), modules))
}

impl App {
    // ---------- Verrouillage automatique ----------

    pub fn lock_config(&self) -> LockConfig {
        LockConfig::load(&self.dir)
    }

    pub fn save_lock_config(&self, c: LockConfig) -> AppResult<LockConfig> {
        let c = c.checked()?;
        storage::write_atomic(&self.dir.join(LOCK_FILE), &serde_json::to_vec_pretty(&c)?)?;
        self.set_auto_lock_after(c.duration());
        self.touch();
        Ok(c)
    }

    // ---------- Compte et appareils ----------

    /// Client connecté, avec le mot de passe du coffre déverrouillé.
    async fn account_client(&self) -> AppResult<std::sync::Arc<Client>> {
        self.touch();
        let (profile, password) = {
            let inner = self.inner.lock().await;
            let p = inner.profile.clone().ok_or(AppError::NotConfigured)?;
            (p, Zeroizing::new(inner.vault.as_ref().ok_or(AppError::Locked)?.password().to_owned()))
        };
        self.connected_client(&profile, &password).await
    }

    /// Termine un appel au serveur : garde les jetons qui ont pu tourner, et
    /// oublie la session si le serveur l'a fermée.
    async fn after_call<T>(&self, client: &Client, r: kittypass_core::Result<T>) -> AppResult<T> {
        self.save_tokens(client)?;
        if matches!(r, Err(CoreError::SessionExpired)) {
            self.inner.lock().await.client = None;
        }
        Ok(r?)
    }

    pub async fn account(&self) -> AppResult<AccountInfo> {
        let c = self.account_client().await?;
        let r = c.account().await;
        self.after_call(&c, r).await
    }

    // ---------- Administration (comptes admin) ----------

    /// Crée une invitation : la personne choisit elle-même son identifiant et
    /// son mot de passe (personne d'autre ne le connaît).
    pub async fn create_invite(&self, admin: bool, hours: i64) -> AppResult<InviteView> {
        if !(1..=24 * 30).contains(&hours) {
            return Err(CoreError::InvalidArgument("durée entre 1 h et 30 jours").into());
        }
        let c = self.account_client().await?;
        let r = c.create_invite(admin, hours).await;
        let inv = self.after_call(&c, r).await?;
        let server_url = self.inner.lock().await.profile.as_ref().map(|p| p.server_url.clone()).unwrap_or_default();
        Ok(InviteView { code: inv.code, expires_in_hours: inv.expires_in_hours, admin, server_url })
    }

    pub async fn users(&self) -> AppResult<Vec<UserInfo>> {
        let c = self.account_client().await?;
        let r = c.list_users().await;
        self.after_call(&c, r).await
    }

    pub async fn set_user_disabled(&self, username: &str, disabled: bool) -> AppResult<()> {
        let c = self.account_client().await?;
        let r = c.set_user_disabled(username, disabled).await;
        self.after_call(&c, r).await
    }

    pub async fn sessions(&self) -> AppResult<Vec<SessionView>> {
        let c = self.account_client().await?;
        let r = c.list_sessions().await;
        let list = self.after_call(&c, r).await?;
        Ok(list
            .into_iter()
            .map(|s| SessionView { id: s.id, device: s.device, created_at: s.created_at, last_seen: s.last_seen, current: s.current })
            .collect())
    }

    /// Déconnecte un autre appareil. Celui-ci ne peut pas se révoquer
    /// lui-même par ce moyen (il perdrait l'accès sans le savoir).
    pub async fn revoke_session(&self, id: &str) -> AppResult<()> {
        let c = self.account_client().await?;
        let r = c.list_sessions().await;
        let list = self.after_call(&c, r).await?;
        if list.iter().any(|s| s.id == id && s.current) {
            return Err(CoreError::InvalidArgument("c'est la session de cet appareil").into());
        }
        let r = c.revoke_session(id).await;
        self.after_call(&c, r).await
    }

    /// Déconnecte tous les autres appareils ; renvoie leur nombre.
    pub async fn revoke_other_sessions(&self) -> AppResult<usize> {
        let c = self.account_client().await?;
        let r = c.list_sessions().await;
        let list = self.after_call(&c, r).await?;
        let mut n = 0;
        for s in list.iter().filter(|s| !s.current) {
            let r = c.revoke_session(&s.id).await;
            match self.after_call(&c, r).await {
                Ok(()) => n += 1,
                // Déjà fermée entre-temps : rien à faire.
                Err(AppError::Core(CoreError::Server(404))) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(n)
    }

    // ---------- Mot de passe maître ----------

    /// Change le mot de passe maître (et du compte). Le serveur change
    /// d'abord la clé d'authentification et ferme les autres sessions, puis
    /// le coffre re-chiffré est envoyé. Si l'envoi échoue, le nouveau mot de
    /// passe est quand même gardé ici : la prochaine synchronisation, dans
    /// cette session, enverra le coffre re-chiffré.
    pub async fn change_master_password(&self, current: &str, new: &str) -> AppResult<SyncOutcome> {
        self.touch();
        let (profile, mut snapshot) = {
            let inner = self.inner.lock().await;
            (inner.profile.clone().ok_or(AppError::NotConfigured)?, inner.vault.clone().ok_or(AppError::Locked)?)
        };
        // Vérifie le mot de passe actuel et la force du nouveau avant tout
        // appel au serveur.
        snapshot.change_password(current, new)?;
        if current == new {
            return Err(CoreError::InvalidArgument("le nouveau mot de passe est identique à l'actuel").into());
        }
        let client = self.connected_client(&profile, current).await?;
        let r = client.change_password(&profile.username, current, new).await;
        self.after_call(&client, r).await?;

        // Le serveur a accepté : ce coffre adopte le nouveau mot de passe.
        {
            let mut inner = self.inner.lock().await;
            let vault = inner.vault.as_mut().ok_or(AppError::Locked)?;
            vault.change_password(current, new)?;
            self.persist(&inner)?;
        }
        self.sync().await
    }

    /// Un autre appareil a changé le mot de passe maître : ce coffre, ouvert
    /// avec l'ancien, adopte le nouveau (vérifié par le serveur puis par le
    /// déchiffrement du coffre distant).
    pub async fn adopt_master_password(&self, new: &str, totp: Option<&str>) -> AppResult<SyncOutcome> {
        self.touch();
        let (profile, mut snapshot) = {
            let inner = self.inner.lock().await;
            (inner.profile.clone().ok_or(AppError::NotConfigured)?, inner.vault.clone().ok_or(AppError::Locked)?)
        };
        let client = self.new_client(&profile.server_url)?;
        client.login(&profile.username, new, totp.filter(|t| !t.trim().is_empty()), &profile.device).await?;
        self.save_tokens(&client)?;
        let client = std::sync::Arc::new(client);
        self.inner.lock().await.client = Some(client.clone());

        let current = Zeroizing::new(snapshot.password().to_owned());
        if current.as_str() != new {
            snapshot.change_password(&current, new)?;
        }
        let r = sync(&mut snapshot, profile.last_seen, &self.limits, &client.remote(&profile.vault_id)?).await;
        let report = self.after_call(&client, r).await?;

        let mut inner = self.inner.lock().await;
        let vault = inner.vault.as_mut().ok_or(AppError::Locked)?;
        if current.as_str() != new {
            vault.change_password(&current, new)?;
        }
        vault.forget_previous_key();
        vault.merge_from(&snapshot)?;
        if let Some(p) = inner.profile.as_mut() {
            p.last_seen = p.last_seen.max(report.version);
        }
        self.persist(&inner)?;
        Ok(SyncOutcome { version: report.version, pulled: report.pulled, pushed: report.pushed })
    }

    // ---------- 2FA ----------

    pub async fn setup_2fa(&self) -> AppResult<TotpSetupView> {
        let c = self.account_client().await?;
        let r = c.setup_2fa().await;
        let s = self.after_call(&c, r).await?;
        let (qr_size, qr) = qr(&s.otpauth_uri)?;
        Ok(TotpSetupView { secret: s.secret, uri: s.otpauth_uri, qr_size, qr })
    }

    /// Active la 2FA ; renvoie les codes de secours, à montrer une seule fois.
    pub async fn enable_2fa(&self, code: &str) -> AppResult<Vec<Zeroizing<String>>> {
        let c = self.account_client().await?;
        let r = c.enable_2fa(code).await;
        self.after_call(&c, r).await
    }

    pub async fn disable_2fa(&self, password: &str, code: &str) -> AppResult<()> {
        let c = self.account_client().await?;
        let username = self.inner.lock().await.profile.as_ref().map(|p| p.username.clone()).ok_or(AppError::NotConfigured)?;
        let r = c.disable_2fa(&username, password, code).await;
        self.after_call(&c, r).await
    }

    // ---------- Versions du coffre ----------

    pub async fn vault_versions(&self) -> AppResult<Vec<VersionInfo>> {
        let c = self.account_client().await?;
        let id = self.inner.lock().await.profile.as_ref().map(|p| p.vault_id.clone()).ok_or(AppError::NotConfigured)?;
        let r = c.list_versions(&id).await;
        self.after_call(&c, r).await
    }

    async fn version_bytes(&self, version: i64) -> AppResult<Zeroizing<Vec<u8>>> {
        let c = self.account_client().await?;
        let id = self.inner.lock().await.profile.as_ref().map(|p| p.vault_id.clone()).ok_or(AppError::NotConfigured)?;
        let r = c.download_version(&id, version).await;
        Ok(Zeroizing::new(self.after_call(&c, r).await?))
    }

    /// Copie une version passée dans un nouveau groupe du coffre actuel,
    /// sans rien écraser ni supprimer : contre une erreur, une suppression
    /// ou un coffre abîmé, on récupère ce qu'il faut puis on fait le tri.
    pub async fn restore_version(&self, req: RestoreRequest) -> AppResult<ImportView> {
        let data = self.version_bytes(req.version).await?;
        let key = match (&req.password, &req.key_file) {
            (None, None) => self.read(|v| Ok(v.master_key().clone())).await?,
            (pw, kf) => MasterKey::new(pw.as_deref().map_or("", |p| p.as_str()), kf.as_deref().map(read_key_file).transpose()?),
        };
        let limits = self.limits;
        let imported = tokio::task::spawn_blocking(move || -> AppResult<import::Imported> {
            let old = Vault::open_with_key(&data, &key, &limits)?;
            Ok(import::parse_kdbx(&old)?)
        })
        .await
        .map_err(|_| AppError::Io("récupération interrompue".into()))??;
        let name = if req.name.trim().is_empty() { format!("Version {}", req.version) } else { req.name };
        let report = self.write(|v| Ok(v.import(&req.parent, &name, imported)?)).await?;
        Ok(report.into())
    }

    /// Enregistre une version passée telle quelle (fichier KeePass chiffré).
    pub async fn save_version(&self, version: i64, path: &Path) -> AppResult<()> {
        let data = self.version_bytes(version).await?;
        crate::transfer::save_outside(self, path, &data)
    }
}
