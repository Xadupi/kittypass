//! Logique applicative commune aux clients (desktop, puis Android) :
//! profil, fichier local, verrouillage, synchronisation, reconnexion.
//!
//! Aucune dépendance à une interface graphique : tout est testable sans écran.
#![deny(unsafe_code)]

mod account;
mod autofill;
mod autotype;
mod browser;
mod browser_hosts;
#[cfg(any(unix, windows))]
mod browser_server;
mod error;
mod keyfile;
mod reports;
mod ssh;
mod storage;
mod transfer;
mod vault_api;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use kittypass_core::{
    client::{Client, Tokens},
    header::OpenLimits,
    sync::{download, sync},
    vault::{MasterKey, Vault},
};
use zeroize::Zeroizing;

pub use account::{DEFAULT_AUTO_LOCK_SECS, InviteView, LockConfig, RestoreRequest, SessionView, TotpSetupView};
pub use kittypass_core::client::{AccountInfo, UserInfo, VersionInfo};
pub use browser::{
    Answer, AssociationView, BROWSER_GROUP, BrowserConnection, BrowserSettings, EntryBrowserView, PROMPT_TIMEOUT, Prompt, PromptEntry, Prompter,
};
pub use autotype::{AssociationItem, AutoTypeConfig, AutoTypeMethod, EntryAutoTypeView, normalize_shortcut};
pub use kittypass_core::autotype::{Key as AutoTypeKey, Mods as AutoTypeMods, Step as AutoTypeStep, Typed};
pub use browser_hosts::{BrowserHost, Hosts, HostsStatus, Owner};
#[cfg(any(unix, windows))]
pub use browser_server::BrowserServer;
pub use autofill::AutofillItem;
pub use error::{AppError, AppResult};
pub use keyfile::KeyFileChange;
pub use ssh::{AgentKeyView, EntrySshView, SshConfig, SshStatus};
pub use kittypass_core::ssh::{AgentSettings as SshSettings, KeyInfo as SshKeyInfo};
pub use reports::{HealthItemView, HealthView, PwnedItemView, PwnedView, QualityView, StrengthInput, StrengthView};
pub use storage::{MemoryStore, SecretStore};
pub use transfer::{ExportFormat, ExportRequest, ImportFormat, ImportRequest, ImportView};
pub use vault_api::{
    AttachmentView, CustomInput, CustomView, EntryInput, EntryList, EntryListItem, EntryView, Generated,
    GeneratorOptions, GroupView, HistoryView, SecretField, TotpView, WordCaseInput,
};

const REFRESH_TOKEN_KEY: &str = "refresh_token";
/// Jeton « appareil de confiance » (2FA demandée seulement à la première connexion).
const DEVICE_TOKEN_KEY: &str = "device_token";

/// Configuration non secrète, stockée en clair dans `profile.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub server_url: String,
    pub username: String,
    pub vault_id: String,
    pub device: String,
    /// Dernière version distante vue (détection de retour en arrière).
    pub last_seen: i64,
    /// Emplacement du fichier clé, si l'utilisateur a demandé de le retenir.
    /// Jamais son contenu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub configured: bool,
    pub unlocked: bool,
    pub server_url: Option<String>,
    pub username: Option<String>,
    pub last_seen: i64,
    /// Fichier clé mémorisé (pour préremplir l'écran de déverrouillage).
    pub key_file: Option<String>,
    /// Le coffre déverrouillé est protégé par un fichier clé.
    pub has_key_file: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SetupMode {
    /// Premier appareil : crée le coffre.
    Create,
    /// Appareil supplémentaire : récupère le coffre existant.
    Join,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub mode: SetupMode,
    pub server_url: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub invite: Option<String>,
    pub totp: Option<String>,
    pub device: String,
    /// Fichier clé : à créer avant (`generate_key_file`) pour un nouveau
    /// coffre, ou celui du coffre existant pour rejoindre.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub remember_key_file: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncOutcome {
    pub version: i64,
    pub pulled: usize,
    pub pushed: bool,
}

#[derive(Default)]
struct Inner {
    profile: Option<Profile>,
    vault: Option<Vault>,
    client: Option<Arc<Client>>,
}

pub struct App {
    dir: PathBuf,
    secrets: Arc<dyn SecretStore>,
    inner: tokio::sync::Mutex<Inner>,
    last_activity: Mutex<Instant>,
    /// Inactivité avant verrouillage (`None` : jamais).
    auto_lock_after: Mutex<Option<Duration>>,
    /// Service Have I Been Pwned (API des plages) ; modifiable pour un miroir.
    pub hibp_url: String,
    limits: OpenLimits,
    /// Une seule confirmation du navigateur à la fois.
    browser_prompt: tokio::sync::Mutex<()>,
    /// Clés ajoutées à l'agent SSH pendant cette session.
    ssh: tokio::sync::Mutex<ssh::SshState>,
}

impl App {
    /// Ouvre (ou initialise) le dossier de données de l'application.
    pub fn open(dir: PathBuf, secrets: Arc<dyn SecretStore>) -> AppResult<Self> {
        storage::ensure_private_dir(&dir)?;
        let profile = storage::read_json::<Profile>(&dir.join("profile.json"))?;
        // Un profil modifié pour pointer vers un serveur en HTTP est refusé ici.
        if let Some(p) = &profile {
            kittypass_core::client::validate_server_url(&p.server_url)?;
        }
        Ok(Self {
            auto_lock_after: Mutex::new(account::LockConfig::load(&dir).duration()),
            dir,
            secrets,
            inner: tokio::sync::Mutex::new(Inner { profile, ..Default::default() }),
            last_activity: Mutex::new(Instant::now()),
            hibp_url: kittypass_core::hibp::DEFAULT_URL.to_owned(),
            limits: OpenLimits::default(),
            browser_prompt: tokio::sync::Mutex::new(()),
            ssh: Default::default(),
        })
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.kdbx")
    }

    /// À appeler à chaque action de l'utilisateur (repousse le verrouillage auto).
    pub fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    /// Change le délai de verrouillage pour cette exécution (sans
    /// l'enregistrer : voir `save_lock_config`).
    pub fn set_auto_lock_after(&self, after: Option<Duration>) {
        *self.auto_lock_after.lock().unwrap_or_else(|e| e.into_inner()) = after;
    }

    /// Verrouille si l'utilisateur est inactif depuis le délai réglé.
    /// Renvoie vrai si un verrouillage vient d'avoir lieu.
    pub async fn lock_if_idle(&self) -> bool {
        let Some(after) = *self.auto_lock_after.lock().unwrap_or_else(|e| e.into_inner()) else { return false };
        let idle = self.last_activity.lock().unwrap_or_else(|e| e.into_inner()).elapsed();
        if idle < after {
            return false;
        }
        let locked = self.inner.lock().await.vault.take().is_some();
        if locked {
            self.ssh_on_lock().await;
        }
        locked
    }

    pub async fn status(&self) -> Status {
        let inner = self.inner.lock().await;
        Status {
            configured: inner.profile.is_some() && self.vault_path().exists(),
            unlocked: inner.vault.is_some(),
            server_url: inner.profile.as_ref().map(|p| p.server_url.clone()),
            username: inner.profile.as_ref().map(|p| p.username.clone()),
            last_seen: inner.profile.as_ref().map_or(0, |p| p.last_seen),
            key_file: inner.profile.as_ref().and_then(|p| p.key_file.as_ref()).map(|p| p.display().to_string()),
            has_key_file: inner.vault.as_ref().is_some_and(Vault::has_key_file),
        }
    }

    /// Client du serveur, avec le jeton d'appareil de confiance s'il existe.
    pub(crate) fn new_client(&self, url: &str) -> AppResult<Client> {
        let c = Client::new(url)?;
        c.set_device_token(self.secrets.load(DEVICE_TOKEN_KEY));
        Ok(c)
    }

    fn save_tokens(&self, client: &Client) -> AppResult<()> {
        if let Some(t) = client.device_token() {
            self.secrets.save(DEVICE_TOKEN_KEY, &t)?;
        }
        match client.tokens() {
            Some(t) => self.secrets.save(REFRESH_TOKEN_KEY, &t.refresh_token),
            None => self.secrets.delete(REFRESH_TOKEN_KEY),
        }
    }

    fn persist(&self, inner: &Inner) -> AppResult<()> {
        if let Some(v) = &inner.vault {
            storage::write_atomic(&self.vault_path(), &v.save()?)?;
        }
        if let Some(p) = &inner.profile {
            storage::write_atomic(&self.dir.join("profile.json"), &serde_json::to_vec_pretty(p)?)?;
        }
        Ok(())
    }

    /// Configure l'application sur cet appareil.
    pub async fn setup(&self, req: SetupRequest) -> AppResult<bool> {
        let mut inner = self.inner.lock().await;
        if inner.profile.is_some() {
            return Err(AppError::AlreadyConfigured);
        }
        let keyfile = req.key_file.as_deref().map(keyfile::read_key_file).transpose()?;
        let master = MasterKey::new(&req.password, keyfile);
        let client = self.new_client(&req.server_url)?;
        if let Some(invite) = req.invite.as_deref().filter(|i| !i.trim().is_empty()) {
            client.register(invite.trim(), &req.username, &req.password).await?;
        }
        let must_setup_2fa = client.login(&req.username, &req.password, req.totp.as_deref(), &req.device).await?;

        let vaults = client.list_vaults().await?;
        let (vault, vault_id, last_seen) = match req.mode {
            SetupMode::Join => {
                let info = vaults.first().ok_or(AppError::NoRemoteVault)?;
                let (v, seen) = download(&client.remote(&info.id)?, &master, &self.limits)
                    .await?
                    .ok_or(AppError::NoRemoteVault)?;
                (v, info.id.clone(), seen)
            }
            SetupMode::Create => {
                if !vaults.is_empty() {
                    // Créer un second coffre indépendant mènerait à des coffres
                    // impossibles à fusionner : il faut rejoindre l'existant.
                    return Err(AppError::RemoteVaultExists);
                }
                let info = client.create_vault("Coffre").await?;
                let mut v = Vault::create_with_key(&master)?;
                let report = sync(&mut v, 0, &self.limits, &client.remote(&info.id)?).await?;
                (v, info.id, report.version)
            }
        };
        inner.profile = Some(Profile {
            server_url: req.server_url.trim().to_owned(),
            username: req.username.trim().to_ascii_lowercase(),
            vault_id,
            device: req.device,
            last_seen,
            key_file: if req.remember_key_file { req.key_file.clone() } else { None },
        });
        inner.vault = Some(vault);
        self.save_tokens(&client)?;
        inner.client = Some(Arc::new(client));
        self.persist(&inner)?;
        self.touch();
        Ok(must_setup_2fa)
    }

    /// Déverrouille le coffre local (fonctionne hors ligne), avec le fichier
    /// clé mémorisé s'il y en a un.
    pub async fn unlock(&self, password: &str) -> AppResult<()> {
        let remembered = self.remembered_key_file().await;
        self.unlock_with_key_file(password, remembered.as_deref(), remembered.is_some()).await
    }

    /// Déverrouille avec un fichier clé explicite (`None` : sans fichier).
    /// `remember` mémorise ou oublie son emplacement, une fois le coffre ouvert.
    pub async fn unlock_with_key_file(&self, password: &str, key_file: Option<&Path>, remember: bool) -> AppResult<()> {
        let keyfile = key_file.map(keyfile::read_key_file).transpose()?;
        let mut inner = self.inner.lock().await;
        if inner.profile.is_none() {
            return Err(AppError::NotConfigured);
        }
        let data = std::fs::read(self.vault_path())?;
        inner.vault = Some(Vault::open_with_key(&data, &MasterKey::new(password, keyfile), &self.limits)?);
        if let Some(p) = inner.profile.as_mut() {
            let before = p.key_file.clone();
            Self::remember_key_file(p, key_file, remember);
            if p.key_file != before {
                storage::write_atomic(&self.dir.join("profile.json"), &serde_json::to_vec_pretty(&*p)?)?;
            }
        }
        drop(inner);
        self.touch();
        self.ssh_on_unlock().await;
        Ok(())
    }

    /// Vérifie le mot de passe principal (avec le fichier clé retenu) sans
    /// toucher au coffre ouvert.
    pub async fn check_password(&self, password: &str) -> AppResult<()> {
        let remembered = self.remembered_key_file().await;
        let keyfile = remembered.as_deref().map(keyfile::read_key_file).transpose()?;
        let data = std::fs::read(self.vault_path())?;
        Vault::open_with_key(&data, &MasterKey::new(password, keyfile), &self.limits)?;
        Ok(())
    }

    /// Verrouille, et retire de l'agent SSH les clés prévues pour.
    pub async fn lock(&self) {
        self.inner.lock().await.vault = None;
        self.ssh_on_lock().await;
    }

    // ---------- Synchronisation ----------

    /// Client connecté : réutilise la session, sinon le jeton de
    /// rafraîchissement du trousseau, sinon se reconnecte avec le mot de passe
    /// du coffre déverrouillé (sans 2FA : `TotpRequired` remonte à l'interface).
    async fn connected_client(&self, profile: &Profile, password: &str) -> AppResult<Arc<Client>> {
        {
            let inner = self.inner.lock().await;
            if let Some(c) = &inner.client
                && c.tokens().is_some()
            {
                return Ok(c.clone());
            }
        }
        let client = self.new_client(&profile.server_url)?;
        let mut ok = false;
        if let Some(refresh) = self.secrets.load(REFRESH_TOKEN_KEY) {
            client.set_tokens(Some(Tokens { access_token: String::new(), refresh_token: refresh }));
            ok = client.refresh().await.is_ok();
        }
        if !ok {
            client.login(&profile.username, password, None, &profile.device).await?;
        }
        self.save_tokens(&client)?;
        let client = Arc::new(client);
        self.inner.lock().await.client = Some(client.clone());
        Ok(client)
    }

    /// Reconnexion explicite avec un code 2FA (après `TotpRequired`).
    pub async fn relogin(&self, totp: &str) -> AppResult<()> {
        let (profile, password) = {
            let inner = self.inner.lock().await;
            let p = inner.profile.clone().ok_or(AppError::NotConfigured)?;
            let pw = Zeroizing::new(inner.vault.as_ref().ok_or(AppError::Locked)?.password().to_owned());
            (p, pw)
        };
        let client = self.new_client(&profile.server_url)?;
        client.login(&profile.username, &password, Some(totp), &profile.device).await?;
        self.save_tokens(&client)?;
        self.inner.lock().await.client = Some(Arc::new(client));
        Ok(())
    }

    /// Synchronise sans bloquer l'interface : on travaille sur une copie du
    /// coffre, puis on fusionne le résultat dans le coffre courant, ce qui
    /// préserve les modifications faites pendant la synchronisation.
    pub async fn sync(&self) -> AppResult<SyncOutcome> {
        match self.sync_once().await {
            // Session fermée par le serveur (révoquée depuis un autre
            // appareil, expirée) : une reconnexion, puis on réessaie.
            Err(AppError::Core(kittypass_core::Error::SessionExpired)) => self.sync_once().await,
            r => r,
        }
    }

    async fn sync_once(&self) -> AppResult<SyncOutcome> {
        let (profile, mut snapshot) = {
            let inner = self.inner.lock().await;
            let profile = inner.profile.clone().ok_or(AppError::NotConfigured)?;
            (profile, inner.vault.clone().ok_or(AppError::Locked)?)
        };
        let client = self.connected_client(&profile, snapshot.password()).await?;
        let result = sync(&mut snapshot, profile.last_seen, &self.limits, &client.remote(&profile.vault_id)?).await;
        // Les jetons ont pu tourner pendant la synchro, même en cas d'échec.
        self.save_tokens(&client)?;
        if matches!(result, Err(kittypass_core::Error::SessionExpired)) {
            self.inner.lock().await.client = None;
        }
        let report = result?;

        let mut inner = self.inner.lock().await;
        if let Some(v) = inner.vault.as_mut() {
            v.merge_from(&snapshot)?;
        }
        if let Some(p) = inner.profile.as_mut() {
            p.last_seen = p.last_seen.max(report.version);
        }
        self.persist(&inner)?;
        Ok(SyncOutcome { version: report.version, pulled: report.pulled, pushed: report.pushed })
    }
}
