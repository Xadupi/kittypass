//! Agent SSH, comme KeePassXC : les clés des entrées sont ajoutées à l'agent
//! SSH du système (`SSH_AUTH_SOCK`) au déverrouillage et retirées au
//! verrouillage. KittyPass ne garde que les clés publiques de ce qu'il a
//! ajouté, pour savoir quoi retirer.
//!
//! Avant d'envoyer une clé, KittyPass vérifie que l'agent tourne sous le même
//! utilisateur : un socket d'un autre compte ne reçoit rien.

use std::path::PathBuf;

use kittypass_core::{
    ssh::{self, AgentSettings, KeyInfo, MAX_KEY_BYTES},
    vault::KeySource,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult};

const SETTINGS_FILE: &str = "ssh.json";

fn err(m: impl Into<String>) -> AppError {
    AppError::Core(kittypass_core::Error::Ssh(m.into()))
}

/// Réglages de l'agent SSH sur cet appareil.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshConfig {
    /// Désactivé par défaut, comme dans KeePassXC.
    pub enabled: bool,
    /// Socket de l'agent à la place de `SSH_AUTH_SOCK`.
    pub socket: Option<PathBuf>,
}

impl SshConfig {
    fn checked(mut self) -> AppResult<Self> {
        self.socket = self.socket.filter(|p| !p.as_os_str().is_empty());
        if self.socket.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err(err("le chemin de l'agent doit être absolu"));
        }
        Ok(self)
    }
}

/// Clé ajoutée par KittyPass pendant cette session.
#[derive(Debug, Clone)]
struct Added {
    entry: String,
    blob: Vec<u8>,
    remove_at_close: bool,
}

#[derive(Default)]
pub(crate) struct SshState {
    added: Vec<Added>,
    /// Problèmes du dernier déverrouillage (« Titre : message »).
    errors: Vec<String>,
}

/// Clé présente dans l'agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentKeyView {
    pub fingerprint: String,
    pub comment: String,
    /// Entrée qui l'a fournie, si c'est KittyPass.
    pub entry: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshStatus {
    pub config: SshConfig,
    /// Socket utilisé (réglage, sinon `SSH_AUTH_SOCK`).
    pub socket: Option<String>,
    /// Joignable et du même utilisateur.
    pub available: bool,
    pub error: Option<String>,
    pub keys: Vec<AgentKeyView>,
    /// Clés non ajoutées au dernier déverrouillage.
    pub unlock_errors: Vec<String>,
}

/// Réglages SSH d'une entrée, avec la description de sa clé.
#[derive(Debug, Clone, Serialize)]
pub struct EntrySshView {
    pub settings: AgentSettings,
    pub key: Option<KeyInfo>,
    pub key_error: Option<String>,
    pub in_agent: bool,
}

/// Chemin d'un fichier de clé : absolu, ou relatif au dossier personnel
/// avec `~/`. Les variables d'environnement ne sont pas développées.
fn resolve_file(name: &str) -> AppResult<PathBuf> {
    let name = name.trim();
    let path = match name.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| err("dossier personnel inconnu"))?.join(rest),
        None => PathBuf::from(name),
    };
    if !path.is_absolute() {
        return Err(err("le chemin du fichier de clé doit être absolu (ou commencer par ~/)"));
    }
    Ok(path)
}

fn read_key_file(name: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let path = resolve_file(name)?;
    let file = std::fs::File::open(&path).map_err(|_| err("fichier de clé illisible"))?;
    if !file.metadata().map_err(|_| err("fichier de clé illisible"))?.is_file() {
        return Err(err("le chemin de la clé n'est pas un fichier"));
    }
    let mut data = Zeroizing::new(Vec::with_capacity(16 * 1024));
    file.take(MAX_KEY_BYTES as u64 + 1).read_to_end(&mut data).map_err(|_| err("fichier de clé illisible"))?;
    if data.len() > MAX_KEY_BYTES {
        return Err(err("fichier de clé trop gros"));
    }
    Ok(data)
}

fn key_data(source: &KeySource) -> AppResult<Zeroizing<Vec<u8>>> {
    match source {
        KeySource::Attachment(d) => Ok(d.clone()),
        KeySource::File(name) => read_key_file(name),
    }
}

#[cfg(unix)]
mod client {
    use std::{path::Path, time::Duration};

    use kittypass_core::ssh::agent;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    use super::err;
    use crate::AppResult;

    const TIMEOUT: Duration = Duration::from_secs(5);

    pub struct Agent(UnixStream);

    impl Agent {
        /// Se connecte et vérifie que l'agent tourne sous notre utilisateur.
        pub async fn connect(path: &Path) -> AppResult<Self> {
            let stream = tokio::time::timeout(TIMEOUT, UnixStream::connect(path))
                .await
                .map_err(|_| err("l'agent SSH ne répond pas"))?
                .map_err(|_| err("agent SSH injoignable"))?;
            let uid = kittypass_core::browser::transport::current_uid().map_err(|_| err("utilisateur inconnu"))?;
            if !stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
                return Err(err("l'agent SSH appartient à un autre utilisateur : rien n'est envoyé"));
            }
            Ok(Self(stream))
        }

        /// Envoie une requête et lit la réponse (corps, sans la longueur).
        pub async fn call(&mut self, msg: &[u8]) -> AppResult<Vec<u8>> {
            let io = async {
                self.0.write_all(msg).await?;
                let mut header = [0u8; 4];
                self.0.read_exact(&mut header).await?;
                let n = agent::reply_len(header).map_err(|_| std::io::Error::other("réponse"))?;
                let mut body = vec![0u8; n];
                self.0.read_exact(&mut body).await?;
                Ok::<_, std::io::Error>(body)
            };
            tokio::time::timeout(TIMEOUT, io)
                .await
                .map_err(|_| err("l'agent SSH ne répond pas"))?
                .map_err(|_| err("réponse de l'agent SSH invalide"))
        }
    }
}

#[cfg(windows)]
mod client {
    use std::{os::windows::io::AsRawHandle, path::Path, time::Duration};

    use kittypass_core::{ssh::agent, winsec};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    };

    use super::err;
    use crate::AppResult;

    const TIMEOUT: Duration = Duration::from_secs(5);
    /// ERROR_PIPE_BUSY : toutes les instances sont occupées, on réessaie.
    const PIPE_BUSY: i32 = 231;

    pub struct Agent(NamedPipeClient);

    impl Agent {
        /// Se connecte au pipe de l'agent (OpenSSH pour Windows :
        /// `\\.\pipe\openssh-ssh-agent`, service sous le compte système ;
        /// ou un agent lancé par l'utilisateur) et vérifie son propriétaire.
        pub async fn connect(path: &Path) -> AppResult<Self> {
            let open = async {
                loop {
                    match ClientOptions::new().open(path) {
                        Ok(c) => return Ok(c),
                        Err(e) if e.raw_os_error() == Some(PIPE_BUSY) => tokio::time::sleep(Duration::from_millis(50)).await,
                        Err(e) => return Err(e),
                    }
                }
            };
            let pipe = tokio::time::timeout(TIMEOUT, open)
                .await
                .map_err(|_| err("l'agent SSH ne répond pas"))?
                .map_err(|_| err("agent SSH injoignable (service « OpenSSH Authentication Agent » démarré ?)"))?;
            let me = winsec::current_user_sid().map_err(|_| err("utilisateur inconnu"))?;
            let owner = winsec::pipe_server_sid(pipe.as_raw_handle()).map_err(|_| err("propriétaire de l'agent SSH inconnu"))?;
            if owner != me && owner != winsec::LOCAL_SYSTEM {
                return Err(err("l'agent SSH appartient à un autre utilisateur : rien n'est envoyé"));
            }
            Ok(Self(pipe))
        }

        /// Envoie une requête et lit la réponse (corps, sans la longueur).
        pub async fn call(&mut self, msg: &[u8]) -> AppResult<Vec<u8>> {
            let io = async {
                self.0.write_all(msg).await?;
                let mut header = [0u8; 4];
                self.0.read_exact(&mut header).await?;
                let n = agent::reply_len(header).map_err(|_| std::io::Error::other("réponse"))?;
                let mut body = vec![0u8; n];
                self.0.read_exact(&mut body).await?;
                Ok::<_, std::io::Error>(body)
            };
            tokio::time::timeout(TIMEOUT, io)
                .await
                .map_err(|_| err("l'agent SSH ne répond pas"))?
                .map_err(|_| err("réponse de l'agent SSH invalide"))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod client {
    use std::path::Path;

    use super::err;
    use crate::AppResult;

    pub struct Agent;

    impl Agent {
        pub async fn connect(_: &Path) -> AppResult<Self> {
            Err(err("agent SSH pas pris en charge sur ce système"))
        }
        pub async fn call(&mut self, _: &[u8]) -> AppResult<Vec<u8>> {
            Err(err("agent SSH pas pris en charge sur ce système"))
        }
    }
}

use client::Agent;
use kittypass_core::ssh::agent;

impl App {
    pub fn ssh_config(&self) -> SshConfig {
        crate::storage::read_json::<SshConfig>(&self.dir.join(SETTINGS_FILE))
            .ok()
            .flatten()
            .and_then(|c| c.checked().ok())
            .unwrap_or_default()
    }

    /// Enregistre les réglages. Désactiver retire les clés ajoutées.
    pub async fn save_ssh_config(&self, c: SshConfig) -> AppResult<SshStatus> {
        let c = c.checked()?;
        let before = self.ssh_config();
        if before.enabled && (!c.enabled || before.socket != c.socket) {
            self.ssh_remove_added(|_| true).await;
        }
        crate::storage::write_atomic(&self.dir.join(SETTINGS_FILE), &serde_json::to_vec_pretty(&c)?)?;
        if c.enabled && !before.enabled && self.status().await.unlocked {
            self.ssh_on_unlock().await;
        }
        Ok(self.ssh_status().await)
    }

    fn ssh_socket(cfg: &SshConfig) -> Option<PathBuf> {
        cfg.socket
            .clone()
            .or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
            .or_else(|| cfg!(windows).then(|| PathBuf::from(r"\\.\pipe\openssh-ssh-agent")))
            .filter(|p| p.is_absolute())
    }

    async fn ssh_agent(&self) -> AppResult<Agent> {
        let cfg = self.ssh_config();
        if !cfg.enabled {
            return Err(err("l'agent SSH est désactivé dans les paramètres"));
        }
        let path = Self::ssh_socket(&cfg).ok_or_else(|| err("aucun agent SSH (SSH_AUTH_SOCK absent)"))?;
        Agent::connect(&path).await
    }

    pub async fn ssh_status(&self) -> SshStatus {
        let config = self.ssh_config();
        let socket = Self::ssh_socket(&config).map(|p| p.display().to_string());
        let state = self.ssh.lock().await;
        let (added, unlock_errors) = (state.added.clone(), state.errors.clone());
        drop(state);
        let mut status = SshStatus { config, socket, available: false, error: None, keys: Vec::new(), unlock_errors };
        if !status.config.enabled {
            return status;
        }
        let listed = async {
            let mut a = self.ssh_agent().await?;
            let body = a.call(&agent::request_identities()).await?;
            Ok::<_, AppError>(agent::parse_identities(&body)?)
        };
        match listed.await {
            Ok(ids) => {
                status.available = true;
                status.keys = ids
                    .into_iter()
                    .map(|(blob, comment)| AgentKeyView {
                        fingerprint: ssh::fingerprint(&blob),
                        comment,
                        entry: added.iter().find(|a| a.blob == blob).map(|a| a.entry.clone()),
                    })
                    .collect();
            }
            Err(e) => status.error = Some(e.to_string()),
        }
        status
    }

    pub async fn entry_ssh(&self, id: &str) -> AppResult<EntrySshView> {
        let (settings, source) = self
            .read(|v| {
                let settings = v.entry_ssh(id)?;
                // La clé est décrite même si l'agent n'est pas encore autorisé.
                let probe = AgentSettings { allow: true, ..settings.clone() };
                let source = match (settings.use_attachment, settings.attachment_name.is_empty(), settings.file_name.trim().is_empty()) {
                    (true, false, _) => v.attachment(id, &probe.attachment_name).ok().map(KeySource::Attachment),
                    (false, _, false) => Some(KeySource::File(probe.file_name.clone())),
                    _ => None,
                };
                Ok((settings, source))
            })
            .await?;
        let (key, key_error) = match source.map(|s| key_data(&s).and_then(|d| Ok(ssh::key_info(&d)?))) {
            None => (None, None),
            Some(Ok(k)) => (Some(k), None),
            Some(Err(e)) => (None, Some(e.to_string())),
        };
        let in_agent = self.ssh.lock().await.added.iter().any(|a| a.entry == id);
        Ok(EntrySshView { settings, key, key_error, in_agent })
    }

    pub async fn set_entry_ssh(&self, id: &str, settings: &AgentSettings) -> AppResult<()> {
        self.write(|v| Ok(v.set_entry_ssh(id, settings)?)).await
    }

    /// Ajoute la clé d'une entrée à l'agent (remplace une version déjà
    /// ajoutée, par exemple pour changer ses contraintes).
    pub async fn ssh_add(&self, id: &str) -> AppResult<()> {
        let key = self.read(|v| Ok(v.ssh_key(id)?)).await?;
        let data = key_data(&key.source)?;
        let loaded = ssh::load_key(&data, &key.password, &key.title)?;
        drop(data);
        let mut a = self.ssh_agent().await?;
        let body = a.call(&agent::add(&loaded, key.settings.confirm, key.settings.lifetime())).await?;
        if !agent::parse_status(&body)? {
            return Err(err("l'agent SSH a refusé la clé (confirmation demandée sans ssh-askpass ?)"));
        }
        let mut state = self.ssh.lock().await;
        state.added.retain(|x| x.entry != id && x.blob != loaded.public_blob);
        state.added.push(Added { entry: id.to_owned(), blob: loaded.public_blob.clone(), remove_at_close: key.settings.remove_at_close });
        Ok(())
    }

    /// Retire la clé d'une entrée de l'agent.
    pub async fn ssh_remove(&self, id: &str) -> AppResult<()> {
        let blob = {
            let state = self.ssh.lock().await;
            state.added.iter().find(|a| a.entry == id).map(|a| a.blob.clone())
        };
        let blob = match blob {
            Some(b) => b,
            // Ajoutée avant (autre session, ssh-add) : on retrouve sa clé publique.
            None => {
                let key = self.read(|v| Ok(v.ssh_key(id)?)).await?;
                let data = key_data(&key.source)?;
                kittypass_core::ssh::public_blob(&data)?
            }
        };
        let mut a = self.ssh_agent().await?;
        let ok = agent::parse_status(&a.call(&agent::remove(&blob)).await?)?;
        self.ssh.lock().await.added.retain(|x| x.blob != blob);
        if !ok {
            return Err(err("cette clé n'est pas dans l'agent"));
        }
        Ok(())
    }

    /// Au déverrouillage : ajoute les clés marquées « ajouter à l'ouverture ».
    /// Les échecs sont gardés pour l'interface, sans bloquer le déverrouillage.
    pub(crate) async fn ssh_on_unlock(&self) {
        let mut errors = Vec::new();
        if self.ssh_config().enabled {
            let entries = self.read(|v| Ok(v.ssh_entries())).await.unwrap_or_default();
            for e in entries.into_iter().filter(|e| e.settings.add_at_open) {
                if let Err(x) = self.ssh_add(&e.id).await {
                    errors.push(format!("{} : {x}", e.title));
                }
            }
        }
        self.ssh.lock().await.errors = errors;
    }

    /// Au verrouillage : retire les clés marquées « retirer à la fermeture ».
    pub(crate) async fn ssh_on_lock(&self) {
        self.ssh_remove_added(|a| a.remove_at_close).await;
    }

    async fn ssh_remove_added(&self, which: impl Fn(&Added) -> bool) {
        let targets: Vec<Added> = {
            let mut state = self.ssh.lock().await;
            state.errors.clear();
            let (go, keep): (Vec<_>, Vec<_>) = state.added.drain(..).partition(|a| which(a));
            state.added = keep;
            go
        };
        if targets.is_empty() {
            return;
        }
        // Agent injoignable : les clés y restent (rien à faire de plus ici),
        // leur éventuelle durée de vie s'applique.
        if let Ok(mut a) = self.ssh_agent_any().await {
            for t in targets {
                let _ = a.call(&agent::remove(&t.blob)).await;
            }
        }
    }

    /// Agent pour retirer des clés, même si le réglage vient d'être désactivé.
    async fn ssh_agent_any(&self) -> AppResult<Agent> {
        let cfg = self.ssh_config();
        let path = Self::ssh_socket(&cfg).ok_or_else(|| err("aucun agent SSH"))?;
        Agent::connect(&path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_checks() {
        let c = SshConfig { enabled: true, socket: Some(PathBuf::new()) }.checked().unwrap();
        assert_eq!(c.socket, None);
        assert!(SshConfig { enabled: true, socket: Some("relatif/agent".into()) }.checked().is_err());
    }

    #[test]
    fn key_paths() {
        assert!(resolve_file("id_ed25519").is_err());
        assert!(resolve_file("../x").is_err());
        assert_eq!(resolve_file("/etc/x").unwrap(), PathBuf::from("/etc/x"));
        if let Some(home) = std::env::var_os("HOME") {
            assert_eq!(resolve_file("~/.ssh/id").unwrap(), PathBuf::from(home).join(".ssh/id"));
        }
        assert!(read_key_file("/").is_err(), "un dossier n'est pas une clé");
    }
}
