//! Fichier clé du coffre : création, ajout, retrait, adoption sur un autre
//! appareil. Le fichier n'est jamais envoyé au serveur ; seul son chemin est
//! mémorisé dans `profile.json` (comme KeePassXC), et seulement si demandé.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use kittypass_core::{Error as CoreError, keyfile::KeyFile, sync::sync};
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult, SyncOutcome};

/// Lit un fichier clé. Seuls les fichiers ordinaires sont acceptés : un tube
/// nommé ou un périphérique pourrait bloquer la lecture indéfiniment.
pub(crate) fn read_key_file(path: &Path) -> AppResult<KeyFile> {
    let meta = std::fs::metadata(path).map_err(|_| CoreError::KeyFile("introuvable ou illisible"))?;
    if !meta.is_file() {
        return Err(CoreError::KeyFile("ce n'est pas un fichier").into());
    }
    let file = std::fs::File::open(path).map_err(|_| CoreError::KeyFile("introuvable ou illisible"))?;
    Ok(KeyFile::from_reader(file)?)
}

impl App {
    /// Crée un nouveau fichier clé aléatoire à `path`. Refuse d'écraser un
    /// fichier existant : ce pourrait être le fichier clé d'un autre coffre.
    pub fn generate_key_file(&self, path: &Path) -> AppResult<()> {
        let (_, xml) = KeyFile::generate()?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => AppError::Io("ce fichier existe déjà, choisissez un autre nom".into()),
            _ => AppError::from(e),
        })?;
        f.write_all(&xml)?;
        f.sync_all()?;
        Ok(())
    }

    /// Fichier clé mémorisé pour ce coffre, s'il y en a un.
    pub async fn remembered_key_file(&self) -> Option<PathBuf> {
        self.inner.lock().await.profile.as_ref().and_then(|p| p.key_file.clone())
    }

    /// Ajoute, remplace ou retire (`None`) le fichier clé, ou adopte celui
    /// qu'un autre appareil a ajouté. Le changement n'est enregistré qu'une
    /// fois la version re-chiffrée acceptée par le serveur : hors ligne, rien
    /// ne change (sinon les autres appareils et celui-ci divergeraient).
    pub async fn set_key_file(&self, password: &str, key_file: Option<&Path>, remember: bool) -> AppResult<SyncOutcome> {
        self.touch();
        let keyfile = key_file.map(read_key_file).transpose()?;
        let (profile, mut snapshot) = {
            let inner = self.inner.lock().await;
            let profile = inner.profile.clone().ok_or(AppError::NotConfigured)?;
            (profile, inner.vault.clone().ok_or(AppError::Locked)?)
        };
        snapshot.set_key_file(password, keyfile.clone())?;
        let client = self.connected_client(&profile, snapshot.password()).await?;
        let result = sync(&mut snapshot, profile.last_seen, &self.limits, &client.remote(&profile.vault_id)?).await;
        self.save_tokens(&client)?;
        let report = result?;

        let mut inner = self.inner.lock().await;
        // Verrouillé pendant l'opération : le serveur a la nouvelle clé, ce
        // coffre l'adoptera au prochain déverrouillage avec le fichier.
        let vault = inner.vault.as_mut().ok_or(AppError::Locked)?;
        vault.set_key_file(password, keyfile)?;
        vault.forget_previous_key();
        vault.merge_from(&snapshot)?;
        if let Some(p) = inner.profile.as_mut() {
            p.last_seen = p.last_seen.max(report.version);
            p.key_file = if remember { key_file.map(Path::to_path_buf) } else { None };
        }
        self.persist(&inner)?;
        Ok(SyncOutcome { version: report.version, pulled: report.pulled, pushed: report.pushed })
    }

    /// Mémorise ou oublie le chemin du fichier clé (sans changer la clé).
    pub(crate) fn remember_key_file(profile: &mut crate::Profile, key_file: Option<&Path>, remember: bool) {
        profile.key_file = if remember { key_file.map(Path::to_path_buf) } else { None };
    }
}

/// Mot de passe et chemin de fichier clé reçus de l'interface.
#[derive(serde::Deserialize)]
pub struct KeyFileChange {
    pub password: Zeroizing<String>,
    pub key_file: Option<PathBuf>,
    #[serde(default = "yes")]
    pub remember: bool,
}

fn yes() -> bool {
    true
}
