//! Stockage local : écritures atomiques, permissions privées, secrets.

use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    sync::Mutex,
};

use crate::AppResult;

/// Stockage des secrets longue durée (jeton de rafraîchissement) : trousseau
/// du système en production (Secret Service, Windows Credential Manager,
/// Android Keystore), mémoire dans les tests.
pub trait SecretStore: Send + Sync {
    fn load(&self, key: &str) -> Option<String>;
    fn save(&self, key: &str, value: &str) -> AppResult<()>;
    fn delete(&self, key: &str) -> AppResult<()>;
}

#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, String>>);

impl SecretStore for MemoryStore {
    fn load(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(key).cloned()
    }
    fn save(&self, key: &str, value: &str) -> AppResult<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> AppResult<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
        Ok(())
    }
}

pub fn ensure_private_dir(dir: &Path) -> AppResult<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> AppResult<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Écrit `data` sans jamais laisser de fichier à moitié écrit : fichier
/// temporaire (0600) + fsync + renommage. L'ancienne version est gardée en
/// `.bak` (une coupure de courant au pire mauvais moment ne perd rien).
pub fn write_atomic(path: &Path, data: &[u8]) -> AppResult<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    if path.exists() {
        std::fs::copy(path, path.with_extension("bak"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path.with_extension("bak"), std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
