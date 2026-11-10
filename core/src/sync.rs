//! Algorithme de synchronisation, indépendant du transport.
//!
//! 1. Récupérer la version distante (fichier + numéro de version).
//! 2. Refuser si le numéro est plus petit que le dernier vu (retour en arrière
//!    imposé par un serveur compromis).
//! 3. Fusionner le distant dans le local.
//! 4. Si le local apporte quelque chose de nouveau, l'envoyer avec la version
//!    distante comme précondition ; en cas de conflit, recommencer.

use std::future::Future;

use crate::{
    Error, Result,
    header::OpenLimits,
    vault::{MasterKey, Vault},
};

const MAX_ATTEMPTS: usize = 5;

pub enum PushOutcome {
    Stored(i64),
    Conflict,
}

/// Accès à un coffre distant (HTTP en production, mémoire dans les tests).
pub trait Remote {
    /// Version courante et contenu (`None` si le coffre distant est vide).
    fn fetch(&self) -> impl Future<Output = Result<(i64, Option<Vec<u8>>)>> + Send;
    fn push(&self, expected: i64, data: Vec<u8>) -> impl Future<Output = Result<PushOutcome>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Version distante après synchronisation (à mémoriser comme « dernière vue »).
    pub version: i64,
    /// Nombre de changements reçus du serveur.
    pub pulled: usize,
    /// Vrai si une nouvelle version a été envoyée.
    pub pushed: bool,
}

/// Synchronise `local` avec le distant. `last_seen` est la dernière version
/// distante connue de cet appareil (0 au premier passage).
///
/// Le fichier distant est ouvert avec la clé du coffre local (mot de passe
/// et fichier clé) : si un autre appareil l'a changée, l'erreur
/// `InvalidKeyOrCorrupted` est renvoyée et l'application doit demander le
/// nouveau mot de passe.
pub async fn sync<R: Remote>(local: &mut Vault, last_seen: i64, limits: &OpenLimits, remote: &R) -> Result<SyncReport> {
    for _ in 0..MAX_ATTEMPTS {
        let (version, data) = remote.fetch().await?;
        if version < last_seen {
            return Err(Error::RollbackDetected);
        }
        let mut pulled = 0;
        let mut must_push = true;
        if let Some(bytes) = data {
            // Après un changement de clé sur cet appareil, la version distante
            // est encore chiffrée avec l'ancienne : on la lit avec celle-ci,
            // puis on la renvoie re-chiffrée.
            let (remote_vault, old_key) = match Vault::open_with_key(&bytes, local.master_key(), limits) {
                Ok(v) => (v, false),
                Err(Error::InvalidKeyOrCorrupted) => match local.previous_master_key() {
                    Some(previous) => (Vault::open_with_key(&bytes, previous, limits)?, true),
                    None => return Err(Error::InvalidKeyOrCorrupted),
                },
                Err(e) => return Err(e),
            };
            // Le distant a-t-il besoin de nos changements ? On fusionne le
            // local dans une copie du distant et on compte les changements.
            let mut probe = remote_vault.clone();
            must_push = probe.merge_from(local)? > 0 || old_key;
            pulled = local.merge_from(&remote_vault)?;
        }
        if !must_push {
            local.forget_previous_key();
            return Ok(SyncReport { version, pulled, pushed: false });
        }
        match remote.push(version, local.save()?).await? {
            PushOutcome::Stored(v) => {
                local.forget_previous_key();
                return Ok(SyncReport { version: v, pulled, pushed: true });
            }
            PushOutcome::Conflict => continue,
        }
    }
    Err(Error::SyncContention)
}

/// Récupère un coffre existant (nouvel appareil). `None` si le coffre distant
/// est encore vide. Renvoie aussi la version, à mémoriser comme « dernière vue ».
pub async fn download<R: Remote>(remote: &R, key: &MasterKey, limits: &OpenLimits) -> Result<Option<(Vault, i64)>> {
    match remote.fetch().await? {
        (version, Some(bytes)) => Ok(Some((Vault::open_with_key(&bytes, key, limits)?, version))),
        (_, None) => Ok(None),
    }
}
