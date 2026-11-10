//! Rapports de santé (mots de passe faibles, réutilisés, expirés) et
//! vérification Have I Been Pwned, tels que l'interface les voit.
//!
//! Aucun mot de passe ni empreinte complète dans les vues. La vérification
//! HIBP n'est jamais lancée automatiquement : elle envoie des préfixes SHA-1
//! de 5 caractères à un service tiers, l'interface doit le dire avant.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use kittypass_core::{
    hibp,
    vault::{self, Quality},
};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult, EntryListItem};

/// Requêtes HIBP simultanées au plus.
const HIBP_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityView {
    Bad,
    Poor,
    Weak,
    Good,
    Excellent,
}

impl From<Quality> for QualityView {
    fn from(q: Quality) -> Self {
        match q {
            Quality::Bad => Self::Bad,
            Quality::Poor => Self::Poor,
            Quality::Weak => Self::Weak,
            Quality::Good => Self::Good,
            Quality::Excellent => Self::Excellent,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StrengthView {
    pub bits: f64,
    pub quality: QualityView,
}

/// Mot de passe en cours de saisie, avec le contexte de l'entrée (un mot de
/// passe qui reprend le titre ou l'identifiant est pénalisé).
#[derive(Deserialize)]
pub struct StrengthInput {
    pub password: Zeroizing<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HealthItemView {
    pub entry: EntryListItem,
    pub bits: f64,
    pub quality: QualityView,
    pub reused: usize,
    pub expired: bool,
    pub excluded: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HealthView {
    pub items: Vec<HealthItemView>,
    pub checked: usize,
    pub excluded: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PwnedItemView {
    pub entry: EntryListItem,
    /// Nombre d'apparitions dans des fuites connues.
    pub count: u64,
    pub excluded: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PwnedView {
    /// Entrées compromises, de la plus fréquente à la moins fréquente.
    pub items: Vec<PwnedItemView>,
    /// Entrées vérifiées.
    pub checked: usize,
    /// Préfixes distincts demandés au service.
    pub queries: usize,
}

impl App {
    /// Robustesse d'un mot de passe saisi (jauge de l'éditeur).
    pub fn strength(&self, input: &StrengthInput) -> StrengthView {
        let s = vault::strength(&input.password, &[&input.title, &input.username, &input.url]);
        StrengthView { bits: s.bits, quality: s.quality.into() }
    }

    pub async fn health_report(&self) -> AppResult<HealthView> {
        self.read(|v| {
            let r = v.health_report();
            Ok(HealthView {
                items: r
                    .items
                    .into_iter()
                    .map(|i| HealthItemView {
                        entry: i.entry.into(),
                        bits: i.bits,
                        quality: i.quality.into(),
                        reused: i.reused,
                        expired: i.expired,
                        excluded: i.excluded,
                    })
                    .collect(),
                checked: r.checked,
                excluded: r.excluded,
            })
        })
        .await
    }

    pub async fn excluded_from_reports(&self, id: &str) -> AppResult<bool> {
        self.read(|v| Ok(v.excluded_from_reports(id)?)).await
    }

    pub async fn set_excluded_from_reports(&self, id: &str, excluded: bool) -> AppResult<()> {
        self.write(|v| Ok(v.set_excluded_from_reports(id, excluded)?)).await
    }

    /// Vérifie tous les mots de passe (hors corbeille) auprès de Have I Been
    /// Pwned. Le coffre n'est pas bloqué pendant les requêtes ; s'il est
    /// verrouillé entre-temps, rien n'est renvoyé.
    pub async fn hibp_check(&self) -> AppResult<PwnedView> {
        let hashes = self.read(|v| Ok(v.password_hashes())).await?;
        let client = Arc::new(hibp::Client::new(&self.hibp_url)?);

        // Un seul appel par préfixe, même pour plusieurs entrées.
        let mut by_prefix: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, h) in hashes.iter().enumerate() {
            by_prefix.entry(hibp::prefix(&h.sha1)?.to_owned()).or_default().push(i);
        }
        let queries = by_prefix.len();
        let mut pending = by_prefix.into_iter();
        let mut tasks = JoinSet::new();
        let mut counts: Vec<(usize, u64)> = Vec::new();
        loop {
            while tasks.len() < HIBP_CONCURRENCY {
                let Some((prefix, indices)) = pending.next() else { break };
                let client = client.clone();
                tasks.spawn(async move { (client.range(&prefix).await, indices) });
            }
            let Some(done) = tasks.join_next().await else { break };
            let (body, indices) = done.map_err(|_| AppError::Core(kittypass_core::Error::Network))?;
            let body = body?;
            for i in indices {
                let n = hibp::count_in_range(&body, &hashes[i].sha1)?;
                if n > 0 {
                    counts.push((i, n));
                }
            }
            self.touch();
        }

        let checked = hashes.len();
        self.read(|v| {
            let mut items: Vec<PwnedItemView> = counts
                .into_iter()
                // Entrée supprimée pendant la vérification : ignorée.
                .filter_map(|(i, count)| {
                    let entry = v.summary(&hashes[i].id).ok()?;
                    Some(PwnedItemView { entry: entry.into(), count, excluded: hashes[i].excluded })
                })
                .collect();
            items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.entry.title.to_lowercase().cmp(&b.entry.title.to_lowercase())));
            Ok(PwnedView { items, checked, queries })
        })
        .await
    }
}
