//! Historique des entrées : consultation, restauration, élagage.

use keepass::db::{Entry, EntryId, History};

use super::{EntryData, Vault, entry_data, parse_id};
use crate::{Error, Result};

/// Limites par défaut de KeePass : 10 versions, 6 MiB par entrée.
pub(super) const DEFAULT_MAX_ITEMS: usize = 10;
pub(super) const DEFAULT_MAX_BYTES: usize = 6 * 1024 * 1024;
/// Plafonds appliqués même si le fichier demande « illimité » (-1) : un
/// historique sans fin finirait par dépasser la limite d'ouverture du coffre.
const HARD_MAX_ITEMS: usize = 100;
const HARD_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Version passée d'une entrée, pour la liste d'historique (sans secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryItem {
    /// Position dans l'historique : 0 = version la plus récente.
    pub index: usize,
    /// Date de modification (secondes Unix, UTC).
    pub modified: Option<i64>,
    pub title: String,
    pub username: String,
    pub url: String,
}

impl Vault {
    /// Versions passées d'une entrée, de la plus récente à la plus ancienne.
    pub fn history(&self, id: &str) -> Result<Vec<HistoryItem>> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(versions(&e)
            .iter()
            .enumerate()
            .map(|(index, v)| HistoryItem {
                index,
                modified: v.times.last_modification.map(|t| t.and_utc().timestamp()),
                title: v.get_title().unwrap_or_default().to_owned(),
                username: v.get_username().unwrap_or_default().to_owned(),
                url: v.get_url().unwrap_or_default().to_owned(),
            })
            .collect())
    }

    /// Nombre de versions passées d'une entrée.
    pub fn history_len(&self, id: &str) -> Result<usize> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(versions(&e).len())
    }

    /// Contenu complet d'une version passée.
    pub fn history_entry(&self, id: &str, index: usize) -> Result<EntryData> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        let v = versions(&e).get(index).ok_or(Error::InvalidArgument("version inconnue"))?;
        Ok(entry_data(v))
    }

    /// Revient à une version passée. La version actuelle n'est pas perdue :
    /// elle part à son tour dans l'historique.
    pub fn restore_history(&mut self, id: &str, index: usize) -> Result<()> {
        let eid = parse_id(id)?;
        let e = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        let v = versions(&e).get(index).ok_or(Error::InvalidArgument("version inconnue"))?.clone();
        self.edit_entry(eid, |t| {
            t.fields = v.fields.clone();
            t.tags = v.tags.clone();
            t.custom_data = v.custom_data.clone();
            t.override_url = v.override_url.clone();
            t.foreground_color = v.foreground_color.clone();
            t.background_color = v.background_color.clone();
            t.times.expires = v.times.expires;
            t.times.expiry = v.times.expiry;
            t.restore_attachments_from_history(index);
        })
    }

    /// Ramène l'historique d'une entrée sous les limites du coffre, en
    /// supprimant les versions les plus anciennes.
    pub(super) fn trim_history(&mut self, id: EntryId) {
        let max_items = limit(self.db.meta.history_max_items, DEFAULT_MAX_ITEMS, HARD_MAX_ITEMS);
        let max_bytes = limit(self.db.meta.history_max_size, DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
        let Some(e) = self.db.entry(id) else { return };
        let all = versions(&e);
        let mut keep = 0;
        let mut total = 0usize;
        for (i, v) in all.iter().enumerate() {
            let size = v.fields.iter().map(|(k, val)| k.len() + val.get().len()).sum::<usize>()
                + e.historical(i)
                    .map_or(0, |h| h.attachments().map(|a| a.data.get().len()).sum::<usize>());
            total = total.saturating_add(size);
            if keep >= max_items || total > max_bytes {
                break;
            }
            keep += 1;
        }
        if keep == all.len() {
            return;
        }
        let kept: Vec<Entry> = all[..keep].to_vec();
        let mut history = History::default();
        // `add_entry` insère en tête : on repart de la plus ancienne.
        for v in kept.into_iter().rev() {
            history.add_entry(v);
        }
        if let Some(mut e) = self.db.entry_mut(id) {
            e.history = Some(history);
        }
    }
}

fn versions(e: &Entry) -> &[Entry] {
    e.history.as_ref().map_or(&[], |h| h.get_entries().as_slice())
}

/// Limite KeePass : absente → défaut, négative (« illimité ») ou trop grande
/// → plafond.
fn limit(value: Option<isize>, default: usize, hard: usize) -> usize {
    match value {
        None => default,
        Some(v) if v < 0 => hard,
        Some(v) => (v as usize).min(hard),
    }
}
