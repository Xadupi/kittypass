//! Pièces jointes des entrées.

use keepass::db::Value;
use zeroize::Zeroizing;

use super::{Vault, parse_id, validate_name};
use crate::{Error, Result};

/// Taille maximale d'une pièce jointe.
pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
/// Taille cumulée maximale des pièces jointes d'un coffre : le fichier doit
/// rester sous la limite d'ouverture (64 MiB par défaut) sur tous les appareils.
pub const MAX_TOTAL_ATTACHMENT_BYTES: usize = 40 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_ENTRY: usize = 100;

/// Pièce jointe listée (sans son contenu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub name: String,
    pub size: usize,
}

/// Nom de fichier acceptable : en plus des règles des noms affichés, pas de
/// séparateur de chemin ni de « . »/« .. », pour qu'enregistrer la pièce
/// jointe sur le disque ne puisse pas écrire ailleurs que prévu.
fn validate_file_name(name: &str) -> Result<()> {
    validate_name(name, "nom de pièce jointe invalide")?;
    if name.contains(['/', '\\']) || matches!(name.trim(), "." | "..") {
        return Err(Error::InvalidArgument("nom de pièce jointe invalide"));
    }
    Ok(())
}

impl Vault {
    /// Pièces jointes d'une entrée, triées par nom.
    pub fn attachments(&self, id: &str) -> Result<Vec<AttachmentInfo>> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        let mut v: Vec<_> = e
            .attachments_named()
            .map(|(name, a)| AttachmentInfo { name: name.to_owned(), size: a.data.get().len() })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    /// Contenu d'une pièce jointe.
    pub fn attachment(&self, id: &str, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        let a = e.attachment_by_name(name).ok_or(Error::AttachmentNotFound)?;
        Ok(Zeroizing::new(a.data.get().clone()))
    }

    /// Ajoute (ou remplace) une pièce jointe. L'ancienne version de l'entrée,
    /// avec ses pièces jointes, reste dans l'historique.
    pub fn add_attachment(&mut self, id: &str, name: &str, data: &[u8]) -> Result<()> {
        validate_file_name(name)?;
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(Error::TooLarge);
        }
        let eid = parse_id(id)?;
        let e = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        let replacing = e.attachment_by_name(name).is_some();
        if !replacing && e.attachments().count() >= MAX_ATTACHMENTS_PER_ENTRY {
            return Err(Error::InvalidArgument("trop de pièces jointes"));
        }
        // Les anciennes données restent (historique) : on les compte toujours.
        let total: usize = self.db.iter_all_attachments().map(|a| a.data.get().len()).sum();
        if total.saturating_add(data.len()) > MAX_TOTAL_ATTACHMENT_BYTES {
            return Err(Error::TooLarge);
        }
        self.edit_entry(eid, |t| {
            t.add_attachment(name, Value::protected(data.to_vec()));
        })
    }

    /// Retire une pièce jointe de l'entrée (elle reste dans l'historique).
    pub fn remove_attachment(&mut self, id: &str, name: &str) -> Result<()> {
        let eid = parse_id(id)?;
        let e = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        if e.attachment_by_name(name).is_none() {
            return Err(Error::AttachmentNotFound);
        }
        self.edit_entry(eid, |t| {
            t.remove_attachment_by_name(name);
        })
    }
}
