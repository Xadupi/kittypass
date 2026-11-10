//! Import d'un autre coffre KeePass/KeePassXC : groupes, entrées, champs,
//! étiquettes, expiration, pièces jointes et exclusion des rapports. Pas
//! l'historique (copie, pas fusion : les entrées reçoivent de nouveaux
//! identifiants). La corbeille du coffre source est ignorée.

use super::{Imported, ImportedEntry};
use crate::{
    Result,
    vault::{GroupNode, Vault},
};

pub fn from_vault(source: &Vault) -> Result<Imported> {
    let mut out = Imported::default();
    walk(source, &source.groups(), &mut Vec::new(), &mut out)?;
    Ok(out)
}

fn walk(source: &Vault, node: &GroupNode, path: &mut Vec<String>, out: &mut Imported) -> Result<()> {
    for s in source.entries_in(&node.id)? {
        let data = source.get(&s.id)?;
        let mut attachments = Vec::new();
        for a in source.attachments(&s.id)? {
            attachments.push((a.name.clone(), source.attachment(&s.id, &a.name)?));
        }
        let excluded_from_reports = source.excluded_from_reports(&s.id)?;
        out.push(ImportedEntry { path: path.clone(), data, attachments, excluded_from_reports })?;
    }
    for child in node.children.iter().filter(|c| !c.is_recycle_bin) {
        path.push(child.name.clone());
        walk(source, child, path, out)?;
        path.pop();
    }
    Ok(())
}
