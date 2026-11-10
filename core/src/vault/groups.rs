//! Groupes (arborescence KeePass) et corbeille.

use keepass::{
    Database,
    db::{GroupId, Icon, Times},
};

use super::{EntrySummary, Vault, next_modification, parse_group_id, parse_id, summary, validate_name};
use crate::{Error, Result};

/// Nom de la corbeille créée par KittyPass.
pub const RECYCLE_BIN_NAME: &str = "Corbeille";
/// Icône KeePass standard « corbeille ».
const RECYCLE_BIN_ICON: usize = 43;
/// Icône KeePass standard « dossier ».
const FOLDER_ICON: usize = 48;
/// Profondeur maximale de l'arborescence. Au-delà d'une centaine de niveaux,
/// la bibliothèque KeePass ne relit plus le fichier qu'elle a écrit : un
/// coffre trop imbriqué serait perdu. Borne aussi l'affichage d'un fichier
/// piégé aux groupes imbriqués sur des milliers de niveaux.
pub const MAX_DEPTH: usize = 64;

/// Nœud de l'arborescence des groupes, pour l'affichage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupNode {
    pub id: String,
    pub name: String,
    /// Icône KeePass standard (index), si le groupe en a une.
    pub icon: Option<usize>,
    /// Entrées directement dans ce groupe.
    pub entry_count: usize,
    pub is_recycle_bin: bool,
    pub children: Vec<GroupNode>,
}

impl Vault {
    /// Identifiant du groupe racine.
    pub fn root_id(&self) -> String {
        self.db.root().id().uuid().to_string()
    }

    /// Identifiant de la corbeille, si elle existe.
    pub fn recycle_bin(&self) -> Option<String> {
        self.existing_recycle_bin().map(|g| g.uuid().to_string())
    }

    pub(super) fn existing_recycle_bin(&self) -> Option<GroupId> {
        self.db.recycle_bin().map(|g| g.id())
    }

    /// Corbeille, créée au besoin à la racine.
    pub(super) fn recycle_bin_id(&mut self) -> GroupId {
        if let Some(id) = self.existing_recycle_bin() {
            return id;
        }
        let mut root = self.db.root_mut();
        let mut bin = root.add_group();
        bin.name = RECYCLE_BIN_NAME.into();
        bin.set_icon_builtin(RECYCLE_BIN_ICON);
        // Comme KeePassXC : ni saisie automatique ni recherche dans la corbeille.
        bin.enable_autotype = Some(false);
        bin.enable_searching = Some(false);
        let id = bin.id();
        self.db.meta.recyclebin_enabled = Some(true);
        self.db.meta.recyclebin_uuid = Some(id.uuid());
        self.db.meta.recyclebin_changed = Some(Times::now());
        id
    }

    /// Vrai si `group` est `ancestor` ou l'un de ses descendants.
    pub(super) fn group_is_within(&self, group: GroupId, ancestor: GroupId) -> bool {
        let mut current = Some(group);
        // Borné : une boucle parent dans un fichier corrompu ne doit pas
        // bloquer l'application.
        for _ in 0..=self.db.num_groups() {
            match current {
                Some(g) if g == ancestor => return true,
                Some(g) => current = self.db.group(g).and_then(|g| g.parent().map(|p| p.id())),
                None => return false,
            }
        }
        false
    }

    /// Profondeur d'un groupe (racine = 0).
    fn depth(&self, group: GroupId) -> usize {
        let mut depth = 0;
        let mut current = self.db.group(group).and_then(|g| g.parent().map(|p| p.id()));
        while let Some(g) = current {
            depth += 1;
            if depth > self.db.num_groups() {
                break;
            }
            current = self.db.group(g).and_then(|g| g.parent().map(|p| p.id()));
        }
        depth
    }

    /// Hauteur du sous-arbre sous `group` (groupe sans enfant = 0).
    fn height(&self, group: GroupId, budget: usize) -> usize {
        if budget == 0 {
            return 0;
        }
        self.db
            .group(group)
            .map(|g| g.group_ids().map(|c| 1 + self.height(c, budget - 1)).max().unwrap_or(0))
            .unwrap_or(0)
    }

    fn in_recycle_bin(&self, group: GroupId) -> bool {
        self.existing_recycle_bin().is_some_and(|bin| self.group_is_within(group, bin))
    }

    fn recycle_bin_enabled(&self) -> bool {
        self.db.meta.recyclebin_enabled != Some(false)
    }

    /// Arborescence complète des groupes, sous-groupes triés par nom
    /// (corbeille en dernier, comme KeePassXC).
    pub fn groups(&self) -> GroupNode {
        let bin = self.existing_recycle_bin();
        self.node(self.db.root().id(), bin, 0)
    }

    fn node(&self, id: GroupId, bin: Option<GroupId>, depth: usize) -> GroupNode {
        #[allow(clippy::expect_used)] // id vient de l'arborescence elle-même
        let g = self.db.group(id).expect("groupe de l'arborescence");
        let mut children: Vec<GroupNode> = if depth < MAX_DEPTH {
            g.groups().map(|c| self.node(c.id(), bin, depth + 1)).collect()
        } else {
            Vec::new()
        };
        children.sort_by_key(|c| (c.is_recycle_bin, c.name.to_lowercase()));
        GroupNode {
            id: id.uuid().to_string(),
            name: g.name.clone(),
            icon: match g.icon() {
                Some(Icon::BuiltIn(i)) => Some(*i),
                _ => None,
            },
            entry_count: g.entry_ids().count(),
            is_recycle_bin: Some(id) == bin,
            children,
        }
    }

    /// Résumé d'une entrée (groupe, étiquettes, expiration…).
    pub fn summary(&self, id: &str) -> Result<EntrySummary> {
        Ok(summary(&self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?))
    }

    /// Vrai si l'entrée est dans la corbeille (ou l'un de ses sous-groupes).
    pub fn entry_in_recycle_bin(&self, id: &str) -> Result<bool> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(self.in_recycle_bin(e.parent().id()))
    }

    /// Entrées directement dans un groupe, triées par titre.
    pub fn entries_in(&self, group_id: &str) -> Result<Vec<EntrySummary>> {
        let g = self.db.group(parse_group_id(group_id)?).ok_or(Error::GroupNotFound)?;
        let mut v: Vec<_> = g.entries().map(|e| summary(&e)).collect();
        v.sort_by_key(|a| a.title.to_lowercase());
        Ok(v)
    }

    pub fn add_group(&mut self, parent_id: &str, name: &str) -> Result<String> {
        validate_name(name, "nom de groupe invalide")?;
        let pid = parse_group_id(parent_id)?;
        if self.db.group(pid).is_none() {
            return Err(Error::GroupNotFound);
        }
        if self.depth(pid) + 1 > MAX_DEPTH {
            return Err(Error::InvalidArgument("arborescence trop profonde"));
        }
        let mut parent = self.db.group_mut(pid).ok_or(Error::GroupNotFound)?;
        let mut g = parent.add_group();
        g.name = name.to_owned();
        g.set_icon_builtin(FOLDER_ICON);
        Ok(g.id().uuid().to_string())
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<()> {
        validate_name(name, "nom de groupe invalide")?;
        let mut g = self.db.group_mut(parse_group_id(id)?).ok_or(Error::GroupNotFound)?;
        g.name = name.to_owned();
        g.times.last_modification = Some(next_modification(g.times.last_modification));
        Ok(())
    }

    /// Déplace un groupe (et tout son contenu) sous `parent_id`.
    pub fn move_group(&mut self, id: &str, parent_id: &str) -> Result<()> {
        let gid = parse_group_id(id)?;
        let pid = parse_group_id(parent_id)?;
        if self.db.group(pid).is_none() || self.db.group(gid).is_none() {
            return Err(Error::GroupNotFound);
        }
        if self.depth(pid) + 1 + self.height(gid, MAX_DEPTH + 1) > MAX_DEPTH {
            return Err(Error::InvalidArgument("arborescence trop profonde"));
        }
        let mut g = self.db.group_mut(gid).ok_or(Error::GroupNotFound)?;
        g.move_to(pid).map_err(|_| Error::InvalidArgument("déplacement de groupe impossible"))?;
        g.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Supprime un groupe : il part dans la corbeille, ou est supprimé
    /// définitivement s'il y est déjà (ou si la corbeille est désactivée).
    pub fn delete_group(&mut self, id: &str) -> Result<()> {
        let gid = parse_group_id(id)?;
        if self.db.group(gid).is_none() {
            return Err(Error::GroupNotFound);
        }
        if gid == self.db.root().id() {
            return Err(Error::InvalidArgument("impossible de supprimer la racine"));
        }
        if self.in_recycle_bin(gid) || !self.recycle_bin_enabled() {
            return self.remove_group_permanently(gid);
        }
        let bin = self.recycle_bin_id();
        if self.group_is_within(bin, gid) {
            return Err(Error::InvalidArgument("le groupe contient la corbeille"));
        }
        self.move_group(id, &bin.uuid().to_string())
    }

    fn remove_group_permanently(&mut self, gid: GroupId) -> Result<()> {
        let bin = self.existing_recycle_bin();
        let removes_bin = bin.is_some_and(|bin| self.group_is_within(bin, gid));
        let mut g = self.db.group_mut(gid).ok_or(Error::GroupNotFound)?;
        g.track_changes()
            .remove()
            .map_err(|_| Error::InvalidArgument("impossible de supprimer la racine"))?;
        if removes_bin {
            self.db.meta.recyclebin_uuid = None;
            self.db.meta.recyclebin_changed = Some(Times::now());
        }
        self.db.remove_unused_attachments();
        Ok(())
    }

    /// Déplace une entrée dans un autre groupe (sans créer de version
    /// d'historique, comme KeePassXC).
    pub fn move_entry(&mut self, id: &str, group_id: &str) -> Result<()> {
        let eid = parse_id(id)?;
        let gid = parse_group_id(group_id)?;
        if self.db.group(gid).is_none() {
            return Err(Error::GroupNotFound);
        }
        let mut e = self.db.entry_mut(eid).ok_or(Error::EntryNotFound)?;
        e.move_to(gid).map_err(|_| Error::GroupNotFound)?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Supprime une entrée : elle part dans la corbeille, ou est supprimée
    /// définitivement si elle y est déjà (ou si la corbeille est désactivée).
    pub fn delete(&mut self, id: &str) -> Result<()> {
        let eid = parse_id(id)?;
        let parent = self.db.entry(eid).ok_or(Error::EntryNotFound)?.parent().id();
        if self.in_recycle_bin(parent) || !self.recycle_bin_enabled() {
            return self.delete_permanently(id);
        }
        let bin = self.recycle_bin_id();
        self.move_entry(id, &bin.uuid().to_string())
    }

    /// Supprime une entrée et l'inscrit dans `DeletedObjects`, pour que la
    /// suppression se propage lors de la synchronisation.
    pub fn delete_permanently(&mut self, id: &str) -> Result<()> {
        let mut entry = self.db.entry_mut(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        entry.track_changes().remove();
        Ok(())
    }

    /// Sort une entrée de la corbeille, vers son groupe d'origine s'il
    /// existe encore (hors corbeille), sinon vers la racine.
    pub fn restore(&mut self, id: &str) -> Result<()> {
        let eid = parse_id(id)?;
        let e = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        if !self.in_recycle_bin(e.parent().id()) {
            return Err(Error::InvalidArgument("l'entrée n'est pas dans la corbeille"));
        }
        let target = self.restore_target(e.previous_parent().map(|g| g.id()));
        self.move_entry(id, &target.uuid().to_string())
    }

    /// Sort un groupe de la corbeille (même règle que `restore`).
    pub fn restore_group(&mut self, id: &str) -> Result<()> {
        let gid = parse_group_id(id)?;
        let g = self.db.group(gid).ok_or(Error::GroupNotFound)?;
        if Some(gid) == self.existing_recycle_bin() || !self.in_recycle_bin(gid) {
            return Err(Error::InvalidArgument("le groupe n'est pas dans la corbeille"));
        }
        let previous = g.previous_parent().map(|p| p.id());
        let target = self.restore_target(previous.filter(|p| !self.group_is_within(*p, gid)));
        self.move_group(id, &target.uuid().to_string())
    }

    fn restore_target(&self, previous: Option<GroupId>) -> GroupId {
        previous
            .filter(|p| self.db.group(*p).is_some() && !self.in_recycle_bin(*p))
            .unwrap_or_else(|| self.db.root().id())
    }

    /// Vide la corbeille : tout son contenu est supprimé définitivement.
    /// Renvoie le nombre d'entrées supprimées.
    pub fn empty_recycle_bin(&mut self) -> Result<usize> {
        let Some(bin) = self.existing_recycle_bin() else {
            return Ok(0);
        };
        let before = self.db.num_entries();
        #[allow(clippy::expect_used)] // existing_recycle_bin vérifie l'existence
        let g = self.db.group(bin).expect("corbeille");
        let groups: Vec<GroupId> = g.group_ids().collect();
        let entries: Vec<_> = g.entry_ids().collect();
        for id in entries {
            if let Some(mut e) = self.db.entry_mut(id) {
                e.track_changes().remove();
            }
        }
        for id in groups {
            if let Some(mut g) = self.db.group_mut(id) {
                g.track_changes().remove().map_err(|_| Error::MergeFailed)?;
            }
        }
        self.db.remove_unused_attachments();
        Ok(before - self.db.num_entries())
    }
}

/// Après une fusion : la bibliothèque ne fusionne pas les métadonnées, donc
/// chaque appareil garderait sa propre idée de la corbeille. On retient, parmi
/// les corbeilles des deux côtés qui existent encore, celle au plus petit
/// UUID : tous les appareils convergent vers la même.
pub(super) fn settle_recycle_bin(merged: &mut Database, other: &Database) {
    let exists = |u: &uuid::Uuid| merged.group(GroupId::from(*u)).is_some();
    let chosen = [merged.meta.recyclebin_uuid, other.meta.recyclebin_uuid]
        .into_iter()
        .flatten()
        .filter(exists)
        .min();
    if chosen != merged.meta.recyclebin_uuid {
        merged.meta.recyclebin_uuid = chosen;
        merged.meta.recyclebin_changed = Some(Times::now());
    }
}
