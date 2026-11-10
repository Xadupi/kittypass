//! Réglages de l'agent SSH des entrées : pièce jointe `KeeAgent.settings`
//! (format de KeePassXC) et clé privée en pièce jointe ou dans un fichier.

use zeroize::Zeroizing;

use super::{Vault, parse_id};
use crate::{
    Error, Result,
    ssh::{AgentSettings, SETTINGS_ATTACHMENT},
};

/// Où se trouve la clé privée d'une entrée.
pub enum KeySource {
    /// Contenu de la pièce jointe.
    Attachment(Zeroizing<Vec<u8>>),
    /// Chemin tel qu'écrit dans les réglages (`~` et variables non résolus :
    /// c'est à l'appareil de le lire).
    File(String),
}

/// Clé d'une entrée, prête à être lue puis déchiffrée.
pub struct SshKeyRef {
    pub source: KeySource,
    /// Mot de passe de l'entrée : phrase de passe d'une clé chiffrée.
    pub password: Zeroizing<String>,
    pub title: String,
    pub settings: AgentSettings,
}

/// Entrée dont la clé est utilisable avec l'agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshEntry {
    pub id: String,
    pub title: String,
    pub settings: AgentSettings,
}

impl Vault {
    fn ssh_in_recycle_bin(&self, group: keepass::db::GroupId) -> bool {
        self.existing_recycle_bin().is_some_and(|bin| self.group_is_within(group, bin))
    }

    /// Réglages de l'entrée (ceux par défaut si elle n'en a pas).
    pub fn entry_ssh(&self, id: &str) -> Result<AgentSettings> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        match e.attachment_by_name(SETTINGS_ATTACHMENT) {
            Some(a) => AgentSettings::parse(a.data.get()),
            None => Ok(AgentSettings::default()),
        }
    }

    /// Enregistre les réglages (l'ancienne version va dans l'historique).
    /// Des réglages par défaut retirent la pièce jointe, comme KeePassXC.
    pub fn set_entry_ssh(&mut self, id: &str, s: &AgentSettings) -> Result<()> {
        s.check()?;
        let eid = parse_id(id)?;
        let e = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        if s.use_attachment && s.allow {
            if s.attachment_name == SETTINGS_ATTACHMENT {
                return Err(Error::Ssh("choisissez la pièce jointe qui contient la clé".into()));
            }
            if e.attachment_by_name(&s.attachment_name).is_none() {
                return Err(Error::AttachmentNotFound);
            }
        }
        let present = e.attachment_by_name(SETTINGS_ATTACHMENT).is_some();
        // Réglages illisibles : on les remplace par les nouveaux.
        if self.entry_ssh(id).ok().as_ref() == Some(s) && (present || *s == AgentSettings::default()) {
            return Ok(());
        }
        if *s == AgentSettings::default() {
            return self.remove_attachment(id, SETTINGS_ATTACHMENT);
        }
        self.add_attachment(id, SETTINGS_ATTACHMENT, s.to_xml().as_bytes())
    }

    /// Entrées hors corbeille dont la clé est autorisée avec l'agent,
    /// triées par titre. Les réglages illisibles sont ignorés.
    pub fn ssh_entries(&self) -> Vec<SshEntry> {
        let mut out: Vec<SshEntry> = self
            .db
            .iter_all_entries()
            .filter(|e| !self.ssh_in_recycle_bin(e.parent().id()))
            .filter_map(|e| {
                let settings = AgentSettings::parse(e.attachment_by_name(SETTINGS_ATTACHMENT)?.data.get()).ok()?;
                settings.allow.then(|| SshEntry {
                    id: e.id().uuid().to_string(),
                    title: e.get_title().unwrap_or_default().to_owned(),
                    settings,
                })
            })
            .collect();
        out.sort_by_key(|e| e.title.to_lowercase());
        out
    }

    /// Clé de l'entrée, si elle est autorisée avec l'agent.
    pub fn ssh_key(&self, id: &str) -> Result<SshKeyRef> {
        let settings = self.entry_ssh(id)?;
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        if !settings.allow {
            return Err(Error::Ssh("cette entrée n'autorise pas l'agent SSH".into()));
        }
        if self.ssh_in_recycle_bin(e.parent().id()) {
            return Err(Error::Ssh("entrée dans la corbeille".into()));
        }
        let source = if settings.use_attachment {
            if settings.attachment_name == SETTINGS_ATTACHMENT {
                return Err(Error::AttachmentNotFound);
            }
            let a = e.attachment_by_name(&settings.attachment_name).ok_or(Error::AttachmentNotFound)?;
            KeySource::Attachment(Zeroizing::new(a.data.get().clone()))
        } else {
            if settings.file_name.trim().is_empty() {
                return Err(Error::Ssh("aucun fichier de clé indiqué".into()));
            }
            KeySource::File(settings.file_name.clone())
        };
        Ok(SshKeyRef {
            source,
            password: Zeroizing::new(e.get(keepass::db::fields::PASSWORD).unwrap_or_default().to_owned()),
            title: e.get_title().unwrap_or_default().to_owned(),
            settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::EntryData;

    fn vault() -> (Vault, String) {
        let mut v = Vault::create("correct horse battery staple").unwrap();
        let id = v
            .add(&EntryData { title: "Serveur".into(), password: Zeroizing::new("phrase".into()), ..Default::default() })
            .unwrap();
        v.add_attachment(&id, "id_ed25519", b"cle").unwrap();
        (v, id)
    }

    fn on(name: &str) -> AgentSettings {
        AgentSettings { allow: true, add_at_open: true, use_attachment: true, attachment_name: name.into(), ..Default::default() }
    }

    #[test]
    fn settings_in_attachment() {
        let (mut v, id) = vault();
        assert_eq!(v.entry_ssh(&id).unwrap(), AgentSettings::default());
        assert!(v.ssh_entries().is_empty());
        let before = v.history_len(&id).unwrap();
        v.set_entry_ssh(&id, &on("id_ed25519")).unwrap();
        assert_eq!(v.entry_ssh(&id).unwrap(), on("id_ed25519"));
        assert_eq!(v.history_len(&id).unwrap(), before + 1);
        // Inchangé : pas de nouvelle version dans l'historique.
        v.set_entry_ssh(&id, &on("id_ed25519")).unwrap();
        assert_eq!(v.history_len(&id).unwrap(), before + 1);
        let list = v.ssh_entries();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "Serveur");
        let k = v.ssh_key(&id).unwrap();
        assert!(matches!(&k.source, KeySource::Attachment(d) if &d[..] == b"cle"));
        assert_eq!(&*k.password, "phrase");
        // Par défaut : la pièce jointe disparaît.
        v.set_entry_ssh(&id, &AgentSettings::default()).unwrap();
        assert!(v.attachments(&id).unwrap().iter().all(|a| a.name != SETTINGS_ATTACHMENT));
        assert!(v.ssh_key(&id).is_err());
    }

    #[test]
    fn refusals() {
        let (mut v, id) = vault();
        assert!(matches!(v.set_entry_ssh(&id, &on("absente")), Err(Error::AttachmentNotFound)));
        assert!(v.set_entry_ssh(&id, &on(SETTINGS_ATTACHMENT)).is_err());
        let bad = AgentSettings { use_lifetime: true, lifetime_secs: 0, ..on("id_ed25519") };
        assert!(v.set_entry_ssh(&id, &bad).is_err());
        let file = AgentSettings { use_attachment: false, ..on("") };
        v.set_entry_ssh(&id, &file).unwrap();
        assert!(v.ssh_key(&id).is_err(), "fichier vide");
        let file = AgentSettings { file_name: "~/.ssh/id".into(), ..file };
        v.set_entry_ssh(&id, &file).unwrap();
        assert!(matches!(v.ssh_key(&id).unwrap().source, KeySource::File(f) if f == "~/.ssh/id"));

        // Réglages corrompus (venus d'un autre appareil) : ignorés par la liste,
        // erreur à la lecture, remplaçables.
        v.add_attachment(&id, SETTINGS_ATTACHMENT, b"<pas>").unwrap();
        assert!(v.ssh_entries().is_empty());
        assert!(v.entry_ssh(&id).is_err());
        v.set_entry_ssh(&id, &on("id_ed25519")).unwrap();
        assert_eq!(v.ssh_entries().len(), 1);

        // Corbeille : ni liste ni clé.
        v.delete(&id).unwrap();
        assert!(v.ssh_entries().is_empty());
        assert!(v.ssh_key(&id).is_err());
    }
}
