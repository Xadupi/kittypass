//! Réglages de saisie automatique des entrées, dans l'élément `AutoType` du
//! format KeePass (lus et écrits aussi par KeePassXC) : activation, séquence
//! propre à l'entrée, associations à des titres de fenêtres.

use keepass::db::{AutoType, AutoTypeAssociation, EntryRef, GroupId};
use zeroize::Zeroizing;

use super::{EntrySummary, Vault, parse_id, summary};
use crate::{
    Error, Result,
    autotype::{self, Field, Typed},
};

const MAX_ASSOCIATIONS: usize = 64;
const MAX_WINDOW_LEN: usize = 512;
/// Titre d'entrée trop court pour reconnaître une fenêtre à lui seul.
const MIN_TITLE_MATCH: usize = 3;

/// Association d'une entrée à des fenêtres (`*` joker).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowAssociation {
    pub window: String,
    /// Séquence propre à ces fenêtres ; sinon celle de l'entrée.
    pub sequence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoTypeSettings {
    pub enabled: bool,
    /// Séquence de l'entrée ; sinon celle du groupe, sinon celle par défaut.
    pub sequence: Option<String>,
    pub associations: Vec<WindowAssociation>,
}

impl Default for AutoTypeSettings {
    fn default() -> Self {
        Self { enabled: true, sequence: None, associations: Vec::new() }
    }
}

fn non_empty(s: &Option<String>) -> Option<String> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
}

fn settings_of(e: &EntryRef<'_>) -> AutoTypeSettings {
    match &e.autotype {
        None => AutoTypeSettings::default(),
        Some(at) => AutoTypeSettings {
            enabled: at.enabled,
            sequence: non_empty(&at.default_sequence),
            associations: at
                .associations
                .iter()
                .map(|a| WindowAssociation { window: a.window.clone(), sequence: non_empty(&Some(a.sequence.clone())) })
                .collect(),
        },
    }
}

impl AutoTypeSettings {
    fn check(&self) -> Result<()> {
        let bad = |e: autotype::SequenceError| Error::AutoType(e.to_string());
        if let Some(s) = &self.sequence {
            autotype::validate(s).map_err(bad)?;
        }
        if self.associations.len() > MAX_ASSOCIATIONS {
            return Err(Error::InvalidArgument("trop d'associations de fenêtres"));
        }
        for a in &self.associations {
            let w = a.window.trim();
            if w.is_empty() || w.len() > MAX_WINDOW_LEN || w.chars().any(char::is_control) {
                return Err(Error::InvalidArgument("titre de fenêtre invalide"));
            }
            if let Some(s) = &a.sequence {
                autotype::validate(s).map_err(bad)?;
            }
        }
        Ok(())
    }
}

impl Vault {
    pub fn entry_autotype(&self, id: &str) -> Result<AutoTypeSettings> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(settings_of(&e))
    }

    /// Enregistre les réglages (l'ancienne version va dans l'historique).
    pub fn set_entry_autotype(&mut self, id: &str, s: &AutoTypeSettings) -> Result<()> {
        let s = AutoTypeSettings {
            enabled: s.enabled,
            sequence: non_empty(&s.sequence),
            associations: s
                .associations
                .iter()
                .map(|a| WindowAssociation { window: a.window.trim().to_owned(), sequence: non_empty(&a.sequence) })
                .collect(),
        };
        s.check()?;
        let eid = parse_id(id)?;
        let current = self.db.entry(eid).ok_or(Error::EntryNotFound)?;
        if settings_of(&current) == s {
            return Ok(());
        }
        // Garde le réglage d'obfuscation éventuellement choisi dans KeePassXC.
        let obfuscation = current.autotype.as_ref().map(|a| a.data_transfer_obfuscation.clone()).unwrap_or_default();
        let value = AutoType {
            enabled: s.enabled,
            default_sequence: s.sequence.clone(),
            data_transfer_obfuscation: obfuscation,
            associations: s
                .associations
                .iter()
                .map(|a| AutoTypeAssociation { window: a.window.clone(), sequence: a.sequence.clone().unwrap_or_default() })
                .collect(),
        };
        self.edit_entry(eid, |t| t.autotype = Some(value))
    }

    /// Saisie désactivée par un groupe parent (`EnableAutoType = false`) ou
    /// entrée dans la corbeille.
    fn autotype_blocked(&self, group: GroupId) -> bool {
        if self.existing_recycle_bin().is_some_and(|bin| self.group_is_within(group, bin)) {
            return true;
        }
        let mut current = Some(group);
        for _ in 0..=self.db.num_groups() {
            let Some(g) = current.and_then(|g| self.db.group(g)) else { return false };
            if g.enable_autotype == Some(false) {
                return true;
            }
            current = g.parent().map(|p| p.id());
        }
        false
    }

    /// Séquence à taper pour une entrée : celle de l'association qui
    /// correspond à `window`, sinon celle de l'entrée, d'un groupe parent,
    /// ou `fallback`. `None` si la saisie est désactivée pour cette entrée.
    pub fn autotype_sequence(&self, id: &str, window: Option<&str>, fallback: &str) -> Result<Option<String>> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        let s = settings_of(&e);
        if !s.enabled || self.autotype_blocked(e.parent().id()) {
            return Ok(None);
        }
        if let Some(w) = window
            && let Some(a) = s.associations.iter().find(|a| autotype::window_matches(&a.window, w))
            && let Some(seq) = &a.sequence
        {
            return Ok(Some(seq.clone()));
        }
        if let Some(seq) = s.sequence {
            return Ok(Some(seq));
        }
        let mut group = Some(e.parent().id());
        for _ in 0..=self.db.num_groups() {
            let Some(g) = group.and_then(|g| self.db.group(g)) else { break };
            if let Some(seq) = non_empty(&g.default_autotype_sequence) {
                return Ok(Some(seq));
            }
            group = g.parent().map(|p| p.id());
        }
        Ok(Some(fallback.to_owned()))
    }

    /// Entrées qui correspondent à une fenêtre : par association, ou parce
    /// que le titre de l'entrée figure dans celui de la fenêtre. Sert à
    /// proposer des entrées ; l'utilisateur confirme toujours son choix.
    pub fn autotype_matches(&self, window: &str) -> Vec<EntrySummary> {
        let lower = window.to_lowercase();
        let mut out: Vec<EntrySummary> = self
            .db
            .iter_all_entries()
            .filter(|e| !self.autotype_blocked(e.parent().id()))
            .filter(|e| {
                let s = settings_of(e);
                if !s.enabled {
                    return false;
                }
                let title = e.get_title().unwrap_or_default().trim().to_lowercase();
                s.associations.iter().any(|a| autotype::window_matches(&a.window, window))
                    || (title.chars().count() >= MIN_TITLE_MATCH && lower.contains(&title))
            })
            .map(|e| summary(&e))
            .collect();
        out.sort_by_key(|e| e.title.to_lowercase());
        out
    }

    /// Touches à taper pour `sequence` avec les champs de l'entrée.
    pub fn autotype_compile(&self, id: &str, sequence: &str) -> Result<Typed> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        let get = |k: &str| e.get(k).map(|v| Zeroizing::new(v.to_owned()));
        let lookup = |f: &Field| -> Option<Zeroizing<String>> {
            match f {
                Field::Title => Some(get(keepass::db::fields::TITLE).unwrap_or_default()),
                Field::Username => Some(get(keepass::db::fields::USERNAME).unwrap_or_default()),
                Field::Password => Some(get(keepass::db::fields::PASSWORD).unwrap_or_default()),
                Field::Url => Some(get(keepass::db::fields::URL).unwrap_or_default()),
                Field::Notes => Some(get(keepass::db::fields::NOTES).unwrap_or_default()),
                Field::Totp => {
                    let uri = e.get(keepass::db::fields::OTP)?;
                    Some(Zeroizing::new(crate::otp::Totp::parse(uri).ok()?.code_now().code.clone()))
                }
                Field::Custom(name) => get(name),
            }
        };
        autotype::compile(sequence, lookup).map_err(|e| match e {
            autotype::SequenceError::MissingField(n) if n.is_empty() => Error::AutoType("cette entrée n'a pas de code 2FA".into()),
            e => Error::AutoType(e.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autotype::{DEFAULT_SEQUENCE, Mods, Step},
        vault::{CustomField, EntryData},
    };

    fn vault() -> Vault {
        let mut v = Vault::create("correct horse battery staple").unwrap();
        v.add(&EntryData {
            title: "Banque".into(),
            username: "alice".into(),
            password: Zeroizing::new("s3cr3t".into()),
            custom: vec![CustomField { key: "PIN".into(), value: Zeroizing::new("1234".into()), protected: true }],
            ..Default::default()
        })
        .unwrap();
        v
    }

    fn first(v: &Vault) -> String {
        v.list()[0].id.clone()
    }

    fn typed(t: &Typed) -> String {
        t.steps().iter().filter_map(|s| if let Step::Char(c, _) = s { Some(*c) } else { None }).collect()
    }

    #[test]
    fn defaults_and_round_trip() {
        let mut v = vault();
        let id = first(&v);
        assert_eq!(v.entry_autotype(&id).unwrap(), AutoTypeSettings::default());
        assert_eq!(v.autotype_sequence(&id, None, DEFAULT_SEQUENCE).unwrap().as_deref(), Some(DEFAULT_SEQUENCE));
        let s = AutoTypeSettings {
            enabled: true,
            sequence: Some("{USERNAME}{ENTER}".into()),
            associations: vec![
                WindowAssociation { window: " *Banque* ".into(), sequence: Some("{S:PIN}{ENTER}".into()) },
                WindowAssociation { window: "Autre*".into(), sequence: Some("  ".into()) },
            ],
        };
        v.set_entry_autotype(&id, &s).unwrap();
        let back = v.entry_autotype(&id).unwrap();
        assert_eq!(back.associations[0].window, "*Banque*");
        assert_eq!(back.associations[1].sequence, None);
        // L'ancienne version est dans l'historique.
        assert_eq!(v.history(&id).unwrap().len(), 1);
        // Pas de nouvelle version si rien ne change.
        v.set_entry_autotype(&id, &back).unwrap();
        assert_eq!(v.history(&id).unwrap().len(), 1);

        let seq = |w| v.autotype_sequence(&id, w, DEFAULT_SEQUENCE).unwrap().unwrap();
        assert_eq!(seq(Some("Ma banque en ligne — Firefox")), "{S:PIN}{ENTER}");
        assert_eq!(seq(Some("Autre fenêtre")), "{USERNAME}{ENTER}");
        assert_eq!(seq(None), "{USERNAME}{ENTER}");

        // Relu après enregistrement (format KDBX, comme KeePassXC).
        let data = v.save().unwrap();
        let v2 = Vault::open(&data, "correct horse battery staple", &Default::default()).unwrap();
        assert_eq!(v2.entry_autotype(&id).unwrap(), back);
    }

    #[test]
    fn compile_reads_the_entry() {
        let v = vault();
        let id = first(&v);
        let t = v.autotype_compile(&id, "{USERNAME}{TAB}{PASSWORD}{TAB}{S:PIN}").unwrap();
        assert_eq!(typed(&t), "alices3cr3t1234");
        assert!(t.steps().contains(&Step::Key(crate::autotype::Key::Tab, Mods::default())));
        assert!(v.autotype_compile(&id, "{TOTP}").unwrap_err().to_string().contains("2FA"));
        assert!(v.autotype_compile(&id, "{S:Nope}").unwrap_err().to_string().contains("Nope"));
        assert!(v.autotype_compile(&id, "{CMD:x}").is_err());
    }

    #[test]
    fn invalid_settings_are_refused() {
        let mut v = vault();
        let id = first(&v);
        let bad = |s: AutoTypeSettings| v.clone().set_entry_autotype(&id, &s).is_err();
        assert!(bad(AutoTypeSettings { sequence: Some("{CMD:sh}".into()), ..Default::default() }));
        assert!(bad(AutoTypeSettings {
            associations: vec![WindowAssociation { window: "  ".into(), sequence: None }],
            ..Default::default()
        }));
        assert!(bad(AutoTypeSettings {
            associations: vec![WindowAssociation { window: "a\nb".into(), sequence: None }],
            ..Default::default()
        }));
        assert!(bad(AutoTypeSettings {
            associations: vec![WindowAssociation { window: "x".repeat(MAX_WINDOW_LEN + 1), sequence: None }],
            ..Default::default()
        }));
        assert!(bad(AutoTypeSettings {
            associations: vec![WindowAssociation { window: "w".into(), sequence: Some("{".into()) }],
            ..Default::default()
        }));
        assert!(bad(AutoTypeSettings {
            associations: vec![WindowAssociation { window: "w".into(), sequence: None }; MAX_ASSOCIATIONS + 1],
            ..Default::default()
        }));
        assert!(v.history(&id).unwrap().is_empty());
        v.set_entry_autotype(&id, &AutoTypeSettings::default()).unwrap();
    }

    #[test]
    fn disabled_binned_and_matches() {
        let mut v = vault();
        let id = first(&v);
        assert_eq!(v.autotype_matches("Connexion à Banque - Firefox").len(), 1);
        assert!(v.autotype_matches("Rien à voir").is_empty());

        // Titre trop court : ne reconnaît pas n'importe quelle fenêtre.
        let short = v.add(&EntryData { title: "a".into(), ..Default::default() }).unwrap();
        assert!(!v.autotype_matches("a a a").iter().any(|e| e.id == short));

        v.set_entry_autotype(&id, &AutoTypeSettings { enabled: false, ..Default::default() }).unwrap();
        assert_eq!(v.autotype_sequence(&id, None, DEFAULT_SEQUENCE).unwrap(), None);
        assert!(v.autotype_matches("Banque").is_empty());

        v.set_entry_autotype(&id, &AutoTypeSettings::default()).unwrap();
        v.delete(&id).unwrap();
        assert_eq!(v.autotype_sequence(&id, None, DEFAULT_SEQUENCE).unwrap(), None);
        assert!(v.autotype_matches("Banque").is_empty());
    }
}
