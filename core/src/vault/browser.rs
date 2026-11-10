//! Données de l'intégration navigateur stockées dans le coffre, au format de
//! KeePassXC (un coffre partagé avec KeePassXC garde ses associations et ses
//! réglages) :
//! - associations : données personnalisées du coffre `KPXC_BROWSER_<nom>`,
//!   valeur = clé d'identification de l'extension (synchronisées) ;
//! - réglages d'accès d'une entrée : donnée personnalisée
//!   « KeePassXC-Browser Settings », JSON `{Allow, Deny, Realm}` ;
//! - entrée masquée au navigateur : donnée `BrowserHideEntry` = `true`.

use std::collections::BTreeSet;

use keepass::db::{CustomDataItem, CustomDataValue, Entry, Times};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Vault, next_modification, parse_id};
use crate::{
    Error, Result,
    browser::{matching, passkeys::Passkey},
};

pub const ASSOCIATION_PREFIX: &str = "KPXC_BROWSER_";
pub const SETTINGS_KEY: &str = "KeePassXC-Browser Settings";
pub const HIDE_KEY: &str = "BrowserHideEntry";
/// URL supplémentaires d'une entrée (convention KeePass2Android, reprise
/// par KeePassXC) : `KP2A_URL`, `KP2A_URL_1`…
pub const EXTRA_URL_PREFIX: &str = "KP2A_URL";

const MAX_ASSOCIATIONS: usize = 64;
const MAX_ASSOCIATION_NAME: usize = 64;
const MAX_LISTED_HOSTS: usize = 256;
const MAX_HOST_LEN: usize = 253;

/// Navigateur associé au coffre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    pub id: String,
    /// Dernière modification (secondes Unix), si connue.
    pub created: Option<i64>,
}

/// Réglages d'accès d'une entrée (sites toujours autorisés / refusés).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessSettings {
    #[serde(rename = "Allow", default)]
    pub allow: BTreeSet<String>,
    #[serde(rename = "Deny", default)]
    pub deny: BTreeSet<String>,
    #[serde(rename = "Realm", default, skip_serializing_if = "String::is_empty")]
    pub realm: String,
}

/// Décision tirée des réglages pour un site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allowed,
    Denied,
    /// Ni autorisé ni refusé : il faut demander.
    Ask,
}

impl AccessSettings {
    /// Décision pour la page `host` (et l'hôte du formulaire, s'il diffère) :
    /// un refus l'emporte, une autorisation doit couvrir les deux hôtes.
    pub fn decide(&self, host: &str, submit_host: Option<&str>) -> Access {
        let hosts: Vec<&str> = std::iter::once(host).chain(submit_host.filter(|s| *s != host)).collect();
        if hosts.iter().any(|h| self.deny.contains(*h)) {
            Access::Denied
        } else if hosts.iter().all(|h| self.allow.contains(*h)) {
            Access::Allowed
        } else {
            Access::Ask
        }
    }

    pub fn allow(&mut self, host: &str) {
        self.deny.remove(host);
        self.allow.insert(host.to_owned());
    }

    pub fn deny(&mut self, host: &str) {
        self.allow.remove(host);
        self.deny.insert(host.to_owned());
    }

    fn sanitize(mut self) -> Self {
        let ok = |h: &String| !h.is_empty() && h.len() <= MAX_HOST_LEN && !h.chars().any(char::is_control);
        self.allow = self.allow.into_iter().filter(ok).take(MAX_LISTED_HOSTS).collect();
        self.deny = self.deny.into_iter().filter(ok).take(MAX_LISTED_HOSTS).collect();
        self.realm = self.realm.chars().take(MAX_HOST_LEN).collect();
        self
    }
}

/// Entrée candidate pour le navigateur : de quoi la faire correspondre à une
/// page, sans secret.
#[derive(Debug, Clone)]
pub struct BrowserCandidate {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub group: String,
    pub group_id: String,
    pub expired: bool,
    pub access: AccessSettings,
}

fn custom_string(item: &CustomDataItem) -> Option<&str> {
    match &item.value {
        Some(CustomDataValue::String(s)) => Some(s),
        _ => None,
    }
}

fn entry_urls(e: &Entry) -> Vec<String> {
    let mut urls: Vec<String> = e.get_url().into_iter().map(str::to_owned).collect();
    let mut extra: Vec<(&String, &str)> = e
        .fields
        .iter()
        .filter(|(k, _)| k.starts_with(EXTRA_URL_PREFIX))
        .map(|(k, v)| (k, v.get().as_str()))
        .collect();
    extra.sort();
    urls.extend(extra.into_iter().map(|(_, v)| v.to_owned()));
    urls.retain(|u| !u.trim().is_empty());
    urls
}

fn access_of(e: &Entry) -> AccessSettings {
    e.custom_data
        .get(SETTINGS_KEY)
        .and_then(custom_string)
        .and_then(|s| serde_json::from_str::<AccessSettings>(s).ok())
        .map(AccessSettings::sanitize)
        .unwrap_or_default()
}

fn is_hidden(e: &Entry) -> bool {
    e.custom_data.get(HIDE_KEY).and_then(custom_string).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn valid_association_name(id: &str) -> bool {
    !id.is_empty() && id.chars().count() <= MAX_ASSOCIATION_NAME && !id.chars().any(|c| c.is_control())
}

impl Vault {
    /// Empreinte du coffre pour l'extension : SHA-256 de l'UUID du groupe
    /// racine (hexadécimal sans tirets), comme KeePassXC. Elle permet à
    /// l'extension de reconnaître le coffre, sans rien révéler de son contenu.
    pub fn browser_hash(&self) -> String {
        let root = self.db.root().id().uuid().simple().to_string();
        Sha256::digest(root.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Clé enregistrée pour l'association `id`, si elle existe.
    pub fn browser_association_key(&self, id: &str) -> Option<String> {
        let item = self.db.meta.custom_data.get(&format!("{ASSOCIATION_PREFIX}{id}"))?;
        custom_string(item).filter(|k| !k.is_empty()).map(str::to_owned)
    }

    pub fn browser_associations(&self) -> Vec<Association> {
        let mut v: Vec<Association> = self
            .db
            .meta
            .custom_data
            .iter()
            .filter_map(|(k, item)| {
                let id = k.strip_prefix(ASSOCIATION_PREFIX)?;
                custom_string(item).filter(|v| !v.is_empty())?;
                Some(Association { id: id.to_owned(), created: item.last_modification_time.map(|t| t.and_utc().timestamp()) })
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Enregistre une association. Le nom ne doit pas déjà servir : une
    /// extension ne peut pas remplacer la clé d'une autre.
    pub fn browser_associate(&mut self, id: &str, key: &str) -> Result<()> {
        if !valid_association_name(id) {
            return Err(Error::InvalidArgument("nom d'association invalide"));
        }
        if key.is_empty() || key.len() > 128 {
            return Err(Error::InvalidArgument("clé d'association invalide"));
        }
        if self.browser_association_key(id).is_some() {
            return Err(Error::InvalidArgument("ce nom d'association existe déjà"));
        }
        if self.browser_associations().len() >= MAX_ASSOCIATIONS {
            return Err(Error::InvalidArgument("trop d'associations"));
        }
        self.set_meta_custom(&format!("{ASSOCIATION_PREFIX}{id}"), key);
        Ok(())
    }

    /// Révoque une association. La clé est effacée mais le nom reste (valeur
    /// vide, datée) : la révocation l'emporte ainsi à la fusion avec un
    /// appareil qui l'aurait encore.
    pub fn browser_revoke(&mut self, id: &str) -> bool {
        if self.browser_association_key(id).is_none() {
            return false;
        }
        self.set_meta_custom(&format!("{ASSOCIATION_PREFIX}{id}"), "");
        true
    }

    fn set_meta_custom(&mut self, key: &str, value: &str) {
        let prev = self.db.meta.custom_data.get(key).and_then(|i| i.last_modification_time);
        self.db.meta.custom_data.insert(
            key.to_owned(),
            CustomDataItem { value: Some(CustomDataValue::String(value.to_owned())), last_modification_time: Some(next_modification(prev)) },
        );
    }

    /// Entrées proposables au navigateur : hors corbeille et hors entrées
    /// masquées, avec au moins une URL.
    pub fn browser_candidates(&self) -> Vec<BrowserCandidate> {
        let bin = self.existing_recycle_bin();
        self.db
            .iter_all_entries()
            .filter(|e| bin.is_none_or(|bin| !self.group_is_within(e.parent().id(), bin)))
            .filter(|e| !is_hidden(e))
            .filter_map(|e| {
                let urls = entry_urls(&e);
                (!urls.is_empty()).then(|| BrowserCandidate {
                    id: e.id().uuid().to_string(),
                    title: e.get_title().unwrap_or_default().to_owned(),
                    username: e.get_username().unwrap_or_default().to_owned(),
                    urls,
                    group: e.parent().name.clone(),
                    group_id: e.parent().id().uuid().to_string(),
                    expired: super::is_expired(&e),
                    access: access_of(&e),
                })
            })
            .collect()
    }

    /// Entrées correspondant à la page, de la meilleure à la moins bonne
    /// correspondance (puis par titre).
    pub fn browser_matches(&self, page_url: &str) -> Vec<(BrowserCandidate, matching::Match)> {
        let Some(page) = matching::parse_page(page_url) else { return vec![] };
        let mut v: Vec<_> = self
            .browser_candidates()
            .into_iter()
            .filter_map(|c| matching::best(&page, c.urls.iter().map(String::as_str)).map(|m| (c, m)))
            .collect();
        v.sort_by(|(a, ma), (b, mb)| mb.cmp(ma).then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase())));
        v
    }

    pub fn browser_access(&self, entry_id: &str) -> Result<AccessSettings> {
        let e = self.db.entry(parse_id(entry_id)?).ok_or(Error::EntryNotFound)?;
        Ok(access_of(&e))
    }

    /// Enregistre les réglages d'accès d'une entrée (« Se souvenir »). Pas de
    /// version d'historique : ce n'est pas une modification de l'identifiant.
    pub fn set_browser_access(&mut self, entry_id: &str, settings: &AccessSettings) -> Result<()> {
        let settings = settings.clone().sanitize();
        let json = serde_json::to_string(&settings).map_err(|_| Error::Save)?;
        let mut e = self.db.entry_mut(parse_id(entry_id)?).ok_or(Error::EntryNotFound)?;
        let modified = next_modification(e.times.last_modification);
        let prev = e.custom_data.get(SETTINGS_KEY).and_then(|i| i.last_modification_time);
        e.custom_data.insert(
            SETTINGS_KEY.to_owned(),
            CustomDataItem { value: Some(CustomDataValue::String(json)), last_modification_time: Some(next_modification(prev)) },
        );
        e.times.last_modification = Some(modified);
        Ok(())
    }

    /// Masque (ou non) une entrée au navigateur.
    pub fn set_browser_hidden(&mut self, entry_id: &str, hidden: bool) -> Result<()> {
        let mut e = self.db.entry_mut(parse_id(entry_id)?).ok_or(Error::EntryNotFound)?;
        let modified = next_modification(e.times.last_modification);
        if hidden {
            e.custom_data.insert(
                HIDE_KEY.to_owned(),
                CustomDataItem { value: Some(CustomDataValue::String("true".into())), last_modification_time: Some(Times::now()) },
            );
        } else {
            e.custom_data.remove(HIDE_KEY);
        }
        e.times.last_modification = Some(modified);
        Ok(())
    }

    pub fn browser_hidden(&self, entry_id: &str) -> Result<bool> {
        let e = self.db.entry(parse_id(entry_id)?).ok_or(Error::EntryNotFound)?;
        Ok(is_hidden(&e))
    }

    /// Passkeys du coffre (hors corbeille) : (id de l'entrée, passkey).
    pub fn passkeys(&self) -> Vec<(String, Passkey)> {
        let bin = self.existing_recycle_bin();
        self.db
            .iter_all_entries()
            .filter(|e| bin.is_none_or(|bin| !self.group_is_within(e.parent().id(), bin)))
            .filter(|e| e.fields.contains_key(crate::browser::passkeys::ATTR_PRIVATE_KEY))
            .filter_map(|e| Passkey::from_entry(&super::entry_data(&e)).map(|p| (e.id().uuid().to_string(), p)))
            .collect()
    }

    /// Fusionne les données personnalisées du coffre d'une autre version :
    /// pour chaque clé, la plus récente gagne (la bibliothèque KeePass ne
    /// fusionne pas les métadonnées).
    pub(super) fn merge_meta_custom_data(db: &mut keepass::Database, other: &keepass::Database) {
        for (k, theirs) in &other.meta.custom_data {
            let take = match db.meta.custom_data.get(k) {
                None => true,
                Some(ours) => theirs.last_modification_time > ours.last_modification_time,
            };
            if take {
                db.meta.custom_data.insert(k.clone(), theirs.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{CustomField, EntryData, MasterKey};
    use zeroize::Zeroizing;

    fn vault() -> Vault {
        Vault::create_with_key(&MasterKey::new("mot-de-passe-test", None)).unwrap()
    }

    fn entry(v: &mut Vault, title: &str, url: &str) -> String {
        v.add(&EntryData { title: title.into(), username: "u".into(), url: url.into(), ..Default::default() }).unwrap()
    }

    #[test]
    fn hash_is_stable_and_hex() {
        let v = vault();
        let h = v.browser_hash();
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(h, v.clone().browser_hash());
        assert_ne!(h, vault().browser_hash());
    }

    #[test]
    fn associations_cannot_be_overwritten_and_revocation_sticks() {
        let mut v = vault();
        v.browser_associate("firefox", "clé-1").unwrap();
        assert!(v.browser_associate("firefox", "clé-2").is_err());
        assert_eq!(v.browser_association_key("firefox").as_deref(), Some("clé-1"));
        assert!(v.browser_associate("", "k").is_err());
        assert!(v.browser_associate("a\u{0}b", "k").is_err());
        assert!(v.browser_associate("x", "").is_err());
        assert_eq!(v.browser_associations().len(), 1);
        // Copie sur un « autre appareil », révocation ici, fusion.
        let other = v.clone();
        assert!(v.browser_revoke("firefox"));
        assert!(!v.browser_revoke("firefox"));
        assert!(v.browser_association_key("firefox").is_none());
        v.merge_from(&other).unwrap();
        assert!(v.browser_association_key("firefox").is_none(), "révocation annulée par la fusion");
        // Dans l'autre sens aussi.
        let mut other = other;
        other.merge_from(&v).unwrap();
        assert!(other.browser_association_key("firefox").is_none());
        // Une association créée ailleurs arrive par la fusion.
        let mut far = v.clone();
        far.browser_associate("chromium", "clé-c").unwrap();
        v.merge_from(&far).unwrap();
        assert_eq!(v.browser_association_key("chromium").as_deref(), Some("clé-c"));
    }

    #[test]
    fn associations_survive_save_and_reopen() {
        let mut v = vault();
        v.browser_associate("firefox", "clé-1").unwrap();
        let bytes = v.save().unwrap();
        let back = Vault::open(&bytes, "mot-de-passe-test", &Default::default()).unwrap();
        assert_eq!(back.browser_association_key("firefox").as_deref(), Some("clé-1"));
    }

    #[test]
    fn access_settings_decide_and_persist() {
        let mut v = vault();
        let id = entry(&mut v, "Site", "https://example.com");
        let mut s = v.browser_access(&id).unwrap();
        assert_eq!(s.decide("example.com", None), Access::Ask);
        s.allow("example.com");
        assert_eq!(s.decide("example.com", None), Access::Allowed);
        assert_eq!(s.decide("example.com", Some("evil.net")), Access::Ask);
        s.deny("evil.net");
        assert_eq!(s.decide("example.com", Some("evil.net")), Access::Denied);
        v.set_browser_access(&id, &s).unwrap();
        let bytes = v.save().unwrap();
        let back = Vault::open(&bytes, "mot-de-passe-test", &Default::default()).unwrap();
        assert_eq!(back.browser_access(&id).unwrap(), s);
        // Format KeePassXC.
        let e = back.db.entry(parse_id(&id).unwrap()).unwrap();
        let raw = custom_string(&e.custom_data[SETTINGS_KEY]).unwrap();
        let json: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(json["Allow"][0], "example.com");
        assert_eq!(json["Deny"][0], "evil.net");
        // Pas de version d'historique pour un réglage.
        assert!(back.history(&id).unwrap().is_empty());
    }

    #[test]
    fn corrupt_settings_are_ignored() {
        let mut v = vault();
        let id = entry(&mut v, "Site", "https://example.com");
        v.db.entry_mut(parse_id(&id).unwrap()).unwrap().custom_data.insert(
            SETTINGS_KEY.into(),
            CustomDataItem { value: Some(CustomDataValue::String("{pas du json".into())), last_modification_time: None },
        );
        assert_eq!(v.browser_access(&id).unwrap(), AccessSettings::default());
    }

    #[test]
    fn candidates_skip_bin_hidden_and_urlless() {
        let mut v = vault();
        let a = entry(&mut v, "A", "https://example.com");
        let b = entry(&mut v, "B", "https://example.com");
        let c = entry(&mut v, "C", "https://example.com");
        entry(&mut v, "Sans URL", "");
        v.delete(&b).unwrap();
        v.set_browser_hidden(&c, true).unwrap();
        let ids: Vec<String> = v.browser_candidates().into_iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![a.clone()]);
        v.set_browser_hidden(&c, false).unwrap();
        assert_eq!(v.browser_candidates().len(), 2);
    }

    #[test]
    fn extra_urls_and_ordering() {
        let mut v = vault();
        let mut d = EntryData { title: "Multi".into(), url: "https://other.net".into(), ..Default::default() };
        d.custom.push(CustomField { key: "KP2A_URL".into(), value: Zeroizing::new("https://login.example.com".into()), protected: false });
        let multi = v.add(&d).unwrap();
        let sub = entry(&mut v, "Domaine", "example.com");
        entry(&mut v, "Ailleurs", "https://elsewhere.org");
        let found = v.browser_matches("https://login.example.com/session");
        let ids: Vec<&str> = found.iter().map(|(c, _)| c.id.as_str()).collect();
        assert_eq!(ids, vec![multi.as_str(), sub.as_str()]);
        assert!(v.browser_matches("not a url").is_empty());
    }
}
