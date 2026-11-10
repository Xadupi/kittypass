//! Import Bitwarden : export JSON **non chiffré** (Outils → Exporter le
//! coffre → .json). Identifiants, notes, cartes, identités, clés SSH,
//! champs personnalisés, dossiers (« Parent/Enfant ») et collections.

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{Imported, ImportedEntry, MAX_IMPORT_BYTES, normalize_otp};
use crate::{
    Error, Result,
    vault::{CustomField, EntryData},
};

type Secret = Zeroizing<String>;

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<Named>,
    #[serde(default)]
    collections: Vec<Named>,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Named {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    #[serde(default)]
    r#type: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<Secret>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    collection_ids: Option<Vec<String>>,
    #[serde(default)]
    fields: Option<Vec<Field>>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    card: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    identity: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    ssh_key: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Field {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<Secret>,
    #[serde(default)]
    r#type: u8,
}

#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<Secret>,
    #[serde(default)]
    totp: Option<Secret>,
    #[serde(default)]
    uris: Option<Vec<Uri>>,
}

#[derive(Deserialize)]
struct Uri {
    #[serde(default)]
    uri: Option<String>,
}

/// Champs de carte, d'identité et de clé SSH : (clé JSON, nom affiché, protégé).
const CARD: &[(&str, &str, bool)] = &[
    ("cardholderName", "Titulaire", false),
    ("brand", "Réseau", false),
    ("number", "Numéro de carte", true),
    ("expMonth", "Mois d'expiration", false),
    ("expYear", "Année d'expiration", false),
    ("code", "Code de sécurité", true),
];
const IDENTITY: &[(&str, &str, bool)] = &[
    ("title", "Civilité", false),
    ("firstName", "Prénom", false),
    ("middleName", "Deuxième prénom", false),
    ("lastName", "Nom", false),
    ("company", "Société", false),
    ("email", "E-mail", false),
    ("phone", "Téléphone", false),
    ("address1", "Adresse", false),
    ("address2", "Adresse (suite)", false),
    ("address3", "Adresse (fin)", false),
    ("postalCode", "Code postal", false),
    ("city", "Ville", false),
    ("state", "Région", false),
    ("country", "Pays", false),
    ("username", "Identifiant", false),
    ("ssn", "Numéro de sécurité sociale", true),
    ("passportNumber", "Numéro de passeport", true),
    ("licenseNumber", "Numéro de permis", true),
];
const SSH: &[(&str, &str, bool)] =
    &[("privateKey", "Clé privée SSH", true), ("publicKey", "Clé publique SSH", false), ("keyFingerprint", "Empreinte SSH", false)];

fn add_map(d: &mut EntryData, map: &serde_json::Map<String, serde_json::Value>, spec: &[(&str, &str, bool)]) {
    for (json, label, protected) in spec {
        let value = match map.get(*json) {
            Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => continue,
        };
        d.custom.push(CustomField { key: (*label).to_owned(), value: Zeroizing::new(value), protected: *protected });
    }
}

pub fn parse_bitwarden(data: &[u8]) -> Result<Imported> {
    if data.len() > MAX_IMPORT_BYTES {
        return Err(Error::TooLarge);
    }
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    // Un export chiffré se reconnaît avant de lire les éléments.
    let probe: serde_json::Value = serde_json::from_slice(data).map_err(|_| Error::InvalidArgument("JSON Bitwarden illisible"))?;
    if probe.get("encrypted").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(Error::InvalidArgument("export Bitwarden chiffré : exportez au format JSON non chiffré"));
    }
    drop(probe);
    let export: Export = serde_json::from_slice(data).map_err(|_| Error::InvalidArgument("JSON Bitwarden illisible"))?;
    if export.encrypted {
        return Err(Error::InvalidArgument("export Bitwarden chiffré : exportez au format JSON non chiffré"));
    }
    let folder_path = |id: &Option<String>, list: &[Named]| -> Option<Vec<String>> {
        let id = id.as_ref()?;
        let name = &list.iter().find(|f| &f.id == id)?.name;
        Some(name.split('/').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect())
    };
    let mut out = Imported::default();
    let mut ignored_types = 0;
    for item in export.items {
        let mut d = EntryData { title: item.name.unwrap_or_default(), ..Default::default() };
        d.notes = item.notes.unwrap_or_default();
        match item.r#type {
            1 => {
                if let Some(l) = item.login {
                    d.username = l.username.unwrap_or_default();
                    d.password = l.password.unwrap_or_default();
                    d.otp = l.totp.as_deref().and_then(|t| normalize_otp(t));
                    let uris: Vec<String> = l.uris.unwrap_or_default().into_iter().filter_map(|u| u.uri).filter(|u| !u.is_empty()).collect();
                    let mut uris = uris.into_iter();
                    d.url = uris.next().unwrap_or_default();
                    // URL supplémentaires : attributs reconnus par KeePassXC-Browser.
                    for (i, u) in uris.enumerate() {
                        let key = if i == 0 { "KP2A_URL".to_owned() } else { format!("KP2A_URL_{i}") };
                        d.custom.push(CustomField { key, value: Zeroizing::new(u), protected: false });
                    }
                }
            }
            2 => d.tags.push("Note".into()),
            3 => {
                d.tags.push("Carte".into());
                add_map(&mut d, &item.card.unwrap_or_default(), CARD);
            }
            4 => {
                d.tags.push("Identité".into());
                add_map(&mut d, &item.identity.unwrap_or_default(), IDENTITY);
            }
            5 => {
                d.tags.push("SSH".into());
                add_map(&mut d, &item.ssh_key.unwrap_or_default(), SSH);
            }
            _ => {
                ignored_types += 1;
                continue;
            }
        }
        for f in item.fields.unwrap_or_default() {
            // 3 = champ lié (renvoie vers un autre champ) : rien à importer.
            if f.r#type == 3 {
                continue;
            }
            let key = f.name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "Champ".into());
            d.custom.push(CustomField { key, value: f.value.unwrap_or_default(), protected: f.r#type == 1 });
        }
        if item.favorite {
            d.tags.push("Favori".into());
        }
        let path = folder_path(&item.folder_id, &export.folders)
            .or_else(|| item.collection_ids.as_ref().and_then(|c| folder_path(&c.first().cloned(), &export.collections)))
            .unwrap_or_default();
        out.push(ImportedEntry { path, data: d, ..Default::default() })?;
    }
    if ignored_types > 0 {
        out.warn(format!("{ignored_types} élément(s) d'un type inconnu ignoré(s)"));
    }
    Ok(out)
}
