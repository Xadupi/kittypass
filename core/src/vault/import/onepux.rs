//! Import 1Password : archive `.1pux` (zip contenant `export.data` en JSON
//! et les pièces jointes dans `files/`). Comptes et coffres deviennent des
//! groupes ; identifiants, mots de passe, sections, 2FA, URL, étiquettes,
//! documents et pièces jointes sont repris.
//!
//! L'archive n'est jamais extraite sur le disque. Contre les bombes zip, la
//! taille décompressée réelle est bornée (pas celle annoncée dans l'en-tête),
//! ainsi que le nombre de fichiers.

use std::io::{Cursor, Read};

use serde_json::Value;
use zeroize::Zeroizing;

use super::{Imported, ImportedEntry, MAX_IMPORT_BYTES, normalize_otp};
use crate::{
    Error, Result,
    vault::{CustomField, EntryData, MAX_ATTACHMENT_BYTES},
};

const MAX_ARCHIVE_FILES: usize = 50_000;
/// Total des pièces jointes lues dans l'archive.
const MAX_TOTAL_FILES_BYTES: usize = 256 * 1024 * 1024;

type Zip = zip::ZipArchive<Cursor<Vec<u8>>>;

/// Lit au plus `max` octets décompressés ; `None` si le fichier est plus gros.
fn read_capped(archive: &mut Zip, index: usize, max: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = archive.by_index(index).map_err(|_| Error::InvalidArgument("archive 1Password abîmée"))?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(max as u64 + 1).read_to_end(&mut buf).map_err(|_| Error::InvalidArgument("archive 1Password abîmée"))?;
    Ok((buf.len() <= max).then_some(buf))
}

fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// Valeur d'un champ de section → (texte, protégé). `None` : pièce jointe
/// ou valeur vide.
fn field_value(value: &Value) -> Option<(String, bool)> {
    let (kind, v) = value.as_object()?.iter().next()?;
    let text = match (kind.as_str(), v) {
        ("file", _) => return None,
        ("concealed" | "creditCardNumber", Value::String(x)) => return (!x.is_empty()).then(|| (x.clone(), true)),
        ("sshKey", Value::Object(o)) => return o.get("privateKey").and_then(Value::as_str).map(|k| (k.to_owned(), true)),
        ("email", Value::Object(o)) => o.get("email_address").and_then(Value::as_str).unwrap_or_default().to_owned(),
        ("monthYear", Value::Number(n)) => {
            let n = n.as_u64().unwrap_or_default();
            format!("{:02}/{}", n % 100, n / 100)
        }
        ("date", Value::Number(n)) => n
            .as_i64()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        ("address", Value::Object(o)) => ["street", "zip", "city", "state", "country"]
            .iter()
            .filter_map(|k| o.get(*k).and_then(Value::as_str).filter(|x| !x.is_empty()))
            .collect::<Vec<_>>()
            .join(", "),
        (_, Value::String(x)) => x.clone(),
        (_, Value::Number(n)) => n.to_string(),
        (_, Value::Bool(b)) => b.to_string(),
        (_, Value::Null) => String::new(),
        (_, other) => other.to_string(),
    };
    (!text.is_empty()).then_some((text, false))
}

/// Référence de fichier d'un champ ou d'un document : (documentId, nom).
fn file_ref(v: &Value) -> Option<(String, String)> {
    let id = v.get("documentId")?.as_str()?.to_owned();
    Some((id, s(v, "fileName")))
}

pub fn parse_1pux(data: &[u8]) -> Result<Imported> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data.to_vec())).map_err(|_| Error::InvalidArgument("ce n'est pas une archive .1pux"))?;
    if archive.len() > MAX_ARCHIVE_FILES {
        return Err(Error::InvalidArgument("archive 1Password : trop de fichiers"));
    }
    let names: Vec<String> = archive.file_names().filter_map(|n| n.ok().map(|n| n.into_owned())).collect();
    let index = |name: &str, archive: &Zip| archive.index_for_name(name);
    let export_index = index("export.data", &archive).ok_or(Error::InvalidArgument("archive .1pux sans export.data"))?;
    let json = read_capped(&mut archive, export_index, MAX_IMPORT_BYTES)?.ok_or(Error::TooLarge)?;
    let root: Value = serde_json::from_slice(&json).map_err(|_| Error::InvalidArgument("export.data illisible"))?;
    drop(json);

    let mut out = Imported::default();
    let mut files_read = 0usize;
    let accounts = root.get("accounts").and_then(Value::as_array).cloned().unwrap_or_default();
    let several_accounts = accounts.len() > 1;
    for account in &accounts {
        let account_name = s(&account["attrs"], "accountName");
        for vault in account.get("vaults").and_then(Value::as_array).into_iter().flatten() {
            let mut base = Vec::new();
            if several_accounts && !account_name.is_empty() {
                base.push(account_name.clone());
            }
            base.push(match s(&vault["attrs"], "name") {
                n if n.is_empty() => "Coffre".to_owned(),
                n => n,
            });
            for item in vault.get("items").and_then(Value::as_array).into_iter().flatten() {
                if item.get("state").and_then(Value::as_str) == Some("trashed") {
                    continue;
                }
                let (overview, details) = (&item["overview"], &item["details"]);
                let mut d = EntryData { title: s(overview, "title"), ..Default::default() };
                let mut files: Vec<(String, String)> = Vec::new();
                // URL : la principale, puis les autres pour KeePassXC-Browser.
                let mut urls: Vec<String> = Vec::new();
                for u in [s(overview, "url")]
                    .into_iter()
                    .chain(overview.get("urls").and_then(Value::as_array).into_iter().flatten().map(|u| s(u, "url")))
                {
                    if !u.is_empty() && !urls.contains(&u) {
                        urls.push(u);
                    }
                }
                let mut urls = urls.into_iter();
                d.url = urls.next().unwrap_or_default();
                for (i, u) in urls.enumerate() {
                    let key = if i == 0 { "KP2A_URL".to_owned() } else { format!("KP2A_URL_{i}") };
                    d.custom.push(CustomField { key, value: Zeroizing::new(u), protected: false });
                }
                for t in overview.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                    d.tags.push(t.to_owned());
                }
                if item.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0 {
                    d.tags.push("Favori".into());
                }
                if item.get("state").and_then(Value::as_str) == Some("archived") {
                    d.tags.push("Archivé".into());
                }
                d.notes = Zeroizing::new(s(details, "notesPlain"));
                if let Some(p) = details.get("password").and_then(Value::as_str) {
                    d.password = Zeroizing::new(p.to_owned());
                }
                for f in details.get("loginFields").and_then(Value::as_array).into_iter().flatten() {
                    let value = s(f, "value");
                    match f.get("designation").and_then(Value::as_str) {
                        Some("username") if d.username.is_empty() => d.username = value,
                        Some("password") if d.password.is_empty() => d.password = Zeroizing::new(value),
                        _ if value.is_empty() => {}
                        _ => {
                            let key = match s(f, "name") {
                                n if n.is_empty() => "Champ".to_owned(),
                                n => n,
                            };
                            d.custom.push(CustomField { key, value: Zeroizing::new(value), protected: s(f, "fieldType") == "P" });
                        }
                    }
                }
                for section in details.get("sections").and_then(Value::as_array).into_iter().flatten() {
                    let section_title = s(section, "title");
                    for f in section.get("fields").and_then(Value::as_array).into_iter().flatten() {
                        let value = &f["value"];
                        if let Some(file) = value.get("file").and_then(file_ref) {
                            files.push(file);
                            continue;
                        }
                        if let Some(totp) = value.get("totp").and_then(Value::as_str)
                            && d.otp.is_none()
                            && !totp.is_empty()
                        {
                            d.otp = normalize_otp(totp);
                            continue;
                        }
                        let Some((text, protected)) = field_value(value) else { continue };
                        let name = match (s(f, "title"), s(f, "id")) {
                            (t, _) if !t.is_empty() => t,
                            (_, id) if !id.is_empty() => id,
                            _ => "Champ".to_owned(),
                        };
                        let key = if section_title.is_empty() { name } else { format!("{section_title} : {name}") };
                        d.custom.push(CustomField { key, value: Zeroizing::new(text), protected });
                    }
                }
                if let Some(doc) = details.get("documentAttributes").and_then(file_ref) {
                    files.push(doc);
                }
                // Pièces jointes : « files/<documentId>__<nom> » dans l'archive.
                let mut attachments = Vec::new();
                for (doc_id, file_name) in files {
                    let prefix = format!("files/{doc_id}");
                    let Some(path) = names.iter().find(|n| n.starts_with(&prefix)) else {
                        out.warn(format!("« {} » : pièce jointe « {file_name} » absente de l'archive", d.title));
                        continue;
                    };
                    let Some(i) = index(path, &archive) else { continue };
                    let budget = MAX_ATTACHMENT_BYTES.min(MAX_TOTAL_FILES_BYTES.saturating_sub(files_read));
                    match read_capped(&mut archive, i, budget)? {
                        Some(bytes) => {
                            files_read += bytes.len();
                            let name = if file_name.is_empty() { path.rsplit("__").next().unwrap_or("fichier").to_owned() } else { file_name };
                            attachments.push((name, bytes));
                        }
                        None => out.warn(format!("« {} » : pièce jointe « {file_name} » trop volumineuse, ignorée", d.title)),
                    }
                }
                out.push(ImportedEntry { path: base.clone(), data: d, attachments, excluded_from_reports: false })?;
            }
        }
    }
    Ok(out)
}
