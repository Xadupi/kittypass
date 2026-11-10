//! Import CSV : colonnes reconnues par leur en-tête (exports de KeePassXC,
//! Chrome, Firefox, Bitwarden, LastPass, 1Password…), séparateur `,` `;` ou
//! tabulation, UTF-8 ou Windows-1252.

use zeroize::Zeroizing;

use super::{Imported, ImportedEntry, MAX_IMPORT_BYTES, normalize_otp};
use crate::{
    Error, Result,
    vault::{CustomField, EntryData},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Col {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Group,
    Totp,
    Tags,
    /// Champs supplémentaires de Bitwarden (`nom: valeur` par ligne).
    BitwardenFields,
    /// Colonne connue mais sans intérêt (dates, identifiants internes…).
    Ignored,
}

/// En-tête normalisé : minuscules, sans espaces, `_`, `-` ni accents courants.
fn normalize(h: &str) -> String {
    h.trim()
        .to_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-' | '.'))
        .map(|c| match c {
            'é' | 'è' | 'ê' => 'e',
            'à' => 'a',
            'î' => 'i',
            'ô' => 'o',
            c => c,
        })
        .collect()
}

fn column(header: &str) -> Option<Col> {
    Some(match normalize(header).as_str() {
        "title" | "name" | "account" | "accountname" | "itemname" | "nom" | "titre" => Col::Title,
        "username" | "user" | "login" | "loginusername" | "identifiant" | "utilisateur" | "nomdutilisateur" => Col::Username,
        "password" | "pass" | "loginpassword" | "motdepasse" | "pwd" => Col::Password,
        "url" | "website" | "uri" | "loginuri" | "site" | "siteweb" | "web" | "address" | "adresse" => Col::Url,
        "notes" | "note" | "extra" | "comments" | "comment" | "remarques" => Col::Notes,
        "group" | "folder" | "grouping" | "groupe" | "dossier" | "path" | "vault" => Col::Group,
        "totp" | "otp" | "logintotp" | "onetimepassword" | "otpauth" | "2fa" | "twofactorsecret" => Col::Totp,
        "tags" | "tag" | "labels" | "etiquettes" => Col::Tags,
        "fields" => Col::BitwardenFields,
        "lastmodified" | "created" | "icon" | "favorite" | "fav" | "type" | "reprompt" | "httprealm" | "formactionorigin"
        | "guid" | "timecreated" | "timelastused" | "timepasswordchanged" | "uuid" => Col::Ignored,
        _ => return None,
    })
}

/// Windows-1252 → Unicode (Excel enregistre souvent ainsi en France).
fn decode_cp1252(data: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž', '\u{8f}', '\u{90}', '‘', '’', '“',
        '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}', 'ž', 'Ÿ',
    ];
    data.iter()
        .map(|&b| match b {
            0x80..=0x9f => HIGH[usize::from(b - 0x80)],
            b => char::from(b),
        })
        .collect()
}

/// Séparateur le plus fréquent dans la ligne d'en-tête (hors guillemets).
fn delimiter(text: &str) -> u8 {
    let first = text.lines().next().unwrap_or_default();
    let mut counts = [0usize; 3];
    let mut quoted = false;
    for c in first.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => counts[0] += 1,
            ';' if !quoted => counts[1] += 1,
            '\t' if !quoted => counts[2] += 1,
            _ => {}
        }
    }
    let best = (0..3).max_by_key(|&i| (counts[i], 2 - i)).unwrap_or(0);
    b",;\t"[best]
}

pub fn parse_csv(data: &[u8]) -> Result<Imported> {
    if data.len() > MAX_IMPORT_BYTES {
        return Err(Error::TooLarge);
    }
    let mut out = Imported::default();
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    if data.starts_with(b"\xFF\xFE") || data.starts_with(b"\xFE\xFF") {
        return Err(Error::InvalidArgument("CSV en UTF-16 : enregistrez-le en UTF-8"));
    }
    let text = Zeroizing::new(match std::str::from_utf8(data) {
        Ok(t) => t.to_owned(),
        Err(_) => {
            out.warn("Fichier non UTF-8 : lu comme Windows-1252");
            decode_cp1252(data)
        }
    });
    let mut reader = ::csv::ReaderBuilder::new()
        .delimiter(delimiter(&text))
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let headers = reader.headers().map_err(|_| Error::InvalidArgument("CSV illisible"))?.clone();
    let cols: Vec<Option<Col>> = headers.iter().map(column).collect();
    let has = |c: Col| cols.contains(&Some(c));
    if !(has(Col::Password) || has(Col::Title)) || !(has(Col::Password) || has(Col::Username) || has(Col::Url)) {
        return Err(Error::InvalidArgument("CSV : en-têtes non reconnus (titre, identifiant, mot de passe, URL…)"));
    }
    let unknown: Vec<&str> = headers.iter().zip(&cols).filter(|(h, c)| c.is_none() && !h.trim().is_empty()).map(|(h, _)| h).collect();
    if !unknown.is_empty() {
        out.warn(format!("Colonnes ignorées : {}", unknown.join(", ")));
    }

    let mut rows: Vec<(Vec<String>, ImportedEntry)> = Vec::new();
    for (line, record) in reader.records().enumerate() {
        let record = match record {
            Ok(r) => r,
            Err(_) => {
                out.warn(format!("Ligne {} illisible, ignorée", line + 2));
                continue;
            }
        };
        if record.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let mut d = EntryData::default();
        let mut group = Vec::new();
        for (value, col) in record.iter().zip(&cols) {
            match col {
                Some(Col::Title) => d.title = value.to_owned(),
                Some(Col::Username) => d.username = value.to_owned(),
                Some(Col::Password) => d.password = Zeroizing::new(value.to_owned()),
                Some(Col::Url) => d.url = value.trim().to_owned(),
                Some(Col::Notes) => d.notes = Zeroizing::new(value.to_owned()),
                Some(Col::Group) => group = value.split('/').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect(),
                Some(Col::Totp) => d.otp = normalize_otp(value),
                Some(Col::Tags) => d.tags = value.split([',', ';']).map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect(),
                Some(Col::BitwardenFields) => {
                    for l in value.lines().filter(|l| !l.trim().is_empty()) {
                        let (k, v) = l.split_once(": ").unwrap_or((l, ""));
                        d.custom.push(CustomField { key: k.to_owned(), value: Zeroizing::new(v.to_owned()), protected: false });
                    }
                }
                Some(Col::Ignored) | None => {}
            }
        }
        rows.push((group, ImportedEntry { data: d, ..Default::default() }));
    }
    // Export KeePassXC : tous les groupes commencent par le groupe racine
    // (« Root/… ») : on le retire.
    let first = rows.iter().find_map(|(g, _)| g.first().cloned());
    if let Some(first) = first
        && rows.iter().all(|(g, _)| g.first() == Some(&first))
    {
        for (g, _) in &mut rows {
            g.remove(0);
        }
    }
    for (path, mut e) in rows {
        e.path = path;
        out.push(e)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimiters_and_encodings() {
        assert_eq!(delimiter("a;b;c\n1,2;3"), b';');
        assert_eq!(delimiter("\"a;b\",c,d"), b',');
        assert_eq!(delimiter("a\tb"), b'\t');
        assert_eq!(decode_cp1252(b"caf\xe9 \x80"), "café €");
        assert_eq!(normalize("Login_Username"), "loginusername");
        assert_eq!(column("Mot de passe"), Some(Col::Password));
    }
}
