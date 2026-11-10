//! Imports : CSV, coffre KeePass (.kdbx), Bitwarden (JSON non chiffré),
//! 1Password (.1pux).
//!
//! Chaque format est d'abord converti dans un modèle neutre
//! ([`Imported`]), puis nettoyé et inséré dans un nouveau groupe. Règles :
//!
//! - un secret (mot de passe, 2FA, attribut protégé) n'est **jamais** modifié :
//!   s'il ne peut pas être enregistré tel quel, l'entrée est ignorée et
//!   signalée ; une 2FA illisible est gardée comme attribut protégé ;
//! - les champs visibles (titre, noms, étiquettes…) sont nettoyés (caractères
//!   de contrôle ou d'usurpation retirés, longueur bornée) ;
//! - l'import est tout ou rien : il travaille sur une copie du coffre ;
//! - les avertissements ne citent que des titres, jamais un secret.
//!
//! Limite connue : les analyseurs (CSV, JSON, zip) gardent des copies
//! intermédiaires du fichier en mémoire sans les effacer.

mod bitwarden;
mod csv;
mod kdbx;
mod onepux;

use std::collections::HashMap;

use keepass::db::EntryId;
use zeroize::Zeroizing;

pub use self::csv::parse_csv;
pub use bitwarden::parse_bitwarden;
pub use kdbx::from_vault as parse_kdbx;
pub use onepux::parse_1pux;

use super::{
    CustomField, EntryData, MAX_FIELD_BYTES, MAX_NAME_BYTES, MAX_NOTES_BYTES, MAX_TAG_BYTES, MAX_TAGS, STANDARD_FIELDS, Vault,
    invalid_xml_char, parse_id, spoofing_char,
};
use crate::{Error, Result, otp::Totp};

/// Taille maximale d'un fichier à importer (CSV, JSON, export.data).
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;
/// Nombre maximal d'entrées par import.
pub const MAX_IMPORT_ENTRIES: usize = 100_000;
/// Profondeur maximale des groupes importés (au-delà, la fin du chemin est
/// réunie dans un seul nom).
const MAX_IMPORT_DEPTH: usize = 16;
const MAX_CUSTOM_FIELDS: usize = 256;
const MAX_WARNINGS: usize = 200;

/// Entrée lue dans un fichier étranger, avant nettoyage.
#[derive(Default)]
pub struct ImportedEntry {
    /// Groupes, du plus haut au plus bas (vide : directement dans le groupe d'import).
    pub path: Vec<String>,
    pub data: EntryData,
    pub attachments: Vec<(String, Zeroizing<Vec<u8>>)>,
    /// Exclue des rapports de santé dans le logiciel d'origine.
    pub excluded_from_reports: bool,
}

/// Résultat d'une lecture de fichier.
#[derive(Default)]
pub struct Imported {
    pub entries: Vec<ImportedEntry>,
    pub warnings: Vec<String>,
}

impl Imported {
    pub(crate) fn warn(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
    }

    pub(crate) fn push(&mut self, e: ImportedEntry) -> Result<()> {
        if self.entries.len() >= MAX_IMPORT_ENTRIES {
            return Err(Error::InvalidArgument("trop d'entrées à importer (100 000 au plus)"));
        }
        self.entries.push(e);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    /// Groupe créé pour l'import.
    pub group_id: String,
    pub imported: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

/// Retire les caractères interdits ou trompeurs et borne la longueur.
pub(crate) fn clean_name(s: &str, max_bytes: usize, fallback: &str) -> String {
    let cleaned: String = s.chars().filter(|&c| !(c.is_control() || invalid_xml_char(c) || spoofing_char(c))).collect();
    let cleaned = truncate(cleaned.trim(), max_bytes).trim().to_owned();
    if cleaned.is_empty() { fallback.to_owned() } else { cleaned }
}

/// Texte visible : seuls les caractères impossibles en XML sont retirés
/// (les retours à la ligne restent).
fn clean_text(s: &str, max_bytes: usize) -> (String, bool) {
    let cleaned: String = s.chars().filter(|&c| !invalid_xml_char(c)).collect();
    let cut = truncate(&cleaned, max_bytes).to_owned();
    let changed = cut != s;
    (cut, changed)
}

fn truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn secret_ok(s: &str, max_bytes: usize) -> bool {
    s.len() <= max_bytes && !s.chars().any(invalid_xml_char)
}

/// Clé TOTP brute (base32) → URI `otpauth://`, comme le font la plupart des
/// gestionnaires à l'import.
pub(crate) fn normalize_otp(raw: &str) -> Option<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.to_ascii_lowercase().starts_with("otpauth://") {
        return Some(Zeroizing::new(raw.to_owned()));
    }
    let secret: Zeroizing<String> = Zeroizing::new(raw.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_uppercase());
    if secret.len() >= 16 && secret.trim_end_matches('=').chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Some(Zeroizing::new(format!("otpauth://totp/KittyPass?secret={}", secret.trim_end_matches('='))));
    }
    // Inconnu (steam://…) : gardé tel quel, la validation le déplacera.
    Some(Zeroizing::new(raw.to_owned()))
}

/// Nom d'attribut libre : pas un champ standard, pas de doublon.
fn unique_key(key: &str, taken: &[CustomField]) -> String {
    let base = clean_name(key, MAX_NAME_BYTES - 16, "Attribut");
    let base = if STANDARD_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(&base)) { format!("{base} (importé)") } else { base };
    let mut candidate = base.clone();
    let mut n = 2;
    while taken.iter().any(|c| c.key == candidate) {
        candidate = format!("{base} ({n})");
        n += 1;
    }
    candidate
}

/// Prépare une entrée pour le coffre. `Err(raison)` : entrée à ignorer.
fn clean_entry(e: &mut ImportedEntry, warnings: &mut Vec<String>) -> std::result::Result<(), String> {
    let d = &mut e.data;
    let (title, _) = clean_text(&d.title, 1024);
    d.title = title.replace(['\n', '\r', '\t'], " ").trim().to_owned();
    if d.title.is_empty() {
        d.title = if !d.url.is_empty() { host_of(&d.url) } else { d.username.clone() };
        d.title = clean_name(&d.title, 1024, "Sans titre");
    }
    let label = format!("« {} »", truncate(&d.title, 80));
    if !secret_ok(&d.password, MAX_FIELD_BYTES) {
        return Err(format!("{label} ignorée : mot de passe trop long ou avec des caractères interdits"));
    }
    if !secret_ok(&d.notes, MAX_NOTES_BYTES) {
        return Err(format!("{label} ignorée : notes trop longues ou avec des caractères interdits"));
    }
    for (field, name) in [(&mut d.username, "identifiant"), (&mut d.url, "URL")] {
        let (v, changed) = clean_text(field, MAX_FIELD_BYTES);
        if changed {
            warnings.push(format!("{label} : {name} nettoyé"));
        }
        *field = v;
    }
    // 2FA : gardée comme attribut protégé si elle n'est pas un otpauth valide.
    if let Some(otp) = d.otp.take() {
        if !secret_ok(&otp, MAX_FIELD_BYTES) {
            return Err(format!("{label} ignorée : 2FA avec des caractères interdits"));
        }
        if Totp::parse(&otp).is_ok() {
            d.otp = Some(otp);
        } else {
            warnings.push(format!("{label} : 2FA non reconnue, gardée dans l'attribut « TOTP importé »"));
            let key = unique_key("TOTP importé", &d.custom);
            d.custom.push(CustomField { key, value: otp, protected: true });
        }
    }
    // Attributs.
    let mut custom: Vec<CustomField> = Vec::new();
    for c in std::mem::take(&mut d.custom) {
        if custom.len() >= MAX_CUSTOM_FIELDS {
            warnings.push(format!("{label} : attributs au-delà de {MAX_CUSTOM_FIELDS} ignorés"));
            break;
        }
        if c.protected && !secret_ok(&c.value, MAX_NOTES_BYTES) {
            return Err(format!("{label} ignorée : attribut protégé trop long ou avec des caractères interdits"));
        }
        let value = if c.protected {
            c.value
        } else {
            let (v, changed) = clean_text(&c.value, MAX_NOTES_BYTES);
            if changed {
                warnings.push(format!("{label} : attribut nettoyé"));
            }
            Zeroizing::new(v)
        };
        let key = unique_key(&c.key, &custom);
        custom.push(CustomField { key, value, protected: c.protected });
    }
    d.custom = custom;
    // Étiquettes.
    let mut tags: Vec<String> = Vec::new();
    for t in std::mem::take(&mut d.tags) {
        let t = clean_name(&t.replace([';', ','], " "), MAX_TAG_BYTES, "");
        if !t.is_empty() && !tags.iter().any(|o| o.to_lowercase() == t.to_lowercase()) && tags.len() < MAX_TAGS {
            tags.push(t);
        }
    }
    d.tags = tags;
    if let Some(t) = d.expires
        && !(super::MIN_TIMESTAMP..=super::MAX_TIMESTAMP).contains(&t)
    {
        warnings.push(format!("{label} : date d'expiration hors limites ignorée"));
        d.expires = None;
    }
    Ok(())
}

pub(crate) fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or_default().rsplit('@').next().unwrap_or_default().to_owned()
}

/// Nom de pièce jointe sans séparateur de chemin, unique dans l'entrée.
fn clean_file_name(name: &str, taken: &[String]) -> String {
    let base = clean_name(&name.replace(['/', '\\'], "_"), MAX_NAME_BYTES - 8, "fichier");
    let base = if matches!(base.as_str(), "." | "..") { "fichier".to_owned() } else { base };
    let mut candidate = base.clone();
    let mut n = 2;
    while taken.contains(&candidate) {
        candidate = match base.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
            _ => format!("{base} ({n})"),
        };
        n += 1;
    }
    candidate
}

impl Vault {
    /// Insère `imported` dans un nouveau groupe `name` sous `parent_id`.
    /// Tout ou rien : en cas d'erreur, le coffre est inchangé.
    pub fn import(&mut self, parent_id: &str, name: &str, imported: Imported) -> Result<ImportReport> {
        let mut work = self.clone();
        let report = work.import_into(parent_id, name, imported)?;
        *self = work;
        Ok(report)
    }

    fn import_into(&mut self, parent_id: &str, name: &str, imported: Imported) -> Result<ImportReport> {
        let root = self.add_group(parent_id, &clean_name(name, MAX_NAME_BYTES, "Import"))?;
        let mut warnings = imported.warnings;
        let mut groups: HashMap<Vec<String>, String> = HashMap::new();
        let (mut done, mut skipped) = (0, 0);
        for mut e in imported.entries {
            if let Err(why) = clean_entry(&mut e, &mut warnings) {
                warnings.push(why);
                skipped += 1;
                continue;
            }
            // Groupes : créés au besoin, noms nettoyés, profondeur bornée.
            let mut path: Vec<String> = e.path.iter().map(|p| clean_name(p, MAX_NAME_BYTES, "Sans nom")).collect();
            if path.len() > MAX_IMPORT_DEPTH {
                let tail = path.split_off(MAX_IMPORT_DEPTH - 1).join(" / ");
                path.push(clean_name(&tail, MAX_NAME_BYTES, "Sans nom"));
            }
            let mut gid = root.clone();
            for i in 0..path.len() {
                let key = path[..=i].to_vec();
                gid = match groups.get(&key) {
                    Some(g) => g.clone(),
                    None => {
                        let g = self.add_group(&gid, &path[i])?;
                        groups.insert(key, g.clone());
                        g
                    }
                };
            }
            let label = format!("« {} »", truncate(&e.data.title, 80));
            let id = match self.add_in(&gid, &e.data) {
                Ok(id) => id,
                Err(err) => {
                    warnings.push(format!("{label} ignorée : {err}"));
                    skipped += 1;
                    continue;
                }
            };
            let mut names: Vec<String> = Vec::new();
            for (name, data) in e.attachments {
                let name = clean_file_name(&name, &names);
                match self.add_attachment(&id, &name, &data) {
                    Ok(()) => names.push(name),
                    Err(err) => warnings.push(format!("{label} : pièce jointe « {name} » ignorée ({err})")),
                }
            }
            if e.excluded_from_reports {
                self.mark_excluded_without_history(&id)?;
            }
            done += 1;
        }
        if warnings.len() > MAX_WARNINGS {
            let more = warnings.len() - MAX_WARNINGS;
            warnings.truncate(MAX_WARNINGS);
            warnings.push(format!("… et {more} autre(s) avertissement(s)"));
        }
        Ok(ImportReport { group_id: root, imported: done, skipped, warnings })
    }

    /// Entrée tout juste importée : pas besoin d'une version d'historique.
    fn mark_excluded_without_history(&mut self, id: &str) -> Result<()> {
        let eid: EntryId = parse_id(id)?;
        let mut e = self.db.entry_mut(eid).ok_or(Error::EntryNotFound)?;
        e.quality_check = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_otp() {
        assert_eq!(clean_name("  a\u{202e}b\0c  ", 256, "x"), "abc");
        assert_eq!(clean_name("\u{200b}", 256, "x"), "x");
        assert_eq!(clean_name(&"é".repeat(300), 10, "x"), "ééééé");
        assert_eq!(clean_file_name("../../etc/passwd", &[]), ".._.._etc_passwd");
        assert_eq!(clean_file_name("..", &[]), "fichier");
        assert_eq!(clean_file_name("a.pdf", &["a.pdf".into()]), "a (2).pdf");
        assert_eq!(normalize_otp("jbsw y3dp ehpk 3pxp").unwrap().as_str(), "otpauth://totp/KittyPass?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(normalize_otp("otpauth://totp/x?secret=A").unwrap().as_str(), "otpauth://totp/x?secret=A");
        assert!(normalize_otp("  ").is_none());
        assert_eq!(host_of("https://user@www.ex.org:8443/p?q"), "www.ex.org:8443");
        assert_eq!(unique_key("password", &[]), "password (importé)");
    }
}
