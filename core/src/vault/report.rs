//! Rapport de santé des mots de passe (« Bilan de santé » de KeePassXC) :
//! robustesse, réutilisation, expiration, et préparation de la vérification
//! Have I Been Pwned.
//!
//! La robustesse est estimée par zxcvbn, comme KeePassXC, avec les mêmes
//! seuils de qualité. Limite connue : zxcvbn copie le mot de passe dans des
//! chaînes qu'il n'efface pas (même défaut que la version C de KeePassXC).

use std::collections::HashMap;

use keepass::db::{CustomDataItem, CustomDataValue, Entry, Times};
use zeroize::Zeroizing;

use super::{EntrySummary, Vault, parse_id, summary};
use crate::{Error, Result, hibp};

/// Ancienne clé de donnée personnalisée de KeePassXC (≤ 2.6) pour exclure une
/// entrée des rapports. Depuis KDBX 4.1, le champ standard est
/// `QualityCheck = False` (KeePass 2.48+, KeePassXC 2.7+). On lit les deux
/// et on écrit les deux.
pub const EXCLUDE_FROM_REPORTS: &str = "KnownBad";

/// Les entrées titre/identifiant/URL passées à zxcvbn sont tronquées : elles
/// servent de dictionnaire et ne doivent pas rallonger le calcul.
const MAX_USER_INPUT_CHARS: usize = 100;

/// Qualité d'un mot de passe, seuils de KeePassXC (en bits d'entropie
/// estimée par zxcvbn).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quality {
    Bad,
    Poor,
    Weak,
    Good,
    Excellent,
}

impl Quality {
    pub fn from_bits(bits: f64) -> Self {
        match bits {
            b if b <= 0.0 || b.is_nan() => Self::Bad,
            b if b < 40.0 => Self::Poor,
            b if b < 75.0 => Self::Weak,
            b if b < 100.0 => Self::Good,
            _ => Self::Excellent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// log2 du nombre d'essais estimé (0 pour un mot de passe vide).
    pub bits: f64,
    pub quality: Quality,
}

/// Robustesse d'un mot de passe. `user_inputs` (titre, identifiant, URL…)
/// pénalise un mot de passe qui les reprend.
pub fn strength(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength { bits: 0.0, quality: Quality::Bad };
    }
    let inputs: Vec<String> = user_inputs
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_USER_INPUT_CHARS).collect())
        .collect();
    let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let estimate = zxcvbn::zxcvbn(password, &inputs);
    // Comme zxcvbn-c (KeePassXC) : somme de l'entropie des motifs trouvés,
    // les segments sans motif comptant selon les jeux de caractères
    // réellement utilisés. zxcvbn-rs, lui, compte 10 possibilités par
    // caractère et plafonne à 64 bits (u64), ce qui classerait « faible » un
    // mot de passe aléatoire de 20 caractères.
    let per_char = charset_bits(password);
    let bits: f64 = estimate
        .sequence()
        .iter()
        .map(|m| match m.pattern {
            zxcvbn::matching::patterns::MatchPattern::BruteForce => m.token.chars().count() as f64 * per_char,
            _ => (m.guesses.unwrap_or(1).max(1) as f64).log2(),
        })
        .sum();
    let bits = if bits.is_finite() { bits.max(0.0) } else { 0.0 };
    Strength { bits, quality: Quality::from_bits(bits) }
}

/// log2 de la taille de l'alphabet utilisé par le mot de passe (les 100
/// premiers caractères, comme zxcvbn).
fn charset_bits(password: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut symbol, mut other) = (false, false, false, false, false);
    for c in password.chars().take(100) {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            ' '..='~' => symbol = true,
            _ => other = true,
        }
    }
    let size = 26 * u32::from(lower) + 26 * u32::from(upper) + 10 * u32::from(digit) + 33 * u32::from(symbol) + 100 * u32::from(other);
    f64::from(size.max(1)).log2()
}

/// Ligne du rapport : une entrée qui pose au moins un problème.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthItem {
    pub entry: EntrySummary,
    pub bits: f64,
    pub quality: Quality,
    /// Nombre d'**autres** entrées qui ont le même mot de passe.
    pub reused: usize,
    pub expired: bool,
    /// Entrée marquée « exclure des rapports » : l'interface la masque par défaut.
    pub excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HealthReport {
    /// Entrées à problème, de la pire à la moins grave.
    pub items: Vec<HealthItem>,
    /// Entrées analysées (hors corbeille, avec un mot de passe).
    pub checked: usize,
    /// Entrées analysées mais exclues des rapports.
    pub excluded: usize,
}

/// Empreinte SHA-1 du mot de passe d'une entrée, pour Have I Been Pwned.
pub struct PasswordHash {
    pub id: String,
    pub sha1: Zeroizing<String>,
    pub excluded: bool,
}

/// zxcvbn prend jusqu'à ~10 ms pour un long mot de passe : calcul réparti
/// sur les cœurs disponibles (8 au plus). `[mot de passe, titre, identifiant, URL]`.
fn parallel_strengths(items: &[[&str; 4]]) -> Vec<Strength> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 8);
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| scope.spawn(move || c.iter().map(|[p, t, u, l]| strength(p, &[t, u, l])).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

fn is_excluded(e: &Entry) -> bool {
    !e.quality_check
        || matches!(
            e.custom_data.get(EXCLUDE_FROM_REPORTS).and_then(|i| i.value.as_ref()),
            Some(CustomDataValue::String(s)) if s.eq_ignore_ascii_case("true")
        )
}

impl Vault {
    /// Entrées hors corbeille qui ont un mot de passe.
    fn live_entries_with_password(&self) -> impl Iterator<Item = keepass::db::EntryRef<'_>> {
        let bin = self.existing_recycle_bin();
        self.db
            .iter_all_entries()
            .filter(move |e| bin.is_none_or(|bin| !self.group_is_within(e.parent().id(), bin)))
            .filter(|e| e.get_password().is_some_and(|p| !p.is_empty()))
    }

    /// Bilan de santé : mots de passe faibles (qualité ≤ Faible), réutilisés,
    /// ou entrées expirées. Les entrées sans mot de passe sont ignorées.
    pub fn health_report(&self) -> HealthReport {
        let entries: Vec<_> = self.live_entries_with_password().collect();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in &entries {
            *counts.entry(e.get_password().unwrap_or_default()).or_default() += 1;
        }
        let inputs: Vec<[&str; 4]> = entries
            .iter()
            .map(|e| {
                [
                    e.get_password().unwrap_or_default(),
                    e.get_title().unwrap_or_default(),
                    e.get_username().unwrap_or_default(),
                    e.get_url().unwrap_or_default(),
                ]
            })
            .collect();
        let strengths = parallel_strengths(&inputs);
        let mut report = HealthReport { checked: entries.len(), ..Default::default() };
        for (e, s) in entries.iter().zip(strengths) {
            let password = e.get_password().unwrap_or_default();
            let reused = counts.get(password).copied().unwrap_or(1) - 1;
            let entry = summary(e);
            let excluded = is_excluded(e);
            report.excluded += usize::from(excluded);
            if s.quality <= Quality::Weak || reused > 0 || entry.expired {
                report.items.push(HealthItem { expired: entry.expired, entry, bits: s.bits, quality: s.quality, reused, excluded });
            }
        }
        report.items.sort_by(|a, b| {
            (a.quality, a.bits, std::cmp::Reverse(a.reused))
                .partial_cmp(&(b.quality, b.bits, std::cmp::Reverse(b.reused)))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.entry.title.to_lowercase().cmp(&b.entry.title.to_lowercase()))
        });
        report
    }

    /// Empreintes SHA-1 des mots de passe (hors corbeille), à vérifier auprès
    /// de Have I Been Pwned. Seuls les 5 premiers caractères partent sur le
    /// réseau (voir [`hibp`]).
    pub fn password_hashes(&self) -> Vec<PasswordHash> {
        self.live_entries_with_password()
            .map(|e| PasswordHash {
                id: e.id().uuid().to_string(),
                sha1: hibp::sha1_hex(e.get_password().unwrap_or_default()),
                excluded: is_excluded(&e),
            })
            .collect()
    }

    pub fn excluded_from_reports(&self, id: &str) -> Result<bool> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(is_excluded(&e))
    }

    /// Exclut une entrée des rapports, ou l'y réintègre (nouvelle version de
    /// l'entrée, comme dans KeePassXC). Sans effet si rien ne change.
    pub fn set_excluded_from_reports(&mut self, id: &str, excluded: bool) -> Result<()> {
        if self.excluded_from_reports(id)? == excluded {
            return Ok(());
        }
        self.edit_entry(parse_id(id)?, |e| {
            e.quality_check = !excluded;
            if excluded {
                e.custom_data.insert(
                    EXCLUDE_FROM_REPORTS.to_owned(),
                    CustomDataItem {
                        value: Some(CustomDataValue::String("true".to_owned())),
                        last_modification_time: Some(Times::now()),
                    },
                );
            } else {
                e.custom_data.remove(EXCLUDE_FROM_REPORTS);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Applique `f` à une entrée neuve puis renvoie `is_excluded`.
    fn excluded_after(f: impl FnOnce(&mut Entry)) -> bool {
        let mut v = Vault::create("mot-de-passe-test").unwrap();
        let id = v.add(&super::super::EntryData { title: "t".into(), ..Default::default() }).unwrap();
        f(&mut v.db.entry_mut(parse_id(&id).unwrap()).unwrap());
        v.excluded_from_reports(&id).unwrap()
    }

    fn known_bad(value: CustomDataValue) -> impl FnOnce(&mut Entry) {
        move |e| {
            e.custom_data.insert(EXCLUDE_FROM_REPORTS.into(), CustomDataItem { value: Some(value), last_modification_time: None });
        }
    }

    #[test]
    fn exclusion_markers() {
        assert!(!excluded_after(|_| {}));
        // Ancien KeePassXC : seule la clé KnownBad.
        assert!(excluded_after(known_bad(CustomDataValue::String("true".into()))));
        assert!(excluded_after(known_bad(CustomDataValue::String("True".into()))));
        assert!(!excluded_after(known_bad(CustomDataValue::String("false".into()))));
        assert!(!excluded_after(known_bad(CustomDataValue::Binary(b"true".to_vec()))));
        // KDBX 4.1 : QualityCheck = False.
        assert!(excluded_after(|e| e.quality_check = false));
    }

    #[test]
    fn charset_and_strength_edges() {
        assert_eq!(strength("", &["x"]).quality, Quality::Bad);
        // Un mot de passe identique à l'identifiant ne vaut presque rien.
        assert!(strength("Zorglub-Marseille-1987", &["Zorglub-Marseille-1987"]).bits < 10.0);
        assert!((charset_bits("abc") - 26f64.log2()).abs() < 1e-9);
        assert!((charset_bits("aB3!") - 95f64.log2()).abs() < 1e-9);
        assert!((charset_bits("é") - 100f64.log2()).abs() < 1e-9);
    }
}
