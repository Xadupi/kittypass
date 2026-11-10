//! Générateur de mots de passe et de phrases de passe (aléa du système,
//! sans biais), options équivalentes à KeePassXC.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::{Error, Result, rng};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 1024;
/// Longueur maximale des listes « inclure » / « exclure ».
const MAX_CUSTOM_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// ASCII étendu (Latin-1 imprimable, U+00A1 à U+00FF sauf trait d'union
    /// conditionnel).
    pub extended: bool,
    pub exclude_ambiguous: bool,
    /// Caractères ajoutés à l'alphabet (« Inclure aussi » de KeePassXC).
    pub include: String,
    /// Caractères retirés de l'alphabet.
    pub exclude: String,
    /// Au moins un caractère de chaque classe choisie.
    pub every_group: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            extended: false,
            exclude_ambiguous: false,
            include: String::new(),
            exclude: String::new(),
            every_group: true,
        }
    }
}

fn extended_chars() -> impl Iterator<Item = char> {
    ('\u{A1}'..='\u{FF}').filter(|c| *c != '\u{AD}')
}

/// Caractère utilisable dans un alphabet personnalisé : visible, sans effet
/// de mise en page ni contrôle de direction.
fn usable_custom_char(c: char) -> bool {
    !c.is_control()
        && !c.is_whitespace()
        && !matches!(c, '\u{AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Classes de caractères effectives, sans doublon entre classes ; une classe
/// vidée par les exclusions disparaît.
fn classes(opts: &Options) -> Result<Vec<Vec<char>>> {
    if opts.include.chars().count() > MAX_CUSTOM_CHARS || opts.exclude.chars().count() > MAX_CUSTOM_CHARS {
        return Err(Error::InvalidArgument("liste de caractères trop longue"));
    }
    if !opts.include.chars().all(usable_custom_char) {
        return Err(Error::InvalidArgument("caractère personnalisé invalide"));
    }
    let builtin: [(bool, Vec<char>); 5] = [
        (opts.lower, LOWER.chars().collect()),
        (opts.upper, UPPER.chars().collect()),
        (opts.digits, DIGITS.chars().collect()),
        (opts.symbols, SYMBOLS.chars().collect()),
        (opts.extended, extended_chars().collect()),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let custom: Vec<char> = opts.include.chars().collect();
    for set in builtin.into_iter().filter(|(on, _)| *on).map(|(_, set)| set).chain([custom]) {
        let class: Vec<char> = set
            .into_iter()
            .filter(|c| !(opts.exclude_ambiguous && AMBIGUOUS.contains(*c)))
            .filter(|c| !opts.exclude.contains(*c))
            .filter(|c| seen.insert(*c))
            .collect();
        if !class.is_empty() {
            out.push(class);
        }
    }
    Ok(out)
}

/// Entropie (en bits) d'un mot de passe généré avec ces options.
/// Légère surestimation : on ignore la contrainte « une classe minimum ».
pub fn entropy_bits(opts: &Options) -> f64 {
    let alphabet: usize = classes(opts).map(|c| c.iter().map(Vec::len).sum()).unwrap_or(0);
    if alphabet == 0 {
        return 0.0;
    }
    opts.length as f64 * (alphabet as f64).log2()
}

/// Génère un mot de passe ; avec `every_group`, au moins un caractère de
/// chaque classe choisie.
pub fn generate(opts: &Options) -> Result<Zeroizing<String>> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) {
        return Err(Error::InvalidArgument("longueur hors limites"));
    }
    let classes = classes(opts)?;
    if classes.is_empty() {
        return Err(Error::InvalidArgument("aucune classe de caractères"));
    }
    if opts.every_group && classes.len() > opts.length {
        return Err(Error::InvalidArgument("longueur inférieure au nombre de classes"));
    }
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();

    let mut chars = Zeroizing::new(Vec::with_capacity(opts.length));
    if opts.every_group {
        for class in &classes {
            chars.push(class[rng::below(class.len() as u32)? as usize]);
        }
    }
    while chars.len() < opts.length {
        chars.push(alphabet[rng::below(alphabet.len() as u32)? as usize]);
    }
    // Mélange de Fisher-Yates : les caractères imposés ne restent pas en tête.
    for i in (1..chars.len()).rev() {
        let j = rng::below(i as u32 + 1)? as usize;
        chars.swap(i, j);
    }
    Ok(Zeroizing::new(chars.iter().collect()))
}

// ---------------------------------------------------------------- phrases de passe

pub const MIN_WORDS: usize = 1;
pub const MAX_WORDS: usize = 100;
const MAX_SEPARATOR_CHARS: usize = 16;

/// Casse des mots d'une phrase de passe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WordCase {
    #[default]
    Lower,
    Upper,
    /// Première lettre de chaque mot en majuscule.
    Title,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub case: WordCase,
}

impl Default for PassphraseOptions {
    /// Valeurs par défaut de KeePassXC : 7 mots (≈ 90 bits).
    fn default() -> Self {
        Self { words: 7, separator: " ".into(), case: WordCase::Lower }
    }
}

/// Liste EFF (version KeePassXC, voir `core/data/README.md`).
fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("../data/eff_large.wordlist")
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

pub fn passphrase_entropy_bits(opts: &PassphraseOptions) -> f64 {
    opts.words as f64 * (wordlist().len() as f64).log2()
}

pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&opts.words) {
        return Err(Error::InvalidArgument("nombre de mots hors limites"));
    }
    if opts.separator.chars().count() > MAX_SEPARATOR_CHARS
        || opts.separator.chars().any(|c| c != ' ' && !usable_custom_char(c))
    {
        return Err(Error::InvalidArgument("séparateur invalide"));
    }
    let list = wordlist();
    let mut out = Zeroizing::new(String::new());
    for i in 0..opts.words {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = list[rng::below(list.len() as u32)? as usize];
        match opts.case {
            WordCase::Lower => out.push_str(word),
            WordCase::Upper => out.push_str(&word.to_uppercase()),
            WordCase::Title => {
                let mut chars = word.chars();
                if let Some(first) = chars.next() {
                    out.extend(first.to_uppercase());
                    out.push_str(chars.as_str());
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn respects_length_and_classes() {
        let opts = Options::default();
        for _ in 0..500 {
            let p = generate(&opts).unwrap();
            assert_eq!(p.chars().count(), 20);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn only_selected_classes() {
        let opts = Options { lower: false, upper: false, symbols: false, length: 64, ..Default::default() };
        let p = generate(&opts).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn excludes_ambiguous() {
        let opts = Options { exclude_ambiguous: true, length: 1024, ..Default::default() };
        for _ in 0..20 {
            let p = generate(&opts).unwrap();
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)), "{}", p.as_str());
        }
    }

    #[test]
    fn rejects_bad_options() {
        assert!(generate(&Options { length: 0, ..Default::default() }).is_err());
        assert!(generate(&Options { length: MIN_LENGTH - 1, ..Default::default() }).is_err());
        assert!(generate(&Options { length: MAX_LENGTH + 1, ..Default::default() }).is_err());
        assert!(generate(&Options { length: usize::MAX, ..Default::default() }).is_err());
        let none = Options { lower: false, upper: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate(&none).is_err());
    }

    #[test]
    fn no_duplicates_in_many_runs() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(generate(&Options::default()).unwrap().to_string()));
        }
    }

    /// Chaque caractère de l'alphabet doit apparaître avec une fréquence proche
    /// de l'uniforme (détecte un biais de modulo ou un mélange raté).
    #[test]
    fn character_distribution_is_uniform() {
        let opts = Options { upper: false, digits: false, symbols: false, length: 1000, ..Default::default() };
        let mut counts: HashMap<char, u32> = HashMap::new();
        for _ in 0..100 {
            for c in generate(&opts).unwrap().chars() {
                *counts.entry(c).or_default() += 1;
            }
        }
        assert_eq!(counts.len(), 26);
        let expected = 100_000.0 / 26.0;
        let chi2: f64 = counts.values().map(|&c| (c as f64 - expected).powi(2) / expected).sum();
        // 25 degrés de liberté : p = 0.0001 vers 59.
        assert!(chi2 < 59.0, "chi2 = {chi2}");
    }

    /// Les caractères imposés (un par classe) ne doivent pas rester en tête.
    #[test]
    fn first_position_is_not_always_lowercase() {
        let opts = Options::default();
        let lower_first = (0..2000)
            .filter(|_| generate(&opts).unwrap().chars().next().unwrap().is_ascii_lowercase())
            .count();
        // Proba attendue ≈ 26/94 = 0.28.
        assert!((400..750).contains(&lower_first), "{lower_first}");
    }

    #[test]
    fn entropy_default_is_strong() {
        assert!(entropy_bits(&Options::default()) > 128.0);
    }

    #[test]
    fn include_exclude_and_extended() {
        let opts = Options {
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            include: "€é".into(),
            exclude: "0123".into(),
            length: 500,
            ..Default::default()
        };
        let p = generate(&opts).unwrap();
        assert!(p.chars().all(|c| "456789€é".contains(c)), "{}", p.as_str());
        assert!(p.contains('€') || p.contains('é'), "classe personnalisée absente");

        let ext = Options { extended: true, length: 1000, ..Default::default() };
        let p = generate(&ext).unwrap();
        assert!(p.chars().any(|c| ('\u{A1}'..='\u{FF}').contains(&c)));
        assert!(!p.contains('\u{AD}'), "trait d'union conditionnel invisible");
    }

    #[test]
    fn exclusions_can_empty_a_class_or_everything() {
        // Tous les chiffres exclus : la classe disparaît, pas d'erreur.
        let opts = Options { exclude: DIGITS.into(), ..Default::default() };
        assert!(!generate(&opts).unwrap().chars().any(|c| c.is_ascii_digit()));
        let all = Options {
            upper: false,
            symbols: false,
            exclude: format!("{LOWER}{DIGITS}"),
            ..Default::default()
        };
        assert!(generate(&all).is_err());
    }

    #[test]
    fn hostile_custom_chars_are_refused() {
        for bad in ["a\u{0}", "\u{202E}", "a b", "\n", "\u{200B}", &"x".repeat(257)] {
            let opts = Options { include: bad.into(), ..Default::default() };
            assert!(generate(&opts).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_group_needs_enough_length() {
        let opts = Options { extended: true, include: "€".into(), length: 8, ..Default::default() };
        // 6 classes pour 8 caractères : possible.
        let p = generate(&opts).unwrap();
        assert!(p.contains('€'));
        let off = Options { every_group: false, length: 8, ..Default::default() };
        assert_eq!(generate(&off).unwrap().chars().count(), 8);
    }

    // ------------------------------------------------ phrases de passe

    #[test]
    fn wordlist_is_the_eff_list() {
        let list = wordlist();
        assert_eq!(list.len(), 7772);
        assert!(list.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())));
        let unique: HashSet<_> = list.iter().collect();
        assert_eq!(unique.len(), list.len());
    }

    #[test]
    fn passphrase_shape_and_case() {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        let words: Vec<_> = p.split(' ').collect();
        assert_eq!(words.len(), 7);
        assert!(words.iter().all(|w| wordlist().contains(w)));

        let t = generate_passphrase(&PassphraseOptions { case: WordCase::Title, separator: "-".into(), words: 5 }).unwrap();
        assert!(t.split('-').all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        let u = generate_passphrase(&PassphraseOptions { case: WordCase::Upper, separator: "".into(), words: 4 }).unwrap();
        assert!(u.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn passphrase_rejects_bad_options() {
        for words in [0, MAX_WORDS + 1, usize::MAX] {
            assert!(generate_passphrase(&PassphraseOptions { words, ..Default::default() }).is_err());
        }
        for sep in ["\u{0}", "\n", "\u{202E}", &"-".repeat(17)] {
            assert!(generate_passphrase(&PassphraseOptions { separator: sep.into(), ..Default::default() }).is_err());
        }
    }

    #[test]
    fn passphrase_entropy() {
        let bits = passphrase_entropy_bits(&PassphraseOptions::default());
        assert!((90.0..91.0).contains(&bits), "{bits}");
    }

    /// Les mots doivent être tirés uniformément (chi² sur les premières
    /// lettres, pondéré par leur fréquence dans la liste).
    #[test]
    fn passphrase_words_are_uniform() {
        let list = wordlist();
        let mut expected: HashMap<char, f64> = HashMap::new();
        for w in list {
            *expected.entry(w.chars().next().unwrap()).or_default() += 1.0 / list.len() as f64;
        }
        let n = 40_000;
        let mut counts: HashMap<char, f64> = HashMap::new();
        let p = generate_passphrase(&PassphraseOptions { words: n, ..Default::default() });
        assert!(p.is_err(), "MAX_WORDS doit borner");
        for _ in 0..n / 100 {
            let p = generate_passphrase(&PassphraseOptions { words: 100, ..Default::default() }).unwrap();
            for w in p.split(' ') {
                *counts.entry(w.chars().next().unwrap()).or_default() += 1.0;
            }
        }
        let chi2: f64 = expected
            .iter()
            .map(|(c, p)| {
                let e = p * n as f64;
                (counts.get(c).copied().unwrap_or(0.0) - e).powi(2) / e
            })
            .sum();
        // ~25 degrés de liberté : p = 0.0001 vers 59.
        assert!(chi2 < 59.0, "chi2 = {chi2}");
    }
}
