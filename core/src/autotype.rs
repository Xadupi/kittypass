//! Séquences de saisie automatique, syntaxe KeePass / KeePassXC :
//! `{USERNAME}{TAB}{PASSWORD}{ENTER}`.
//!
//! - champs : `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{NOTES}`,
//!   `{TOTP}`, `{S:Nom}` (attribut personnalisé) ; leur valeur est tapée
//!   telle quelle, sans être réinterprétée ;
//! - touches : `{TAB}`, `{ENTER}` (ou `~`), `{SPACE}`, `{BACKSPACE}`,
//!   `{DELETE}`, `{ESC}`, flèches, `{F1}`…`{F16}`… avec répétition
//!   `{TAB 3}` ;
//! - modificateurs devant une touche ou un caractère : `+` Maj, `^` Ctrl,
//!   `%` Alt, `#` Super ; `{+}`, `{^}`, `{%}`, `{~}`, `{#}`, `{{}`, `{}}`
//!   tapent le caractère lui-même ;
//! - `{DELAY 500}` (pause en ms), `{DELAY=50}` (délai entre touches),
//!   `{CLEARFIELD}` (vide le champ).
//!
//! Tout le reste (`{CMD}`, `{REF}`…) est refusé : une séquence ne lance
//! jamais de programme et ne lit que l'entrée choisie.

use std::fmt;

use zeroize::Zeroizing;

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Longueur maximale d'une séquence écrite par l'utilisateur.
pub const MAX_SEQUENCE_LEN: usize = 1024;
const MAX_REPEAT: u32 = 100;
pub const MAX_DELAY_MS: u32 = 10_000;
/// Nombre maximal de touches d'une saisie, valeurs des champs comprises.
const MAX_STEPS: usize = 20_000;

/// Touches spéciales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Tab,
    Enter,
    Space,
    Backspace,
    Delete,
    Insert,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    /// F1 à F16.
    F(u8),
}

/// Modificateurs tenus pendant une touche.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mods {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
}

impl Mods {
    pub fn is_empty(&self) -> bool {
        !(self.shift || self.ctrl || self.alt || self.meta)
    }
}

/// Une action de la saisie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Caractère à taper (les modificateurs s'ajoutent à ceux qu'il demande).
    Char(char, Mods),
    Key(Key, Mods),
    /// Pause, en millisecondes.
    Delay(u32),
    /// Nouveau délai entre deux touches, en millisecondes.
    KeyDelay(u32),
}

/// Champ de l'entrée lu par un paramètre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Totp,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceError {
    TooLong,
    Unclosed,
    UnexpectedBrace,
    Unknown(String),
    Unsupported(String),
    BadNumber(String),
    /// Modificateur suivi d'un champ, d'une pause ou de rien.
    DanglingModifier,
    MissingField(String),
    TooManyKeys,
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "séquence trop longue ({MAX_SEQUENCE_LEN} caractères au plus)"),
            Self::Unclosed => write!(f, "accolade « {{ » non refermée"),
            Self::UnexpectedBrace => write!(f, "accolade « }} » isolée (écrire {{}}}} pour la taper)"),
            Self::Unknown(p) => write!(f, "paramètre inconnu : {{{p}}}"),
            Self::Unsupported(p) => write!(f, "paramètre non pris en charge : {{{p}}}"),
            Self::BadNumber(p) => write!(f, "nombre invalide dans {{{p}}}"),
            Self::DanglingModifier => write!(f, "un modificateur (+ ^ % #) doit précéder une touche ou un caractère"),
            Self::MissingField(n) => write!(f, "l'entrée n'a pas d'attribut « {n} »"),
            Self::TooManyKeys => write!(f, "saisie trop longue"),
        }
    }
}

impl std::error::Error for SequenceError {}

/// Élément d'une séquence avant lecture des champs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Step(Step),
    Field(Field),
    ClearField,
}

/// Touches à taper. Les caractères (donc les secrets) sont effacés de la
/// mémoire à la fin.
#[derive(PartialEq, Eq)]
pub struct Typed(Vec<Step>);

impl Typed {
    pub fn steps(&self) -> &[Step] {
        &self.0
    }
}

impl fmt::Debug for Typed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Typed({} actions)", self.0.len())
    }
}

impl Drop for Typed {
    fn drop(&mut self) {
        for s in self.0.iter_mut() {
            *s = Step::Delay(0);
        }
        std::hint::black_box(&self.0);
    }
}

/// Vérifie une séquence sans lire aucune entrée.
pub fn validate(seq: &str) -> Result<(), SequenceError> {
    parse(seq).map(|_| ())
}

/// Champs lus par la séquence (pour savoir s'il faut un code TOTP…).
pub fn fields(seq: &str) -> Result<Vec<Field>, SequenceError> {
    Ok(parse(seq)?.into_iter().filter_map(|t| if let Token::Field(f) = t { Some(f) } else { None }).collect())
}

/// Traduit la séquence en touches, en lisant les champs par `lookup`
/// (`None` : attribut absent).
pub fn compile(seq: &str, lookup: impl Fn(&Field) -> Option<Zeroizing<String>>) -> Result<Typed, SequenceError> {
    let mut out = Typed(Vec::new());
    let push = |out: &mut Typed, s: Step| {
        if out.0.len() >= MAX_STEPS {
            return Err(SequenceError::TooManyKeys);
        }
        out.0.push(s);
        Ok(())
    };
    for token in parse(seq)? {
        match token {
            Token::Step(s) => push(&mut out, s)?,
            Token::ClearField => {
                let none = Mods::default();
                push(&mut out, Step::Key(Key::Home, none))?;
                push(&mut out, Step::Key(Key::End, Mods { shift: true, ..none }))?;
                push(&mut out, Step::Key(Key::Backspace, none))?;
            }
            Token::Field(f) => {
                let value = lookup(&f).ok_or_else(|| match &f {
                    Field::Custom(n) => SequenceError::MissingField(n.clone()),
                    _ => SequenceError::MissingField(String::new()),
                })?;
                for c in value.chars() {
                    let step = match c {
                        '\n' => Step::Key(Key::Enter, Mods::default()),
                        '\t' => Step::Key(Key::Tab, Mods::default()),
                        c if c.is_control() => continue,
                        c => Step::Char(c, Mods::default()),
                    };
                    push(&mut out, step)?;
                }
            }
        }
    }
    Ok(out)
}

fn parse(seq: &str) -> Result<Vec<Token>, SequenceError> {
    if seq.len() > MAX_SEQUENCE_LEN {
        return Err(SequenceError::TooLong);
    }
    let mut tokens = Vec::new();
    let mut steps = 0usize;
    let mut mods = Mods::default();
    let mut chars = seq.chars();
    while let Some(c) = chars.next() {
        let token = match c {
            '+' => {
                mods.shift = true;
                continue;
            }
            '^' => {
                mods.ctrl = true;
                continue;
            }
            '%' => {
                mods.alt = true;
                continue;
            }
            '#' => {
                mods.meta = true;
                continue;
            }
            '~' => vec![Token::Step(Step::Key(Key::Enter, mods))],
            '}' => return Err(SequenceError::UnexpectedBrace),
            '{' => {
                // `{}}` : accolade fermante littérale.
                let mut inner = String::new();
                if chars.as_str().starts_with("}}") {
                    chars.next();
                    inner.push('}');
                }
                loop {
                    match chars.next() {
                        None => return Err(SequenceError::Unclosed),
                        Some('}') => break,
                        Some(c) => inner.push(c),
                    }
                }
                placeholder(&inner, mods)?
            }
            '\n' | '\r' => continue,
            c if c.is_control() => continue,
            c => vec![Token::Step(Step::Char(c, mods))],
        };
        let applies_mods = token.iter().all(|t| matches!(t, Token::Step(Step::Char(..) | Step::Key(..))));
        if !mods.is_empty() && !applies_mods {
            return Err(SequenceError::DanglingModifier);
        }
        mods = Mods::default();
        steps += token.len();
        if steps > MAX_STEPS {
            return Err(SequenceError::TooManyKeys);
        }
        tokens.extend(token);
    }
    if !mods.is_empty() {
        return Err(SequenceError::DanglingModifier);
    }
    Ok(tokens)
}

/// Contenu d'une accolade : `NOM`, `NOM n`, `NOM=n` ou `S:attribut`.
fn placeholder(inner: &str, mods: Mods) -> Result<Vec<Token>, SequenceError> {
    if let Some(name) = inner.strip_prefix("S:").or_else(|| inner.strip_prefix("s:")) {
        if name.is_empty() {
            return Err(SequenceError::Unknown(inner.to_owned()));
        }
        return Ok(vec![Token::Field(custom_field(name))]);
    }
    // Caractères spéciaux tapés tels quels : {+} {^} {%} {~} {#} {{} {}} {(} {)} {[} {]}
    let mut it = inner.chars();
    if let (Some(c), None) = (it.next(), it.next())
        && "+^%~#{}()[]".contains(c)
    {
        return Ok(vec![Token::Step(Step::Char(c, mods))]);
    }

    let (name, arg) = match inner.split_once(['=', ' ']) {
        Some((n, a)) => (n, Some((a.trim(), inner.as_bytes()[n.len()] == b'='))),
        None => (inner, None),
    };
    let upper = name.to_ascii_uppercase();
    let number = |a: &str, max: u32| -> Result<u32, SequenceError> {
        a.parse::<u32>().ok().filter(|n| *n <= max).ok_or_else(|| SequenceError::BadNumber(inner.to_owned()))
    };

    if upper == "DELAY" {
        return match arg {
            Some((a, false)) => Ok(vec![Token::Step(Step::Delay(number(a, MAX_DELAY_MS)?))]),
            Some((a, true)) => Ok(vec![Token::Step(Step::KeyDelay(number(a, 1000)?))]),
            None => Err(SequenceError::BadNumber(inner.to_owned())),
        };
    }

    let field = match upper.as_str() {
        "TITLE" => Some(Field::Title),
        "USERNAME" => Some(Field::Username),
        "PASSWORD" => Some(Field::Password),
        "URL" => Some(Field::Url),
        "NOTES" => Some(Field::Notes),
        "TOTP" => Some(Field::Totp),
        _ => None,
    };
    if let Some(f) = field {
        return if arg.is_some() { Err(SequenceError::Unknown(inner.to_owned())) } else { Ok(vec![Token::Field(f)]) };
    }
    if upper == "CLEARFIELD" && arg.is_none() {
        return Ok(vec![Token::ClearField]);
    }

    let key = match upper.as_str() {
        "TAB" => Key::Tab,
        "ENTER" => Key::Enter,
        "SPACE" => Key::Space,
        "BACKSPACE" | "BS" | "BKSP" => Key::Backspace,
        "DELETE" | "DEL" => Key::Delete,
        "INSERT" | "INS" => Key::Insert,
        "ESC" | "ESCAPE" => Key::Escape,
        "UP" => Key::Up,
        "DOWN" => Key::Down,
        "LEFT" => Key::Left,
        "RIGHT" => Key::Right,
        "HOME" => Key::Home,
        "END" => Key::End,
        "PGUP" => Key::PageUp,
        "PGDN" => Key::PageDown,
        f if f.len() >= 2 && f.starts_with('F') && f[1..].bytes().all(|b| b.is_ascii_digit()) => match f[1..].parse::<u8>() {
            Ok(n @ 1..=16) => Key::F(n),
            _ => return Err(SequenceError::Unknown(inner.to_owned())),
        },
        // Lancent un programme, lisent d'autres entrées ou demandent une
        // interaction : jamais pris en charge.
        "CMD" | "REF" | "PICKCHARS" | "PICKFIELD" | "VKEY" | "VKEY-NX" | "VKEY-EX" | "APPACTIVATE" | "BEEP" | "C"
        | "T-CONV" | "T-REPLACE-RX" | "HMACOTP" | "SMARTCARD" => {
            return Err(SequenceError::Unsupported(name.to_owned()));
        }
        _ if upper.starts_with("CMD:") || upper.starts_with("REF:") || upper.starts_with("T-") => {
            return Err(SequenceError::Unsupported(name.to_owned()));
        }
        _ => return Err(SequenceError::Unknown(inner.to_owned())),
    };
    let times = match arg {
        None => 1,
        Some((a, false)) => number(a, MAX_REPEAT)?,
        Some((_, true)) => return Err(SequenceError::Unknown(inner.to_owned())),
    };
    Ok((0..times).map(|_| Token::Step(Step::Key(key, mods))).collect())
}

fn custom_field(name: &str) -> Field {
    match name {
        // `{S:Password}` désigne le champ standard, comme dans KeePass.
        "Title" => Field::Title,
        "UserName" => Field::Username,
        "Password" => Field::Password,
        "URL" => Field::Url,
        "Notes" => Field::Notes,
        _ => Field::Custom(name.to_owned()),
    }
}

/// Correspondance d'un titre de fenêtre avec un motif d'association
/// (`*` = n'importe quelle suite), sans tenir compte de la casse.
pub fn window_matches(pattern: &str, title: &str) -> bool {
    let p: Vec<char> = pattern.trim().chars().flat_map(char::to_lowercase).collect();
    let t: Vec<char> = title.chars().flat_map(char::to_lowercase).collect();
    if p.is_empty() {
        return false;
    }
    // Algorithme glouton à retour unique : linéaire, sans explosion sur des
    // motifs comme `*a*a*a*a*b`.
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(f: &Field) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(match f {
            Field::Title => "Titre".into(),
            Field::Username => "alice".into(),
            Field::Password => "p{^}+%~#".into(),
            Field::Url => "https://x".into(),
            Field::Notes => "a\r\nb\tc\u{7}".into(),
            Field::Totp => "123456".into(),
            Field::Custom(n) if n == "PIN" => "42".into(),
            Field::Custom(_) => return None,
        }))
    }

    fn none() -> Mods {
        Mods::default()
    }

    fn text(s: &str) -> Vec<Step> {
        s.chars().map(|c| Step::Char(c, none())).collect()
    }

    #[test]
    fn default_sequence() {
        let t = compile(DEFAULT_SEQUENCE, lookup).unwrap();
        let mut want = text("alice");
        want.push(Step::Key(Key::Tab, none()));
        want.extend(text("p{^}+%~#"));
        want.push(Step::Key(Key::Enter, none()));
        assert_eq!(t.steps(), want);
    }

    #[test]
    fn field_values_are_typed_literally() {
        // Une valeur pleine de syntaxe n'est jamais réinterprétée.
        let t = compile("{PASSWORD}", lookup).unwrap();
        assert_eq!(t.steps(), text("p{^}+%~#"));
        // Retours à la ligne et tabulations des notes : vraies touches ;
        // autres caractères de contrôle : ignorés.
        let t = compile("{NOTES}", lookup).unwrap();
        assert_eq!(
            t.steps(),
            [
                Step::Char('a', none()),
                Step::Key(Key::Enter, none()),
                Step::Char('b', none()),
                Step::Key(Key::Tab, none()),
                Step::Char('c', none()),
            ]
        );
    }

    #[test]
    fn modifiers_keys_and_escapes() {
        let ctrl = Mods { ctrl: true, ..none() };
        let t = compile("^a+{TAB}%^{F4}~{+}{{}{}}{~}x", lookup).unwrap();
        assert_eq!(
            t.steps(),
            [
                Step::Char('a', ctrl),
                Step::Key(Key::Tab, Mods { shift: true, ..none() }),
                Step::Key(Key::F(4), Mods { alt: true, ctrl: true, ..none() }),
                Step::Key(Key::Enter, none()),
                Step::Char('+', none()),
                Step::Char('{', none()),
                Step::Char('}', none()),
                Step::Char('~', none()),
                Step::Char('x', none()),
            ]
        );
    }

    #[test]
    fn repeats_delays_and_case() {
        let t = compile("{tab 3}{Delay 250}{DELAY=40}{s:PIN}{S:Password}", lookup).unwrap();
        let mut want = vec![Step::Key(Key::Tab, none()); 3];
        want.extend([Step::Delay(250), Step::KeyDelay(40)]);
        want.extend(text("42"));
        want.extend(text("p{^}+%~#"));
        assert_eq!(t.steps(), want);
        let t = compile("{CLEARFIELD}", lookup).unwrap();
        assert_eq!(t.steps().len(), 3);
    }

    #[test]
    fn rejects_dangerous_and_malformed() {
        for (seq, err) in [
            ("{CMD:/bin/sh -c id/}", "non pris en charge"),
            ("{REF:P@I:0123}", "non pris en charge"),
            ("{PICKCHARS}", "non pris en charge"),
            ("{T-CONV:/x/u/}", "non pris en charge"),
            ("{APPACTIVATE x}", "non pris en charge"),
            ("{USERNAME", "non refermée"),
            ("abc}", "isolée"),
            ("{NOPE}", "inconnu"),
            ("{F17}", "inconnu"),
            ("{F0}", "inconnu"),
            ("{TAB 101}", "invalide"),
            ("{TAB -1}", "invalide"),
            ("{TAB x}", "invalide"),
            ("{DELAY 10001}", "invalide"),
            ("{DELAY}", "invalide"),
            ("{DELAY=1001}", "invalide"),
            ("{PASSWORD 3}", "inconnu"),
            ("{S:}", "inconnu"),
            ("^{PASSWORD}", "modificateur"),
            ("+{DELAY 5}", "modificateur"),
            ("abc^", "modificateur"),
            ("{S:Missing}", "Missing"),
        ] {
            let e = compile(seq, lookup).unwrap_err().to_string();
            assert!(e.contains(err), "{seq} : {e}");
        }
        assert_eq!(validate(&"a".repeat(MAX_SEQUENCE_LEN + 1)), Err(SequenceError::TooLong));
        // Pas d'explosion du nombre de touches.
        let many = "{TAB 100}".repeat(100);
        assert!(many.len() <= MAX_SEQUENCE_LEN);
        assert!(compile(&many, lookup).is_ok());
        let many = "{TAB 100}".repeat(114);
        assert_eq!(validate(&many), Err(SequenceError::TooLong));
    }

    #[test]
    fn huge_field_values_are_capped() {
        let big = |_: &Field| Some(Zeroizing::new("x".repeat(MAX_STEPS + 1)));
        assert_eq!(compile("{PASSWORD}", big).unwrap_err(), SequenceError::TooManyKeys);
    }

    #[test]
    fn lists_fields() {
        assert_eq!(fields("{USERNAME}{TAB}{TOTP}{S:PIN}").unwrap(), [Field::Username, Field::Totp, Field::Custom("PIN".into())]);
    }

    #[test]
    fn window_patterns() {
        assert!(window_matches("*Firefox*", "Connexion – Mozilla Firefox"));
        assert!(window_matches("ssh*", "SSH root@host"));
        assert!(window_matches("Exact", "exact"));
        assert!(!window_matches("Exact", "exactly"));
        assert!(!window_matches("", "x"));
        assert!(!window_matches("  ", "x"));
        assert!(window_matches("*", "anything"));
        assert!(window_matches("a*b*c", "a-x-b-y-c"));
        assert!(!window_matches("a*b*c", "a-x-c-y-b"));
        // Motif pathologique : reste rapide.
        let title = "a".repeat(5000);
        let pattern = format!("{}b", "*a".repeat(200));
        let start = std::time::Instant::now();
        assert!(!window_matches(&pattern, &title));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
