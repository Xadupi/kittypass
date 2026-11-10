//! Recherche avancée, syntaxe de KeePassXC.
//!
//! - termes séparés par des espaces, tous requis (ET) ;
//! - `"phrase avec espaces"` ;
//! - `champ:terme` avec `title`/`t`, `username`/`u`, `password`/`p`/`pw`,
//!   `url`, `notes`/`n`, `attribute`/`attr`, `attachment`/`attach`, `tag`,
//!   `group`/`g`, `uuid`, et `is:expired` ;
//! - modificateurs en tête : `-` ou `!` exclut, `+` exige une correspondance
//!   exacte du champ entier ;
//! - jokers `*` (n'importe quelle suite) et `?` (un caractère).
//!
//! Sans champ, la recherche porte sur titre, identifiant, URL, notes et
//! étiquettes ; jamais sur le mot de passe, sauf `password:` explicite.
//! Insensible à la casse. Pas d'expressions régulières : aucune requête ne
//! peut faire exploser le temps de recherche (ReDoS).

use keepass::db::{EntryRef, GroupId, fields};

use super::{EntrySummary, Vault, is_expired, parse_group_id, summary};
use crate::{Error, Result};

/// Longueur maximale d'une requête.
pub const MAX_QUERY_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Default,
    Title,
    Username,
    Password,
    Url,
    Notes,
    Attribute,
    Attachment,
    Tag,
    Group,
    Uuid,
    Is,
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_lowercase().as_str() {
            "title" | "t" => Self::Title,
            "username" | "user" | "u" => Self::Username,
            "password" | "pass" | "pw" | "p" => Self::Password,
            "url" => Self::Url,
            "notes" | "n" => Self::Notes,
            "attribute" | "attr" => Self::Attribute,
            "attachment" | "attach" => Self::Attachment,
            "tag" => Self::Tag,
            "group" | "g" => Self::Group,
            "uuid" => Self::Uuid,
            "is" => Self::Is,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Term {
    field: Field,
    /// Motif en minuscules.
    pattern: Vec<char>,
    exclude: bool,
    exact: bool,
}

fn parse(query: &str) -> Result<Vec<Term>> {
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(Error::InvalidArgument("requête trop longue"));
    }
    let chars: Vec<char> = query.chars().collect();
    let mut terms = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let (mut exclude, mut exact) = (false, false);
        while i < chars.len() && matches!(chars[i], '-' | '!' | '+') {
            match chars[i] {
                '+' => exact = true,
                _ => exclude = true,
            }
            i += 1;
        }
        // Champ : lettres suivies de « : », seulement si le nom est connu
        // (sinon « https://… » serait lu comme un champ « https »).
        let mut field = Field::Default;
        let mut j = i;
        while j < chars.len() && chars[j].is_alphabetic() {
            j += 1;
        }
        if j < chars.len() && chars[j] == ':' && j > i {
            let name: String = chars[i..j].iter().collect();
            if let Some(f) = Field::parse(&name) {
                field = f;
                i = j + 1;
            }
        }
        let mut pattern = String::new();
        if i < chars.len() && chars[i] == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                pattern.push(chars[i]);
                i += 1;
            }
            i += 1; // guillemet fermant (ou fin)
        } else {
            while i < chars.len() && !chars[i].is_whitespace() {
                pattern.push(chars[i]);
                i += 1;
            }
        }
        if pattern.is_empty() && field == Field::Default {
            continue;
        }
        terms.push(Term { field, pattern: pattern.to_lowercase().chars().collect(), exclude, exact });
    }
    Ok(terms)
}

/// Correspondance avec jokers `*` et `?`, motif ancré aux deux bouts.
/// Algorithme glouton à retour sur le dernier `*` : O(motif × texte) au pire.
fn glob(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
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

fn matches(term: &Term, value: &str) -> bool {
    if term.pattern.is_empty() {
        // « url: » : le champ est renseigné (« -url: » : il est vide).
        return !value.is_empty();
    }
    let value = value.to_lowercase();
    let wild = term.pattern.iter().any(|c| matches!(c, '*' | '?'));
    if term.exact {
        let v: Vec<char> = value.chars().collect();
        return if wild { glob(&term.pattern, &v) } else { v == term.pattern };
    }
    if !wild {
        let p: String = term.pattern.iter().collect();
        return value.contains(&p);
    }
    let mut p = Vec::with_capacity(term.pattern.len() + 2);
    p.push('*');
    p.extend_from_slice(&term.pattern);
    p.push('*');
    glob(&p, &value.chars().collect::<Vec<_>>())
}

impl Vault {
    /// Recherche dans tout le coffre (hors corbeille et groupes exclus de la
    /// recherche).
    pub fn search(&self, query: &str) -> Result<Vec<EntrySummary>> {
        self.search_scoped(None, query)
    }

    /// Recherche limitée à un groupe et ses sous-groupes.
    pub fn search_in(&self, group_id: &str, query: &str) -> Result<Vec<EntrySummary>> {
        let gid = parse_group_id(group_id)?;
        if self.db.group(gid).is_none() {
            return Err(Error::GroupNotFound);
        }
        self.search_scoped(Some(gid), query)
    }

    fn search_scoped(&self, scope: Option<GroupId>, query: &str) -> Result<Vec<EntrySummary>> {
        let terms = parse(query)?;
        let bin = self.existing_recycle_bin();
        let mut v: Vec<_> = self
            .db
            .iter_all_entries()
            .filter(|e| {
                let g = e.parent().id();
                scope.is_none_or(|s| self.group_is_within(g, s))
                    && bin.is_none_or(|b| !self.group_is_within(g, b))
                    && self.searchable(g)
            })
            .filter(|e| terms.iter().all(|t| self.term_matches(t, e) != t.exclude))
            .map(|e| summary(&e))
            .collect();
        v.sort_by_key(|a| a.title.to_lowercase());
        Ok(v)
    }

    /// `EnableSearching` d'un groupe, hérité du parent quand il n'est pas fixé.
    fn searchable(&self, group: GroupId) -> bool {
        let mut current = Some(group);
        for _ in 0..=self.db.num_groups() {
            let Some(g) = current.and_then(|id| self.db.group(id)) else { return true };
            if let Some(v) = g.enable_searching {
                return v;
            }
            current = g.parent().map(|p| p.id());
        }
        true
    }

    fn group_path(&self, group: GroupId) -> String {
        let mut names = Vec::new();
        let mut current = Some(group);
        for _ in 0..=self.db.num_groups() {
            let Some(g) = current.and_then(|id| self.db.group(id)) else { break };
            names.push(g.name.clone());
            current = g.parent().map(|p| p.id());
        }
        names.reverse();
        names.join("/")
    }

    fn term_matches(&self, t: &Term, e: &EntryRef<'_>) -> bool {
        let get = |k: &str| e.get(k).unwrap_or_default();
        match t.field {
            Field::Default => {
                [get(fields::TITLE), get(fields::USERNAME), get(fields::URL), get(fields::NOTES)]
                    .iter()
                    .any(|v| matches(t, v))
                    || e.tags.iter().any(|tag| matches(t, tag))
            }
            Field::Title => matches(t, get(fields::TITLE)),
            Field::Username => matches(t, get(fields::USERNAME)),
            Field::Password => matches(t, get(fields::PASSWORD)),
            Field::Url => matches(t, get(fields::URL)),
            Field::Notes => matches(t, get(fields::NOTES)),
            Field::Attribute => e.fields.iter().any(|(k, v)| {
                !super::STANDARD_FIELDS.contains(&k.as_str())
                    && (matches(t, k) || (!v.is_protected() && matches(t, v.get())))
            }),
            Field::Attachment => e.attachments_named().any(|(name, _)| matches(t, name)),
            Field::Tag => {
                let tags = super::clean_tags(&e.tags);
                if t.pattern.is_empty() { !tags.is_empty() } else { tags.iter().any(|tag| matches(t, tag)) }
            }
            Field::Group => matches(t, &self.group_path(e.parent().id())),
            Field::Uuid => {
                let u = e.id().uuid();
                matches(t, &u.to_string()) || matches(t, &u.simple().to_string())
            }
            Field::Is => match t.pattern.iter().collect::<String>().as_str() {
                "expired" => is_expired(e),
                _ => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(p: &str, t: &str) -> bool {
        glob(&p.chars().collect::<Vec<_>>(), &t.chars().collect::<Vec<_>>())
    }

    #[test]
    fn glob_basics() {
        assert!(g("*", ""));
        assert!(g("a*c", "abbbc"));
        assert!(g("a?c", "abc"));
        assert!(!g("a?c", "ac"));
        assert!(g("*.example.*", "www.example.org"));
        assert!(!g("abc", "abcd"));
        assert!(g("é*ü", "éàü"));
    }

    /// Le pire cas classique des moteurs à retour arrière reste rapide.
    #[test]
    fn glob_has_no_catastrophic_backtracking() {
        let text: String = "a".repeat(100_000);
        let pat: String = "*a".repeat(500) + "b";
        let start = std::time::Instant::now();
        assert!(!g(&pat, &text));
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }

    #[test]
    fn parser() {
        let t = parse(r#"  -title:"mot de passe"  +u:bob https://x.org !is:expired url:"#).unwrap();
        assert_eq!(t.len(), 5);
        assert_eq!((t[0].field, t[0].exclude, t[0].exact), (Field::Title, true, false));
        assert_eq!(t[0].pattern.iter().collect::<String>(), "mot de passe");
        assert_eq!((t[1].field, t[1].exact), (Field::Username, true));
        assert_eq!(t[2].field, Field::Default, "« https: » n'est pas un champ");
        assert_eq!(t[2].pattern.iter().collect::<String>(), "https://x.org");
        assert_eq!((t[3].field, t[3].exclude), (Field::Is, true));
        assert_eq!((t[4].field, t[4].pattern.len()), (Field::Url, 0));
        assert!(parse("").unwrap().is_empty());
        assert!(parse("   - + ").unwrap().is_empty());
        assert!(parse(&"x".repeat(MAX_QUERY_CHARS + 1)).is_err());
        // Guillemet non fermé : jusqu'à la fin, sans plantage.
        assert_eq!(parse("\"abc").unwrap()[0].pattern.iter().collect::<String>(), "abc");
    }
}
