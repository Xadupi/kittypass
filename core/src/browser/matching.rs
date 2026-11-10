//! Correspondance entre l'adresse d'une page et les URL d'une entrée.
//!
//! Plus strict que le simple « contient le domaine » :
//! - le schéma doit correspondre (une entrée `https` n'est jamais proposée
//!   sur une page `http` ; l'inverse est permis, c'est une montée en
//!   sécurité) ; une URL d'entrée sans schéma vaut `https` ;
//! - un sous-domaine correspond à son domaine seulement à une frontière de
//!   label (`a.example.com` oui, `evilexample.com` non) ;
//! - jamais sur un suffixe public (une entrée « co.uk » ne vaut pas pour
//!   tous les sites britanniques) ni sur une adresse IP autre qu'exacte ;
//! - le port doit être le même (port par défaut du schéma si absent).

use url::{Host, Url};

/// Qualité d'une correspondance, de la meilleure à la plus faible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    /// Même domaine que l'entrée, sous-domaine de la page.
    Subdomain = 1,
    /// Même hôte.
    Host = 2,
    /// Même hôte et chemin de l'entrée préfixe de celui de la page.
    Path = 3,
    /// Adresse identique (hors requête et fragment).
    Exact = 4,
}

/// Adresse de page analysée : seules `http` et `https` (et `ftp`) ont un sens
/// pour le remplissage.
pub fn parse_page(url: &str) -> Option<Url> {
    let u = Url::parse(url.trim()).ok()?;
    matches!(u.scheme(), "http" | "https" | "ftp").then_some(())?;
    u.host()?;
    Some(u)
}

/// URL d'entrée analysée : sans schéma, on suppose `https://`. Les
/// références et marqueurs KeePass (`{REF:…}`, `cmd://`) sont ignorés.
pub fn parse_entry(url: &str) -> Option<Url> {
    let url = url.trim();
    if url.is_empty() || url.starts_with('{') || url.starts_with("cmd://") {
        return None;
    }
    let u = if url.contains("://") { Url::parse(url).ok()? } else { Url::parse(&format!("https://{url}")).ok()? };
    matches!(u.scheme(), "http" | "https" | "ftp").then_some(())?;
    u.host()?;
    Some(u)
}

fn scheme_ok(entry: &str, page: &str) -> bool {
    entry == page || (entry == "http" && page == "https")
}

/// Le domaine `base` (non suffixe public) contient-il `host` ?
fn is_subdomain(host: &str, base: &str) -> bool {
    host.len() > base.len()
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
        && psl::suffix_str(base).is_some_and(|s| s != base)
}

/// Compare une adresse de page à une URL d'entrée.
pub fn compare(page: &Url, entry: &Url) -> Option<Match> {
    if !scheme_ok(entry.scheme(), page.scheme()) {
        return None;
    }
    if entry.port_or_known_default() != page.port_or_known_default() {
        // Une entrée http sans port sur une page https : ports par défaut
        // différents (80/443) mais même site.
        let upgraded = entry.scheme() == "http" && entry.port().is_none() && page.port().is_none();
        if !upgraded {
            return None;
        }
    }
    let host_match = match (entry.host()?, page.host()?) {
        (Host::Domain(e), Host::Domain(p)) => {
            let e = e.trim_end_matches('.').trim_start_matches("*.");
            let p = p.trim_end_matches('.');
            if e.eq_ignore_ascii_case(p) {
                Match::Host
            } else if is_subdomain(&p.to_ascii_lowercase(), &e.to_ascii_lowercase()) {
                Match::Subdomain
            } else {
                return None;
            }
        }
        (e, p) if e == p => Match::Host,
        _ => return None,
    };
    if host_match == Match::Host {
        let (ep, pp) = (entry.path(), page.path());
        if ep == pp && entry.scheme() == page.scheme() {
            return Some(Match::Exact);
        }
        if ep != "/" && pp.starts_with(ep) {
            return Some(Match::Path);
        }
    }
    Some(host_match)
}

/// Meilleure correspondance parmi les URL d'une entrée.
pub fn best<'a>(page: &Url, entry_urls: impl IntoIterator<Item = &'a str>) -> Option<Match> {
    entry_urls.into_iter().filter_map(parse_entry).filter_map(|e| compare(page, &e)).max()
}

/// Hôte d'une adresse, tel que gardé dans les listes Autoriser / Refuser.
pub fn host_of(url: &str) -> Option<String> {
    parse_page(url).and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(page: &str, entry: &str) -> Option<Match> {
        compare(&parse_page(page).unwrap(), &parse_entry(entry)?)
    }

    #[test]
    fn exact_path_host_subdomain() {
        assert_eq!(m("https://example.com/login", "https://example.com/login"), Some(Match::Exact));
        assert_eq!(m("https://example.com/login?next=1#x", "https://example.com/login"), Some(Match::Exact));
        assert_eq!(m("https://example.com/account/login", "https://example.com/account"), Some(Match::Path));
        assert_eq!(m("https://example.com/other", "https://example.com/account"), Some(Match::Host));
        assert_eq!(m("https://www.example.com/", "example.com"), Some(Match::Subdomain));
        assert_eq!(m("https://a.b.example.com/", "https://example.com"), Some(Match::Subdomain));
        assert_eq!(m("https://EXAMPLE.com./", "https://example.COM"), Some(Match::Exact));
        assert_eq!(m("https://www.example.com/", "*.example.com"), Some(Match::Subdomain));
    }

    #[test]
    fn lookalike_domains_never_match() {
        assert_eq!(m("https://evilexample.com/", "example.com"), None);
        assert_eq!(m("https://example.com.evil.net/", "example.com"), None);
        assert_eq!(m("https://example.co/", "example.com"), None);
        assert_eq!(m("https://xn--exmple-cua.com/", "example.com"), None);
        // Le domaine de l'entrée n'est pas un sous-domaine de la page.
        assert_eq!(m("https://example.com/", "login.example.com"), None);
    }

    #[test]
    fn public_suffixes_do_not_act_as_wildcards() {
        assert_eq!(m("https://bank.co.uk/", "co.uk"), None);
        assert_eq!(m("https://anything.github.io/", "github.io"), None);
        assert_eq!(m("https://site.com/", "com"), None);
        // Mais l'hôte exact reste utilisable.
        assert_eq!(m("https://user.github.io/", "user.github.io"), Some(Match::Exact));
    }

    #[test]
    fn scheme_is_never_downgraded() {
        assert_eq!(m("http://example.com/", "https://example.com/"), None);
        assert_eq!(m("http://example.com/", "example.com"), None);
        assert_eq!(m("https://example.com/", "http://example.com/"), Some(Match::Host));
        assert_eq!(m("ftp://example.com/", "https://example.com/"), None);
        assert!(parse_page("javascript:alert(1)").is_none());
        assert!(parse_page("file:///etc/passwd").is_none());
        assert!(parse_page("data:text/html,x").is_none());
        assert!(parse_entry("{REF:U@I:0123}").is_none());
        assert!(parse_entry("cmd://xterm").is_none());
    }

    #[test]
    fn ports_must_match() {
        assert_eq!(m("https://example.com:8443/", "https://example.com/"), None);
        assert_eq!(m("https://example.com/", "https://example.com:8443/"), None);
        assert_eq!(m("https://example.com:8443/", "https://example.com:8443"), Some(Match::Exact));
        assert_eq!(m("https://example.com:443/", "https://example.com"), Some(Match::Exact));
        assert_eq!(m("https://example.com:8080/", "http://example.com:8080/"), Some(Match::Host));
        assert_eq!(m("https://example.com/", "http://example.com:8080/"), None);
    }

    #[test]
    fn ip_addresses_match_exactly() {
        assert_eq!(m("https://192.168.1.10/", "https://192.168.1.10"), Some(Match::Exact));
        assert_eq!(m("https://192.168.1.10/", "https://168.1.10"), None);
        assert_eq!(m("https://10.0.0.1/", "https://0.1"), None);
        assert_eq!(m("http://[::1]:8080/", "http://[::1]:8080/"), Some(Match::Exact));
    }

    #[test]
    fn best_of_several_urls() {
        let page = parse_page("https://login.example.com/x").unwrap();
        assert_eq!(best(&page, ["https://other.net", "example.com", "https://login.example.com"]), Some(Match::Host));
        assert_eq!(best(&page, ["", "{REF:x}", "nope nope"]), None);
    }

    #[test]
    fn host_of_normalizes() {
        assert_eq!(host_of("https://WWW.Example.com.:443/a").as_deref(), Some("www.example.com"));
        assert_eq!(host_of("about:blank"), None);
    }
}
