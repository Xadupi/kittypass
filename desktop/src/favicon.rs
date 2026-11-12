//! Icônes des sites (favicons) pour la liste des entrées.
//!
//! Seul le nom d'hôte de l'URL est utilisé : on demande `https://hôte/favicon.ico`
//! (puis `/apple-touch-icon.png`), jamais le chemin complet. Pas de HTTP en clair,
//! pas d'adresses IP ni de noms locaux (pour ne pas sonder le réseau domestique).
//! Les réponses sont gardées dans le cache de l'appli ; un échec est mémorisé
//! une semaine pour ne pas redemander sans cesse.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Manager, State};
use tokio::sync::Semaphore;

const MAX_BYTES: usize = 200 * 1024;
const RETRY_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

pub struct FaviconState {
    client: reqwest::Client,
    gate: Arc<Semaphore>,
}

impl FaviconState {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .redirect(reqwest::redirect::Policy::limited(3))
            .https_only(true)
            .user_agent("KittyPass");
        let client = kittypass_core::client::android_roots(client)
            .build()
            .expect("client HTTP");
        Self { client, gate: Arc::new(Semaphore::new(6)) }
    }
}

/// Nom d'hôte public tiré d'une URL d'entrée, ou `None`.
pub fn public_host(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let full = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let parsed = reqwest::Url::parse(&full).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return None;
    }
    if !host.contains('.') {
        return None;
    }
    for local in [".local", ".lan", ".home", ".internal", ".localhost", ".arpa", ".home.arpa"] {
        if host.ends_with(local) {
            return None;
        }
    }
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return None;
    }
    Some(host)
}

fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG") {
        Some("image/png")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else if bytes.starts_with(b"GIF8") {
        Some("image/gif")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let mut resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        out.extend_from_slice(&chunk);
        if out.len() > MAX_BYTES {
            return None;
        }
    }
    sniff(&out).map(|_| out)
}

fn cache_path(handle: &AppHandle, host: &str) -> Option<PathBuf> {
    let dir = handle.path().app_cache_dir().ok()?.join("favicons");
    std::fs::create_dir_all(&dir).ok()?;
    let name: String = Sha256::digest(host.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    Some(dir.join(name))
}

fn data_url(bytes: &[u8]) -> Option<String> {
    let mime = sniff(bytes)?;
    Some(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes)))
}

/// Liens d'icônes déclarés dans le HTML d'une page (`<link rel="…icon…" href>`),
/// les plus grandes (apple-touch-icon) d'abord. Seules les URL https sont gardées.
fn icon_links(html: &str, base: &reqwest::Url) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut touch = Vec::new();
    let mut plain = Vec::new();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<link") {
        let start = from + i;
        let Some(len) = lower[start..].find('>') else { break };
        let tag = &html[start..start + len];
        let tag_l = &lower[start..start + len];
        from = start + len;
        let attr = |name: &str| -> Option<String> {
            let mut at = 0;
            while let Some(j) = tag_l[at..].find(name) {
                let k = at + j;
                at = k + name.len();
                // le nom doit être précédé d'un blanc et suivi de « = »
                if !tag_l[..k].ends_with(|c: char| c.is_ascii_whitespace()) {
                    continue;
                }
                let rest = tag[at..].trim_start();
                let Some(rest) = rest.strip_prefix('=') else { continue };
                let rest = rest.trim_start();
                let v = match rest.chars().next()? {
                    q @ ('"' | '\'') => rest[1..].split(q).next()?,
                    _ => rest.split(|c: char| c.is_ascii_whitespace() || c == '/' && rest.starts_with("/>")).next()?,
                };
                return Some(v.trim().to_string());
            }
            None
        };
        let Some(rel) = attr("rel") else { continue };
        let rel = rel.to_ascii_lowercase();
        if !rel.split_whitespace().any(|r| r == "icon" || r == "apple-touch-icon" || r == "apple-touch-icon-precomposed") {
            continue;
        }
        let Some(href) = attr("href") else { continue };
        if href.to_ascii_lowercase().ends_with(".svg") || href.starts_with("data:") {
            continue;
        }
        let Ok(u) = base.join(&href) else { continue };
        if u.scheme() != "https" {
            continue;
        }
        if rel.contains("apple-touch-icon") { touch.push(u.to_string()) } else { plain.push(u.to_string()) }
    }
    touch.extend(plain);
    touch.dedup();
    touch.truncate(4);
    touch
}

/// Page d'accueil (HTML seulement, taille limitée) et son URL finale.
async fn fetch_html(client: &reqwest::Client, url: &str) -> Option<(String, reqwest::Url)> {
    let mut resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let html = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("html"));
    if !html {
        return None;
    }
    let base = resp.url().clone();
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        out.extend_from_slice(&chunk);
        if out.len() > 512 * 1024 {
            break;
        }
    }
    Some((String::from_utf8_lossy(&out).into_owned(), base))
}

/// Hôtes à essayer : l'hôte lui-même, puis ses domaines parents
/// (auth.exemple.fr → exemple.fr), jamais un suffixe d'un seul niveau.
fn candidate_hosts(host: &str) -> Vec<String> {
    let labels: Vec<&str> = host.split('.').collect();
    let mut out = vec![host.to_string()];
    for i in 1..labels.len().saturating_sub(1) {
        let parent = labels[i..].join(".");
        // co.uk, com.br… : un parent dont le premier niveau fait 2-3 lettres
        // et le second ≤ 3 lettres est probablement un suffixe public.
        if labels.len() - i == 2 && labels[i].len() <= 3 && labels[labels.len() - 1].len() == 2 {
            break;
        }
        out.push(parent);
    }
    out
}

async fn find_icon(client: &reqwest::Client, host: &str) -> Option<Vec<u8>> {
    for h in candidate_hosts(host) {
        if let Some(b) = fetch(client, &format!("https://{h}/favicon.ico")).await {
            return Some(b);
        }
        if let Some((html, base)) = fetch_html(client, &format!("https://{h}/")).await {
            for link in icon_links(&html, &base) {
                if let Some(b) = fetch(client, &link).await {
                    return Some(b);
                }
            }
        }
        if let Some(b) = fetch(client, &format!("https://{h}/apple-touch-icon.png")).await {
            return Some(b);
        }
    }
    None
}

/// Icône d'un hôte : cache, sinon téléchargement. `retry` ignore un échec mémorisé.
async fn icon_for_host(handle: &AppHandle, state: &FaviconState, host: &str, retry: bool) -> Result<Option<Vec<u8>>, String> {
    let path = cache_path(handle, host);
    if let Some(p) = &path
        && let Ok(meta) = std::fs::metadata(p)
    {
        let fresh = meta.modified().ok().and_then(|m| SystemTime::now().duration_since(m).ok()).is_some_and(|age| age < RETRY_AFTER);
        if meta.len() > 0 {
            return Ok(std::fs::read(p).ok());
        }
        if fresh && !retry {
            return Ok(None);
        }
    }
    let _permit = state.gate.clone().acquire_owned().await.map_err(|e| e.to_string())?;
    let got = find_icon(&state.client, host).await;
    if let Some(p) = &path {
        let _ = std::fs::write(p, got.as_deref().unwrap_or_default());
    }
    Ok(got)
}

/// Icône du site d'une URL, en `data:` URL, ou `null` si aucune.
#[tauri::command]
pub async fn favicon(handle: AppHandle, state: State<'_, FaviconState>, url: String) -> Result<Option<String>, String> {
    let Some(host) = public_host(&url) else { return Ok(None) };
    Ok(icon_for_host(&handle, &state, &host, false).await?.and_then(|b| data_url(&b)))
}

#[derive(serde::Serialize, Clone)]
pub struct FaviconProgress {
    done: usize,
    total: usize,
    found: usize,
}

/// Télécharge d'un coup les icônes de toutes les URL données (une par site).
/// `retry` redemande aussi les sites qui avaient échoué. Avance : événement
/// `favicon_progress`.
#[tauri::command]
pub async fn favicons_fetch_all(handle: AppHandle, state: State<'_, FaviconState>, urls: Vec<String>, retry: bool) -> Result<FaviconProgress, String> {
    use tauri::Emitter;
    let mut hosts: Vec<String> = urls.iter().filter_map(|u| public_host(u)).collect();
    hosts.sort();
    hosts.dedup();
    let total = hosts.len();
    let mut tasks = tokio::task::JoinSet::new();
    for h in hosts {
        let handle = handle.clone();
        tasks.spawn(async move {
            let st = handle.state::<FaviconState>();
            icon_for_host(&handle, &st, &h, retry).await.ok().flatten().is_some()
        });
    }
    let _ = &state;
    let (mut done, mut found) = (0, 0);
    while let Some(r) = tasks.join_next().await {
        done += 1;
        found += usize::from(r.unwrap_or(false));
        let _ = handle.emit("favicon_progress", FaviconProgress { done, total, found });
    }
    Ok(FaviconProgress { done, total, found })
}

/// Oublie l'icône en cache (« Télécharger une favicône » la redemande).
#[tauri::command]
pub fn forget_favicon(handle: AppHandle, url: String) {
    if let Some(p) = public_host(&url).and_then(|h| cache_path(&handle, &h)) {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(public_host("https://www.Example.com/login?x=1").as_deref(), Some("www.example.com"));
        assert_eq!(public_host("github.com").as_deref(), Some("github.com"));
        assert_eq!(public_host("http://192.168.1.5:8006"), None);
        assert_eq!(public_host("https://[::1]/"), None);
        assert_eq!(public_host("http://nas.local"), None);
        assert_eq!(public_host("http://routeur"), None);
        assert_eq!(public_host("file:///etc/passwd"), None);
        assert_eq!(public_host("ssh://srv.example.com"), None);
        assert_eq!(public_host(""), None);
    }

    #[test]
    fn links() {
        let base = reqwest::Url::parse("https://site.example/app/").unwrap();
        let html = r#"<head><LINK rel="shortcut icon" href="/f.png"><link href='t.png' rel="apple-touch-icon" sizes=180x180>
            <link rel=stylesheet href=x.css><link rel="icon" href="http://insecure.example/i.ico"><link rel="icon" href="l.svg"></head>"#;
        assert_eq!(icon_links(html, &base), vec!["https://site.example/app/t.png", "https://site.example/f.png"]);
    }

    #[test]
    fn parents() {
        assert_eq!(candidate_hosts("auth.eu.ovhcloud.com"), vec!["auth.eu.ovhcloud.com", "eu.ovhcloud.com", "ovhcloud.com"]);
        assert_eq!(candidate_hosts("www.bbc.co.uk"), vec!["www.bbc.co.uk", "bbc.co.uk"]);
        assert_eq!(candidate_hosts("github.com"), vec!["github.com"]);
    }

    #[test]
    fn sniffing() {
        assert_eq!(sniff(b"\x89PNG\r\n"), Some("image/png"));
        assert_eq!(sniff(b"<html>"), None);
        assert_eq!(sniff(b"<svg onload=alert(1)>"), None);
    }
}

#[cfg(test)]
mod net_tests {
    #[tokio::test]
    #[ignore = "réseau"]
    async fn real_sites() {
        let st = super::FaviconState::new();
        for h in ["github.com", "www.wikipedia.org"] {
            let b = super::fetch(&st.client, &format!("https://{h}/favicon.ico")).await;
            assert!(b.is_some(), "{h}");
        }
    }
}
