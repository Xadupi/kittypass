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

/// Icône du site d'une URL, en `data:` URL, ou `null` si aucune.
#[tauri::command]
pub async fn favicon(handle: AppHandle, state: State<'_, FaviconState>, url: String) -> Result<Option<String>, String> {
    let Some(host) = public_host(&url) else { return Ok(None) };
    let path = cache_path(&handle, &host);
    if let Some(p) = &path
        && let Ok(meta) = std::fs::metadata(p)
    {
        let fresh = meta.modified().ok().and_then(|m| SystemTime::now().duration_since(m).ok()).is_some_and(|age| age < RETRY_AFTER);
        if meta.len() > 0 {
            return Ok(std::fs::read(p).ok().and_then(|b| data_url(&b)));
        }
        if fresh {
            return Ok(None);
        }
    }
    let _permit = state.gate.clone().acquire_owned().await.map_err(|e| e.to_string())?;
    let mut got = None;
    for path in ["/favicon.ico", "/apple-touch-icon.png"] {
        if let Some(b) = fetch(&state.client, &format!("https://{host}{path}")).await {
            got = Some(b);
            break;
        }
    }
    if let Some(p) = &path {
        let _ = std::fs::write(p, got.as_deref().unwrap_or_default());
    }
    Ok(got.and_then(|b| data_url(&b)))
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
