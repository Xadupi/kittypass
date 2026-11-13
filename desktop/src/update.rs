#![cfg_attr(mobile, allow(dead_code))]
//! Mises à jour de l'application depuis les Releases GitHub.
//!
//! Windows, macOS et AppImage : installation intégrée (greffon updater de
//! Tauri, fichiers signés par la clé du projet, vérifiés avant installation).
//! Paquet .deb, Android, iOS : l'appli signale seulement la nouvelle version
//! et ouvre la page de téléchargement.

use serde::Serialize;
use tauri::AppHandle;

const API_LATEST: &str = "https://api.github.com/repos/Xadupi/kittypass/releases/latest";
const PAGE_LATEST: &str = "https://github.com/Xadupi/kittypass/releases/latest";

#[derive(Serialize)]
pub struct UpdateInfo {
    current: String,
    /// Version plus récente que `current`, s'il y en a une.
    latest: Option<String>,
    notes: String,
    /// L'appli peut s'installer elle-même (sinon : page de téléchargement).
    installable: bool,
}

/// « 1.2.3 » ou « v1.2.3 » → (1, 2, 3) ; `None` si ce n'est pas une version.
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split(['.', '-', '+']).map(|p| p.parse::<u64>());
    Some((it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?))
}

fn newer(latest: &str, current: &str) -> bool {
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

fn short(notes: &str) -> String {
    notes.chars().take(4000).collect()
}

/// Installation intégrée possible sur cette plateforme et ce mode d'installation.
fn self_install() -> bool {
    cfg!(any(target_os = "windows", target_os = "macos")) || (cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_some())
}

/// Dernière Release publiée, par l'API GitHub : (version, notes).
async fn github_latest() -> Result<(String, String), String> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
        #[serde(default)]
        body: Option<String>,
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("KittyPass/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| "client HTTP indisponible".to_string())?;
    let resp = client
        .get(API_LATEST)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "GitHub injoignable".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("GitHub a répondu {}", resp.status().as_u16()));
    }
    let bytes = resp.bytes().await.map_err(|_| "réponse de GitHub incomplète".to_string())?;
    let r: Release = serde_json::from_slice(&bytes).map_err(|_| "réponse de GitHub illisible".to_string())?;
    Ok((r.tag_name.trim_start_matches('v').to_owned(), short(r.body.as_deref().unwrap_or(""))))
}

#[tauri::command]
pub async fn update_check(handle: AppHandle) -> Result<UpdateInfo, String> {
    let current = handle.package_info().version.to_string();
    #[cfg(desktop)]
    if self_install() {
        use tauri_plugin_updater::UpdaterExt;
        let updater = handle.updater().map_err(|e| format!("mise à jour : {e}"))?;
        return match updater.check().await {
            Ok(Some(u)) => Ok(UpdateInfo { latest: Some(u.version.clone()), notes: short(u.body.as_deref().unwrap_or("")), installable: true, current }),
            Ok(None) => Ok(UpdateInfo { latest: None, notes: String::new(), installable: true, current }),
            Err(e) => Err(format!("recherche de mise à jour impossible : {e}")),
        };
    }
    let (latest, notes) = github_latest().await?;
    Ok(UpdateInfo { latest: newer(&latest, &current).then_some(latest), notes, installable: false, current })
}

#[derive(Clone, Serialize)]
struct Progress {
    done: u64,
    total: Option<u64>,
}

/// Télécharge, vérifie la signature, installe puis redémarre l'appli.
#[tauri::command]
pub async fn update_install(handle: AppHandle) -> Result<(), String> {
    #[cfg(desktop)]
    if self_install() {
        use tauri::Emitter;
        use tauri_plugin_updater::UpdaterExt;
        let updater = handle.updater().map_err(|e| format!("mise à jour : {e}"))?;
        let update = updater.check().await.map_err(|e| format!("recherche de mise à jour impossible : {e}"))?.ok_or("déjà à jour")?;
        let mut done = 0u64;
        let h = handle.clone();
        update
            .download_and_install(
                move |chunk, total| {
                    done += chunk as u64;
                    let _ = h.emit("update_progress", Progress { done, total });
                },
                || {},
            )
            .await
            .map_err(|e| format!("installation impossible : {e}"))?;
        handle.restart();
    }
    let _ = handle;
    Err("installation intégrée indisponible : téléchargez la nouvelle version".into())
}

/// Ouvre la page de la dernière Release (paquet .deb, Android, iOS).
#[tauri::command]
pub fn update_open_page(handle: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    handle.opener().open_url(PAGE_LATEST, None::<&str>).map_err(|_| "navigateur introuvable".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse("1.10.0-beta"), Some((1, 10, 0)));
        assert_eq!(parse("nightly"), None);
        assert!(newer("1.0.1", "1.0.0"));
        assert!(newer("v1.10.0", "1.9.9"));
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("0.9.0", "1.0.0"));
        assert!(!newer("bad", "1.0.0"));
    }
}
