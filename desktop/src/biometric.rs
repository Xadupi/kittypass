//! Déverrouillage par empreinte digitale.
//!
//! Linux : fprintd (D-Bus système), le service déjà utilisé par sudo, GDM ou
//! SDDM. Le mot de passe principal est gardé dans le trousseau du système
//! (Secret Service : KWallet / GNOME Keyring, chiffré par la session) et n'en
//! sort qu'après une empreinte reconnue. Ce n'est pas un chiffrement par
//! l'empreinte : quelqu'un qui a déjà accès à la session ouverte et au
//! trousseau pourrait lire le mot de passe. D'où l'option désactivée par défaut.
//! Windows : Windows Hello (visage, empreinte ou code PIN), mot de passe
//! gardé dans le Gestionnaire d'identification, avec la même réserve.
#![cfg_attr(target_os = "android", allow(dead_code))]

use kittypass_app::AppError;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::{AppState, R};

#[cfg(any(target_os = "linux", windows))]
const KEY: &str = "biometric-unlock";
#[cfg(any(target_os = "linux", windows))]
const SERVICE: &str = "org.kittypass.desktop";

#[derive(Serialize)]
pub struct BiometricStatus {
    pub available: bool,
    pub enabled: bool,
    /// Pourquoi ce n'est pas disponible (pour l'interface).
    pub reason: Option<String>,
    /// Nom affiché : « l'empreinte », « Windows Hello »…
    pub label: &'static str,
    /// Titre de la section des réglages.
    pub title: &'static str,
    /// Où est gardé le mot de passe.
    pub hint: &'static str,
}

#[cfg(windows)]
const TEXTS: (&str, &str, &str) = (
    "Windows Hello",
    "Windows Hello",
    "Le mot de passe maître est gardé dans le Gestionnaire d'identification de Windows et n'en sort qu'après une vérification Windows Hello (visage, empreinte ou code PIN).",
);
#[cfg(not(windows))]
const TEXTS: (&str, &str, &str) = (
    "l'empreinte",
    "Empreinte digitale",
    "Le mot de passe maître est gardé dans le trousseau de votre session (KWallet / GNOME Keyring) et n'en sort qu'après une empreinte reconnue par le lecteur (fprintd).",
);

#[cfg(not(any(target_os = "linux", windows)))]
fn stored() -> Option<Zeroizing<String>> {
    None
}
#[cfg(not(any(target_os = "linux", windows)))]
fn store(_: &str) -> Result<(), String> {
    Err("trousseau indisponible".into())
}
#[cfg(not(any(target_os = "linux", windows)))]
fn forget() {}

#[cfg(any(target_os = "linux", windows))]
fn stored() -> Option<Zeroizing<String>> {
    keyring::Entry::new(SERVICE, KEY).ok()?.get_password().ok().map(Zeroizing::new)
}

#[cfg(any(target_os = "linux", windows))]
fn store(password: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, KEY).and_then(|e| e.set_password(password)).map_err(|e| e.to_string())
}

#[cfg(any(target_os = "linux", windows))]
fn forget() {
    if let Ok(e) = keyring::Entry::new(SERVICE, KEY) {
        let _ = e.delete_credential();
    }
}

fn err(msg: &'static str) -> AppError {
    kittypass_core::Error::InvalidArgument(msg).into()
}

#[cfg(target_os = "linux")]
mod fprint {
    use futures_util::StreamExt;
    use std::time::Duration;
    use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

    const BUS: &str = "net.reactivated.Fprint";

    async fn device(conn: &Connection) -> zbus::Result<Proxy<'static>> {
        let mgr = Proxy::new(conn, BUS, "/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager").await?;
        let path: OwnedObjectPath = mgr.call("GetDefaultDevice", &()).await?;
        Proxy::new(conn, BUS, path, "net.reactivated.Fprint.Device").await
    }

    /// `Ok(())` si un lecteur est présent avec au moins un doigt enregistré.
    pub async fn ready() -> Result<(), String> {
        let conn = Connection::system().await.map_err(|_| "bus système indisponible".to_string())?;
        let dev = device(&conn).await.map_err(|_| "aucun lecteur d'empreintes (fprintd)".to_string())?;
        let fingers: Vec<String> = dev.call("ListEnrolledFingers", &("",)).await.unwrap_or_default();
        if fingers.is_empty() {
            return Err("aucune empreinte enregistrée (Paramètres du système → Utilisateurs)".into());
        }
        Ok(())
    }

    /// Attend une empreinte reconnue (3 essais, 30 s). `progress` reçoit les
    /// messages à afficher.
    pub async fn verify(progress: impl Fn(&str)) -> Result<(), String> {
        let conn = Connection::system().await.map_err(|e| e.to_string())?;
        let dev = device(&conn).await.map_err(|_| "aucun lecteur d'empreintes".to_string())?;
        dev.call::<_, _, ()>("Claim", &("",)).await.map_err(|e| format!("lecteur occupé ou refusé : {e}"))?;
        let result = async {
            let mut stream = dev.receive_signal("VerifyStatus").await.map_err(|e| e.to_string())?;
            for attempt in 0..3 {
                progress(if attempt == 0 { "Posez votre doigt sur le lecteur…" } else { "Empreinte non reconnue, réessayez…" });
                dev.call::<_, _, ()>("VerifyStart", &("any",)).await.map_err(|e| e.to_string())?;
                let outcome = tokio::time::timeout(Duration::from_secs(30), async {
                    while let Some(msg) = stream.next().await {
                        let Ok((status, done)) = msg.body().deserialize::<(String, bool)>() else { continue };
                        match status.as_str() {
                            "verify-match" => return Ok(true),
                            "verify-no-match" => return Ok(false),
                            "verify-retry-scan" | "verify-swipe-too-short" | "verify-finger-not-centered"
                            | "verify-remove-and-retry" => progress("Reposez le doigt bien à plat…"),
                            "verify-disconnected" => return Err("lecteur débranché".to_string()),
                            _ if done => return Err("erreur du lecteur".to_string()),
                            _ => {}
                        }
                    }
                    Err("fprintd a coupé la vérification".to_string())
                })
                .await;
                let _ = dev.call::<_, _, ()>("VerifyStop", &()).await;
                match outcome {
                    Ok(Ok(true)) => return Ok(()),
                    Ok(Ok(false)) => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err("délai dépassé".to_string()),
                }
            }
            Err("empreinte non reconnue".to_string())
        }
        .await;
        let _ = dev.call::<_, _, ()>("Release", &()).await;
        result
    }
}

/// Windows Hello (UserConsentVerifier), fenêtre de KittyPass en parent.
#[cfg(windows)]
mod hello {
    #![allow(unsafe_code)]
    use tauri::{AppHandle, Manager};
    use windows::{
        Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability},
        Win32::System::WinRT::IUserConsentVerifierInterop,
        core::HSTRING,
    };

    pub async fn ready() -> Result<(), String> {
        tauri::async_runtime::spawn_blocking(|| {
            let a = UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join()).map_err(|e| e.message())?;
            match a {
                UserConsentVerifierAvailability::Available => Ok(()),
                UserConsentVerifierAvailability::DeviceNotPresent => Err("aucun capteur Windows Hello".into()),
                UserConsentVerifierAvailability::NotConfiguredForUser => Err("Windows Hello n'est pas configuré (Paramètres → Comptes → Options de connexion)".into()),
                UserConsentVerifierAvailability::DisabledByPolicy => Err("Windows Hello est désactivé par une stratégie".into()),
                _ => Err("Windows Hello indisponible pour le moment".into()),
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn verify(handle: &AppHandle) -> Result<(), String> {
        let hwnd = handle.get_webview_window("main").and_then(|w| w.hwnd().ok()).ok_or("fenêtre introuvable")?;
        let hwnd = hwnd.0 as isize;
        tauri::async_runtime::spawn_blocking(move || {
            let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(|e| e.message())?;
            let msg = HSTRING::from("Déverrouiller KittyPass");
            // SAFETY : `hwnd` est la fenêtre principale de KittyPass, vivante.
            let op: windows_future::IAsyncOperation<UserConsentVerificationResult> = unsafe {
                interop.RequestVerificationForWindowAsync(windows::Win32::Foundation::HWND(hwnd as *mut _), &msg)
            }
            .map_err(|e| e.message())?;
            match op.join().map_err(|e| e.message())? {
                UserConsentVerificationResult::Verified => Ok(()),
                UserConsentVerificationResult::Canceled => Err("annulé".into()),
                _ => Err("non reconnu".into()),
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
#[allow(dead_code)]
mod fprint {
    pub async fn ready() -> Result<(), String> {
        Err("pas pris en charge sur ce système".into())
    }
    pub async fn verify(_: impl Fn(&str)) -> Result<(), String> {
        ready().await
    }
}

async fn ready() -> Result<(), String> {
    #[cfg(windows)]
    return hello::ready().await;
    #[cfg(not(windows))]
    fprint::ready().await
}

async fn verify(handle: &AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    return hello::verify(handle).await;
    #[cfg(not(windows))]
    fprint::verify(emitter(handle)).await
}

#[cfg_attr(windows, allow(dead_code))]
fn emitter(handle: &AppHandle) -> impl Fn(&str) + '_ {
    move |m: &str| {
        let _ = handle.emit("biometric-progress", m.to_string());
    }
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn biometric_status() -> BiometricStatus {
    let ready = ready().await;
    let enabled = stored().is_some();
    BiometricStatus { available: ready.is_ok(), enabled, reason: ready.err(), label: TEXTS.0, title: TEXTS.1, hint: TEXTS.2 }
}

/// Active : vérifie le mot de passe, demande une empreinte, puis range le mot
/// de passe dans le trousseau.
#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn biometric_enable(handle: AppHandle, app: AppState<'_>, password: Zeroizing<String>) -> R<()> {
    app.check_password(&password).await?;
    ready().await.map_err(|_| err("lecteur d'empreintes indisponible"))?;
    verify(&handle).await.map_err(|_| err("empreinte non reconnue"))?;
    store(&password).map_err(|_| err("trousseau du système indisponible"))?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub fn biometric_disable() {
    forget();
}

/// Déverrouille après une empreinte reconnue.
#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn biometric_unlock(
    handle: AppHandle,
    app: AppState<'_>,
    b: State<'_, crate::browser::BrowserState>,
) -> R<()> {
    if stored().is_none() {
        return Err(err("empreinte non activée"));
    }
    verify(&handle).await.map_err(|_| err("empreinte non reconnue"))?;
    let password = stored().ok_or(err("empreinte non activée"))?;
    if let Err(e) = app.unlock(&password).await {
        // Mot de passe changé depuis : on oublie l'ancien.
        if e.code() == "invalid_password" {
            forget();
            return Err(err("mot de passe changé : réactivez l'empreinte"));
        }
        return Err(e);
    }
    b.notify(false).await;
    Ok(())
}

// ---------- Android : BiometricPrompt + Keystore ----------

#[cfg(target_os = "android")]
const ANDROID_TEXTS: (&str, &str, &str) = (
    "la biométrie",
    "Déverrouillage biométrique",
    "Le mot de passe maître est chiffré par une clé du Keystore Android qui n'est utilisable qu'après une biométrie forte (empreinte ou visage). Ajouter une empreinte au téléphone désactive ce déverrouillage.",
);

#[cfg(target_os = "android")]
async fn on_secure<T: Send + 'static>(
    handle: &AppHandle,
    f: impl FnOnce(crate::android_secure::Secure) -> T + Send + 'static,
) -> T {
    let s = crate::android_secure::Secure::from(handle);
    tauri::async_runtime::spawn_blocking(move || f(s)).await.expect("tâche biométrie")
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn biometric_status(handle: AppHandle) -> BiometricStatus {
    let st = on_secure(&handle, |s| s.status()).await;
    let (available, enabled, reason) = match st {
        Ok(s) => (s.available, s.enabled, s.reason),
        Err(e) => (false, false, Some(e)),
    };
    BiometricStatus { available, enabled, reason, label: ANDROID_TEXTS.0, title: ANDROID_TEXTS.1, hint: ANDROID_TEXTS.2 }
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn biometric_enable(handle: AppHandle, app: AppState<'_>, password: Zeroizing<String>) -> R<()> {
    app.check_password(&password).await?;
    on_secure(&handle, move |s| s.seal(KEY_ANDROID, &password, true))
        .await
        .map_err(|e| if e.contains("annulé") { err("annulé") } else { err("biométrie refusée ou indisponible") })
}

#[cfg(target_os = "android")]
const KEY_ANDROID: &str = "biometric-unlock";

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn biometric_disable(handle: AppHandle) {
    on_secure(&handle, |s| s.remove(KEY_ANDROID, true)).await;
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn biometric_unlock(
    handle: AppHandle,
    app: AppState<'_>,
    b: State<'_, crate::browser::BrowserState>,
) -> R<()> {
    let opened = on_secure(&handle, |s| s.open(KEY_ANDROID, true)).await;
    let password = match opened {
        Ok(Some(p)) => Zeroizing::new(p),
        Ok(None) => return Err(err("biométrie non activée")),
        Err(e) if e.contains("réactivez") => return Err(err("biométrie modifiée sur le téléphone : réactivez-la dans KittyPass")),
        Err(e) if e.contains("annulé") => return Err(err("annulé")),
        Err(_) => return Err(err("biométrie non reconnue")),
    };
    if let Err(e) = app.unlock(&password).await {
        if e.code() == "invalid_password" {
            on_secure(&handle, |s| s.remove(KEY_ANDROID, true)).await;
            return Err(err("mot de passe changé : réactivez la biométrie"));
        }
        return Err(e);
    }
    b.notify(false).await;
    Ok(())
}
