//! Android : secrets dans le Keystore du téléphone, par le plugin Kotlin
//! `KittySecurePlugin` (voir `gen/android/.../KittySecurePlugin.kt`).
//!
//! - jeton de session : clé sans authentification (l'appli reste connectée
//!   au serveur entre deux lancements, comme sur ordinateur) ;
//! - mot de passe maître pour le déverrouillage biométrique : clé qui exige
//!   une biométrie forte à chaque usage.

use kittypass_app::{AppResult, SecretStore};
use serde::{Deserialize, Serialize};
use tauri::{
    Manager, Runtime, Wry,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

#[derive(Clone)]
pub struct Secure(PluginHandle<Wry>);

pub fn plugin() -> TauriPlugin<Wry> {
    Builder::new("kittysecure")
        .setup(|app, api| {
            let h = api.register_android_plugin("org.kittypass.app", "KittySecurePlugin")?;
            app.manage(Secure(h));
            Ok(())
        })
        .build()
}

#[derive(Serialize)]
struct SealArgs<'a> {
    key: &'a str,
    value: &'a str,
    bio: bool,
    title: &'a str,
}

#[derive(Serialize)]
struct KeyArgs<'a> {
    key: &'a str,
    bio: bool,
    title: &'a str,
}

#[derive(Deserialize, Default)]
struct Opened {
    value: Option<String>,
}

#[derive(Deserialize)]
pub struct Status {
    pub available: bool,
    pub enabled: bool,
    pub reason: Option<String>,
}

const TITLE: &str = "Déverrouiller KittyPass";

impl Secure {
    pub fn from<R: Runtime>(m: &impl Manager<R>) -> Self {
        m.state::<Secure>().inner().clone()
    }

    pub fn seal(&self, key: &str, value: &str, bio: bool) -> Result<(), String> {
        self.0.run_mobile_plugin::<serde_json::Value>("seal", SealArgs { key, value, bio, title: TITLE }).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn open(&self, key: &str, bio: bool) -> Result<Option<String>, String> {
        self.0.run_mobile_plugin::<Opened>("open", KeyArgs { key, bio, title: TITLE }).map(|o| o.value).map_err(|e| e.to_string())
    }

    pub fn remove(&self, key: &str, bio: bool) {
        let _ = self.0.run_mobile_plugin::<serde_json::Value>("remove", KeyArgs { key, bio, title: TITLE });
    }

    pub fn status(&self) -> Result<Status, String> {
        self.0.run_mobile_plugin::<Status>("status", ()).map_err(|e| e.to_string())
    }
}

/// Jeton de session chiffré par le Keystore.
pub struct AndroidStore(pub Secure);

impl SecretStore for AndroidStore {
    fn load(&self, key: &str) -> Option<String> {
        self.0.open(key, false).ok().flatten()
    }

    fn save(&self, key: &str, value: &str) -> AppResult<()> {
        if let Err(e) = self.0.seal(key, value, false) {
            eprintln!("Keystore indisponible, jeton non conservé : {e}");
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> AppResult<()> {
        self.0.remove(key, false);
        Ok(())
    }
}

// ---------- Remplissage automatique ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FillRequest {
    id: i64,
    web_domain: Option<String>,
    package: Option<String>,
    /// Recherche manuelle (activité « Rechercher dans KittyPass… »).
    query: Option<String>,
    /// Entrée choisie à associer à `web_domain`.
    remember: Option<String>,
}

#[derive(Serialize)]
struct FillReply {
    id: i64,
    locked: bool,
    items: Vec<kittypass_app::AutofillItem>,
}

/// Canal gardé en vie tant que l'appli tourne.
pub struct AutofillChannel(#[allow(dead_code)] tauri::ipc::Channel<serde_json::Value>);

/// Branche le service de remplissage d'Android sur le coffre : chaque demande
/// arrive par un canal, la réponse repart directement au service.
pub fn register_autofill(handle: &tauri::AppHandle) {
    let h = handle.clone();
    let channel = tauri::ipc::Channel::<serde_json::Value>::new(move |body| {
        let parsed = match &body {
            tauri::ipc::InvokeResponseBody::Json(raw) => serde_json::from_str::<FillRequest>(raw),
            tauri::ipc::InvokeResponseBody::Raw(raw) => serde_json::from_slice::<FillRequest>(raw),
        };
        let Ok(req) = parsed else {
            eprintln!("kittypass: demande de remplissage illisible");
            return Ok(());
        };
        let h = h.clone();
        tauri::async_runtime::spawn(async move {
            let app = h.state::<std::sync::Arc<kittypass_app::App>>().inner().clone();
            if let (Some(entry), Some(domain)) = (&req.remember, &req.web_domain) {
                let ok = app.autofill_remember(entry, domain).await.is_ok();
                let reply = FillReply { id: req.id, locked: !ok, items: vec![] };
                let secure = Secure::from(&h);
                let _ = tauri::async_runtime::spawn_blocking(move || {
                    secure.0.run_mobile_plugin::<serde_json::Value>("autofillReply", reply)
                })
                .await;
                return;
            }
            let found = match &req.query {
                Some(q) => app.autofill_search(q).await,
                None => app.autofill_candidates(req.web_domain.as_deref(), req.package.as_deref()).await,
            };
            let reply = match found {
                Ok(items) => FillReply { id: req.id, locked: false, items },
                Err(_) => FillReply { id: req.id, locked: true, items: vec![] },
            };
            let secure = Secure::from(&h);
            let _ = tauri::async_runtime::spawn_blocking(move || {
                secure.0.run_mobile_plugin::<serde_json::Value>("autofillReply", reply)
            })
            .await;
        });
        Ok(())
    });
    #[derive(Serialize)]
    struct Register<'a> {
        channel: &'a tauri::ipc::Channel<serde_json::Value>,
    }
    let secure = Secure::from(handle);
    if secure.0.run_mobile_plugin::<serde_json::Value>("registerAutofill", Register { channel: &channel }).is_ok() {
        handle.manage(AutofillChannel(channel));
    }
}

#[derive(Serialize, Deserialize)]
pub struct AutofillStatus {
    pub supported: bool,
    pub enabled: bool,
}

pub async fn autofill_status(handle: tauri::AppHandle) -> AutofillStatus {
    let s = Secure::from(&handle);
    tauri::async_runtime::spawn_blocking(move || s.0.run_mobile_plugin::<AutofillStatus>("autofillStatus", ()))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(AutofillStatus { supported: false, enabled: false })
}

pub async fn autofill_settings(handle: tauri::AppHandle) -> Result<(), String> {
    let s = Secure::from(&handle);
    tauri::async_runtime::spawn_blocking(move || s.0.run_mobile_plugin::<serde_json::Value>("openAutofillSettings", ()))
        .await
        .map_err(|e| e.to_string())?
        .map(|_| ())
        .map_err(|e| e.to_string())
}
