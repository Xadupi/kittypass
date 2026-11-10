//! Intégration navigateur côté bureau : interrupteur KittyPass / KeePassXC,
//! serveur du socket local et questions posées dans la fenêtre.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use kittypass_app::{
    Answer, App, AppError, AssociationView, BrowserSettings, EntryBrowserView, Hosts, HostsStatus, Prompt, Prompter,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;

type R<T> = Result<T, AppError>;

/// Questions en attente de réponse, par numéro.
pub struct DesktopPrompter {
    handle: AppHandle,
    next: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Option<Answer>>>>,
}

#[derive(Serialize, Clone)]
struct PromptEvent {
    id: u64,
    prompt: Prompt,
}

/// Retire la question si elle est abandonnée (délai dépassé, connexion
/// fermée) et prévient la fenêtre de fermer la boîte.
struct Pending<'a> {
    p: &'a DesktopPrompter,
    id: u64,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let removed = self.p.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
        if removed.is_some() {
            let _ = self.p.handle.emit("browser_prompt_closed", self.id);
        }
    }
}

impl DesktopPrompter {
    pub fn new(handle: AppHandle) -> Self {
        Self { handle, next: AtomicU64::new(1), pending: Mutex::new(HashMap::new()) }
    }

    fn raise(&self) {
        #[cfg(desktop)]
        if let Some(w) = self.handle.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
            let _ = w.request_user_attention(Some(tauri::UserAttentionType::Critical));
            // X11 : passer brièvement « au-dessus » force le premier plan.
            let _ = w.set_always_on_top(true);
            let w2 = w.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                let _ = w2.set_always_on_top(false);
            });
        }
        // KDE Wayland refuse le premier plan sans jeton d'activation : on
        // demande à KWin lui-même d'activer la fenêtre.
        #[cfg(target_os = "linux")]
        tauri::async_runtime::spawn(crate::raise::kwin_activate());
    }

    pub fn answer(&self, id: u64, answer: Option<Answer>) {
        let tx = self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(answer);
        }
    }
}

impl Prompter for DesktopPrompter {
    async fn ask(&self, prompt: Prompt) -> Option<Answer> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        let _guard = Pending { p: self, id };
        self.raise();
        self.handle.emit("browser_prompt", PromptEvent { id, prompt }).ok()?;
        rx.await.ok().flatten()
    }

    fn unlock_requested(&self) {
        self.raise();
        let _ = self.handle.emit("browser_unlock_requested", ());
    }

    fn locked(&self) {
        let _ = self.handle.emit("locked", ());
        let handle = self.handle.clone();
        tauri::async_runtime::spawn(async move { handle.state::<BrowserState>().notify(true).await });
    }
}

/// Serveur du socket, présent quand l'intégration est activée.
#[derive(Default)]
pub struct BrowserState {
    #[cfg(any(unix, windows))]
    server: tokio::sync::Mutex<Option<kittypass_app::BrowserServer>>,
}

impl BrowserState {
    /// Prévient les navigateurs du verrouillage / déverrouillage.
    pub async fn notify(&self, locked: bool) {
        #[cfg(any(unix, windows))]
        if let Some(s) = self.server.lock().await.as_ref() {
            s.notify(if locked { "database-locked" } else { "database-unlocked" });
        }
        #[cfg(not(any(unix, windows)))]
        let _ = locked;
    }

    #[cfg(any(unix, windows))]
    async fn start(&self, handle: &AppHandle) -> R<()> {
        let mut server = self.server.lock().await;
        if server.is_none() {
            let app = handle.state::<Arc<App>>().inner().clone();
            let prompter = handle.state::<Arc<DesktopPrompter>>().inner().clone();
            *server = Some(kittypass_app::BrowserServer::start(app, prompter).await?);
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    async fn start(&self, _: &AppHandle) -> R<()> {
        Err(AppError::Io("intégration navigateur pas encore disponible sur ce système".into()))
    }

    async fn stop(&self) {
        #[cfg(any(unix, windows))]
        self.server.lock().await.take();
    }

    async fn running(&self) -> bool {
        #[cfg(any(unix, windows))]
        return self.server.lock().await.is_some();
        #[cfg(not(any(unix, windows)))]
        false
    }
}

/// Au lancement : reprend l'état choisi par l'utilisateur.
pub async fn restore(handle: AppHandle) {
    let app = handle.state::<Arc<App>>().inner().clone();
    if app.browser_settings().enabled {
        let state = handle.state::<BrowserState>();
        if let Err(e) = state.start(&handle).await {
            let _ = handle.emit("browser_error", serde_json::json!({"message": e.to_string()}));
            return;
        }
        // KeePassXC réécrit les manifestes à son lancement : on les reprend.
        if let Ok(hosts) = Hosts::system()
            && let Err(e) = hosts.use_kittypass()
        {
            let _ = handle.emit("browser_error", serde_json::json!({"message": e.to_string()}));
        }
        // Et s'il est lancé après KittyPass : vérification toutes les 30 s.
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                if !app.browser_settings().enabled {
                    continue;
                }
                if let Ok(hosts) = Hosts::system()
                    && hosts.status().browsers.iter().any(|b| b.owner == kittypass_app::Owner::KeePassXc)
                {
                    let _ = hosts.use_kittypass();
                }
            }
        });
    }
}

#[derive(Serialize)]
pub struct BrowserStatus {
    enabled: bool,
    running: bool,
    hosts: Option<HostsStatus>,
}

#[tauri::command]
pub async fn browser_status(app: State<'_, Arc<App>>, state: State<'_, BrowserState>) -> R<BrowserStatus> {
    Ok(BrowserStatus { enabled: app.browser_settings().enabled, running: state.running().await, hosts: Hosts::system().ok().map(|h| h.status()) })
}

/// Interrupteur : l'extension parle à KittyPass, ou de nouveau à KeePassXC.
#[tauri::command]
pub async fn browser_set_enabled(
    handle: AppHandle,
    app: State<'_, Arc<App>>,
    state: State<'_, BrowserState>,
    enabled: bool,
) -> R<BrowserStatus> {
    let hosts = Hosts::system()?;
    if enabled {
        state.start(&handle).await?;
        if let Err(e) = hosts.use_kittypass() {
            state.stop().await;
            return Err(e);
        }
    } else {
        state.stop().await;
        hosts.use_keepassxc()?;
    }
    app.save_browser_settings(&BrowserSettings { enabled })?;
    browser_status(app, state).await
}

#[tauri::command]
pub fn browser_answer(prompter: State<'_, Arc<DesktopPrompter>>, id: u64, answer: Option<Answer>) {
    prompter.answer(id, answer);
}

#[tauri::command]
pub async fn browser_associations(app: State<'_, Arc<App>>) -> R<Vec<AssociationView>> {
    app.browser_associations().await
}

#[tauri::command]
pub async fn browser_revoke(app: State<'_, Arc<App>>, id: String) -> R<bool> {
    app.browser_revoke(&id).await
}

#[tauri::command]
pub async fn entry_browser(app: State<'_, Arc<App>>, id: String) -> R<EntryBrowserView> {
    app.entry_browser(&id).await
}

#[tauri::command]
pub async fn set_entry_browser(app: State<'_, Arc<App>>, id: String, view: EntryBrowserView) -> R<()> {
    app.set_entry_browser(&id, &view).await
}
