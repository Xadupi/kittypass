//! Saisie automatique : tape une entrée dans la fenêtre précédente, par le
//! portail du bureau (Wayland) ou XTest (X11), et raccourci global qui
//! ouvre le choix d'une entrée.
//!
//! Garde-fous : la saisie n'a lieu que si KittyPass n'a plus le focus, et
//! s'arrête si KittyPass le reprend (sous X11 : si la fenêtre active change).
//! Le raccourci global ne tape jamais sans que l'utilisateur ait choisi
//! l'entrée : une fenêtre ne peut pas obtenir un mot de passe en imitant un
//! titre.

mod keysym;
#[cfg(target_os = "linux")]
mod keymap;
#[cfg(target_os = "linux")]
mod portal;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(windows)]
mod windows;

#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use std::{
    fmt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use kittypass_app::{App, AppError, AutoTypeConfig, AutoTypeMethod, EntryAutoTypeView, EntryListItem};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

type R<T> = Result<T, AppError>;

#[derive(Debug)]
pub enum TypeError {
    /// Autorisation refusée par l'utilisateur (portail).
    Refused,
    /// KittyPass ou une autre fenêtre a pris le focus pendant la saisie.
    FocusLost,
    /// La fenêtre active est KittyPass lui-même.
    OwnWindow,
    /// Touches de l'utilisateur toujours enfoncées.
    KeysHeld,
    Unavailable,
    Backend(String),
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => write!(f, "émulation du clavier refusée"),
            Self::FocusLost => write!(f, "saisie interrompue : la fenêtre active a changé"),
            Self::OwnWindow => write!(f, "aucune autre fenêtre n'a le focus"),
            Self::KeysHeld => write!(f, "relâchez les touches du raccourci"),
            Self::Unavailable => write!(f, "aucun moyen d'émuler le clavier sur ce système"),
            Self::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl From<TypeError> for AppError {
    fn from(e: TypeError) -> Self {
        AppError::Core(kittypass_core::Error::AutoType(e.to_string()))
    }
}

/// Moyen réellement utilisé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effective {
    Portal,
    X11,
    /// Windows : SendInput.
    SendInput,
}

fn effective(m: AutoTypeMethod) -> Option<Effective> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    match m {
        AutoTypeMethod::Portal if cfg!(target_os = "linux") => Some(Effective::Portal),
        AutoTypeMethod::X11 if x11 && cfg!(target_os = "linux") => Some(Effective::X11),
        AutoTypeMethod::Auto if wayland && cfg!(target_os = "linux") => Some(Effective::Portal),
        AutoTypeMethod::Auto if x11 && cfg!(target_os = "linux") => Some(Effective::X11),
        AutoTypeMethod::Auto if cfg!(windows) => Some(Effective::SendInput),
        _ => None,
    }
}

enum Global {
    #[cfg(target_os = "linux")]
    Portal(tauri::async_runtime::JoinHandle<()>),
    #[cfg(target_os = "linux")]
    X11(Arc<AtomicBool>),
    #[cfg(windows)]
    Hotkey(AppHandle, String),
}

impl Drop for Global {
    fn drop(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            Self::Portal(task) => task.abort(),
            #[cfg(target_os = "linux")]
            Self::X11(stop) => stop.store(true, Ordering::Relaxed),
            #[cfg(windows)]
            Self::Hotkey(h, s) => {
                use tauri_plugin_global_shortcut::GlobalShortcutExt;
                let _ = h.global_shortcut().unregister(s.as_str());
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
}

pub struct AutoTypeState {
    dir: PathBuf,
    busy: tokio::sync::Mutex<()>,
    global: Mutex<Option<Global>>,
}

impl AutoTypeState {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, busy: tokio::sync::Mutex::new(()), global: Mutex::new(None) }
    }
}

fn raise(handle: &AppHandle) {
    #[cfg(mobile)]
    let _ = handle;
    #[cfg(desktop)]
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Raccourci global pressé : la fenêtre rapide propose les entrées.
fn on_global(handle: &AppHandle, window: Option<String>) {
    #[cfg(desktop)]
    crate::quick::show(handle);
    #[cfg(mobile)]
    raise(handle);
    let _ = handle.emit("autotype_global", serde_json::json!({ "window": window }));
}

/// (Re)lance l'écoute du raccourci global selon les réglages.
pub fn apply_global(handle: &AppHandle, cfg: &AutoTypeConfig) {
    let state = handle.state::<AutoTypeState>();
    let mut global = state.global.lock().unwrap_or_else(|e| e.into_inner());
    global.take();
    let Some(shortcut) = cfg.global_shortcut.clone() else { return };
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = shortcut;
    let report = |h: &AppHandle, e: TypeError| {
        let _ = h.emit("autotype_error", serde_json::json!({ "message": format!("raccourci global : {e}") }));
    };
    match effective(cfg.method) {
        #[cfg(target_os = "linux")]
        Some(Effective::Portal) => {
            let h = handle.clone();
            let task = tauri::async_runtime::spawn(async move {
                let h2 = h.clone();
                if let Err(e) = portal::global_shortcut(shortcut, move || on_global(&h2, None)).await {
                    report(&h, e);
                }
            });
            *global = Some(Global::Portal(task));
        }
        #[cfg(target_os = "linux")]
        Some(Effective::X11) => {
            let stop = Arc::new(AtomicBool::new(false));
            let (h, s) = (handle.clone(), stop.clone());
            std::thread::spawn(move || {
                let h2 = h.clone();
                if let Err(e) = x11::global_shortcut(&shortcut, s, move |title| on_global(&h2, title)) {
                    report(&h, e);
                }
            });
            *global = Some(Global::X11(stop));
        }
        #[cfg(windows)]
        Some(Effective::SendInput) => {
            use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
            let h = handle.clone();
            // Titre lu au moment de l'appui, avant que KittyPass ne passe
            // au premier plan.
            let r = handle.global_shortcut().on_shortcut(shortcut.as_str(), move |_, _, ev| {
                if ev.state == ShortcutState::Pressed {
                    on_global(&h, windows::foreground_title());
                }
            });
            match r {
                Ok(()) => *global = Some(Global::Hotkey(handle.clone(), shortcut)),
                Err(e) => report(handle, TypeError::Backend(format!("raccourci déjà utilisé ou invalide ({e})"))),
            }
        }
        _ => report(handle, TypeError::Unavailable),
    }
}

/// Au lancement.
pub fn restore(handle: &AppHandle) {
    let cfg = handle.state::<Arc<App>>().autotype_config();
    if cfg.global_shortcut.is_some() {
        apply_global(handle, &cfg);
    }
}

#[derive(Serialize)]
pub struct AutoTypeStatus {
    config: AutoTypeConfig,
    effective: Option<Effective>,
    wayland: bool,
}

#[tauri::command]
pub fn autotype_status(app: State<'_, Arc<App>>) -> AutoTypeStatus {
    let config = app.autotype_config();
    AutoTypeStatus { effective: effective(config.method), config, wayland: std::env::var_os("WAYLAND_DISPLAY").is_some() }
}

#[tauri::command]
pub fn save_autotype_config(handle: AppHandle, app: State<'_, Arc<App>>, config: AutoTypeConfig) -> R<AutoTypeStatus> {
    let before = app.autotype_config();
    let config = app.save_autotype_config(config)?;
    if before.global_shortcut != config.global_shortcut || before.method != config.method {
        apply_global(&handle, &config);
    }
    Ok(autotype_status(app))
}

#[tauri::command]
pub async fn entry_autotype(app: State<'_, Arc<App>>, id: String) -> R<EntryAutoTypeView> {
    app.entry_autotype(&id).await
}

#[tauri::command]
pub async fn set_entry_autotype(app: State<'_, Arc<App>>, id: String, view: EntryAutoTypeView) -> R<()> {
    app.set_entry_autotype(&id, &view).await
}

#[tauri::command]
pub async fn autotype_matches(app: State<'_, Arc<App>>, window: String) -> R<Vec<EntryListItem>> {
    app.autotype_matches(&window).await
}

/// Tape l'entrée dans la fenêtre qui avait le focus avant KittyPass :
/// KittyPass se réduit, attend, puis tape.
#[tauri::command]
pub async fn autotype_entry(
    handle: AppHandle,
    caller: tauri::WebviewWindow,
    app: State<'_, Arc<App>>,
    state: State<'_, AutoTypeState>,
    id: String,
    window: Option<String>,
) -> R<()> {
    let Ok(_busy) = state.busy.try_lock() else {
        return Err(TypeError::Backend("une saisie est déjà en cours".into()).into());
    };
    let cfg = app.autotype_config();
    let method = effective(cfg.method).ok_or(TypeError::Unavailable)?;
    let typed = app.autotype_prepare(&id, window.as_deref(), None).await?;
    // La fenêtre qui a lancé la saisie s'efface : la fenêtre rapide se
    // cache, la principale se réduit.
    let main = caller;
    #[cfg(desktop)]
    let _ = if main.label() == crate::quick::LABEL { main.hide() } else { main.minimize() };
    #[cfg(mobile)]
    let _ = &main;
    tokio::time::sleep(Duration::from_millis(cfg.start_delay_ms.into())).await;
    let delay = Duration::from_millis(cfg.key_delay_ms.into());
    let focused = {
        let main = main.clone();
        move || main.is_focused().unwrap_or(true)
    };
    let result = if focused() {
        Err(TypeError::OwnWindow)
    } else {
        type_with(method, &state.dir, typed, delay, focused).await
    };
    if let Err(e) = result {
        #[cfg(desktop)]
        if main.label() == crate::quick::LABEL {
            crate::quick::show(&handle);
            return Err(e.into());
        }
        raise(&handle);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn type_with(
    method: Effective,
    dir: &std::path::Path,
    typed: kittypass_app::Typed,
    delay: Duration,
    focused: impl Fn() -> bool + Send + 'static,
) -> Result<(), TypeError> {
    match method {
        Effective::SendInput => Err(TypeError::Unavailable),
        Effective::Portal => portal::type_steps(dir, &typed, delay, || !focused()).await,
        Effective::X11 => {
            // Sous Wayland, la fenêtre active vue par X11 ne dit rien des
            // fenêtres Wayland : seul le focus de KittyPass est surveillé.
            let check_window = std::env::var_os("WAYLAND_DISPLAY").is_none();
            tauri::async_runtime::spawn_blocking(move || {
                let x = x11::X11::connect()?;
                let target = x.active_window();
                if check_window && (target.is_none() || target.is_some_and(|w| x.is_own(w))) {
                    return Err(TypeError::OwnWindow);
                }
                x.type_steps(&typed, delay, |x| !focused() && (!check_window || x.active_window() == target))
            })
            .await
            .map_err(|_| TypeError::Unavailable)?
        }
    }
}

#[cfg(windows)]
async fn type_with(
    _: Effective,
    _: &std::path::Path,
    typed: kittypass_app::Typed,
    delay: Duration,
    focused: impl Fn() -> bool + Send + 'static,
) -> Result<(), TypeError> {
    tauri::async_runtime::spawn_blocking(move || {
        let target = windows::foreground().ok_or(TypeError::OwnWindow)?;
        if windows::is_own(target) {
            return Err(TypeError::OwnWindow);
        }
        windows::type_steps(&typed, delay, || !focused() && windows::foreground() == Some(target))
    })
    .await
    .map_err(|_| TypeError::Unavailable)?
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn type_with(
    _: Effective,
    _: &std::path::Path,
    _: kittypass_app::Typed,
    _: Duration,
    _: impl Fn() -> bool + Send + 'static,
) -> Result<(), TypeError> {
    Err(TypeError::Unavailable)
}
