//! Fenêtre « accès rapide » (bureau) : demandes de l'extension navigateur et
//! choix de l'entrée pour la saisie automatique. Toujours au premier plan,
//! elle s'affiche seule, sans faire venir la fenêtre principale.
//!
//! Créée cachée au démarrage pour que ses écouteurs d'événements soient
//! prêts avant la première demande.

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Window, WindowEvent};

pub const LABEL: &str = "quick";
const TITLE: &str = "KittyPass — Accès rapide";
const WIDTH: f64 = 520.0;

fn build(handle: &AppHandle) -> tauri::Result<WebviewWindow> {
    WebviewWindowBuilder::new(handle, LABEL, WebviewUrl::App("index.html".into()))
        .title(TITLE)
        .inner_size(WIDTH, 420.0)
        .min_inner_size(360.0, 160.0)
        .always_on_top(true)
        .center()
        .visible(false)
        .build()
}

/// À appeler au démarrage.
pub fn create(handle: &AppHandle) {
    if handle.get_webview_window(LABEL).is_none() {
        let _ = build(handle);
    }
}

/// Affiche la fenêtre rapide au premier plan.
pub fn show(handle: &AppHandle) {
    let Some(w) = handle.get_webview_window(LABEL).or_else(|| build(handle).ok()) else { return };
    let _ = w.unminimize();
    let _ = w.center();
    let _ = w.show();
    let _ = w.set_always_on_top(true);
    let _ = w.set_focus();
    let _ = w.request_user_attention(Some(tauri::UserAttentionType::Critical));
    // KDE Wayland refuse le premier plan sans jeton d'activation.
    #[cfg(target_os = "linux")]
    tauri::async_runtime::spawn(crate::raise::kwin_activate(Some(TITLE)));
}

pub fn hide(handle: &AppHandle) {
    if let Some(w) = handle.get_webview_window(LABEL) {
        let _ = w.hide();
    }
}

/// Ajuste la hauteur à ce que la fenêtre montre (bornée à l'écran).
#[tauri::command]
pub fn quick_resize(handle: AppHandle, height: f64) {
    let Some(w) = handle.get_webview_window(LABEL) else { return };
    let max = w
        .current_monitor()
        .ok()
        .flatten()
        .map(|m| m.size().height as f64 / m.scale_factor() * 0.85)
        .unwrap_or(800.0);
    let h = height.clamp(160.0, max);
    let _ = w.set_size(tauri::LogicalSize::new(WIDTH, h));
    let _ = w.center();
}

/// Plus rien à montrer : la fenêtre rapide se cache.
#[tauri::command]
pub fn quick_hide(handle: AppHandle) {
    hide(&handle);
}

/// Fermer la fenêtre rapide la cache seulement (ses demandes sont refusées) ;
/// fermer la fenêtre principale quitte l'application.
pub fn on_window_event(w: &Window, ev: &WindowEvent) {
    match (w.label(), ev) {
        (LABEL, WindowEvent::CloseRequested { api, .. }) => {
            api.prevent_close();
            let _ = w.hide();
            let _ = w.emit_to(LABEL, "quick_closed", ());
        }
        ("main", WindowEvent::Destroyed) => w.app_handle().exit(0),
        _ => {}
    }
}
