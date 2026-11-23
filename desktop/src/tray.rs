//! Icône dans la zone de notification (bureau).
//!
//! Fermer la fenêtre principale la cache seulement : KittyPass reste lancé
//! pour répondre à l'extension navigateur, au raccourci de saisie
//! automatique et à l'agent SSH. On quitte par le menu de l'icône.
//!
//! `--hidden` (démarrage de session) lance KittyPass sans afficher la
//! fenêtre principale.

use std::sync::Arc;

use kittypass_app::App;
use tauri::{
    AppHandle, Emitter, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

const MAIN: &str = "main";

/// Option de ligne de commande : démarrer caché dans la zone de notification.
pub fn start_hidden() -> bool {
    std::env::args().skip(1).any(|a| a == "--hidden" || a == "--minimized")
}

/// Affiche et met au premier plan la fenêtre principale.
pub fn show_main(handle: &AppHandle) {
    let Some(w) = handle.get_webview_window(MAIN) else { return };
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
    #[cfg(target_os = "linux")]
    tauri::async_runtime::spawn(crate::raise::kwin_activate(Some("KittyPass")));
}

fn toggle_main(handle: &AppHandle) {
    let Some(w) = handle.get_webview_window(MAIN) else { return };
    if w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false) {
        let _ = w.hide();
    } else {
        show_main(handle);
    }
}

/// À appeler au démarrage. Sans zone de notification (ou en cas d'erreur),
/// la fenêtre principale reste affichée pour ne pas « perdre » l'appli.
pub fn create(handle: &AppHandle) -> bool {
    match build(handle) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("KittyPass : icône de notification indisponible ({e})");
            false
        }
    }
}

fn build(handle: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(handle, "open", "Ouvrir KittyPass", true, None::<&str>)?;
    let lock = MenuItem::with_id(handle, "lock", "Verrouiller", true, None::<&str>)?;
    let quit = MenuItem::with_id(handle, "quit", "Quitter", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(handle)?;
    let menu = Menu::with_items(handle, &[&open, &lock, &sep, &quit])?;
    let mut tray = TrayIconBuilder::with_id("kittypass")
        .tooltip("KittyPass")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|h, ev| match ev.id().as_ref() {
            "open" => show_main(h),
            "lock" => {
                let h = h.clone();
                tauri::async_runtime::spawn(async move {
                    let app = h.state::<Arc<App>>().inner().clone();
                    app.lock().await;
                    let _ = h.emit("locked", ());
                });
            }
            "quit" => h.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|t, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                toggle_main(t.app_handle());
            }
        });
    if let Some(icon) = handle.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(handle)?;
    Ok(())
}
