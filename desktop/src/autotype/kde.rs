//! Raccourci global sous KDE Plasma par `kglobalaccel` (D-Bus), le service
//! de raccourcis de KDE lui-même.
//!
//! Le portail GlobalShortcuts de KDE n'est pas fiable pour une appli hors
//! Flatpak : sa fenêtre de confirmation peut ne pas s'afficher et
//! l'enregistrement se perd. `kglobalaccel` enregistre le raccourci
//! directement ; il apparaît dans Configuration › Raccourcis › KittyPass,
//! où l'utilisateur peut le modifier ou le retirer.

use futures_util::StreamExt;

use super::TypeError;

// Pas de nom en « .desktop » : kglobalaccel le prend pour un fichier de
// lanceur et refuse alors tout raccourci (setShortcut renvoie une liste vide).
const COMPONENT: &str = "kittypass";
const FRIENDLY: &str = "KittyPass";
const ACTION: &str = "autotype";
const ACTION_FRIENDLY: &str = "Saisie automatique KittyPass";

// Modificateurs Qt (Qt::KeyboardModifier).
const SHIFT: i32 = 0x0200_0000;
const CTRL: i32 = 0x0400_0000;
const ALT: i32 = 0x0800_0000;
const META: i32 = 0x1000_0000;

/// `setShortcut` : SetPresent | NoAutoloading = imposer ces touches.
const SET_FLAGS: u32 = 2 | 4;

/// Sous KDE Plasma ?
pub fn is_kde() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_ascii_uppercase().split(':').any(|d| d == "KDE")
}

/// `Ctrl+Shift+5` → code de touche Qt. `None` si la touche n'est pas prise en charge.
pub fn qt_key(shortcut: &str) -> Option<i32> {
    let mut code = 0;
    let mut key = None;
    for part in shortcut.split('+').map(str::trim) {
        match part.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => code |= CTRL,
            "shift" => code |= SHIFT,
            "alt" => code |= ALT,
            "super" | "meta" | "logo" => code |= META,
            _ if key.is_some() => return None,
            p => {
                key = Some(match p {
                    "space" => 0x20,
                    k if k.len() == 1 && k.chars().all(|c| c.is_ascii_alphanumeric()) => k.to_ascii_uppercase().as_bytes()[0] as i32,
                    k if k.starts_with('f') && k.len() > 1 => match k[1..].parse::<i32>() {
                        Ok(n @ 1..=35) => 0x0100_0030 + n - 1,
                        _ => return None,
                    },
                    _ => return None,
                })
            }
        }
    }
    key.map(|k| code | k)
}

/// Touches à enregistrer. Sur un clavier AZERTY, les chiffres demandent
/// déjà Maj : KDE reçoit alors `Ctrl+5` pour un appui sur Ctrl+Maj+5. Les
/// deux formes sont donc enregistrées pour Maj + chiffre.
fn variants(key: i32) -> Vec<i32> {
    let base = key & 0x01FF_FFFF;
    if key & SHIFT != 0 && (0x30..=0x39).contains(&base) { vec![key, key & !SHIFT] } else { vec![key] }
}

fn err(e: zbus::Error) -> TypeError {
    TypeError::Backend(format!("kglobalaccel : {e}"))
}

/// Enregistre le raccourci et appelle `on_press` à chaque appui, jusqu'à
/// l'abandon de la tâche.
pub async fn global_shortcut(shortcut: &str, on_press: impl Fn() + Send + 'static) -> Result<(), TypeError> {
    let key = qt_key(shortcut).ok_or_else(|| TypeError::Backend(format!("raccourci non pris en charge : {shortcut}")))?;
    let conn = zbus::Connection::session().await.map_err(err)?;
    let accel = zbus::Proxy::new(&conn, "org.kde.kglobalaccel", "/kglobalaccel", "org.kde.KGlobalAccel").await.map_err(err)?;
    let id = vec![COMPONENT, ACTION, FRIENDLY, ACTION_FRIENDLY];
    accel.call_method("doRegister", &(id.clone(),)).await.map_err(err)?;
    let got: Vec<i32> = accel.call("setShortcut", &(id, variants(key), SET_FLAGS)).await.map_err(err)?;
    if !got.contains(&key) {
        return Err(TypeError::Backend(format!("{shortcut} est déjà utilisé par un autre raccourci de KDE ({got:?} / {key})")));
    }
    let path: zbus::zvariant::OwnedObjectPath = accel.call("getComponent", &(COMPONENT,)).await.map_err(err)?;
    let component = zbus::Proxy::new(&conn, "org.kde.kglobalaccel", path, "org.kde.kglobalaccel.Component").await.map_err(err)?;
    let mut pressed = component.receive_signal("globalShortcutPressed").await.map_err(err)?;
    while let Some(msg) = pressed.next().await {
        if let Ok((comp, action, _ts)) = msg.body().deserialize::<(String, String, i64)>()
            && comp == COMPONENT
            && action == ACTION
        {
            on_press();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(qt_key("Ctrl+5"), Some(CTRL | 0x35));
        assert_eq!(qt_key("Ctrl+Shift+5"), Some(CTRL | SHIFT | 0x35));
        assert_eq!(qt_key("Ctrl+Alt+v"), Some(CTRL | ALT | 0x56));
        assert_eq!(qt_key("Super+F12"), Some(META | 0x0100_003B));
        assert_eq!(qt_key("Ctrl+Alt+T"), Some(201_326_676), "même code que kitty dans kglobalaccel");
        assert_eq!(qt_key("Ctrl+é"), None);
        assert_eq!(qt_key("Ctrl"), None);
        assert_eq!(variants(CTRL | SHIFT | 0x35), vec![CTRL | SHIFT | 0x35, CTRL | 0x35]);
        assert_eq!(variants(CTRL | SHIFT | 0x4B), vec![CTRL | SHIFT | 0x4B]);
    }
}

#[cfg(test)]
mod live {
    /// Essai réel sous Plasma : `cargo test -p kittypass-desktop --lib kde_live -- --ignored`.
    #[test]
    #[ignore]
    fn kde_live() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let r = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(3), super::global_shortcut("Ctrl+Alt+F11", || {})).await
        });
        eprintln!("resultat : {:?}", r.map(|x| x.map_err(|e| e.to_string())));
    }
}
