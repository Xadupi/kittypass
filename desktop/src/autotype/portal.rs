//! Saisie et raccourci global par les portails du bureau (Wayland) :
//! « Bureau à distance » pour émuler le clavier, « Raccourcis globaux ».
//!
//! La première saisie fait apparaître la demande d'autorisation du bureau ;
//! le jeton rendu (gardé en 0600) évite de la reposer ensuite, jusqu'à ce
//! que l'utilisateur la révoque dans les réglages du système.

use std::{path::Path, time::Duration};

use ashpd::desktop::{
    PersistMode,
    global_shortcuts::{GlobalShortcuts, NewShortcut},
    remote_desktop::{DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions},
};
use futures_util::StreamExt;
use kittypass_app::{AutoTypeStep as Step, Typed};

use super::{TypeError, keymap, keysym};

const TOKEN_FILE: &str = "autotype-portal.token";

fn err(e: ashpd::Error) -> TypeError {
    match e {
        ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled) => TypeError::Refused,
        e => TypeError::Backend(format!("portail du bureau : {e}")),
    }
}

fn read_token(dir: &Path) -> Option<String> {
    let t = std::fs::read_to_string(dir.join(TOKEN_FILE)).ok()?;
    let t = t.trim();
    (!t.is_empty() && t.len() < 256 && t.bytes().all(|b| b.is_ascii_graphic())).then(|| t.to_owned())
}

fn write_token(dir: &Path, token: &str) {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    if let Ok(mut f) = o.open(dir.join(TOKEN_FILE)) {
        let _ = f.write_all(token.as_bytes());
    }
}

/// Action résolue en codes de touches (evdev).
enum Press {
    Keys { key: u32, mods: Vec<u32> },
    Delay(u32),
    KeyDelay(u32),
}

/// Traduit toutes les touches avant de commencer : un caractère absent de
/// la disposition arrête tout, rien n'est tapé à moitié.
fn resolve(layout: &keymap::Layout, typed: &Typed) -> Result<Vec<Press>, TypeError> {
    typed
        .steps()
        .iter()
        .map(|step| {
            let (combo, mods) = match *step {
                Step::Delay(ms) => return Ok(Press::Delay(ms)),
                Step::KeyDelay(ms) => return Ok(Press::KeyDelay(ms)),
                Step::Char(c, m) => (layout.find_char(c), m),
                Step::Key(k, m) => (layout.find(keysym::of_key(k)), m),
            };
            let combo = combo.ok_or_else(|| {
                TypeError::Backend("un caractère de l'entrée n'existe pas dans la disposition du clavier".into())
            })?;
            let mut held = keysym::of_mods(mods).into_iter().map(|m| layout.modifier(m)).collect::<Result<Vec<_>, _>>()?;
            for m in &combo.mods {
                if !held.contains(m) {
                    held.push(*m);
                }
            }
            Ok(Press::Keys { key: combo.key, mods: held })
        })
        .collect()
}

/// Tape les touches dans la fenêtre active. `still_ok` est consulté avant
/// chaque touche : s'il renvoie faux, la saisie s'arrête.
pub async fn type_steps(dir: &Path, typed: &Typed, mut delay: Duration, still_ok: impl Fn() -> bool) -> Result<(), TypeError> {
    let layout = tokio::task::spawn_blocking(keymap::current).await.map_err(|_| TypeError::Unavailable)??;
    let presses = resolve(&layout, typed)?;
    let proxy = RemoteDesktop::new().await.map_err(err)?;
    let session = proxy.create_session(Default::default()).await.map_err(err)?;
    let result = async {
        let token = read_token(dir);
        proxy
            .select_devices(
                &session,
                SelectDevicesOptions::default()
                    .set_devices(Some(DeviceType::Keyboard.into()))
                    .set_persist_mode(PersistMode::ExplicitlyRevoked)
                    .set_restore_token(token.as_deref()),
            )
            .await
            .map_err(err)?
            .response()
            .map_err(err)?;
        let started = proxy.start(&session, None, Default::default()).await.map_err(err)?.response().map_err(err)?;
        if let Some(t) = started.restore_token() {
            write_token(dir, t);
        }
        if !started.devices().contains(DeviceType::Keyboard) {
            return Err(TypeError::Refused);
        }
        // Après une demande d'autorisation, la fenêtre cible doit reprendre
        // le focus.
        if token.is_none() {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        let key = |code: u32, state: KeyState| {
            let (proxy, session) = (&proxy, &session);
            async move { proxy.notify_keyboard_keycode(session, code as i32, state, Default::default()).await.map_err(err) }
        };
        for p in &presses {
            if !still_ok() {
                return Err(TypeError::FocusLost);
            }
            match p {
                Press::Delay(ms) => tokio::time::sleep(Duration::from_millis((*ms).into())).await,
                Press::KeyDelay(ms) => delay = Duration::from_millis((*ms).into()),
                Press::Keys { key: k, mods } => {
                    for m in mods {
                        key(*m, KeyState::Pressed).await?;
                    }
                    key(*k, KeyState::Pressed).await?;
                    key(*k, KeyState::Released).await?;
                    for m in mods.iter().rev() {
                        key(*m, KeyState::Released).await?;
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Ok(())
    }
    .await;
    let _ = session.close().await;
    result
}

/// Forme attendue par le portail : `CTRL+ALT+a`.
fn portal_trigger(shortcut: &str) -> String {
    shortcut
        .split('+')
        .map(|p| match p {
            "Ctrl" => "CTRL".to_owned(),
            "Alt" => "ALT".to_owned(),
            "Shift" => "SHIFT".to_owned(),
            "Super" => "LOGO".to_owned(),
            k if k.len() == 1 => k.to_ascii_lowercase(),
            k => k.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// Enregistre le raccourci global et appelle `on_press` à chaque appui,
/// jusqu'à l'abandon de la tâche.
pub async fn global_shortcut(shortcut: String, on_press: impl Fn() + Send + 'static) -> Result<(), TypeError> {
    let proxy = GlobalShortcuts::new().await.map_err(err)?;
    let session = proxy.create_session(Default::default()).await.map_err(err)?;
    let wanted = [NewShortcut::new("autotype", "Saisie automatique KittyPass").preferred_trigger(portal_trigger(&shortcut).as_str())];
    // Déjà enregistré lors d'un lancement précédent : ne pas redemander, car
    // KDE ouvre sa fenêtre de réglage des raccourcis à chaque enregistrement.
    let known = match proxy.list_shortcuts(&session, Default::default()).await {
        Ok(r) => r.response().map(|l| l.shortcuts().iter().any(|s| s.id() == "autotype")).unwrap_or(false),
        Err(_) => false,
    };
    if !known {
        proxy.bind_shortcuts(&session, &wanted, None, Default::default()).await.map_err(err)?.response().map_err(err)?;
    }
    let mut activated = proxy.receive_activated().await.map_err(err)?;
    // Une seule session par processus : l'identifiant suffit.
    while let Some(a) = activated.next().await {
        if a.shortcut_id() == "autotype" {
            on_press();
        }
    }
    let _ = session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers() {
        assert_eq!(portal_trigger("Ctrl+Alt+A"), "CTRL+ALT+a");
        assert_eq!(portal_trigger("Super+Shift+F5"), "LOGO+SHIFT+F5");
    }

    #[test]
    fn token_file() {
        let dir = std::env::temp_dir().join(format!("kp-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_token(&dir), None);
        write_token(&dir, "abc-123");
        assert_eq!(read_token(&dir).as_deref(), Some("abc-123"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(TOKEN_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(dir.join(TOKEN_FILE), "bad token\n\0").unwrap();
        assert_eq!(read_token(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Vraie saisie par le portail KDE dans un xterm : le bureau demande
    /// l'autorisation (à accepter à la main).
    /// `KP_PORTAL_TEST=1 cargo test -p kittypass-desktop -- --ignored portal_types`
    #[test]
    #[ignore]
    fn portal_types_into_xterm() {
        use std::time::Instant;

        use kittypass_core::autotype::{Field, compile};
        use zeroize::Zeroizing;

        use super::super::x11::X11;
        if std::env::var_os("KP_PORTAL_TEST").is_none() {
            return;
        }
        // Dossier gardé entre deux essais (jeton) si KP_PORTAL_DIR est donné.
        let keep = std::env::var_os("KP_PORTAL_DIR");
        let dir = keep.clone().map(std::path::PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join(format!("kp-portal-{}", std::process::id())));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let script = format!("IFS= read -r a; IFS= read -r b; printf '%s\\n%s\\n' \"$a\" \"$b\" > '{}'", out.display());
        let mut child = std::process::Command::new("xterm")
            .args(["-T", "KPTEST-PORTAL", "-e", "sh", "-c", &script])
            .env("LC_ALL", "C.UTF-8")
            .spawn()
            .unwrap();
        let x = X11::connect().unwrap();
        let is_target = |x: &X11| x.active_window().and_then(|w| x.window_title(w)).as_deref() == Some("KPTEST-PORTAL");
        let start = Instant::now();
        while !is_target(&x) {
            assert!(start.elapsed() < Duration::from_secs(8), "la fenêtre de test n'a pas le focus");
            std::thread::sleep(Duration::from_millis(100));
        }
        let lookup = |f: &Field| {
            Some(Zeroizing::new(match f {
                Field::Username => "alice".to_owned(),
                Field::Password => "p@ss ùµ€{}~^% \"x\"!".to_owned(),
                _ => String::new(),
            }))
        };
        let typed = compile(&std::env::var("KP_PORTAL_SEQ").unwrap_or("{USERNAME}{ENTER}{PASSWORD}{ENTER}".into()), lookup).unwrap();
        // Le temps d'accepter la demande d'autorisation : le contrôle de la
        // fenêtre ne commence qu'à la première touche.
        let res = tauri::async_runtime::block_on(type_steps(&dir, &typed, Duration::from_millis(15), || is_target(&x)));
        let start = Instant::now();
        while !out.exists() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        let got = std::fs::read_to_string(&out).unwrap_or_default();
        let token = read_token(&dir).is_some();
        let _ = std::fs::remove_file(&out);
        if keep.is_none() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        res.unwrap();
        assert_eq!(got, "alice\np@ss ùµ€{}~^% \"x\"!\n");
        assert!(token, "jeton de restauration non enregistré");
    }
}

