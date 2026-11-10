//! Saisie et raccourci global sous X11 (extension XTest, saisie de touche
//! sur la fenêtre racine). Sous Wayland, ne touche que les fenêtres XWayland.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use kittypass_app::{AutoTypeStep as Step, Typed};
use x11rb::{
    connection::{Connection, RequestConnection as _},
    protocol::{
        Event,
        xproto::{AtomEnum, ConnectionExt as _, GrabMode, KEY_PRESS_EVENT, KEY_RELEASE_EVENT, Keycode, ModMask, Window},
        xtest::ConnectionExt as _,
    },
    rust_connection::RustConnection,
    wrapper::ConnectionExt as _,
};

use super::{TypeError, keysym};

/// Attente maximale du relâchement des touches de l'utilisateur.
const RELEASE_WAIT: Duration = Duration::from_secs(3);

fn err<E: std::fmt::Display>(e: E) -> TypeError {
    TypeError::Backend(format!("X11 : {e}"))
}

pub struct X11 {
    conn: RustConnection,
    root: Window,
    min: Keycode,
    per: usize,
    /// Keysyms par touche, depuis `min`.
    map: Vec<u32>,
}

impl X11 {
    pub fn connect() -> Result<Self, TypeError> {
        let (conn, screen) = x11rb::connect(None).map_err(err)?;
        let root = conn.setup().roots[screen].root;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)
            .map_err(err)?
            .ok_or_else(|| err("extension XTest absente"))?;
        let m = conn.get_keyboard_mapping(min, max - min + 1).map_err(err)?.reply().map_err(err)?;
        Ok(Self { conn, root, min, per: m.keysyms_per_keycode as usize, map: m.keysyms })
    }

    fn atom(&self, name: &str) -> Option<u32> {
        Some(self.conn.intern_atom(false, name.as_bytes()).ok()?.reply().ok()?.atom)
    }

    pub fn active_window(&self) -> Option<Window> {
        let a = self.atom("_NET_ACTIVE_WINDOW")?;
        let r = self.conn.get_property(false, self.root, a, AtomEnum::WINDOW, 0, 1).ok()?.reply().ok()?;
        r.value32()?.next().filter(|w| *w != 0)
    }

    pub fn window_title(&self, w: Window) -> Option<String> {
        let utf8 = self.atom("UTF8_STRING")?;
        let name = self.atom("_NET_WM_NAME")?;
        let r = self.conn.get_property(false, w, name, utf8, 0, 1024).ok()?.reply().ok()?;
        let bytes = if r.value.is_empty() {
            self.conn.get_property(false, w, AtomEnum::WM_NAME, AtomEnum::STRING, 0, 1024).ok()?.reply().ok()?.value
        } else {
            r.value
        };
        let t = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).collect::<String>();
        (!t.is_empty()).then_some(t)
    }

    fn window_pid(&self, w: Window) -> Option<u32> {
        let a = self.atom("_NET_WM_PID")?;
        self.conn.get_property(false, w, a, AtomEnum::CARDINAL, 0, 1).ok()?.reply().ok()?.value32()?.next()
    }

    /// Fenêtre de KittyPass elle-même (sous X11 seulement).
    pub fn is_own(&self, w: Window) -> bool {
        self.window_pid(w) == Some(std::process::id())
    }

    /// Touche et niveau (Maj ou non) qui produisent ce keysym.
    fn find(&self, sym: u32) -> Option<(Keycode, bool)> {
        self.map.chunks(self.per).enumerate().find_map(|(i, syms)| {
            let kc = self.min.checked_add(i as u8)?;
            syms.iter().take(2).position(|s| *s == sym).map(|lvl| (kc, lvl == 1))
        })
    }

    /// Touche sans aucun keysym, utilisable pour un caractère absent de la
    /// disposition du clavier.
    fn spare(&self) -> Option<Keycode> {
        self.map
            .chunks(self.per)
            .enumerate()
            .rev()
            .find(|(_, syms)| syms.iter().all(|s| *s == 0))
            .and_then(|(i, _)| self.min.checked_add(i as u8))
    }

    fn remap(&self, kc: Keycode, sym: u32) -> Result<(), TypeError> {
        let mut syms = vec![0u32; self.per];
        syms[0] = sym;
        if self.per > 1 {
            syms[1] = sym;
        }
        self.conn.change_keyboard_mapping(1, kc, self.per as u8, &syms).map_err(err)?.check().map_err(err)?;
        self.conn.sync().map_err(err)?;
        Ok(())
    }

    fn fake(&self, kc: Keycode, press: bool) -> Result<(), TypeError> {
        let t = if press { KEY_PRESS_EVENT } else { KEY_RELEASE_EVENT };
        self.conn.xtest_fake_input(t, kc, 0, self.root, 0, 0, 0).map_err(err)?;
        self.conn.flush().map_err(err)
    }

    fn tap(&self, kc: Keycode) -> Result<(), TypeError> {
        self.fake(kc, true)?;
        self.fake(kc, false)
    }

    fn keycode_of(&self, sym: u32) -> Result<Keycode, TypeError> {
        self.find(sym).map(|(kc, _)| kc).ok_or_else(|| err("touche de modification introuvable"))
    }

    /// Touches de modification tenues par l'utilisateur (Ctrl, Alt…).
    fn modifiers_down(&self) -> bool {
        let Ok(Ok(mods)) = self.conn.get_modifier_mapping().map(|c| c.reply()) else { return false };
        let Ok(Ok(keys)) = self.conn.query_keymap().map(|c| c.reply()) else { return false };
        mods.keycodes.iter().filter(|kc| **kc != 0).any(|kc| keys.keys[(*kc / 8) as usize] & (1 << (*kc % 8)) != 0)
    }

    fn caps_lock_on(&self) -> bool {
        self.conn
            .query_pointer(self.root)
            .ok()
            .and_then(|c| c.reply().ok())
            .is_some_and(|r| u16::from(r.mask) & u16::from(ModMask::LOCK) != 0)
    }

    /// Tape les touches. `still_ok` est consulté avant chaque touche.
    pub fn type_steps(&self, typed: &Typed, mut delay: Duration, still_ok: impl Fn(&Self) -> bool) -> Result<(), TypeError> {
        // Les touches encore tenues (raccourci) se mêleraient à la saisie.
        let start = Instant::now();
        while self.modifiers_down() {
            if start.elapsed() > RELEASE_WAIT {
                return Err(TypeError::KeysHeld);
            }
            thread::sleep(Duration::from_millis(20));
        }
        let caps = self.caps_lock_on();
        let caps_kc = if caps { Some(self.keycode_of(keysym::CAPS_LOCK)?) } else { None };
        if let Some(kc) = caps_kc {
            self.tap(kc)?;
        }
        let spare = self.spare();
        let mut remapped = false;
        let mut last_remap: Option<u32> = None;
        let result = (|| {
            let shift = self.keycode_of(keysym::SHIFT_L)?;
            for step in typed.steps() {
                if !still_ok(self) {
                    return Err(TypeError::FocusLost);
                }
                let (sym, mods) = match *step {
                    Step::Delay(ms) => {
                        thread::sleep(Duration::from_millis(ms.into()));
                        continue;
                    }
                    Step::KeyDelay(ms) => {
                        delay = Duration::from_millis(ms.into());
                        continue;
                    }
                    Step::Char(c, m) => (keysym::of_char(c), m),
                    Step::Key(k, m) => (keysym::of_key(k), m),
                };
                // Caractères : toujours par la touche libre, réassignée au
                // caractère voulu. La disposition annoncée par le serveur X
                // peut différer de celle des applications (XWayland : « us »
                // annoncé, AZERTY utilisé) ; ainsi le texte tapé n'en dépend pas.
                let is_char = matches!(step, Step::Char(..));
                let (kc, needs_shift) = match (is_char, spare, self.find(sym)) {
                    (true, Some(kc), _) | (false, Some(kc), None) => {
                        if last_remap != Some(sym) {
                            self.remap(kc, sym)?;
                            remapped = true;
                            last_remap = Some(sym);
                            thread::sleep(Duration::from_millis(10));
                        }
                        (kc, false)
                    }
                    (_, _, Some(found)) => found,
                    (_, None, None) => return Err(err("caractère absent de la disposition du clavier")),
                };
                let mut held = keysym::of_mods(mods).into_iter().map(|s| self.keycode_of(s)).collect::<Result<Vec<_>, _>>()?;
                if needs_shift && !mods.shift {
                    held.push(shift);
                }
                for m in &held {
                    self.fake(*m, true)?;
                }
                self.tap(kc)?;
                for m in held.iter().rev() {
                    self.fake(*m, false)?;
                }
                thread::sleep(delay);
            }
            Ok(())
        })();
        if remapped && let Some(kc) = spare {
            thread::sleep(Duration::from_millis(20));
            let _ = self.conn.change_keyboard_mapping(1, kc, self.per as u8, &vec![0; self.per]);
        }
        if let Some(kc) = caps_kc {
            let _ = self.tap(kc);
        }
        let _ = self.conn.sync();
        result
    }
}

/// Keysym de la touche d'un raccourci (`A`, `5`, `F5`).
fn shortcut_key(key: &str) -> Option<u32> {
    match key.len() {
        1 => Some(u32::from(key.as_bytes()[0].to_ascii_lowercase())),
        _ => key.strip_prefix('F')?.parse::<u32>().ok().map(|n| 0xffbe + n - 1),
    }
}

/// Saisit le raccourci global sur l'écran et appelle `on_press` avec le
/// titre de la fenêtre active, jusqu'à ce que `stop` passe à vrai.
pub fn global_shortcut(shortcut: &str, stop: Arc<AtomicBool>, on_press: impl Fn(Option<String>)) -> Result<(), TypeError> {
    let x = X11::connect()?;
    let mut parts: Vec<&str> = shortcut.split('+').collect();
    let key = parts.pop().and_then(shortcut_key).ok_or_else(|| err("raccourci invalide"))?;
    let kc = x.keycode_of(key)?;
    let mut mods = 0u16;
    for p in parts {
        mods |= u16::from(match p {
            "Ctrl" => ModMask::CONTROL,
            "Alt" => ModMask::M1,
            "Shift" => ModMask::SHIFT,
            "Super" => ModMask::M4,
            _ => return Err(err("raccourci invalide")),
        });
    }
    // Avec ou sans Verr. Maj / Verr. Num.
    let extras = [0, u16::from(ModMask::LOCK), u16::from(ModMask::M2), u16::from(ModMask::LOCK) | u16::from(ModMask::M2)];
    for e in extras {
        x.conn
            .grab_key(false, x.root, ModMask::from(mods | e), kc, GrabMode::ASYNC, GrabMode::ASYNC)
            .map_err(err)?
            .check()
            .map_err(|_| TypeError::Backend("ce raccourci est déjà utilisé par une autre application".into()))?;
    }
    while !stop.load(Ordering::Relaxed) {
        match x.conn.poll_for_event() {
            Ok(Some(Event::KeyPress(e))) if e.detail == kc => {
                let title = x.active_window().and_then(|w| x.window_title(w));
                on_press(title);
            }
            Ok(Some(_)) => {}
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    for e in extras {
        let _ = x.conn.ungrab_key(kc, x.root, ModMask::from(mods | e));
    }
    let _ = x.conn.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_keys() {
        assert_eq!(shortcut_key("A"), Some(0x61));
        assert_eq!(shortcut_key("7"), Some(0x37));
        assert_eq!(shortcut_key("F5"), Some(0xffc2));
        assert_eq!(shortcut_key("Tab"), None);
    }

    /// Vraie saisie dans un xterm (écran X requis) :
    /// `KP_X11_TEST=1 cargo test -p kittypass-desktop -- --ignored x11_types`.
    /// Ne tape que si la fenêtre active est bien celle du test.
    #[test]
    #[ignore]
    fn x11_types_into_xterm() {
        use kittypass_core::autotype::{Field, compile};
        use zeroize::Zeroizing;
        if std::env::var_os("KP_X11_TEST").is_none() {
            return;
        }
        let out = std::env::temp_dir().join(format!("kp-x11-{}.txt", std::process::id()));
        let script = format!(
            "IFS= read -r a; IFS= read -r b; printf '%s\\n%s\\n' \"$a\" \"$b\" > '{}'",
            out.display()
        );
        let mut child = std::process::Command::new("xterm")
            .args(["-T", "KPTEST-AUTOTYPE", "-e", "sh", "-c", &script])
            .env("LC_ALL", "C.UTF-8")
            .spawn()
            .unwrap();
        let x = X11::connect().unwrap();
        let start = Instant::now();
        let target = loop {
            let w = x.active_window();
            if w.and_then(|w| x.window_title(w)).as_deref() == Some("KPTEST-AUTOTYPE") {
                break w;
            }
            assert!(start.elapsed() < Duration::from_secs(8), "la fenêtre de test n'a pas le focus");
            thread::sleep(Duration::from_millis(100));
        };
        thread::sleep(Duration::from_millis(300));
        let lookup = |f: &Field| {
            Some(Zeroizing::new(match f {
                Field::Username => "alice".to_owned(),
                Field::Password => "p@ss É€{}~^% \"x\"!".to_owned(),
                _ => String::new(),
            }))
        };
        let typed = compile("{USERNAME}{ENTER}{PASSWORD}{ENTER}", lookup).unwrap();
        x.type_steps(&typed, Duration::from_millis(10), |x| x.active_window() == target).unwrap();
        let start = Instant::now();
        while !out.exists() && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        let got = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        assert_eq!(got, "alice\np@ss É€{}~^% \"x\"!\n");
        // La disposition du clavier est restaurée.
        let after = X11::connect().unwrap();
        assert_eq!(after.map, x.map);
    }
}

