//! Saisie automatique sous Windows : `SendInput`.
//!
//! Les caractères sont envoyés en Unicode (`KEYEVENTF_UNICODE`) : le texte
//! tapé ne dépend pas de la disposition du clavier (AZERTY, QWERTY…). Les
//! touches spéciales et les combinaisons (Ctrl+…) passent par leur code de
//! touche virtuelle. La saisie s'arrête si la fenêtre au premier plan change.
#![allow(unsafe_code)]

use std::{
    thread,
    time::{Duration, Instant},
};

use kittypass_app::{AutoTypeKey as Key, AutoTypeMods as Mods, AutoTypeStep as Step, Typed};
use windows_sys::Win32::{
    Foundation::HWND,
    System::Threading::GetCurrentProcessId,
    UI::{
        Input::KeyboardAndMouse::{
            GetAsyncKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
            KEYEVENTF_UNICODE, SendInput, VIRTUAL_KEY, VK_BACK, VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE,
            VK_F1, VK_HOME, VK_INSERT, VK_LEFT, VK_LMENU, VK_LWIN, VK_MENU, VK_NEXT, VK_PRIOR, VK_RETURN, VK_RIGHT,
            VK_RWIN, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP, VkKeyScanW,
        },
        WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId},
    },
};

use super::TypeError;

const RELEASE_WAIT: Duration = Duration::from_millis(1500);

/// Fenêtre au premier plan (poignée sous forme d'entier, pour la comparer
/// et la passer d'un fil à l'autre).
pub fn foreground() -> Option<isize> {
    // SAFETY : sans argument ; peut renvoyer NULL.
    let h = unsafe { GetForegroundWindow() };
    (!h.is_null()).then_some(h as isize)
}

/// La fenêtre appartient à KittyPass.
pub fn is_own(w: isize) -> bool {
    let mut pid = 0u32;
    // SAFETY : `w` vient de GetForegroundWindow ; une poignée périmée fait
    // seulement renvoyer 0.
    unsafe { GetWindowThreadProcessId(w as HWND, &mut pid) };
    pid == unsafe { GetCurrentProcessId() }
}

/// Titre de la fenêtre au premier plan.
pub fn foreground_title() -> Option<String> {
    let w = foreground()?;
    if is_own(w) {
        return None;
    }
    let mut buf = [0u16; 512];
    // SAFETY : tampon de la taille annoncée.
    let n = unsafe { GetWindowTextW(w as HWND, buf.as_mut_ptr(), buf.len() as i32) };
    (n > 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
}

fn down(vk: VIRTUAL_KEY) -> bool {
    // SAFETY : lecture de l'état d'une touche.
    unsafe { GetAsyncKeyState(vk.into()) as u16 & 0x8000 != 0 }
}

fn modifiers_down() -> bool {
    [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN].into_iter().any(down)
}

fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
    }
}

fn send(inputs: &[INPUT]) -> Result<(), TypeError> {
    // SAFETY : tableau d'INPUT initialisés, taille exacte.
    let sent = unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
    if sent as usize != inputs.len() {
        // Bloqué par l'UIPI : la fenêtre cible tourne avec plus de droits.
        return Err(TypeError::Backend("saisie bloquée par Windows (fenêtre lancée en administrateur ?)".into()));
    }
    Ok(())
}

fn vk_of(k: Key) -> (VIRTUAL_KEY, bool) {
    match k {
        Key::Tab => (VK_TAB, false),
        Key::Enter => (VK_RETURN, false),
        Key::Space => (VK_SPACE, false),
        Key::Backspace => (VK_BACK, false),
        Key::Delete => (VK_DELETE, true),
        Key::Insert => (VK_INSERT, true),
        Key::Escape => (VK_ESCAPE, false),
        Key::Up => (VK_UP, true),
        Key::Down => (VK_DOWN, true),
        Key::Left => (VK_LEFT, true),
        Key::Right => (VK_RIGHT, true),
        Key::Home => (VK_HOME, true),
        Key::End => (VK_END, true),
        Key::PageUp => (VK_PRIOR, true),
        Key::PageDown => (VK_NEXT, true),
        Key::F(n) => (VK_F1 + u16::from(n.clamp(1, 24)) - 1, false),
    }
}

fn mod_keys(m: Mods) -> Vec<VIRTUAL_KEY> {
    let mut v = Vec::new();
    if m.ctrl {
        v.push(VK_CONTROL);
    }
    if m.alt {
        v.push(VK_LMENU);
    }
    if m.shift {
        v.push(VK_SHIFT);
    }
    if m.meta {
        v.push(VK_LWIN);
    }
    v
}

/// Touche (avec modificateurs) : modificateurs enfoncés, touche, relâchés.
fn chord(vk: VIRTUAL_KEY, extended: bool, mods: &[VIRTUAL_KEY]) -> Result<(), TypeError> {
    let ext = if extended { KEYEVENTF_EXTENDEDKEY } else { 0 };
    let mut v: Vec<INPUT> = mods.iter().map(|&m| key_input(m, 0, 0)).collect();
    v.push(key_input(vk, 0, ext));
    v.push(key_input(vk, 0, ext | KEYEVENTF_KEYUP));
    v.extend(mods.iter().rev().map(|&m| key_input(m, 0, KEYEVENTF_KEYUP)));
    send(&v)
}

fn unicode(c: char) -> Result<(), TypeError> {
    let mut units = [0u16; 2];
    let mut v = Vec::new();
    for &u in c.encode_utf16(&mut units).iter() {
        v.push(key_input(0, u, KEYEVENTF_UNICODE));
        v.push(key_input(0, u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
    }
    send(&v)
}

/// Caractère avec modificateurs demandés (ex. `^a`) : il faut la touche
/// réelle de la disposition courante.
fn char_with_mods(c: char, m: Mods) -> Result<(), TypeError> {
    let mut units = [0u16; 2];
    if c.encode_utf16(&mut units).len() != 1 {
        return unicode(c);
    }
    // SAFETY : simple consultation de la disposition du clavier.
    let scan = unsafe { VkKeyScanW(units[0]) };
    if scan == -1 {
        return unicode(c);
    }
    let vk = (scan as u16) & 0xff;
    let state = ((scan as u16) >> 8) as u8;
    let mut all = m;
    all.shift |= state & 1 != 0;
    all.ctrl |= state & 2 != 0;
    all.alt |= state & 4 != 0;
    chord(vk, false, &mod_keys(all))
}

/// Tape les étapes, tant que `still_ok` le permet.
pub fn type_steps(typed: &Typed, mut delay: Duration, still_ok: impl Fn() -> bool) -> Result<(), TypeError> {
    let start = Instant::now();
    while modifiers_down() {
        if start.elapsed() > RELEASE_WAIT {
            return Err(TypeError::KeysHeld);
        }
        thread::sleep(Duration::from_millis(20));
    }
    for step in typed.steps() {
        if !still_ok() {
            return Err(TypeError::FocusLost);
        }
        match *step {
            Step::Delay(ms) => {
                thread::sleep(Duration::from_millis(ms.into()));
                continue;
            }
            Step::KeyDelay(ms) => {
                delay = Duration::from_millis(ms.into());
                continue;
            }
            Step::Char(c, m) if m.is_empty() => unicode(c)?,
            Step::Char(c, m) => char_with_mods(c, m)?,
            Step::Key(k, m) => {
                let (vk, ext) = vk_of(k);
                chord(vk, ext, &mod_keys(m))?;
            }
        }
        thread::sleep(delay);
    }
    Ok(())
}
