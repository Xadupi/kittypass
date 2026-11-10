//! Codes de touches X (« keysyms »), communs au portail et à X11.

use kittypass_app::{AutoTypeKey as Key, AutoTypeMods as Mods};

pub const SHIFT_L: u32 = 0xffe1;
pub const CONTROL_L: u32 = 0xffe3;
pub const ALT_L: u32 = 0xffe9;
pub const SUPER_L: u32 = 0xffeb;
pub const CAPS_LOCK: u32 = 0xffe5;
pub const ISO_LEVEL3_SHIFT: u32 = 0xfe03;

/// Keysym d'un caractère : Latin-1 tel quel, le reste en Unicode.
pub fn of_char(c: char) -> u32 {
    let u = c as u32;
    match u {
        0x20..=0x7e | 0xa0..=0xff => u,
        _ => 0x0100_0000 | u,
    }
}

pub fn of_key(k: Key) -> u32 {
    match k {
        Key::Tab => 0xff09,
        Key::Enter => 0xff0d,
        Key::Space => 0x20,
        Key::Backspace => 0xff08,
        Key::Delete => 0xffff,
        Key::Insert => 0xff63,
        Key::Escape => 0xff1b,
        Key::Home => 0xff50,
        Key::Left => 0xff51,
        Key::Up => 0xff52,
        Key::Right => 0xff53,
        Key::Down => 0xff54,
        Key::PageUp => 0xff55,
        Key::PageDown => 0xff56,
        Key::End => 0xff57,
        Key::F(n) => 0xffbe + u32::from(n.clamp(1, 35)) - 1,
    }
}

/// Keysyms des modificateurs à tenir.
pub fn of_mods(m: Mods) -> Vec<u32> {
    [(m.ctrl, CONTROL_L), (m.alt, ALT_L), (m.shift, SHIFT_L), (m.meta, SUPER_L)]
        .into_iter()
        .filter_map(|(on, k)| on.then_some(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysyms() {
        assert_eq!(of_char('a'), 0x61);
        assert_eq!(of_char('é'), 0xe9);
        assert_eq!(of_char('€'), 0x0100_20ac);
        assert_eq!(of_char('😺'), 0x0101_f63a);
        assert_eq!(of_key(Key::F(1)), 0xffbe);
        assert_eq!(of_key(Key::F(12)), 0xffc9);
        assert_eq!(of_mods(Mods { shift: true, ctrl: true, ..Default::default() }), [CONTROL_L, SHIFT_L]);
    }
}
