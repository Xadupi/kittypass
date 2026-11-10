//! Disposition réelle du clavier sous Wayland : le compositeur l'envoie à
//! chaque client (`wl_keyboard.keymap`). Elle sert à trouver la touche et
//! les modificateurs (Maj, AltGr) de chaque caractère, que le portail tape
//! ensuite par codes de touches : un caractère absent de la disposition
//! est refusé avant de taper quoi que ce soit, au lieu d'être mal tapé.

use std::{collections::HashMap, io::Read};

use wayland_client::{
    Connection, Dispatch, QueueHandle, WEnum,
    protocol::{
        wl_keyboard::{self, KeymapFormat, WlKeyboard},
        wl_registry::{self, WlRegistry},
        wl_seat::{self, WlSeat},
    },
};
use xkbcommon::xkb;

use super::{TypeError, keysym};

/// Plus grande disposition acceptée (une disposition réelle fait ~60 Kio).
const MAX_KEYMAP: u64 = 4 << 20;

/// Touche (code evdev) et modificateurs à tenir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combo {
    pub key: u32,
    pub mods: Vec<u32>,
}

pub struct Layout {
    /// keysym → touche, la plus simple d'abord.
    keys: HashMap<u32, Combo>,
    /// Caractère produit → touche (« € » est le keysym `EuroSign`…).
    chars: HashMap<char, Combo>,
}

impl Layout {
    /// Analyse une disposition au format texte XKB.
    pub fn parse(text: &str) -> Result<Self, TypeError> {
        let ctx = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
        let text = text.trim_end_matches('\0').to_owned();
        if text.contains('\0') {
            return Err(TypeError::Backend("disposition du clavier invalide".into()));
        }
        let keymap = xkb::Keymap::new_from_string(&ctx, text, xkb::KEYMAP_FORMAT_TEXT_V1, xkb::KEYMAP_COMPILE_NO_FLAGS)
            .ok_or_else(|| TypeError::Backend("disposition du clavier illisible".into()))?;
        let (min, max) = (keymap.min_keycode().raw(), keymap.max_keycode().raw());

        // Touches des modificateurs (niveau de base).
        let mut base: HashMap<u32, u32> = HashMap::new();
        for kc in min..=max {
            for s in keymap.key_get_syms_by_level(kc.into(), 0, 0) {
                base.entry(s.raw()).or_insert(kc);
            }
        }
        let shift = base.get(&keysym::SHIFT_L).copied();
        let level3 = base.get(&keysym::ISO_LEVEL3_SHIFT).copied();

        let idx = |name: &str| {
            let i = keymap.mod_get_index(name);
            (i != xkb::MOD_INVALID).then(|| 1u32 << i)
        };
        let shift_mask = idx(xkb::MOD_NAME_SHIFT).unwrap_or(0);
        let l3_mask = idx("LevelThree").or_else(|| idx("Mod5")).unwrap_or(0);
        // Essais dans l'ordre : sans rien, Maj, AltGr, Maj+AltGr ; chaque
        // combinaison est vérifiée par un état XKB (pas de supposition sur
        // le type des touches).
        let mut tries = vec![(0u32, vec![])];
        if let Some(s) = shift {
            tries.push((shift_mask, vec![s]));
        }
        if let Some(l) = level3 {
            tries.push((l3_mask, vec![l]));
            if let Some(s) = shift {
                tries.push((shift_mask | l3_mask, vec![s, l]));
            }
        }
        let mut keys = HashMap::new();
        let mut chars = HashMap::new();
        for (mask, held) in &tries {
            let mut state = xkb::State::new(&keymap);
            state.update_mask(*mask, 0, 0, 0, 0, 0);
            for kc in min..=max {
                let sym = state.key_get_one_sym(kc.into()).raw();
                if sym == 0 {
                    continue;
                }
                let combo = Combo { key: kc - 8, mods: held.iter().map(|m| m - 8).collect() };
                if let Some(c) = char::from_u32(xkb::keysym_to_utf32(sym.into())).filter(|c| *c != '\0' && !c.is_control()) {
                    prefer(&mut chars, c, combo.clone());
                }
                prefer(&mut keys, sym, combo);
            }
        }
        Ok(Self { keys, chars })
    }

    pub fn find(&self, sym: u32) -> Option<&Combo> {
        self.keys.get(&sym)
    }

    pub fn find_char(&self, c: char) -> Option<&Combo> {
        self.chars.get(&c)
    }

    /// Touche d'un modificateur (Ctrl, Alt…).
    pub fn modifier(&self, sym: u32) -> Result<u32, TypeError> {
        self.keys.get(&sym).filter(|c| c.mods.is_empty()).map(|c| c.key).ok_or_else(|| {
            TypeError::Backend("touche de modification absente de la disposition du clavier".into())
        })
    }
}

/// Garde la combinaison la plus simple, mais une touche du clavier
/// principal (code evdev < 128) plutôt qu'une touche spéciale (« Euro »
/// 435…) qui n'existe sur aucun clavier réel.
fn prefer<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Combo>, k: K, c: Combo) {
    match map.get(&k) {
        Some(old) if old.key < 128 || c.key >= 128 => {}
        _ => {
            map.insert(k, c);
        }
    }
}

#[derive(Default)]
struct Probe {
    seat: Option<WlSeat>,
    keymap: Option<Result<String, TypeError>>,
}

impl Dispatch<WlRegistry, ()> for Probe {
    fn event(state: &mut Self, reg: &WlRegistry, event: wl_registry::Event, _: &(), _: &Connection, qh: &QueueHandle<Self>) {
        if let wl_registry::Event::Global { name, interface, version } = event
            && interface == "wl_seat"
            && state.seat.is_none()
        {
            state.seat = Some(reg.bind::<WlSeat, _, _>(name, version.min(5), qh, ()));
        }
    }
}

impl Dispatch<WlSeat, ()> for Probe {
    fn event(_: &mut Self, seat: &WlSeat, event: wl_seat::Event, _: &(), _: &Connection, qh: &QueueHandle<Self>) {
        if let wl_seat::Event::Capabilities { capabilities: WEnum::Value(c) } = event
            && c.contains(wl_seat::Capability::Keyboard)
        {
            seat.get_keyboard(qh, ());
        }
    }
}

impl Dispatch<WlKeyboard, ()> for Probe {
    fn event(state: &mut Self, _: &WlKeyboard, event: wl_keyboard::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {
        if let wl_keyboard::Event::Keymap { format, fd, size } = event {
            state.keymap = Some(if format != WEnum::Value(KeymapFormat::XkbV1) || u64::from(size) > MAX_KEYMAP {
                Err(TypeError::Backend("disposition du clavier non prise en charge".into()))
            } else {
                let mut text = String::new();
                std::fs::File::from(fd)
                    .take(u64::from(size))
                    .read_to_string(&mut text)
                    .map(|_| text)
                    .map_err(|_| TypeError::Backend("disposition du clavier illisible".into()))
            });
        }
    }
}

/// Lit la disposition du clavier auprès du compositeur Wayland.
pub fn current() -> Result<Layout, TypeError> {
    let fail = |e: &dyn std::fmt::Display| TypeError::Backend(format!("Wayland : {e}"));
    let conn = Connection::connect_to_env().map_err(|e| fail(&e))?;
    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    conn.display().get_registry(&qh, ());
    let mut probe = Probe::default();
    // Registre, puis siège, puis clavier : quelques allers-retours suffisent.
    for _ in 0..4 {
        queue.roundtrip(&mut probe).map_err(|e| fail(&e))?;
        if probe.keymap.is_some() {
            break;
        }
    }
    Layout::parse(&probe.keymap.ok_or_else(|| fail(&"pas de clavier"))??)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Disposition française compilée par xkbcommon (comme celle envoyée
    /// par le compositeur).
    fn layout(name: &str) -> Layout {
        let ctx = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
        let km = xkb::Keymap::new_from_names(&ctx, "evdev", "pc105", name, "", None, xkb::KEYMAP_COMPILE_NO_FLAGS).unwrap();
        Layout::parse(&km.get_as_string(xkb::KEYMAP_FORMAT_TEXT_V1)).unwrap()
    }

    #[test]
    fn azerty() {
        let fr = layout("fr");
        let shift = fr.modifier(keysym::SHIFT_L).unwrap();
        let altgr = fr.find(keysym::ISO_LEVEL3_SHIFT).unwrap().key;
        // a : touche Q physique (evdev 16), sans modificateur.
        assert_eq!(fr.find_char('a'), Some(&Combo { key: 16, mods: vec![] }));
        assert_eq!(fr.find_char('A'), Some(&Combo { key: 16, mods: vec![shift] }));
        assert_eq!(fr.find_char('é'), Some(&Combo { key: 3, mods: vec![] }));
        // € = AltGr+E, @ = AltGr+à.
        assert_eq!(fr.find_char('€'), Some(&Combo { key: 18, mods: vec![altgr] }));
        assert_eq!(fr.find_char('@').map(|c| c.mods.clone()), Some(vec![altgr]));
        // Absent de la disposition : refusé plutôt que mal tapé.
        assert_eq!(fr.find_char('😺'), None);
        let us = layout("us");
        assert_eq!(us.find_char('a'), Some(&Combo { key: 30, mods: vec![] }));
        assert_eq!(us.find_char('é'), None);
    }

    #[test]
    fn garbage_is_refused() {
        assert!(Layout::parse("pas une disposition").is_err());
        assert!(Layout::parse("xkb_keymap {\0}").is_err());
    }
}
