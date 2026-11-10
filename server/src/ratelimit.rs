//! Limitation du débit en mémoire (fenêtre fixe), par clé (IP, compte…).

use std::collections::HashMap;
use std::sync::Mutex;

const MAX_KEYS: usize = 100_000;

#[derive(Default)]
pub struct Limiter {
    map: Mutex<HashMap<String, (i64, u32)>>,
}

impl Limiter {
    /// Vrai si la requête est autorisée (`limit` par `window` secondes).
    pub fn allow(&self, key: &str, limit: u32, window: i64, now: i64) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        // Borne la mémoire : un attaquant qui varie les clés (IP, noms) ne
        // peut pas faire grossir la table indéfiniment.
        if map.len() >= MAX_KEYS {
            map.retain(|_, (start, _)| now - *start < 3600);
            if map.len() >= MAX_KEYS {
                map.clear();
            }
        }
        let slot = map.entry(key.to_owned()).or_insert((now, 0));
        if now - slot.0 >= window {
            *slot = (now, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        slot.1 <= limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_resets() {
        let l = Limiter::default();
        for _ in 0..5 {
            assert!(l.allow("k", 5, 60, 100));
        }
        assert!(!l.allow("k", 5, 60, 100));
        assert!(!l.allow("k", 5, 60, 159));
        assert!(l.allow("other", 5, 60, 100), "les clés doivent être indépendantes");
        assert!(l.allow("k", 5, 60, 160), "la fenêtre doit se réinitialiser");
    }

    #[test]
    fn memory_is_bounded() {
        let l = Limiter::default();
        for i in 0..(MAX_KEYS + 10) {
            l.allow(&i.to_string(), 1, 60, 0);
        }
        assert!(l.map.lock().unwrap().len() <= MAX_KEYS);
    }
}
