//! Saisie automatique : réglages de l'appareil et préparation des touches à
//! taper. L'émulation du clavier elle-même dépend du système (application
//! de bureau).

use kittypass_core::{
    autotype::{self, DEFAULT_SEQUENCE, MAX_DELAY_MS, Typed},
    vault::{AutoTypeSettings, WindowAssociation},
};
use serde::{Deserialize, Serialize};

use crate::{App, AppError, AppResult, EntryListItem};

const SETTINGS_FILE: &str = "autotype.json";
const MAX_KEY_DELAY_MS: u32 = 1000;

/// Moyen d'émuler le clavier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AutoTypeMethod {
    /// Portail du bureau sous Wayland, X11 sinon.
    #[default]
    Auto,
    /// Portail « Bureau à distance » (KDE, GNOME…), sous Wayland.
    Portal,
    /// Extension XTest d'X11 (sous Wayland : fenêtres XWayland seulement).
    X11,
}

/// Réglages de la saisie automatique sur cet appareil.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoTypeConfig {
    /// Séquence des entrées qui n'en ont pas.
    pub default_sequence: String,
    /// Délai entre deux touches (ms).
    pub key_delay_ms: u32,
    /// Attente avant de taper, le temps que l'autre fenêtre reprenne la main (ms).
    pub start_delay_ms: u32,
    /// Raccourci global (`Ctrl+Alt+A`…), ou aucun.
    pub global_shortcut: Option<String>,
    pub method: AutoTypeMethod,
}

impl Default for AutoTypeConfig {
    fn default() -> Self {
        Self {
            default_sequence: DEFAULT_SEQUENCE.into(),
            key_delay_ms: 25,
            start_delay_ms: 500,
            global_shortcut: None,
            method: AutoTypeMethod::Auto,
        }
    }
}

const MODIFIERS: [&str; 4] = ["Ctrl", "Alt", "Shift", "Super"];

/// Vérifie un raccourci global et le remet en forme : modificateurs dans
/// l'ordre `Ctrl+Alt+Shift+Super`, puis une touche (lettre, chiffre, F1–F12).
/// Il faut Ctrl, Alt ou Super : un raccourci sans eux gênerait la frappe.
pub fn normalize_shortcut(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('+').map(str::trim).collect();
    let (key, mods) = parts.split_last()?;
    let mut have = [false; 4];
    for m in mods {
        let i = MODIFIERS.iter().position(|x| x.eq_ignore_ascii_case(m))?;
        if have[i] {
            return None;
        }
        have[i] = true;
    }
    if !(have[0] || have[1] || have[3]) {
        return None;
    }
    let key = match key.len() {
        1 if key.as_bytes()[0].is_ascii_alphanumeric() => key.to_ascii_uppercase(),
        2..=3 if key.as_bytes()[0].eq_ignore_ascii_case(&b'f') => match key[1..].parse::<u8>() {
            Ok(n @ 1..=12) => format!("F{n}"),
            _ => return None,
        },
        _ => return None,
    };
    let mut out: Vec<String> = MODIFIERS.iter().zip(have).filter(|(_, h)| *h).map(|(m, _)| m.to_string()).collect();
    out.push(key);
    Some(out.join("+"))
}

impl AutoTypeConfig {
    fn checked(mut self) -> AppResult<Self> {
        let seq = self.default_sequence.trim();
        self.default_sequence = if seq.is_empty() { DEFAULT_SEQUENCE.into() } else { seq.into() };
        autotype::validate(&self.default_sequence).map_err(|e| AppError::Core(kittypass_core::Error::AutoType(e.to_string())))?;
        if self.key_delay_ms > MAX_KEY_DELAY_MS || self.start_delay_ms > MAX_DELAY_MS {
            return Err(AppError::Core(kittypass_core::Error::InvalidArgument("délai trop long")));
        }
        self.global_shortcut = match self.global_shortcut.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(s) => Some(normalize_shortcut(s).ok_or(AppError::Core(kittypass_core::Error::InvalidArgument("raccourci global invalide")))?),
        };
        Ok(self)
    }
}

/// Réglages de saisie d'une entrée, tels que l'éditeur les voit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryAutoTypeView {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AssociationItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationItem {
    pub window: String,
    pub sequence: Option<String>,
}

impl From<AutoTypeSettings> for EntryAutoTypeView {
    fn from(s: AutoTypeSettings) -> Self {
        Self {
            enabled: s.enabled,
            sequence: s.sequence,
            associations: s.associations.into_iter().map(|a| AssociationItem { window: a.window, sequence: a.sequence }).collect(),
        }
    }
}

impl From<&EntryAutoTypeView> for AutoTypeSettings {
    fn from(v: &EntryAutoTypeView) -> Self {
        Self {
            enabled: v.enabled,
            sequence: v.sequence.clone(),
            associations: v
                .associations
                .iter()
                .map(|a| WindowAssociation { window: a.window.clone(), sequence: a.sequence.clone() })
                .collect(),
        }
    }
}

impl App {
    pub fn autotype_config(&self) -> AutoTypeConfig {
        crate::storage::read_json::<AutoTypeConfig>(&self.dir.join(SETTINGS_FILE))
            .ok()
            .flatten()
            .and_then(|c| c.checked().ok())
            .unwrap_or_default()
    }

    /// Enregistre les réglages ; renvoie la version remise en forme.
    pub fn save_autotype_config(&self, c: AutoTypeConfig) -> AppResult<AutoTypeConfig> {
        let c = c.checked()?;
        crate::storage::write_atomic(&self.dir.join(SETTINGS_FILE), &serde_json::to_vec_pretty(&c)?)?;
        Ok(c)
    }

    pub async fn entry_autotype(&self, id: &str) -> AppResult<EntryAutoTypeView> {
        self.read(|v| Ok(v.entry_autotype(id)?.into())).await
    }

    pub async fn set_entry_autotype(&self, id: &str, view: &EntryAutoTypeView) -> AppResult<()> {
        self.write(|v| Ok(v.set_entry_autotype(id, &view.into())?)).await
    }

    /// Entrées proposées pour une fenêtre (titre connu sous X11 seulement).
    pub async fn autotype_matches(&self, window: &str) -> AppResult<Vec<EntryListItem>> {
        self.read(|v| Ok(v.autotype_matches(window).into_iter().map(Into::into).collect())).await
    }

    /// Touches à taper pour une entrée, et la séquence retenue.
    pub async fn autotype_prepare(&self, id: &str, window: Option<&str>, sequence: Option<&str>) -> AppResult<Typed> {
        let fallback = self.autotype_config().default_sequence;
        self.read(|v| {
            let seq = match sequence {
                Some(s) => s.to_owned(),
                None => v
                    .autotype_sequence(id, window, &fallback)?
                    .ok_or(AppError::Core(kittypass_core::Error::AutoType("désactivée pour cette entrée".into())))?,
            };
            Ok(v.autotype_compile(id, &seq)?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcuts() {
        assert_eq!(normalize_shortcut("alt + ctrl + a").as_deref(), Some("Ctrl+Alt+A"));
        assert_eq!(normalize_shortcut("Super+f5").as_deref(), Some("Super+F5"));
        assert_eq!(normalize_shortcut("Ctrl+Shift+9").as_deref(), Some("Ctrl+Shift+9"));
        for bad in ["A", "Shift+A", "Ctrl+Ctrl+A", "Ctrl+", "Ctrl+F13", "Ctrl+F0", "Ctrl+Tab", "Hyper+A", "Ctrl+é", ""] {
            assert_eq!(normalize_shortcut(bad), None, "{bad}");
        }
    }

    #[test]
    fn config_checks() {
        let ok = AutoTypeConfig { default_sequence: "  ".into(), global_shortcut: Some(" ".into()), ..Default::default() };
        let c = ok.checked().unwrap();
        assert_eq!(c.default_sequence, DEFAULT_SEQUENCE);
        assert_eq!(c.global_shortcut, None);
        assert!(AutoTypeConfig { default_sequence: "{CMD:x}".into(), ..Default::default() }.checked().is_err());
        assert!(AutoTypeConfig { key_delay_ms: 5000, ..Default::default() }.checked().is_err());
        assert!(AutoTypeConfig { start_delay_ms: 60_000, ..Default::default() }.checked().is_err());
        assert!(AutoTypeConfig { global_shortcut: Some("A".into()), ..Default::default() }.checked().is_err());
    }
}
