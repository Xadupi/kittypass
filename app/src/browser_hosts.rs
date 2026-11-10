//! Déclaration de KittyPass auprès des navigateurs (messagerie native),
//! à la place de KeePassXC ou en lui rendant la main : l'extension
//! KeePassXC-Browser ne parle qu'à un seul hôte, `org.keepassxc.keepassxc_browser`.
//!
//! Passer à KittyPass met de côté le manifeste de KeePassXC
//! (`….json.keepassxc`) ; revenir à KeePassXC le remet en place. Rien n'est
//! supprimé qui ne soit à nous.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{AppError, AppResult, storage};

pub const HOST_NAME: &str = "org.keepassxc.keepassxc_browser";
#[cfg(not(windows))]
const MANIFEST: &str = "org.keepassxc.keepassxc_browser.json";
#[cfg(not(windows))]
const BACKUP_SUFFIX: &str = ".keepassxc";
const FIREFOX_EXTENSION: &str = "keepassxc-browser@keepassxc.org";
/// Extension sur le Chrome Web Store et sur le magasin d'Edge.
const CHROMIUM_ORIGINS: [&str; 2] =
    ["chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", "chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Firefox,
    Chromium,
}

/// Navigateurs pris en charge : (nom, dossier de configuration relatif au
/// dossier personnel, dossier des manifestes dedans).
#[cfg(not(windows))]
const BROWSERS: [(&str, Family, &str, &str); 7] = [
    ("Firefox", Family::Firefox, ".mozilla", "native-messaging-hosts"),
    ("Chromium", Family::Chromium, ".config/chromium", "NativeMessagingHosts"),
    ("Google Chrome", Family::Chromium, ".config/google-chrome", "NativeMessagingHosts"),
    ("Brave", Family::Chromium, ".config/BraveSoftware/Brave-Browser", "NativeMessagingHosts"),
    ("Microsoft Edge", Family::Chromium, ".config/microsoft-edge", "NativeMessagingHosts"),
    ("Vivaldi", Family::Chromium, ".config/vivaldi", "NativeMessagingHosts"),
    ("LibreWolf", Family::Firefox, ".librewolf", "native-messaging-hosts"),
];

/// Qui répond à l'extension dans un navigateur.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    KittyPass,
    KeePassXc,
    /// Manifeste d'un autre programme.
    Other,
    None,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserHost {
    pub browser: String,
    pub owner: Owner,
    /// Le manifeste de KeePassXC est mis de côté (retour possible).
    pub backup: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostsStatus {
    pub browsers: Vec<BrowserHost>,
    /// KeePassXC a sa propre intégration activée : il réécrira ses
    /// manifestes à son prochain lancement.
    pub keepassxc_overrides: bool,
}

/// Emplacements (dossier personnel, relais KittyPass), modifiables pour les tests.
pub struct Hosts {
    pub home: PathBuf,
    pub proxy: PathBuf,
}

fn manifest_owner(path: &Path, proxy: &Path) -> Owner {
    let Ok(raw) = std::fs::read(path) else { return Owner::None };
    let Ok(v) = serde_json::from_slice::<Value>(&raw) else { return Owner::Other };
    match v.get("path").and_then(Value::as_str) {
        Some(p) if same_path(Path::new(p), proxy) => Owner::KittyPass,
        Some(p) if p.to_ascii_lowercase().contains("keepassxc") => Owner::KeePassXc,
        _ => Owner::Other,
    }
}

/// Windows ne distingue pas la casse des chemins.
fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

fn manifest(family: Family, proxy: &Path) -> Value {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "KittyPass (compatible KeePassXC-Browser)",
        "path": proxy.to_string_lossy(),
        "type": "stdio",
    });
    match family {
        Family::Firefox => m["allowed_extensions"] = json!([FIREFOX_EXTENSION]),
        Family::Chromium => m["allowed_origins"] = json!(CHROMIUM_ORIGINS),
    }
    m
}

#[cfg(not(windows))]
impl Hosts {
    /// Emplacements réels : `$HOME` et le relais installé à côté de
    /// l'exécutable de l'application.
    ///
    /// Dans une AppImage, l'exécutable vit dans un montage temporaire dont le
    /// chemin change à chaque lancement : le manifeste pointerait vers un
    /// fichier disparu. Le relais est alors recopié dans
    /// `~/.local/share/kittypass/bin/` (chemin stable), et cette copie est
    /// remise à jour à chaque lancement si elle existe déjà.
    pub fn system() -> AppResult<Self> {
        let home = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute()).ok_or(AppError::Io("HOME".into()))?;
        let exe = std::env::current_exe()?;
        let bundled = exe.with_file_name("kittypass-proxy");
        if std::env::var_os("APPIMAGE").is_none() {
            return Ok(Self { home, proxy: bundled });
        }
        let stable = home.join(".local/share/kittypass/bin/kittypass-proxy");
        if stable.is_file() {
            let _ = install_proxy_copy(&bundled, &stable);
        }
        Ok(Self { home, proxy: stable })
    }

    fn present(&self) -> impl Iterator<Item = (&'static str, Family, PathBuf)> + '_ {
        BROWSERS
            .iter()
            .filter(|(_, _, conf, _)| self.home.join(conf).is_dir())
            .map(|(name, fam, conf, sub)| (*name, *fam, self.home.join(conf).join(sub)))
    }

    pub fn status(&self) -> HostsStatus {
        let browsers = self
            .present()
            .map(|(name, _, dir)| BrowserHost {
                browser: name.to_owned(),
                owner: manifest_owner(&dir.join(MANIFEST), &self.proxy),
                backup: dir.join(format!("{MANIFEST}{BACKUP_SUFFIX}")).is_file(),
            })
            .collect();
        HostsStatus { browsers, keepassxc_overrides: self.keepassxc_integration_enabled() }
    }

    fn keepassxc_integration_enabled(&self) -> bool {
        let Ok(ini) = std::fs::read_to_string(self.home.join(".config/keepassxc/keepassxc.ini")) else { return false };
        let mut in_browser = false;
        for line in ini.lines().map(str::trim) {
            if line.starts_with('[') {
                in_browser = line.eq_ignore_ascii_case("[browser]");
            } else if in_browser && line.replace(' ', "").eq_ignore_ascii_case("enabled=true") {
                return true;
            }
        }
        false
    }

    /// L'extension parle à KittyPass dans tous les navigateurs installés.
    pub fn use_kittypass(&self) -> AppResult<HostsStatus> {
        if std::env::var_os("APPIMAGE").is_some() {
            let bundled = std::env::current_exe()?.with_file_name("kittypass-proxy");
            install_proxy_copy(&bundled, &self.proxy)?;
        }
        if !self.proxy.is_absolute() || !self.proxy.is_file() {
            return Err(AppError::Io("relais kittypass-proxy introuvable".into()));
        }
        for (_, family, dir) in self.present().collect::<Vec<_>>() {
            let file = dir.join(MANIFEST);
            let backup = dir.join(format!("{MANIFEST}{BACKUP_SUFFIX}"));
            match manifest_owner(&file, &self.proxy) {
                Owner::KittyPass => {}
                Owner::None => {}
                // On garde le manifeste de KeePassXC (ou d'un autre) une
                // seule fois : jamais d'écrasement d'une sauvegarde.
                _ if !backup.exists() => std::fs::rename(&file, &backup)?,
                _ => std::fs::remove_file(&file)?,
            }
            std::fs::create_dir_all(&dir)?;
            storage::write_atomic(&file, &serde_json::to_vec_pretty(&manifest(family, &self.proxy))?)?;
            set_mode(&file, 0o644)?;
        }
        Ok(self.status())
    }

    /// Rend la main à KeePassXC : remet son manifeste, ou retire le nôtre.
    pub fn use_keepassxc(&self) -> AppResult<HostsStatus> {
        for (_, _, dir) in self.present().collect::<Vec<_>>() {
            let file = dir.join(MANIFEST);
            let backup = dir.join(format!("{MANIFEST}{BACKUP_SUFFIX}"));
            if manifest_owner(&file, &self.proxy) != Owner::KittyPass {
                continue;
            }
            if backup.is_file() {
                std::fs::rename(&backup, &file)?;
            } else {
                std::fs::remove_file(&file)?;
            }
        }
        Ok(self.status())
    }
}

/// Windows : les navigateurs trouvent le manifeste par une clé du registre
/// (`HKCU\Software\…\NativeMessagingHosts\org.keepassxc.keepassxc_browser`,
/// valeur par défaut = chemin du manifeste). Passer à KittyPass garde
/// l'ancienne valeur dans `KittyPassBackup` ; revenir à KeePassXC la remet.
#[cfg(windows)]
mod windows_hosts {
    use std::path::{Path, PathBuf};

    use winreg::{RegKey, enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE}};

    use super::*;

    /// (nom, clé dont la présence signale le navigateur, clé des hôtes).
    const WIN_BROWSERS: [(&str, Family, &str, &str); 5] = [
        ("Firefox", Family::Firefox, r"Software\Mozilla\Firefox", r"Software\Mozilla\NativeMessagingHosts"),
        ("Google Chrome", Family::Chromium, r"Software\Google\Chrome", r"Software\Google\Chrome\NativeMessagingHosts"),
        ("Chromium", Family::Chromium, r"Software\Chromium", r"Software\Chromium\NativeMessagingHosts"),
        ("Microsoft Edge", Family::Chromium, r"Software\Microsoft\Edge", r"Software\Microsoft\Edge\NativeMessagingHosts"),
        ("Brave", Family::Chromium, r"Software\BraveSoftware\Brave-Browser", r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts"),
    ];
    const BACKUP_VALUE: &str = "KittyPassBackup";

    fn hkcu() -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
    }

    fn host_key(base: &str) -> String {
        format!(r"{base}\{HOST_NAME}")
    }

    /// Chemin du manifeste déclaré pour l'hôte, s'il y en a un.
    fn declared(base: &str) -> Option<PathBuf> {
        let k = hkcu().open_subkey_with_flags(host_key(base), KEY_READ).ok()?;
        k.get_value::<String, _>("").ok().filter(|v| !v.is_empty()).map(PathBuf::from)
    }

    fn has_backup(base: &str) -> bool {
        hkcu()
            .open_subkey_with_flags(host_key(base), KEY_READ)
            .is_ok_and(|k| k.get_value::<String, _>(BACKUP_VALUE).is_ok())
    }

    fn reg_err(e: std::io::Error) -> AppError {
        AppError::Io(format!("registre : {e}"))
    }

    impl Hosts {
        /// `home` : dossier de KittyPass où sont écrits nos manifestes
        /// (`%LOCALAPPDATA%\KittyPass\native-messaging`) ; le relais est
        /// installé à côté de l'exécutable.
        pub fn system() -> AppResult<Self> {
            let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).filter(|h| h.is_absolute()).ok_or(AppError::Io("LOCALAPPDATA".into()))?;
            let proxy = std::env::current_exe()?.with_file_name("kittypass-proxy.exe");
            Ok(Self { home: local.join("KittyPass").join("native-messaging"), proxy })
        }

        fn present(&self) -> impl Iterator<Item = (&'static str, Family, &'static str)> {
            WIN_BROWSERS
                .iter()
                .filter(|(_, _, detect, _)| hkcu().open_subkey_with_flags(detect, KEY_READ).is_ok())
                .map(|(n, f, _, base)| (*n, *f, *base))
        }

        fn owner(&self, base: &str) -> Owner {
            declared(base).map_or(Owner::None, |m| manifest_owner(&m, &self.proxy))
        }

        fn our_manifest(&self, family: Family) -> PathBuf {
            self.home.join(match family {
                Family::Firefox => "kittypass-firefox.json",
                Family::Chromium => "kittypass-chromium.json",
            })
        }

        pub fn status(&self) -> HostsStatus {
            let browsers = self
                .present()
                .map(|(name, _, base)| BrowserHost { browser: name.to_owned(), owner: self.owner(base), backup: has_backup(base) })
                .collect();
            HostsStatus { browsers, keepassxc_overrides: keepassxc_integration_enabled() }
        }

        pub fn use_kittypass(&self) -> AppResult<HostsStatus> {
            if !self.proxy.is_absolute() || !self.proxy.is_file() {
                return Err(AppError::Io("relais kittypass-proxy introuvable".into()));
            }
            std::fs::create_dir_all(&self.home)?;
            for (_, family, base) in self.present().collect::<Vec<_>>() {
                let file = self.our_manifest(family);
                storage::write_atomic(&file, &serde_json::to_vec_pretty(&manifest(family, &self.proxy))?)?;
                let (key, _) = hkcu().create_subkey_with_flags(host_key(base), KEY_READ | KEY_WRITE).map_err(reg_err)?;
                let before = declared(base);
                if let Some(old) = before.filter(|_| self.owner(base) != Owner::KittyPass)
                    && key.get_value::<String, _>(BACKUP_VALUE).is_err()
                {
                    // Gardée une seule fois : jamais d'écrasement de la sauvegarde.
                    key.set_value(BACKUP_VALUE, &old.to_string_lossy().into_owned()).map_err(reg_err)?;
                }
                key.set_value("", &file.to_string_lossy().into_owned()).map_err(reg_err)?;
            }
            Ok(self.status())
        }

        pub fn use_keepassxc(&self) -> AppResult<HostsStatus> {
            for (_, _, base) in self.present().collect::<Vec<_>>() {
                if self.owner(base) != Owner::KittyPass {
                    continue;
                }
                let key = hkcu().open_subkey_with_flags(host_key(base), KEY_READ | KEY_WRITE).map_err(reg_err)?;
                match key.get_value::<String, _>(BACKUP_VALUE) {
                    Ok(old) => {
                        key.set_value("", &old).map_err(reg_err)?;
                        let _ = key.delete_value(BACKUP_VALUE);
                    }
                    Err(_) => {
                        drop(key);
                        hkcu().delete_subkey(host_key(base)).map_err(reg_err)?;
                    }
                }
            }
            Ok(self.status())
        }
    }

    fn keepassxc_integration_enabled() -> bool {
        ["LOCALAPPDATA", "APPDATA"].iter().filter_map(std::env::var_os).any(|d| {
            let Ok(ini) = std::fs::read_to_string(Path::new(&d).join("KeePassXC").join("keepassxc.ini")) else { return false };
            let mut in_browser = false;
            for line in ini.lines().map(str::trim) {
                if line.starts_with('[') {
                    in_browser = line.eq_ignore_ascii_case("[browser]");
                } else if in_browser && line.replace(' ', "").eq_ignore_ascii_case("enabled=true") {
                    return true;
                }
            }
            false
        })
    }
}

#[cfg(not(windows))]
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(windows))]
#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> AppResult<()> {
    Ok(())
}

#[cfg(not(windows))]
/// Copie le relais vers un chemin stable (0755, remplacement atomique), sauf
/// s'il est déjà identique.
fn install_proxy_copy(from: &Path, to: &Path) -> AppResult<()> {
    let data = std::fs::read(from).map_err(|_| AppError::Io("relais kittypass-proxy introuvable".into()))?;
    if std::fs::read(to).is_ok_and(|old| old == data) {
        return Ok(());
    }
    let dir = to.parent().ok_or(AppError::Io("chemin du relais".into()))?;
    std::fs::create_dir_all(dir)?;
    let tmp = to.with_extension("tmp");
    std::fs::write(&tmp, &data)?;
    set_mode(&tmp, 0o755)?;
    std::fs::rename(&tmp, to)?;
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn home(name: &str) -> Hosts {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let h = std::env::temp_dir().join(format!("kp-hosts-{}-{name}-{t}", std::process::id()));
        std::fs::create_dir_all(&h).unwrap();
        let proxy = h.join("bin/kittypass-proxy");
        std::fs::create_dir_all(proxy.parent().unwrap()).unwrap();
        std::fs::write(&proxy, b"#!/bin/sh\n").unwrap();
        Hosts { home: h, proxy }
    }

    fn keepassxc_manifest(dir: &Path) -> Vec<u8> {
        std::fs::create_dir_all(dir).unwrap();
        let m = br#"{"name":"org.keepassxc.keepassxc_browser","path":"/usr/bin/keepassxc-proxy","type":"stdio","allowed_extensions":["keepassxc-browser@keepassxc.org"]}"#.to_vec();
        std::fs::write(dir.join(MANIFEST), &m).unwrap();
        m
    }

    #[test]
    fn switch_back_and_forth_keeps_keepassxc_manifest() {
        let h = home("switch");
        let ff = h.home.join(".mozilla/native-messaging-hosts");
        let original = keepassxc_manifest(&ff);
        std::fs::create_dir_all(h.home.join(".config/chromium")).unwrap();
        let st = h.status();
        assert_eq!(st.browsers.len(), 2, "seuls les navigateurs présents sont listés");
        assert_eq!(st.browsers[0].owner, Owner::KeePassXc);

        let st = h.use_kittypass().unwrap();
        assert!(st.browsers.iter().all(|b| b.owner == Owner::KittyPass));
        let ours: Value = serde_json::from_slice(&std::fs::read(ff.join(MANIFEST)).unwrap()).unwrap();
        assert_eq!(ours["allowed_extensions"][0], FIREFOX_EXTENSION);
        assert!(ours.get("allowed_origins").is_none());
        let chromium: Value = serde_json::from_slice(
            &std::fs::read(h.home.join(".config/chromium/NativeMessagingHosts").join(MANIFEST)).unwrap(),
        )
        .unwrap();
        assert_eq!(chromium["allowed_origins"].as_array().unwrap().len(), 2);
        // Deux fois de suite : la sauvegarde de KeePassXC n'est pas écrasée
        // par notre propre manifeste.
        h.use_kittypass().unwrap();
        assert_eq!(std::fs::read(ff.join(format!("{MANIFEST}{BACKUP_SUFFIX}"))).unwrap(), original);

        let st = h.use_keepassxc().unwrap();
        assert_eq!(std::fs::read(ff.join(MANIFEST)).unwrap(), original);
        assert_eq!(st.browsers[0].owner, Owner::KeePassXc);
        // Chromium n'avait rien : notre manifeste est retiré, rien d'autre.
        assert_eq!(st.browsers[1].owner, Owner::None);
        std::fs::remove_dir_all(&h.home).unwrap();
    }

    #[test]
    fn keepassxc_rewrite_is_detected_and_respected() {
        let h = home("rewrite");
        let ff = h.home.join(".mozilla/native-messaging-hosts");
        keepassxc_manifest(&ff);
        h.use_kittypass().unwrap();
        // KeePassXC réécrit son manifeste à son lancement.
        keepassxc_manifest(&ff);
        assert_eq!(h.status().browsers[0].owner, Owner::KeePassXc);
        // Revenir à KeePassXC ne touche pas à son manifeste réécrit.
        h.use_keepassxc().unwrap();
        assert_eq!(h.status().browsers[0].owner, Owner::KeePassXc);
        let conf = h.home.join(".config/keepassxc");
        std::fs::create_dir_all(&conf).unwrap();
        std::fs::write(conf.join("keepassxc.ini"), "[General]\nEnabled=true\n[Browser]\nCustomProxyLocation=\nEnabled=true\n").unwrap();
        assert!(h.status().keepassxc_overrides);
        std::fs::write(conf.join("keepassxc.ini"), "[Browser]\nEnabled=false\n[Other]\nEnabled=true\n").unwrap();
        assert!(!h.status().keepassxc_overrides);
        std::fs::remove_dir_all(&h.home).unwrap();
    }

    #[test]
    fn missing_proxy_changes_nothing() {
        let mut h = home("noproxy");
        let ff = h.home.join(".mozilla/native-messaging-hosts");
        let original = keepassxc_manifest(&ff);
        h.proxy = h.home.join("absent");
        assert!(h.use_kittypass().is_err());
        assert_eq!(std::fs::read(ff.join(MANIFEST)).unwrap(), original);
        std::fs::remove_dir_all(&h.home).unwrap();
    }

    #[test]
    fn other_programs_manifest_is_backed_up_not_lost() {
        let h = home("other");
        let ff = h.home.join(".mozilla/native-messaging-hosts");
        std::fs::create_dir_all(&ff).unwrap();
        std::fs::write(ff.join(MANIFEST), b"{\"path\": \"/opt/autre/proxy\"}").unwrap();
        h.use_kittypass().unwrap();
        assert_eq!(std::fs::read(ff.join(format!("{MANIFEST}{BACKUP_SUFFIX}"))).unwrap(), b"{\"path\": \"/opt/autre/proxy\"}");
        h.use_keepassxc().unwrap();
        assert_eq!(std::fs::read(ff.join(MANIFEST)).unwrap(), b"{\"path\": \"/opt/autre/proxy\"}");
        std::fs::remove_dir_all(&h.home).unwrap();
    }
}

#[cfg(all(test, unix))]
mod proxy_copy_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn stable_copy_is_executable_and_refreshed() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("kp-proxy-copy-{}-{t}", std::process::id()));
        let from = d.join("mnt/kittypass-proxy");
        let to = d.join("share/bin/kittypass-proxy");
        std::fs::create_dir_all(from.parent().unwrap()).unwrap();
        std::fs::write(&from, b"v1").unwrap();
        install_proxy_copy(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"v1");
        assert_eq!(std::fs::metadata(&to).unwrap().permissions().mode() & 0o777, 0o755);
        std::fs::write(&from, b"v2").unwrap();
        install_proxy_copy(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"v2");
        assert!(install_proxy_copy(&d.join("absent"), &to).is_err());
        assert_eq!(std::fs::read(&to).unwrap(), b"v2", "copie intacte si la source manque");
        let _ = std::fs::remove_dir_all(&d);
    }
}
