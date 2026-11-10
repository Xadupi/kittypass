//! Jeton de rafraîchissement dans le trousseau du système :
//! Secret Service (GNOME Keyring, KWallet) sous Linux, Credential Manager
//! sous Windows.

use std::sync::Arc;

use kittypass_app::SecretStore;
#[cfg(any(target_os = "linux", windows))]
use kittypass_app::AppResult;

/// Trousseau du système ; Keystore sous Android ; mémoire seule ailleurs
/// (le jeton de session est alors redemandé au déverrouillage).
pub fn store(handle: &tauri::AppHandle) -> Arc<dyn SecretStore> {
    let _ = handle;
    #[cfg(any(target_os = "linux", windows))]
    return Arc::new(KeyringStore);
    #[cfg(target_os = "android")]
    return Arc::new(crate::android_secure::AndroidStore(crate::android_secure::Secure::from(handle)));
    #[cfg(not(any(target_os = "linux", windows, target_os = "android")))]
    return Arc::new(kittypass_app::MemoryStore::default());
}

#[cfg(any(target_os = "linux", windows))]
const SERVICE: &str = "org.kittypass.desktop";

#[cfg(any(target_os = "linux", windows))]
pub struct KeyringStore;

#[cfg(any(target_os = "linux", windows))]
impl SecretStore for KeyringStore {
    fn load(&self, key: &str) -> Option<String> {
        keyring::Entry::new(SERVICE, key).ok()?.get_password().ok()
    }

    /// Sans trousseau disponible (session sans Secret Service), le jeton n'est
    /// simplement pas conservé : l'application se reconnecte avec le mot de
    /// passe au prochain déverrouillage. On n'écrit jamais le jeton en clair.
    fn save(&self, key: &str, value: &str) -> AppResult<()> {
        if let Err(e) = keyring::Entry::new(SERVICE, key).and_then(|e| e.set_password(value)) {
            eprintln!("trousseau indisponible, jeton non conservé : {e}");
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> AppResult<()> {
        if let Ok(e) = keyring::Entry::new(SERVICE, key) {
            let _ = e.delete_credential();
        }
        Ok(())
    }
}
