//! Application KittyPass (bureau et Android) : commandes Tauri et démarrage.
#![deny(unsafe_code)]

mod account;
#[cfg(target_os = "android")]
mod android_secure;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod autotype;
mod biometric;
#[cfg(target_os = "linux")]
mod raise;
mod browser;
mod favicon;
mod secrets;
mod ssh;

use std::{path::PathBuf, sync::Arc, time::Duration};

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder};
use kittypass_app::{
    App, AppError, EntryInput, ExportFormat, ExportRequest, ImportRequest, ImportView, KeyFileChange, HealthView, PwnedView, StrengthInput, StrengthView, EntryList, EntryView, Generated, GeneratorOptions, GroupView, SecretField,
    SetupRequest, Status, SyncOutcome, TotpView,
};
use kittypass_core::vault::MAX_ATTACHMENT_BYTES;
use zeroize::Zeroizing;

type R<T> = Result<T, AppError>;
type AppState<'a> = State<'a, Arc<App>>;

/// Délai avant effacement du presse-papiers après une copie.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const AUTO_SYNC_EVERY: Duration = Duration::from_secs(5 * 60);

#[tauri::command]
async fn status(app: AppState<'_>) -> R<Status> {
    Ok(app.status().await)
}

#[tauri::command]
async fn setup(app: AppState<'_>, req: SetupRequest) -> R<bool> {
    app.setup(req).await
}

#[tauri::command]
async fn unlock(app: AppState<'_>, b: State<'_, browser::BrowserState>, password: Zeroizing<String>) -> R<()> {
    app.unlock(&password).await?;
    b.notify(false).await;
    Ok(())
}

/// Déverrouille avec un fichier clé choisi (ou sans : `None`).
#[tauri::command]
async fn unlock_with_key_file(
    app: AppState<'_>,
    b: State<'_, browser::BrowserState>,
    password: Zeroizing<String>,
    key_file: Option<PathBuf>,
    remember: bool,
) -> R<()> {
    app.unlock_with_key_file(&password, key_file.as_deref(), remember).await?;
    b.notify(false).await;
    Ok(())
}

#[tauri::command]
async fn lock(app: AppState<'_>, b: State<'_, browser::BrowserState>) -> R<()> {
    app.lock().await;
    b.notify(true).await;
    Ok(())
}

#[tauri::command]
fn touch(app: AppState<'_>) {
    app.touch();
}

// ---------- Groupes ----------

#[tauri::command]
async fn groups(app: AppState<'_>) -> R<GroupView> {
    app.groups().await
}

#[tauri::command]
async fn tags(app: AppState<'_>) -> R<Vec<(String, usize)>> {
    app.tags().await
}

#[tauri::command]
async fn add_group(app: AppState<'_>, parent: String, name: String) -> R<String> {
    app.add_group(&parent, &name).await
}

#[tauri::command]
async fn rename_group(app: AppState<'_>, id: String, name: String) -> R<()> {
    app.rename_group(&id, &name).await
}

#[tauri::command]
async fn move_group(app: AppState<'_>, id: String, parent: String) -> R<()> {
    app.move_group(&id, &parent).await
}

#[tauri::command]
async fn delete_group(app: AppState<'_>, id: String) -> R<()> {
    app.delete_group(&id).await
}

#[tauri::command]
async fn restore_group(app: AppState<'_>, id: String) -> R<()> {
    app.restore_group(&id).await
}

#[tauri::command]
async fn empty_recycle_bin(app: AppState<'_>) -> R<usize> {
    app.empty_recycle_bin().await
}

// ---------- Entrées ----------

#[tauri::command]
async fn entries(app: AppState<'_>, query: String, group: Option<String>) -> R<EntryList> {
    app.entries(&query, group.as_deref()).await
}

#[tauri::command]
async fn entry(app: AppState<'_>, id: String) -> R<EntryView> {
    app.entry(&id).await
}

#[tauri::command]
async fn history_entry(app: AppState<'_>, id: String, index: usize) -> R<EntryView> {
    app.history_entry(&id, index).await
}

#[tauri::command]
async fn add_entry(app: AppState<'_>, group: Option<String>, input: EntryInput) -> R<String> {
    app.add(group.as_deref(), input).await
}

#[tauri::command]
async fn update_entry(app: AppState<'_>, id: String, input: EntryInput) -> R<()> {
    app.update(&id, input).await
}

#[tauri::command]
async fn clone_entry(app: AppState<'_>, id: String) -> R<String> {
    app.clone_entry(&id).await
}

#[tauri::command]
async fn set_entry_tags(app: AppState<'_>, id: String, tags: Vec<String>) -> R<()> {
    app.set_entry_tags(&id, tags).await
}

/// Ouvre l'URL d'une entrée dans le navigateur par défaut (http/https seulement).
#[tauri::command]
async fn open_entry_url(handle: AppHandle, app: AppState<'_>, id: String) -> R<()> {
    let url = app.secret(&id, SecretField::Url, None).await?;
    let url = url.trim();
    let full = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let lower = full.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) || full.chars().any(char::is_control) {
        return Err(kittypass_core::Error::InvalidArgument("URL non web").into());
    }
    use tauri_plugin_opener::OpenerExt;
    handle.opener().open_url(full, None::<&str>).map_err(|_| kittypass_core::Error::InvalidArgument("navigateur introuvable").into())
}

#[tauri::command]
async fn expire_entry(app: AppState<'_>, id: String) -> R<()> {
    app.expire_entry(&id).await
}

#[tauri::command]
async fn delete_entry(app: AppState<'_>, id: String) -> R<()> {
    app.delete(&id).await
}

#[tauri::command]
async fn restore_entry(app: AppState<'_>, id: String) -> R<()> {
    app.restore(&id).await
}

#[tauri::command]
async fn move_entry(app: AppState<'_>, id: String, group: String) -> R<()> {
    app.move_entry(&id, &group).await
}

#[tauri::command]
async fn restore_history(app: AppState<'_>, id: String, index: usize) -> R<()> {
    app.restore_history(&id, index).await
}

/// Affichage explicite d'un secret (bouton « Afficher »).
#[tauri::command]
async fn reveal(app: AppState<'_>, id: String, field: SecretField, history: Option<usize>) -> R<Zeroizing<String>> {
    app.secret(&id, field, history).await
}

#[tauri::command]
async fn totp(app: AppState<'_>, id: String) -> R<TotpView> {
    app.totp(&id).await
}

/// Jauge de robustesse de l'éditeur (asynchrone : zxcvbn peut prendre
/// quelques millisecondes, hors du fil de l'interface).
#[tauri::command]
async fn strength(app: AppState<'_>, input: StrengthInput) -> R<StrengthView> {
    app.touch();
    Ok(app.strength(&input))
}

#[tauri::command]
async fn health_report(app: AppState<'_>) -> R<HealthView> {
    app.health_report().await
}

#[tauri::command]
async fn set_excluded_from_reports(app: AppState<'_>, id: String, excluded: bool) -> R<()> {
    app.set_excluded_from_reports(&id, excluded).await
}

/// Lancée uniquement par l'utilisateur, après confirmation dans l'interface.
#[tauri::command]
async fn hibp_check(app: AppState<'_>) -> R<PwnedView> {
    app.hibp_check().await
}

/// Écrit dans le presse-papiers et l'efface après 30 s, sauf si
/// l'utilisateur y a copié autre chose entre-temps.
fn copy_with_expiry(handle: AppHandle, value: Zeroizing<String>) -> R<u64> {
    handle
        .clipboard()
        .write_text(value.to_string())
        .map_err(|_| AppError::Io("presse-papiers indisponible".into()))?;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(CLIPBOARD_CLEAR_AFTER).await;
        let still_ours = handle.clipboard().read_text().map(|t| *t == **value).unwrap_or(false);
        if still_ours {
            let _ = handle.clipboard().write_text(String::new());
        }
    });
    Ok(CLIPBOARD_CLEAR_AFTER.as_secs())
}

/// Copie un secret depuis Rust : le mot de passe ne transite pas par le
/// JavaScript.
#[tauri::command]
async fn copy(handle: AppHandle, app: AppState<'_>, id: String, field: SecretField, history: Option<usize>) -> R<u64> {
    let value = app.secret(&id, field, history).await?;
    copy_with_expiry(handle, value)
}

/// Copie une valeur déjà affichée (mot de passe généré), avec effacement.
#[tauri::command]
fn copy_value(handle: AppHandle, value: Zeroizing<String>) -> R<u64> {
    copy_with_expiry(handle, value)
}

#[tauri::command]
fn generate(app: AppState<'_>, opts: GeneratorOptions) -> R<Generated> {
    app.generate(&opts)
}

// ---------- Boîtes de dialogue ----------

/// Boîte « Ouvrir » (`save` faux) ou « Enregistrer » du système ; `None` si
/// l'utilisateur annule.
pub(crate) async fn choose(dialog: FileDialogBuilder<tauri::Wry>, save: bool) -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(answer) = test_dialog_answer() {
        return answer;
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let send = move |f: Option<tauri_plugin_dialog::FilePath>| {
        let _ = tx.send(f);
    };
    if save { dialog.save_file(send) } else { dialog.pick_file(send) }
    rx.await.ok().flatten().and_then(|f| f.into_path().ok())
}

/// Version de développement seulement (absente des versions distribuées) :
/// les tests WebDriver ne peuvent pas piloter les boîtes du système. Si
/// `KITTYPASS_TEST_DIALOG` désigne un fichier, son contenu tient lieu de
/// réponse (vide : annulation).
#[cfg(debug_assertions)]
fn test_dialog_answer() -> Option<Option<PathBuf>> {
    let file = std::env::var_os("KITTYPASS_TEST_DIALOG")?;
    let answer = std::fs::read_to_string(file).unwrap_or_default();
    let answer = answer.trim();
    Some((!answer.is_empty()).then(|| PathBuf::from(answer)))
}

// ---------- Pièces jointes ----------

/// Joint un fichier choisi dans la boîte de dialogue du système. Le fichier
/// est lu côté Rust : le JavaScript n'a aucun accès au disque. Renvoie le nom
/// du fichier joint, ou rien si l'utilisateur a annulé.
#[tauri::command]
async fn attach_file(handle: AppHandle, app: AppState<'_>, id: String) -> R<Option<String>> {
    let Some(path) = choose(handle.dialog().file().set_title("Joindre un fichier"), false).await else {
        return Ok(None);
    };
    // Taille vérifiée avant lecture : un fichier énorme n'est pas chargé.
    let len = std::fs::metadata(&path)?.len();
    if len > MAX_ATTACHMENT_BYTES as u64 {
        return Err(kittypass_core::Error::TooLarge.into());
    }
    let data = Zeroizing::new(std::fs::read(&path)?);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "fichier".into());
    app.add_attachment(&id, &name, &data).await?;
    Ok(Some(name))
}

/// Enregistre une pièce jointe à l'endroit choisi par l'utilisateur.
#[tauri::command]
async fn export_attachment(handle: AppHandle, app: AppState<'_>, id: String, name: String) -> R<bool> {
    let data = app.attachment(&id, &name).await?;
    let Some(path) = choose(handle.dialog().file().set_title("Enregistrer la pièce jointe").set_file_name(&name), true).await else {
        return Ok(false);
    };
    std::fs::write(path, &*data)?;
    Ok(true)
}

#[tauri::command]
async fn remove_attachment(app: AppState<'_>, id: String, name: String) -> R<()> {
    app.remove_attachment(&id, &name).await
}

// ---------- Fichier clé, import, export ----------

/// Boîte de dialogue « Ouvrir » du système. Seul le chemin choisi par
/// l'utilisateur revient à l'interface ; le fichier est lu plus tard par Rust.
#[tauri::command]
async fn pick_file(handle: AppHandle, purpose: String) -> R<Option<String>> {
    let (title, filter): (&str, Option<(&str, &[&str])>) = match purpose.as_str() {
        "key_file" => ("Choisir le fichier clé", None),
        "csv" => ("Importer un fichier CSV", Some(("CSV", &["csv", "txt", "tsv"]))),
        "kdbx" => ("Importer un coffre KeePass", Some(("KeePass", &["kdbx"]))),
        "bitwarden" => ("Importer un export Bitwarden", Some(("Bitwarden JSON", &["json"]))),
        "1pux" => ("Importer un export 1Password", Some(("1Password", &["1pux"]))),
        _ => return Err(kittypass_core::Error::InvalidArgument("type de fichier inconnu").into()),
    };
    let mut dialog = handle.dialog().file().set_title(title);
    if let Some((name, ext)) = filter {
        dialog = dialog.add_filter(name, ext);
    }
    Ok(choose(dialog, false).await.map(|p| p.display().to_string()))
}

/// Crée un nouveau fichier clé à l'endroit choisi ; renvoie son chemin.
#[tauri::command]
async fn generate_key_file(handle: AppHandle, app: AppState<'_>) -> R<Option<String>> {
    let Some(path) = choose(handle.dialog().file().set_title("Créer un fichier clé").set_file_name("kittypass.keyx"), true).await else {
        return Ok(None);
    };
    app.generate_key_file(&path)?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn set_key_file(app: AppState<'_>, change: KeyFileChange) -> R<SyncOutcome> {
    app.set_key_file(&change.password, change.key_file.as_deref(), change.remember).await
}

#[tauri::command]
async fn import_file(app: AppState<'_>, req: ImportRequest) -> R<ImportView> {
    app.import_file(req).await
}

/// Exporte vers l'emplacement choisi dans la boîte « Enregistrer » ; `false`
/// si l'utilisateur a annulé.
#[tauri::command]
async fn export_file(handle: AppHandle, app: AppState<'_>, req: ExportRequest) -> R<bool> {
    let name = format!("kittypass.{}", req.format.extension());
    let label = match req.format {
        ExportFormat::Kdbx => "KeePass",
        ExportFormat::Csv => "CSV",
        ExportFormat::Xml => "KeePass XML",
        ExportFormat::Html => "HTML",
    };
    let dialog = handle.dialog().file().set_title("Exporter le coffre").set_file_name(&name).add_filter(label, &[req.format.extension()]);
    let Some(path) = choose(dialog, true).await else {
        return Ok(false);
    };
    app.export_to(&path, &req).await?;
    Ok(true)
}

// ---------- Synchronisation ----------

#[tauri::command]
async fn sync(app: AppState<'_>) -> R<SyncOutcome> {
    app.sync().await
}

#[tauri::command]
async fn relogin(app: AppState<'_>, totp: String) -> R<()> {
    app.relogin(&totp).await
}

/// Tâche de fond : verrouillage automatique et synchronisation périodique.
fn spawn_background(handle: AppHandle, app: Arc<App>) {
    tauri::async_runtime::spawn(async move {
        let mut since_sync = Duration::ZERO;
        let tick = Duration::from_secs(5);
        loop {
            tokio::time::sleep(tick).await;
            if app.lock_if_idle().await {
                handle.state::<browser::BrowserState>().notify(true).await;
                let _ = handle.emit("locked", ());
                continue;
            }
            since_sync += tick;
            if since_sync >= AUTO_SYNC_EVERY && app.status().await.unlocked {
                since_sync = Duration::ZERO;
                match app.sync().await {
                    Ok(o) => {
                        let _ = handle.emit("synced", o);
                    }
                    Err(e) => {
                        let _ = handle.emit("sync_error", serde_json::json!({"code": e.code(), "message": e.to_string()}));
                    }
                }
            }
        }
    });
}

/// Arrêt par signal (fin de session, `kill`) : l'événement de fermeture n'a
/// pas lieu, on verrouille donc ici avant de quitter, pour retirer les clés
/// de l'agent SSH.
#[cfg(unix)]
fn spawn_signal_lock(handle: AppHandle, app: Arc<App>) {
    use tokio::signal::unix::{SignalKind, signal};
    tauri::async_runtime::spawn(async move {
        let (Ok(mut term), Ok(mut int), Ok(mut hup)) =
            (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup()))
        else {
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
        }
        app.lock().await;
        handle.exit(0);
    });
}

/// Remplissage automatique : seulement sous Android.
#[tauri::command]
async fn autofill_status(handle: AppHandle) -> serde_json::Value {
    #[cfg(target_os = "android")]
    return serde_json::to_value(android_secure::autofill_status(handle).await).unwrap_or_default();
    #[cfg(not(target_os = "android"))]
    {
        let _ = handle;
        serde_json::json!({ "supported": false, "enabled": false })
    }
}

#[tauri::command]
async fn autofill_settings(handle: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "android")]
    return android_secure::autofill_settings(handle).await;
    #[cfg(not(target_os = "android"))]
    {
        let _ = handle;
        Err("seulement sous Android".into())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_global_shortcut::Builder::new().build());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android_secure::plugin());
    builder
        .setup(|tauri_app| {
            let dir = tauri_app.path().app_data_dir()?;
            let dir_for_autotype = dir.clone();
            let app = Arc::new(App::open(dir, secrets::store(tauri_app.handle()))?);
            spawn_background(tauri_app.handle().clone(), app.clone());
            #[cfg(unix)]
            spawn_signal_lock(tauri_app.handle().clone(), app.clone());
            tauri_app.manage(app);
            tauri_app.manage(Arc::new(browser::DesktopPrompter::new(tauri_app.handle().clone())));
            tauri_app.manage(browser::BrowserState::default());
            tauri_app.manage(favicon::FaviconState::new());
            tauri::async_runtime::spawn(browser::restore(tauri_app.handle().clone()));
            tauri_app.manage(autotype::AutoTypeState::new(dir_for_autotype));
            autotype::restore(tauri_app.handle());
            #[cfg(target_os = "android")]
            {
                let h = tauri_app.handle().clone();
                std::thread::spawn(move || android_secure::register_autofill(&h));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status, setup, unlock, lock, touch, groups, tags, add_group, rename_group, move_group, delete_group,
            restore_group, empty_recycle_bin, entries, entry, history_entry, add_entry, update_entry, delete_entry,
            restore_entry, move_entry, restore_history, reveal, totp, copy, copy_value, generate, attach_file,
            export_attachment, remove_attachment, sync, relogin, strength, health_report, set_excluded_from_reports,
            hibp_check, unlock_with_key_file, pick_file, generate_key_file, set_key_file, import_file, export_file,
            browser::browser_status, browser::browser_set_enabled, browser::browser_answer, browser::browser_associations,
            browser::browser_revoke, browser::entry_browser, browser::set_entry_browser, autotype::autotype_status,
            autotype::save_autotype_config, autotype::entry_autotype, autotype::set_entry_autotype,
            autotype::autotype_matches, autotype::autotype_entry, ssh::ssh_status, ssh::save_ssh_config,
            ssh::entry_ssh, ssh::set_entry_ssh, ssh::ssh_add, ssh::ssh_remove,
            account::lock_config, account::save_lock_config, account::account, account::sessions, account::revoke_session,
            account::revoke_other_sessions, account::change_master_password, account::adopt_master_password,
            account::setup_2fa, account::enable_2fa, account::disable_2fa, account::vault_versions,
            account::restore_version, account::save_version, account::create_invite, account::users,
            account::set_user_disabled, favicon::favicon, favicon::forget_favicon, clone_entry, expire_entry, set_entry_tags, open_entry_url,
            biometric::biometric_status, biometric::biometric_enable, biometric::biometric_disable, biometric::biometric_unlock,
            autofill_status, autofill_settings
        ])
        .build(tauri::generate_context!())
        .expect("erreur au lancement de KittyPass")
        .run(|handle, event| {
            // À la fermeture : verrouiller retire de l'agent SSH les clés
            // prévues pour (et efface le coffre de la mémoire).
            if let tauri::RunEvent::Exit = event {
                let app = handle.state::<Arc<App>>().inner().clone();
                tauri::async_runtime::block_on(app.lock());
            }
        });
}
