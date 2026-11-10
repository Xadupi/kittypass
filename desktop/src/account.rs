//! Compte : commandes de l'interface (la logique est dans `kittypass-app`).

use std::sync::Arc;

use kittypass_app::{AccountInfo, App, AppError, ImportView, InviteView, UserInfo, LockConfig, RestoreRequest, SessionView, SyncOutcome, TotpSetupView, VersionInfo};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

type R<T> = Result<T, AppError>;
type AppState<'a> = State<'a, Arc<App>>;

#[tauri::command]
pub fn lock_config(app: AppState<'_>) -> LockConfig {
    app.lock_config()
}

#[tauri::command]
pub fn save_lock_config(app: AppState<'_>, config: LockConfig) -> R<LockConfig> {
    app.save_lock_config(config)
}

#[tauri::command]
pub async fn account(app: AppState<'_>) -> R<AccountInfo> {
    app.account().await
}

#[tauri::command]
pub async fn sessions(app: AppState<'_>) -> R<Vec<SessionView>> {
    app.sessions().await
}

#[tauri::command]
pub async fn revoke_session(app: AppState<'_>, id: String) -> R<()> {
    app.revoke_session(&id).await
}

#[tauri::command]
pub async fn revoke_other_sessions(app: AppState<'_>) -> R<usize> {
    app.revoke_other_sessions().await
}

#[tauri::command]
pub async fn change_master_password(app: AppState<'_>, current: Zeroizing<String>, new: Zeroizing<String>) -> R<SyncOutcome> {
    app.change_master_password(&current, &new).await
}

#[tauri::command]
pub async fn adopt_master_password(app: AppState<'_>, password: Zeroizing<String>, totp: Option<String>) -> R<SyncOutcome> {
    app.adopt_master_password(&password, totp.as_deref()).await
}

#[tauri::command]
pub async fn setup_2fa(app: AppState<'_>) -> R<TotpSetupView> {
    app.setup_2fa().await
}

#[tauri::command]
pub async fn enable_2fa(app: AppState<'_>, code: String) -> R<Vec<Zeroizing<String>>> {
    app.enable_2fa(&code).await
}

#[tauri::command]
pub async fn disable_2fa(app: AppState<'_>, password: Zeroizing<String>, code: String) -> R<()> {
    app.disable_2fa(&password, &code).await
}

#[tauri::command]
pub async fn vault_versions(app: AppState<'_>) -> R<Vec<VersionInfo>> {
    app.vault_versions().await
}

#[tauri::command]
pub async fn restore_version(app: AppState<'_>, req: RestoreRequest) -> R<ImportView> {
    app.restore_version(req).await
}

/// Enregistre une version passée (fichier chiffré) ; `false` si annulé.
#[tauri::command]
pub async fn save_version(handle: AppHandle, app: AppState<'_>, version: i64) -> R<bool> {
    let dialog = handle
        .dialog()
        .file()
        .set_title("Enregistrer la version du coffre")
        .set_file_name(format!("kittypass-version-{version}.kdbx"))
        .add_filter("KeePass", &["kdbx"]);
    let Some(path) = crate::choose(dialog, true).await else { return Ok(false) };
    app.save_version(version, &path).await?;
    Ok(true)
}

#[tauri::command]
pub async fn create_invite(app: AppState<'_>, admin: bool, hours: i64) -> R<InviteView> {
    app.create_invite(admin, hours).await
}

#[tauri::command]
pub async fn users(app: AppState<'_>) -> R<Vec<UserInfo>> {
    app.users().await
}

#[tauri::command]
pub async fn set_user_disabled(app: AppState<'_>, username: String, disabled: bool) -> R<()> {
    app.set_user_disabled(&username, disabled).await
}
