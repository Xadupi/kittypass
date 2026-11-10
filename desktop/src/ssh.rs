//! Agent SSH : commandes de l'interface (la logique est dans `kittypass-app`).

use std::sync::Arc;

use kittypass_app::{App, AppError, EntrySshView, SshConfig, SshSettings, SshStatus};
use tauri::State;

type R<T> = Result<T, AppError>;

#[tauri::command]
pub async fn ssh_status(app: State<'_, Arc<App>>) -> R<SshStatus> {
    Ok(app.ssh_status().await)
}

#[tauri::command]
pub async fn save_ssh_config(app: State<'_, Arc<App>>, config: SshConfig) -> R<SshStatus> {
    app.save_ssh_config(config).await
}

#[tauri::command]
pub async fn entry_ssh(app: State<'_, Arc<App>>, id: String) -> R<EntrySshView> {
    app.entry_ssh(&id).await
}

#[tauri::command]
pub async fn set_entry_ssh(app: State<'_, Arc<App>>, id: String, settings: SshSettings) -> R<()> {
    app.set_entry_ssh(&id, &settings).await
}

#[tauri::command]
pub async fn ssh_add(app: State<'_, Arc<App>>, id: String) -> R<()> {
    app.ssh_add(&id).await
}

#[tauri::command]
pub async fn ssh_remove(app: State<'_, Arc<App>>, id: String) -> R<()> {
    app.ssh_remove(&id).await
}
