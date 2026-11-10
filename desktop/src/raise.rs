//! Mettre la fenêtre au premier plan sous KDE Plasma (Wayland compris), via
//! un script KWin chargé par D-Bus. Sans KWin, ne fait rien.

const SCRIPT: &str = r#"
for (const w of (workspace.windowList ? workspace.windowList() : workspace.clientList())) {
  const c = String(w.resourceClass).toLowerCase();
  if (c.indexOf("kittypass") !== -1 && w.normalWindow) {
    if (w.minimized) w.minimized = false;
    if (workspace.activeWindow !== undefined) workspace.activeWindow = w; else workspace.activeClient = w;
  }
}
"#;

pub async fn kwin_activate() {
    let _ = run().await;
}

async fn run() -> zbus::Result<()> {
    if !std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_ascii_uppercase().contains("KDE") {
        return Ok(());
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("kittypass-raise-{}.js", std::process::id()));
    std::fs::write(&path, SCRIPT).map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let conn = zbus::Connection::session().await?;
    let scripting = zbus::Proxy::new(&conn, "org.kde.KWin", "/Scripting", "org.kde.kwin.Scripting").await?;
    let name = "kittypass-raise";
    let _: Result<bool, _> = scripting.call("unloadScript", &(name,)).await;
    let id: i32 = scripting.call("loadScript", &(path.to_string_lossy().as_ref(), name)).await?;
    // KWin 6 : /Scripting/ScriptN ; KWin 5 : /N.
    for obj in [format!("/Scripting/Script{id}"), format!("/{id}")] {
        if let Ok(p) = zbus::Proxy::new(&conn, "org.kde.KWin", obj.as_str(), "org.kde.kwin.Script").await
            && p.call::<_, _, ()>("run", &()).await.is_ok()
        {
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _: Result<bool, _> = scripting.call("unloadScript", &(name,)).await;
    let _ = std::fs::remove_file(&path);
    Ok(())
}
