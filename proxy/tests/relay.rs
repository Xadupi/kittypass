//! Le vrai relais, lancé comme par le navigateur, face à l'application.

use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use kittypass_app::{Answer, App, BrowserServer, MemoryStore, Prompt, Prompter};
use kittypass_core::{
    browser::{
        crypto::{Session, increment_nonce, random_nonce},
        transport::{read_frame, write_frame},
    },
    vault::{MasterKey, Vault},
};
use serde_json::{Value, json};

struct Never;
impl Prompter for Never {
    async fn ask(&self, _: Prompt) -> Option<Answer> {
        None
    }
}

fn tmp(name: &str) -> PathBuf {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("kp-relay-{}-{name}-{t}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

async fn app(dir: &std::path::Path) -> Arc<App> {
    let v = Vault::create_with_key(&MasterKey::new("mot-de-passe-relais", None)).unwrap();
    std::fs::write(dir.join("vault.kdbx"), v.save().unwrap()).unwrap();
    let profile = json!({"server_url": "http://127.0.0.1:9", "username": "a", "vault_id": "v", "device": "t", "last_seen": 0});
    std::fs::write(dir.join("profile.json"), profile.to_string()).unwrap();
    let app = App::open(dir.to_path_buf(), Arc::new(MemoryStore::default())).unwrap();
    app.unlock("mot-de-passe-relais").await.unwrap();
    Arc::new(app)
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_relays_both_ways_and_notifications() {
    let run = tmp("run");
    let data = tmp("data");
    let app = app(&data).await;
    let sock = run.join("kittypass/browser.sock");
    let server = BrowserServer::start_at(sock.clone(), app.clone(), Arc::new(Never)).await.unwrap();
    let meta = std::fs::metadata(&sock).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(sock.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    // Chemin au-delà de la limite des sockets Unix : erreur claire.
    let long = run.join("x".repeat(120)).join("browser.sock");
    let e = BrowserServer::start_at(long, app.clone(), Arc::new(Never)).await.err().unwrap();
    assert!(e.to_string().contains("trop long"), "{e}");
    // Une deuxième instance ne vole pas le socket.
    assert!(BrowserServer::start_at(sock.clone(), app.clone(), Arc::new(Never)).await.is_err());

    let mut child = Command::new(env!("CARGO_BIN_EXE_kittypass-proxy"))
        .args(["/chemin/du/manifeste.json", "keepassxc-browser@keepassxc.org"])
        .env("XDG_RUNTIME_DIR", &run)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Échange de clés puis requête chiffrée, en messagerie native.
    let mut ext = Session::new().unwrap();
    let n = random_nonce().unwrap();
    let req = json!({"action": "change-public-keys", "publicKey": ext.public_key_b64(), "nonce": B64.encode(n), "clientID": "c"});
    let (r, out) = tokio::task::spawn_blocking(move || {
        write_frame(&mut stdin, req.to_string().as_bytes(), true).unwrap();
        let r: Value = serde_json::from_slice(&read_frame(&mut stdout, true).unwrap().unwrap()).unwrap();
        (r, (stdin, stdout))
    })
    .await
    .unwrap();
    let (mut stdin, mut stdout) = out;
    assert_eq!(r["success"], "true");
    ext.set_peer(r["publicKey"].as_str().unwrap()).unwrap();

    let n = random_nonce().unwrap();
    let msg = ext.encrypt(br#"{"action":"get-databasehash"}"#, &n).unwrap();
    let req = json!({"action": "get-databasehash", "message": msg, "nonce": B64.encode(n), "clientID": "c"});
    write_frame(&mut stdin, req.to_string().as_bytes(), true).unwrap();
    let r: Value = serde_json::from_slice(&read_frame(&mut stdout, true).unwrap().unwrap()).unwrap();
    let plain = ext.decrypt(r["message"].as_str().unwrap(), &increment_nonce(&n)).unwrap();
    let v: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(v["hash"].as_str().unwrap().len(), 64);

    // Notification poussée par l'application.
    server.notify("database-locked");
    let r: Value = serde_json::from_slice(&read_frame(&mut stdout, true).unwrap().unwrap()).unwrap();
    assert_eq!(r, json!({"action": "database-locked"}));

    // Le navigateur ferme le relais.
    drop(stdin);
    assert!(child.wait().unwrap().success());

    // Arrêt du serveur : socket retiré, le relais échoue proprement.
    server.stop();
    assert!(!sock.exists());
    let out = Command::new(env!("CARGO_BIN_EXE_kittypass-proxy")).env("XDG_RUNTIME_DIR", &run).stdin(Stdio::null()).output().unwrap();
    assert!(!out.status.success());

    // Socket orphelin (application tuée) : remplacé au démarrage.
    let stale = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    drop(stale);
    let server = BrowserServer::start_at(sock.clone(), app.clone(), Arc::new(Never)).await.unwrap();
    drop(server);
    std::fs::remove_dir_all(&run).unwrap();
    std::fs::remove_dir_all(&data).unwrap();
}

#[test]
fn proxy_refuses_a_socket_dir_open_to_others() {
    let run = tmp("open");
    let dir = run.join("kittypass");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let _l = std::os::unix::net::UnixListener::bind(dir.join("browser.sock")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kittypass-proxy"))
        .env("XDG_RUNTIME_DIR", &run)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(&[2, 0, 0, 0, b'{', b'}']);
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("accessible à d'autres"));
    std::fs::remove_dir_all(&run).unwrap();
}
