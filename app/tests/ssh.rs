//! Agent SSH contre un vrai `ssh-agent` jetable (jamais celui de la session :
//! le socket est toujours imposé par les réglages).

#![cfg(unix)]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    time::Duration,
};

use kittypass_app::{App, EntryInput, MemoryStore, SetupMode, SetupRequest, SshConfig, SshSettings};
use kittypass_server::{AppState, clock::MockClock, config::Config, crypto::ServerKeys, new_invite, router};
use rusqlite::Connection;
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-application";
const PHRASE: &str = "phrase de la cle";

fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    // Court : un socket Unix est limité à 108 octets.
    let d = std::env::temp_dir().join(format!("kps-{name}-{}-{}", std::process::id(), nanos % 1_000_000_000));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("-h").output().is_ok()
}

struct Agent {
    child: Child,
    sock: PathBuf,
}

impl Agent {
    fn start(dir: &Path) -> Self {
        let sock = dir.join("agent.sock");
        let child = Command::new("ssh-agent").arg("-D").arg("-a").arg(&sock).stdout(std::process::Stdio::null()).spawn().unwrap();
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child, sock }
    }

    /// Empreintes listées par `ssh-add -l`.
    fn list(&self) -> String {
        let out = Command::new("ssh-add").arg("-l").env("SSH_AUTH_SOCK", &self.sock).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Clé jetable chiffrée par `PHRASE` ; renvoie (clé privée, empreinte).
fn keygen(dir: &Path, name: &str) -> (Vec<u8>, String) {
    let path = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-a", "4", "-N", PHRASE, "-C", name, "-f"])
        .arg(&path)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let out = Command::new("ssh-keygen").arg("-lf").arg(path.with_extension("pub")).output().unwrap();
    let fp = String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap().to_owned();
    (std::fs::read(&path).unwrap(), fp)
}

async fn app(dir: &Path) -> App {
    let state = Arc::new(
        AppState::new(Connection::open_in_memory().unwrap(), ServerKeys::from_master(&[5; 32]), Arc::new(MockClock::new(1_800_000_000)), Config::default())
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let svc = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, svc).await.unwrap() });
    let app = App::open(dir.join("profil"), Arc::new(MemoryStore::default())).unwrap();
    let invite = new_invite(&state.db(), &state, false, 1).unwrap();
    app.setup(SetupRequest {
        mode: SetupMode::Create,
        server_url: format!("http://127.0.0.1:{port}"),
        username: "alice".into(),
        password: Zeroizing::new(PW.into()),
        invite: Some(invite),
        totp: None,
        device: "test".into(),
        key_file: None,
        remember_key_file: false,
    })
    .await
    .unwrap();
    app
}

fn input(title: &str, pw: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: String::new(),
        password: Zeroizing::new(pw.into()),
        url: String::new(),
        notes: Zeroizing::new(String::new()),
        otp: None,
        keep_otp: false,
        tags: Vec::new(),
        expires: None,
        custom: None,
    }
}

fn settings(attachment: &str) -> SshSettings {
    SshSettings {
        allow: true,
        add_at_open: true,
        remove_at_close: true,
        use_attachment: true,
        attachment_name: attachment.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn keys_follow_lock_and_unlock() {
    if !have("ssh-agent") || !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("OpenSSH absent : test ignoré");
        return;
    }
    let dir = tmpdir("a");
    let agent = Agent::start(&dir);
    let app = app(&dir).await;
    app.save_ssh_config(SshConfig { enabled: true, socket: Some(agent.sock.clone()) }).await.unwrap();

    let (key, fp) = keygen(&dir, "serveur");
    let id = app.add(None, input("Serveur", PHRASE)).await.unwrap();
    app.add_attachment(&id, "id_ed25519", &key).await.unwrap();
    app.set_entry_ssh(&id, &settings("id_ed25519")).await.unwrap();

    // Mauvaise phrase de passe : l'entrée est signalée, le déverrouillage passe.
    let (key2, fp2) = keygen(&dir, "autre");
    let bad = app.add(None, input("Mauvaise phrase", "pas la bonne")).await.unwrap();
    app.add_attachment(&bad, "cle", &key2).await.unwrap();
    app.set_entry_ssh(&bad, &settings("cle")).await.unwrap();

    // Clé non autorisée : jamais ajoutée.
    let (key3, fp3) = keygen(&dir, "interdite");
    let off = app.add(None, input("Interdite", PHRASE)).await.unwrap();
    app.add_attachment(&off, "cle", &key3).await.unwrap();
    app.set_entry_ssh(&off, &SshSettings { allow: false, ..settings("cle") }).await.unwrap();

    let view = app.entry_ssh(&id).await.unwrap();
    assert_eq!(view.key.as_ref().unwrap().fingerprint, fp);
    assert!(view.key.unwrap().encrypted);

    app.lock().await;
    assert!(!agent.list().contains("SHA256"));
    app.unlock(PW).await.unwrap();
    let listed = agent.list();
    assert!(listed.contains(&fp), "{listed}");
    assert!(!listed.contains(&fp2) && !listed.contains(&fp3));
    let status = app.ssh_status().await;
    assert!(status.available);
    assert_eq!(status.keys.iter().find(|k| k.fingerprint == fp).unwrap().entry.as_deref(), Some(id.as_str()));
    assert_eq!(status.unlock_errors.len(), 1);
    assert!(status.unlock_errors[0].starts_with("Mauvaise phrase : "), "{:?}", status.unlock_errors);
    assert!(app.entry_ssh(&id).await.unwrap().in_agent);

    // L'agent peut signer avec la clé (preuve qu'elle est complète et juste).
    let msg = dir.join("message");
    std::fs::write(&msg, b"bonjour").unwrap();
    let signed = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "file", "-f"])
        .arg(dir.join("serveur.pub"))
        .arg(&msg)
        .env("SSH_AUTH_SOCK", &agent.sock)
        .output()
        .unwrap();
    assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));

    app.lock().await;
    assert!(!agent.list().contains(&fp), "retirée au verrouillage");

    // Ajout et retrait manuels, avec durée de vie.
    app.unlock(PW).await.unwrap();
    app.ssh_remove(&id).await.unwrap();
    assert!(!agent.list().contains(&fp));
    app.set_entry_ssh(&id, &SshSettings { add_at_open: false, use_lifetime: true, lifetime_secs: 60, ..settings("id_ed25519") }).await.unwrap();
    app.ssh_add(&id).await.unwrap();
    assert!(agent.list().contains(&fp));
    assert!(app.ssh_add(&off).await.is_err(), "clé non autorisée");

    // Désactiver l'agent retire les clés ajoutées.
    app.save_ssh_config(SshConfig { enabled: false, socket: Some(agent.sock.clone()) }).await.unwrap();
    assert!(!agent.list().contains(&fp));
    assert!(app.ssh_add(&id).await.is_err(), "agent désactivé");
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn key_in_file_and_refusals() {
    if !have("ssh-agent") || !have("ssh-keygen") {
        return;
    }
    let dir = tmpdir("b");
    let agent = Agent::start(&dir);
    let app = app(&dir).await;
    app.save_ssh_config(SshConfig { enabled: true, socket: Some(agent.sock.clone()) }).await.unwrap();
    let (_, fp) = keygen(&dir, "fichier");
    let id = app.add(None, input("Fichier", PHRASE)).await.unwrap();
    let file = SshSettings { use_attachment: false, file_name: dir.join("fichier").display().to_string(), ..settings("") };
    app.set_entry_ssh(&id, &file).await.unwrap();
    app.ssh_add(&id).await.unwrap();
    assert!(agent.list().contains(&fp));

    // Chemin relatif ou dossier : refusés.
    app.set_entry_ssh(&id, &SshSettings { file_name: "fichier".into(), ..file.clone() }).await.unwrap();
    assert!(app.ssh_add(&id).await.is_err());
    assert!(app.entry_ssh(&id).await.unwrap().key_error.is_some());
    app.set_entry_ssh(&id, &SshSettings { file_name: dir.display().to_string(), ..file }).await.unwrap();
    assert!(app.ssh_add(&id).await.is_err());

    // Socket relatif refusé ; socket absent : erreur claire, pas de blocage.
    assert!(app.save_ssh_config(SshConfig { enabled: true, socket: Some("agent.sock".into()) }).await.is_err());
    let missing = dir.join("absent.sock");
    let st = app.save_ssh_config(SshConfig { enabled: true, socket: Some(missing) }).await.unwrap();
    assert!(!st.available && st.error.is_some());
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Faux agent qui annonce une réponse énorme, puis un qui se tait : erreur,
/// sans allouer ni bloquer indéfiniment.
#[tokio::test]
async fn hostile_agent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tmpdir("c");
    let sock = dir.join("faux.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&[0xff, 0xff, 0xff, 0xff, 12]).await;
        }
    });
    let app = app(&dir).await;
    let st = app.save_ssh_config(SshConfig { enabled: true, socket: Some(sock) }).await.unwrap();
    assert!(!st.available);
    assert!(st.error.unwrap().contains("invalide"));
    let _ = std::fs::remove_dir_all(&dir);
}
