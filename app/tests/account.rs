//! Compte : mot de passe maître, appareils, 2FA, versions, verrouillage.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use kittypass_app::{App, AppError, EntryInput, LockConfig, MemoryStore, RestoreRequest, SetupMode, SetupRequest};
use kittypass_server::{AppState, clock::MockClock, config::Config, crypto::ServerKeys, new_invite, router, totp};
use rusqlite::Connection;
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-application";
const NEW_PW: &str = "nouveau-mot-de-passe-solide";

struct Srv {
    url: String,
    state: Arc<AppState>,
    clock: Arc<MockClock>,
}

async fn server() -> Srv {
    let clock = Arc::new(MockClock::new(1_800_000_000));
    let state = Arc::new(
        AppState::new(Connection::open_in_memory().unwrap(), ServerKeys::from_master(&[5; 32]), clock.clone(), Config::default())
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Srv { url: format!("http://127.0.0.1:{port}"), state, clock }
}

fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("kp-acct-{}-{name}-{nanos}", std::process::id()))
}

fn req(s: &Srv, mode: SetupMode, invite: Option<String>, device: &str) -> SetupRequest {
    SetupRequest {
        mode,
        server_url: s.url.clone(),
        username: "alice".into(),
        password: Zeroizing::new(PW.into()),
        invite,
        totp: None,
        device: device.into(),
        key_file: None,
        remember_key_file: false,
    }
}

fn entry(title: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: String::new(),
        password: Zeroizing::new("secret".into()),
        url: String::new(),
        notes: Zeroizing::new(String::new()),
        otp: None,
        keep_otp: false,
        tags: Vec::new(),
        expires: None,
        custom: None,
    }
}

async fn devices(s: &Srv) -> (App, App, PathBuf) {
    let dir = tmpdir("a");
    let a = App::open(dir.clone(), Arc::new(MemoryStore::default())).unwrap();
    let invite = new_invite(&s.state.db(), &s.state, false, 1).unwrap();
    a.setup(req(s, SetupMode::Create, Some(invite), "Portable")).await.unwrap();
    let b = App::open(tmpdir("b"), Arc::new(MemoryStore::default())).unwrap();
    b.setup(req(s, SetupMode::Join, None, "Bureau")).await.unwrap();
    (a, b, dir)
}

fn code(s: &Srv, secret_b32: &str) -> String {
    let secret = base32(secret_b32);
    let step = kittypass_server::clock::Clock::now(&*s.clock) / totp::STEP;
    format!("{:06}", totp::code_at(&secret, step))
}

fn base32(s: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        buf = (buf << 5) | alphabet.iter().position(|&a| a == c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_and_adopt_on_other_device() {
    let s = server().await;
    let (a, b, dir) = devices(&s).await;
    let id = a.add(None, entry("Banque")).await.unwrap();
    a.sync().await.unwrap();

    // Refus avant tout appel au serveur : mauvais actuel, nouveau trop court.
    assert!(matches!(a.change_master_password("faux-mot-de-passe", NEW_PW).await, Err(AppError::Core(_))));
    assert!(a.change_master_password(PW, "court").await.is_err());
    assert!(a.change_master_password(PW, PW).await.is_err());

    let out = a.change_master_password(PW, NEW_PW).await.unwrap();
    assert!(out.pushed);
    // Le fichier local et le serveur utilisent le nouveau mot de passe.
    a.lock().await;
    assert!(a.unlock(PW).await.is_err());
    a.unlock(NEW_PW).await.unwrap();
    a.sync().await.unwrap();
    let c = kittypass_core::client::Client::new(&s.url).unwrap();
    assert!(c.login("alice", PW, None, "x").await.is_err());
    c.login("alice", NEW_PW, None, "x").await.unwrap();
    drop(std::fs::read(dir.join("vault.kdbx")).unwrap());

    // L'autre appareil a été déconnecté ; il ouvre encore son coffre local
    // avec l'ancien mot de passe, puis adopte le nouveau.
    let e = b.sync().await.unwrap_err();
    assert_eq!(e.code(), "invalid_credentials", "{e}");
    assert_eq!(b.adopt_master_password(PW, None).await.unwrap_err().code(), "invalid_credentials");
    let out = b.adopt_master_password(NEW_PW, None).await.unwrap();
    assert!(out.pulled >= 1);
    assert_eq!(b.entry(&id).await.unwrap().title, "Banque");
    b.lock().await;
    b.unlock(NEW_PW).await.unwrap();
    b.sync().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_list_and_revoke() {
    let s = server().await;
    let (a, b, _) = devices(&s).await;
    let list = a.sessions().await.unwrap();
    assert_eq!(list.len(), 2);
    let me = list.iter().find(|x| x.current).unwrap();
    assert_eq!(me.device, "Portable");
    let other = list.iter().find(|x| !x.current).unwrap();
    assert_eq!(other.device, "Bureau");

    assert!(a.revoke_session(&me.id).await.is_err(), "propre session");
    assert!(a.revoke_session("../admin").await.is_err());
    a.revoke_session(&other.id).await.unwrap();
    assert_eq!(a.sessions().await.unwrap().len(), 1);
    // L'autre appareil se reconnecte tout seul avec le mot de passe du coffre.
    b.sync().await.unwrap();
    assert_eq!(a.revoke_other_sessions().await.unwrap(), 1);
    assert_eq!(a.sessions().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_factor_setup_enable_disable() {
    let s = server().await;
    let (a, _b, _) = devices(&s).await;
    assert!(!a.account().await.unwrap().totp_enabled);
    let setup = a.setup_2fa().await.unwrap();
    assert!(setup.uri.starts_with("otpauth://totp/"));
    assert_eq!(setup.qr.len(), setup.qr_size * setup.qr_size);
    assert!(setup.qr_size >= 21);

    assert_eq!(a.enable_2fa("000000").await.unwrap_err().code(), "invalid_totp");
    let codes = a.enable_2fa(&code(&s, &setup.secret)).await.unwrap();
    assert_eq!(codes.len(), 10);
    assert!(a.account().await.unwrap().totp_enabled);
    assert!(a.setup_2fa().await.is_err(), "déjà active");

    // Désactiver : mot de passe ET code exigés.
    s.clock.advance(30);
    assert!(a.disable_2fa("faux-mot-de-passe", &code(&s, &setup.secret)).await.is_err());
    s.clock.advance(30);
    assert!(a.disable_2fa(PW, "123456").await.is_err());
    s.clock.advance(30);
    a.disable_2fa(PW, &code(&s, &setup.secret)).await.unwrap();
    assert!(!a.account().await.unwrap().totp_enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_old_version_into_group() {
    let s = server().await;
    let (a, _b, dir) = devices(&s).await;
    let id = a.add(None, entry("Ancienne")).await.unwrap();
    a.sync().await.unwrap();
    a.delete(&id).await.unwrap();
    a.empty_recycle_bin().await.unwrap();
    a.sync().await.unwrap();

    let versions = a.vault_versions().await.unwrap();
    assert!(versions.len() >= 2);
    assert!(versions.windows(2).all(|w| w[0].version > w[1].version));
    let root = a.groups().await.unwrap().id;
    // La version qui contenait l'entrée (avant la dernière).
    let mut found = false;
    for v in &versions {
        let r = a
            .restore_version(RestoreRequest { version: v.version, parent: root.clone(), name: format!("V{}", v.version), password: None, key_file: None })
            .await
            .unwrap();
        let list = a.entries("Ancienne", Some(&r.group_id)).await.unwrap();
        if !list.items.is_empty() {
            found = true;
        }
    }
    assert!(found, "l'entrée supprimée n'a été retrouvée dans aucune version");

    // Version d'avant un changement de mot de passe : l'ancien est demandé.
    let before = a.vault_versions().await.unwrap()[0].version;
    a.change_master_password(PW, NEW_PW).await.unwrap();
    let r = RestoreRequest { version: before, parent: root.clone(), name: "Avant".into(), password: None, key_file: None };
    assert_eq!(a.restore_version(r).await.unwrap_err().code(), "invalid_password");
    let r = RestoreRequest { version: before, parent: root.clone(), name: "Avant".into(), password: Some(Zeroizing::new(PW.into())), key_file: None };
    a.restore_version(r).await.unwrap();

    // Enregistrer une version : jamais dans le dossier de KittyPass.
    assert!(a.save_version(before, &dir.join("copie.kdbx")).await.is_err());
    let out = tmpdir("copie");
    std::fs::create_dir_all(&out).unwrap();
    a.save_version(before, &out.join("v.kdbx")).await.unwrap();
    let data = std::fs::read(out.join("v.kdbx")).unwrap();
    assert!(kittypass_core::vault::Vault::open(&data, PW, &Default::default()).is_ok());
    let _ = std::fs::remove_dir_all(&out);
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_lock_delay_is_saved_and_bounded() {
    let s = server().await;
    let (a, _b, dir) = devices(&s).await;
    assert_eq!(a.lock_config(), LockConfig::default());
    assert!(a.save_lock_config(LockConfig { auto_lock_secs: Some(5) }).is_err());
    assert!(a.save_lock_config(LockConfig { auto_lock_secs: Some(10 * 24 * 3600) }).is_err());
    a.save_lock_config(LockConfig { auto_lock_secs: Some(600) }).unwrap();
    let again = App::open(dir.clone(), Arc::new(MemoryStore::default())).unwrap();
    assert_eq!(again.lock_config().auto_lock_secs, Some(600));

    // « Jamais » : pas de verrouillage même après inactivité.
    a.save_lock_config(LockConfig { auto_lock_secs: None }).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!a.lock_if_idle().await);
    // Fichier modifié à la main avec une valeur absurde : défaut, pas « jamais ».
    std::fs::write(dir.join("lock.json"), br#"{"auto_lock_secs": 1}"#).unwrap();
    assert_eq!(a.lock_config(), LockConfig::default());
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_invites_and_manages_accounts() {
    let s = server().await;
    let (a, _b, _) = devices(&s).await;
    // alice n'est pas admin.
    assert!(!a.account().await.unwrap().is_admin);
    assert!(a.create_invite(false, 72).await.is_err());
    assert!(a.users().await.is_err());

    let root = App::open(tmpdir("root"), Arc::new(MemoryStore::default())).unwrap();
    let invite = new_invite(&s.state.db(), &s.state, true, 1).unwrap();
    let mut r = req(&s, SetupMode::Create, Some(invite), "Admin");
    r.username = "root".into();
    root.setup(r).await.unwrap();
    assert!(root.account().await.unwrap().is_admin);

    assert!(root.create_invite(false, 0).await.is_err());
    assert!(root.create_invite(false, 24 * 31).await.is_err());
    let inv = root.create_invite(false, 72).await.unwrap();
    assert_eq!(inv.server_url, s.url);
    // La personne invitée crée son compte avec le code.
    let bob = App::open(tmpdir("bob"), Arc::new(MemoryStore::default())).unwrap();
    let mut r = req(&s, SetupMode::Create, Some(inv.code.to_string()), "Bob");
    r.username = "bob".into();
    bob.setup(r).await.unwrap();

    let users = root.users().await.unwrap();
    let names: Vec<_> = users.iter().map(|u| u.username.as_str()).collect();
    assert_eq!(names, ["alice", "bob", "root"]);
    assert!(root.set_user_disabled("root", true).await.is_err(), "soi-même");
    assert!(root.set_user_disabled("../x", true).await.is_err());
    root.set_user_disabled("bob", true).await.unwrap();
    assert!(bob.sync().await.is_err());
    root.set_user_disabled("bob", false).await.unwrap();
    bob.sync().await.unwrap();
}
