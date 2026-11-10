//! Logique applicative contre un vrai serveur local.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use rusqlite::Connection;
use kittypass_app::{
    App, AppError, CustomInput, EntryInput, GeneratorOptions, MemoryStore, SecretField, SecretStore, SetupMode, SetupRequest,
};
use kittypass_server::{AppState, clock::MockClock, config::Config, crypto::ServerKeys, new_invite, router, totp};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-application";

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
    let d = std::env::temp_dir().join(format!("vs-app-{}-{name}-{}", std::process::id(), uuid_like()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn uuid_like() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn req(s: &Srv, mode: SetupMode, invite: Option<String>) -> SetupRequest {
    SetupRequest {
        mode,
        server_url: s.url.clone(),
        username: "alice".into(),
        password: Zeroizing::new(PW.into()),
        invite,
        totp: None,
        device: format!("{mode:?}"),
        key_file: None,
        remember_key_file: false,
    }
}

fn entry(title: &str, pw: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: "alice@example.org".into(),
        password: Zeroizing::new(pw.into()),
        url: "https://example.org".into(),
        notes: Zeroizing::new(String::new()),
        otp: None,
        keep_otp: false,
        tags: Vec::new(),
        expires: None,
        custom: None,
    }
}

async fn first_device(s: &Srv) -> (App, Arc<MemoryStore>, PathBuf) {
    let dir = tmpdir("a");
    let store = Arc::new(MemoryStore::default());
    let app = App::open(dir.clone(), store.clone()).unwrap();
    let invite = new_invite(&s.state.db(), &s.state, false, 1).unwrap();
    app.setup(req(s, SetupMode::Create, Some(invite))).await.unwrap();
    (app, store, dir)
}

async fn second_device(s: &Srv) -> App {
    let app = App::open(tmpdir("b"), Arc::new(MemoryStore::default())).unwrap();
    app.setup(req(s, SetupMode::Join, None)).await.unwrap();
    app
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_writes_private_files_without_secrets() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    assert!(app.status().await.configured && app.status().await.unlocked);

    let profile = std::fs::read_to_string(dir.join("profile.json")).unwrap();
    assert!(!profile.contains(PW), "mot de passe dans le profil");
    let refresh = store.load("refresh_token").expect("jeton non rangé dans le trousseau");
    assert!(!profile.contains(&refresh), "jeton dans le profil en clair");

    let kdbx = std::fs::read(dir.join("vault.kdbx")).unwrap();
    assert!(!kdbx.windows(5).any(|w| w == b"alice"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.clone()), 0o700);
        assert_eq!(mode(dir.join("vault.kdbx")), 0o600);
        assert_eq!(mode(dir.join("profile.json")), 0o600);
    }
    // Configurer deux fois est refusé.
    assert!(matches!(app.setup(req(&s, SetupMode::Create, None)).await, Err(AppError::AlreadyConfigured)));
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_unlock_and_offline_access() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    let id = app.add(None, entry("Banque", "s3cret")).await.unwrap();
    app.lock().await;
    assert!(matches!(app.entries("", None).await, Err(AppError::Locked)));
    assert!(matches!(app.secret(&id, SecretField::Password, None).await, Err(AppError::Locked)));
    assert!(matches!(app.unlock("mauvais-mot-de-passe").await, Err(AppError::Core(_))));
    assert!(!app.status().await.unlocked);

    // Redémarrage de l'application, serveur injoignable : le coffre local s'ouvre.
    drop(app);
    let app = App::open(dir, store).unwrap();
    app.unlock(PW).await.unwrap();
    assert_eq!(app.secret(&id, SecretField::Password, None).await.unwrap().as_str(), "s3cret");
}

#[tokio::test(flavor = "multi_thread")]
async fn entry_view_never_contains_password() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let id = app.add(None, entry("Banque", "ne-doit-pas-fuiter")).await.unwrap();
    let view = serde_json_string(&app.entry(&id).await.unwrap());
    let list = serde_json_string(&app.entries("", None).await.unwrap().items);
    assert!(!view.contains("ne-doit-pas-fuiter") && !list.contains("ne-doit-pas-fuiter"));
}

fn serde_json_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_through_app() {
    let s = server().await;
    let (a, _, _) = first_device(&s).await;
    let b = second_device(&s).await;
    a.add(None, entry("Depuis A", "1")).await.unwrap();
    b.add(None, entry("Depuis B", "2")).await.unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    let titles = |l: Vec<kittypass_app::EntryListItem>| l.into_iter().map(|e| e.title).collect::<Vec<_>>();
    assert_eq!(titles(a.entries("", None).await.unwrap().items), ["Depuis A", "Depuis B"]);
    assert_eq!(titles(b.entries("", None).await.unwrap().items), ["Depuis A", "Depuis B"]);
    assert!(!b.sync().await.unwrap().pushed, "synchro inutile");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_refused_when_vault_already_exists() {
    let s = server().await;
    first_device(&s).await;
    let app = App::open(tmpdir("c"), Arc::new(MemoryStore::default())).unwrap();
    let r = app.setup(req(&s, SetupMode::Create, None)).await;
    assert!(matches!(r, Err(AppError::RemoteVaultExists)));
    assert!(!app.status().await.configured, "configuration partielle laissée");
}

#[tokio::test(flavor = "multi_thread")]
async fn join_with_wrong_password_writes_nothing() {
    let s = server().await;
    first_device(&s).await;
    let dir = tmpdir("d");
    let app = App::open(dir.clone(), Arc::new(MemoryStore::default())).unwrap();
    let mut r = req(&s, SetupMode::Join, None);
    r.password = Zeroizing::new("pas-le-bon-mot-de-passe".into());
    assert!(app.setup(r).await.is_err());
    assert!(!dir.join("profile.json").exists() && !dir.join("vault.kdbx").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_session_relogs_automatically() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    // Un mois plus tard, jeton de rafraîchissement expiré, application relancée.
    s.clock.advance(31 * 24 * 3600);
    drop(app);
    let app = App::open(dir, store).unwrap();
    app.unlock(PW).await.unwrap();
    app.add(None, entry("x", "1")).await.unwrap();
    assert!(app.sync().await.unwrap().pushed);
}

#[tokio::test(flavor = "multi_thread")]
async fn totp_required_on_relogin_then_relogin_with_code() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    // Active la 2FA côté compte via l'API du cœur.
    let c = kittypass_core::client::Client::new(&s.url).unwrap();
    c.login("alice", PW, None, "setup").await.unwrap();
    let setup = c.setup_2fa().await.unwrap();
    let secret = base32(&setup.secret);
    let now = || kittypass_server::clock::Clock::now(&*s.clock) / totp::STEP;
    c.enable_2fa(&format!("{:06}", totp::code_at(&secret, now()))).await.unwrap();

    // L'activation a fermé les autres sessions : la synchro demande la 2FA.
    s.clock.advance(30);
    drop(app);
    let app = App::open(dir, store).unwrap();
    app.unlock(PW).await.unwrap();
    let err = app.sync().await.unwrap_err();
    assert_eq!(err.code(), "totp_required");
    app.relogin(&format!("{:06}", totp::code_at(&secret, now()))).await.unwrap();
    app.sync().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_lock_after_inactivity() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    app.set_auto_lock_after(Some(Duration::from_millis(200)));
    app.touch();
    assert!(!app.lock_if_idle().await);
    std::thread::sleep(Duration::from_millis(250));
    assert!(app.lock_if_idle().await);
    assert!(!app.status().await.unlocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_profile_with_plain_http_is_refused() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    drop(app);
    let p = dir.join("profile.json");
    let txt = std::fs::read_to_string(&p).unwrap().replace(&s.url, "http://attaquant.example.org");
    std::fs::write(&p, txt).unwrap();
    assert!(App::open(dir, store).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn local_writes_keep_a_backup_and_survive_leftover_tmp() {
    let s = server().await;
    let (app, store, dir) = first_device(&s).await;
    app.add(None, entry("un", "1")).await.unwrap();
    app.add(None, entry("deux", "2")).await.unwrap();
    assert!(dir.join("vault.bak").exists());
    // Fichier temporaire orphelin (coupure pendant une écriture) : sans effet.
    std::fs::write(dir.join("vault.tmp"), b"garbage").unwrap();
    app.add(None, entry("trois", "3")).await.unwrap();
    drop(app);
    let app = App::open(dir, store).unwrap();
    app.unlock(PW).await.unwrap();
    assert_eq!(app.entries("", None).await.unwrap().items.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_totp_uri_rejected_and_valid_one_works() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let mut e = entry("2fa", "x");
    e.otp = Some(Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0".into()));
    assert!(app.add(None, e).await.is_err());
    let mut e = entry("2fa", "x");
    e.otp = Some(Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()));
    let id = app.add(None, e).await.unwrap();
    let code = app.secret(&id, SecretField::Totp, None).await.unwrap();
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));
    let plain = app.add(None, entry("sans", "y")).await.unwrap();
    assert!(matches!(app.secret(&plain, SecretField::Totp, None).await, Err(AppError::NoTotp)));
}

fn base32(s: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0, Vec::new());
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
async fn editing_keeps_totp_only_when_asked() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let mut e = entry("2fa", "x");
    e.otp = Some(Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()));
    let id = app.add(None, e).await.unwrap();
    let mut keep = entry("2fa", "y");
    keep.keep_otp = true;
    app.update(&id, keep).await.unwrap();
    assert!(app.entry(&id).await.unwrap().has_totp, "lien 2FA perdu à la modification");
    app.update(&id, entry("2fa", "z")).await.unwrap();
    assert!(!app.entry(&id).await.unwrap().has_totp, "lien 2FA non retiré");
}

// ---------------------------------------------------------------- interface

fn custom(key: &str, value: Option<&str>, protected: bool) -> CustomInput {
    CustomInput { key: key.into(), value: value.map(|v| Zeroizing::new(v.into())), protected, original_key: None }
}

/// Ni mot de passe, ni lien 2FA, ni valeur d'attribut protégé dans ce que
/// l'interface reçoit sans le demander ; tout reste accessible via `secret`.
#[tokio::test(flavor = "multi_thread")]
async fn views_never_carry_secrets() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let mut input = entry("Banque", "mdp-SECRET-1");
    input.otp = Some(Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXPOTPSECRET".into()));
    input.custom = Some(vec![custom("PIN", Some("PIN-SECRET-2"), true), custom("Agence", Some("Lyon"), false)]);
    input.tags = vec!["finance".into()];
    let id = app.add(None, input).await.unwrap();
    let mut changed = entry("Banque", "mdp-SECRET-3");
    changed.keep_otp = true;
    changed.custom = Some(vec![custom("PIN", None, true), custom("Agence", Some("Paris"), false)]);
    app.update(&id, changed).await.unwrap();

    let dumps = [
        serde_json_string(&app.entry(&id).await.unwrap()),
        serde_json_string(&app.entries("", None).await.unwrap()),
        serde_json_string(&app.history_entry(&id, 0).await.unwrap()),
        serde_json_string(&app.groups().await.unwrap()),
    ];
    for d in &dumps {
        for secret in ["SECRET", "JBSWY3DP"] {
            assert!(!d.contains(secret), "fuite de « {secret} » : {d}");
        }
    }
    let view = app.entry(&id).await.unwrap();
    assert!(view.has_totp, "lien 2FA perdu malgré keep_otp");
    assert_eq!(view.custom.iter().find(|c| c.key == "Agence").unwrap().value.as_deref(), Some("Paris"));
    assert_eq!(view.custom.iter().find(|c| c.key == "PIN").unwrap().value, None);
    let pin = app.secret(&id, SecretField::Custom("PIN".into()), None).await.unwrap();
    assert_eq!(pin.as_str(), "PIN-SECRET-2", "valeur protégée non conservée");
    let old = app.secret(&id, SecretField::Password, Some(0)).await.unwrap();
    assert_eq!(old.as_str(), "mdp-SECRET-1");
    assert!(app.secret(&id, SecretField::Totp, Some(0)).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_attribute_rename_and_missing_value() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let mut input = entry("x", "x");
    input.custom = Some(vec![custom("Ancien", Some("valeur-cachée"), true)]);
    let id = app.add(None, input).await.unwrap();

    let mut rename = entry("x", "x");
    rename.custom = Some(vec![CustomInput {
        key: "Nouveau".into(),
        value: None,
        protected: true,
        original_key: Some("Ancien".into()),
    }]);
    app.update(&id, rename).await.unwrap();
    let v = app.secret(&id, SecretField::Custom("Nouveau".into()), None).await.unwrap();
    assert_eq!(v.as_str(), "valeur-cachée");
    assert!(app.secret(&id, SecretField::Custom("Ancien".into()), None).await.is_err());

    // Une valeur « à garder » qui n'existe pas : refus, rien n'est écrit.
    let mut bad = entry("x", "modifié");
    bad.custom = Some(vec![custom("Inconnu", None, true)]);
    assert!(app.update(&id, bad).await.is_err());
    assert_eq!(app.secret(&id, SecretField::Password, None).await.unwrap().as_str(), "x");
    // Et sans entrée existante (ajout), pareil.
    let mut bad = entry("y", "y");
    bad.custom = Some(vec![custom("PIN", None, true)]);
    assert!(app.add(None, bad).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn groups_bin_and_scoped_listing_persist() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let root = app.groups().await.unwrap();
    let travail = app.add_group(&root.id, "Travail").await.unwrap();
    let id = app.add(Some(&travail), entry("VPN", "x")).await.unwrap();
    app.add(None, entry("Perso", "x")).await.unwrap();

    let in_group = app.entries("", Some(&travail)).await.unwrap().items;
    assert_eq!(in_group.len(), 1);
    assert_eq!(in_group[0].group_id, travail);
    assert_eq!(app.entries("vpn", Some(&root.id)).await.unwrap().items.len(), 1, "sous-groupes inclus");
    assert!(app.entries("perso", Some(&travail)).await.unwrap().items.is_empty());

    app.delete(&id).await.unwrap();
    assert!(app.entry(&id).await.unwrap().in_recycle_bin);
    assert!(app.entries("", None).await.unwrap().items.iter().all(|e| e.id != id));
    // Verrouiller puis rouvrir : tout a été enregistré sur le disque.
    app.lock().await;
    assert!(matches!(app.groups().await, Err(AppError::Locked)));
    app.unlock(PW).await.unwrap();
    app.restore(&id).await.unwrap();
    assert_eq!(app.entries("", Some(&travail)).await.unwrap().items.len(), 1);

    app.delete_group(&travail).await.unwrap();
    app.restore_group(&travail).await.unwrap();
    app.rename_group(&travail, "Boulot").await.unwrap();
    let tree = app.groups().await.unwrap();
    assert!(tree.children.iter().any(|g| g.name == "Boulot" && g.entry_count == 1));
    assert!(tree.children.iter().any(|g| g.is_recycle_bin));
    app.delete(&id).await.unwrap();
    assert_eq!(app.empty_recycle_bin().await.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_and_history_through_app() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let id = app.add(None, entry("x", "v1")).await.unwrap();
    app.add_attachment(&id, "note.txt", b"bonjour").await.unwrap();
    app.update(&id, entry("x", "v2")).await.unwrap();
    let view = app.entry(&id).await.unwrap();
    assert_eq!(view.attachments.len(), 1);
    assert_eq!(view.attachments[0].size, 7);
    assert_eq!(view.history.len(), 2);
    app.remove_attachment(&id, "note.txt").await.unwrap();
    app.lock().await;
    app.unlock(PW).await.unwrap();
    assert!(app.entry(&id).await.unwrap().attachments.is_empty());
    // Version 1 : avant l'ajout de la pièce jointe → index le plus ancien.
    let oldest = app.entry(&id).await.unwrap().history.len() - 1;
    app.restore_history(&id, oldest).await.unwrap();
    assert_eq!(app.secret(&id, SecretField::Password, None).await.unwrap().as_str(), "v1");
    app.restore_history(&id, 1).await.unwrap();
    assert_eq!(&*app.attachment(&id, "note.txt").await.unwrap(), b"bonjour");
}

/// Les formats JSON que l'interface envoie réellement.
#[tokio::test(flavor = "multi_thread")]
async fn ui_json_formats() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let f: SecretField = serde_json::from_str(r#""password""#).unwrap();
    assert_eq!(f, SecretField::Password);
    let f: SecretField = serde_json::from_str(r#"{"custom":"PIN"}"#).unwrap();
    assert_eq!(f, SecretField::Custom("PIN".into()));
    assert!(serde_json::from_str::<SecretField>(r#""notes""#).is_err());

    let pw: GeneratorOptions = serde_json::from_str(
        r#"{"kind":"password","length":24,"lower":true,"upper":true,"digits":true,"symbols":false,"exclude":"0O"}"#,
    )
    .unwrap();
    let g = app.generate(&pw).unwrap();
    assert_eq!(g.value.chars().count(), 24);
    assert!(!g.value.contains(['0', 'O']));
    assert!(g.entropy > 100.0);

    let pp: GeneratorOptions =
        serde_json::from_str(r#"{"kind":"passphrase","words":5,"separator":"-","case":"title"}"#).unwrap();
    let g = app.generate(&pp).unwrap();
    assert_eq!(g.value.split('-').count(), 5);
    assert!((64.0..65.0).contains(&g.entropy), "{}", g.entropy);

    let bad: GeneratorOptions = serde_json::from_str(r#"{"kind":"passphrase","words":0,"separator":" "}"#).unwrap();
    assert!(app.generate(&bad).is_err());
    assert!(serde_json::from_str::<GeneratorOptions>(r#"{"kind":"autre"}"#).is_err());

    let input: EntryInput = serde_json::from_str(
        r#"{"title":"t","username":"u","password":"p","url":"","notes":"","otp":null,
            "tags":["a","b"],"expires":4102444800,
            "custom":[{"key":"K","value":"V","protected":false}]}"#,
    )
    .unwrap();
    let id = app.add(None, input).await.unwrap();
    let v = app.entry(&id).await.unwrap();
    assert_eq!((v.tags.len(), v.expires, v.custom.len()), (2, Some(4_102_444_800), 1));
}

// ---------------------------------------------------------------- rapports et HIBP

#[derive(Clone, Copy)]
enum Hibp {
    Normal,
    Error500,
    Malformed,
    Huge,
    Redirect,
}

#[derive(Default)]
struct HibpLog {
    /// Chemin + requête + en-têtes de chaque appel reçu.
    requests: std::sync::Mutex<Vec<String>>,
}

/// Faux service HIBP : « password » apparaît 9 659 365 fois, « 123456 » 42 fois.
async fn hibp_server(mode: Hibp) -> (String, Arc<HibpLog>) {
    use axum::{extract::Path, http::{HeaderMap, StatusCode, Uri, header}, response::IntoResponse, routing::get};
    let log = Arc::new(HibpLog::default());
    let l = log.clone();
    let handler = move |Path(prefix): Path<String>, uri: Uri, headers: HeaderMap| {
        let l = l.clone();
        async move {
            let mut dump = uri.to_string();
            for (k, v) in &headers {
                dump.push_str(&format!("\n{k}: {}", v.to_str().unwrap_or("?")));
            }
            l.requests.lock().unwrap().push(dump);
            match mode {
                Hibp::Error500 => return (StatusCode::INTERNAL_SERVER_ERROR, "boom".to_string()).into_response(),
                Hibp::Malformed => return "<html>pas une plage</html>".to_string().into_response(),
                Hibp::Huge => return "0".repeat(5 * 1024 * 1024).into_response(),
                Hibp::Redirect => {
                    return (StatusCode::FOUND, [(header::LOCATION, "https://evil.example/")], String::new()).into_response();
                }
                Hibp::Normal => {}
            }
            let mut body = String::new();
            for (pw, n) in [("password", 9_659_365u64), ("123456", 42)] {
                let h = kittypass_core::hibp::sha1_hex(pw);
                if h[..5] == prefix {
                    body.push_str(&format!("{}:{n}\r\n", &h[5..]));
                }
            }
            // Remplissage, comme le vrai service avec Add-Padding.
            for i in 0..50 {
                body.push_str(&format!("{:035X}:0\r\n", i));
            }
            body.into_response()
        }
    };
    let app = axum::Router::new().route("/range/{prefix}", get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{port}/range/"), log)
}

#[tokio::test(flavor = "multi_thread")]
async fn hibp_finds_pwned_and_sends_only_prefixes() {
    let s = server().await;
    let (mut app, _, _) = first_device(&s).await;
    let (url, log) = hibp_server(Hibp::Normal).await;
    app.hibp_url = url;
    let a = app.add(None, entry("Faible A", "password")).await.unwrap();
    let b = app.add(None, entry("Faible B", "password")).await.unwrap();
    let c = app.add(None, entry("Chiffres", "123456")).await.unwrap();
    app.add(None, entry("Unique", "jamais-vu-ailleurs-Q9!x")).await.unwrap();
    app.add(None, entry("Sans mot de passe", "")).await.unwrap();
    let binned = app.add(None, entry("Jetée", "mot-jete-dans-la-corbeille")).await.unwrap();
    app.delete(&binned).await.unwrap();
    app.set_excluded_from_reports(&c, true).await.unwrap();

    let r = app.hibp_check().await.unwrap();
    assert_eq!(r.checked, 4, "corbeille et mots de passe vides exclus");
    assert_eq!(r.queries, 3, "un seul appel pour le préfixe partagé");
    let ids: Vec<_> = r.items.iter().map(|i| (i.entry.id.as_str(), i.count, i.excluded)).collect();
    assert!(ids.contains(&(a.as_str(), 9_659_365, false)));
    assert!(ids.contains(&(b.as_str(), 9_659_365, false)));
    assert_eq!(r.items.last().unwrap().entry.id, c, "trié par nombre de fuites");
    assert!(r.items.last().unwrap().excluded);
    assert_eq!(r.items.len(), 3);

    // Ce qui est parti sur le réseau : 5 caractères hexadécimaux, rien d'autre.
    let requests = log.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    let secrets = ["password", "123456", "jamais-vu", "mot-jete"];
    for r in &requests {
        let path = r.lines().next().unwrap();
        let prefix = path.strip_prefix("/range/").unwrap();
        assert!(prefix.len() == 5 && prefix.bytes().all(|b| b.is_ascii_hexdigit()), "{path}");
        assert!(r.to_lowercase().contains("add-padding: true"), "{r}");
        for s in secrets {
            assert!(!r.contains(s), "fuite dans la requête : {r}");
        }
        for h in secrets.map(kittypass_core::hibp::sha1_hex) {
            assert!(!r.to_uppercase().contains(&h[5..]), "suffixe d'empreinte envoyé : {r}");
        }
    }
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("password") && !json.contains("5BAA6"), "{json}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hibp_bad_servers_are_errors_not_crashes() {
    let s = server().await;
    let (mut app, _, _) = first_device(&s).await;
    app.add(None, entry("Faible", "password")).await.unwrap();
    for mode in [Hibp::Error500, Hibp::Malformed, Hibp::Huge, Hibp::Redirect] {
        let (url, _) = hibp_server(mode).await;
        app.hibp_url = url;
        assert!(app.hibp_check().await.is_err());
    }
    // En clair vers une machine distante : refusé avant toute requête.
    app.hibp_url = "http://api.pwnedpasswords.com/range/".into();
    assert_eq!(app.hibp_check().await.unwrap_err().code(), "insecure_url");
    // Serveur injoignable.
    app.hibp_url = "http://127.0.0.1:9/range/".into();
    assert_eq!(app.hibp_check().await.unwrap_err().code(), "network");
}

#[tokio::test(flavor = "multi_thread")]
async fn hibp_and_reports_need_unlocked_vault() {
    let s = server().await;
    let (mut app, _, _) = first_device(&s).await;
    let (url, log) = hibp_server(Hibp::Normal).await;
    app.hibp_url = url;
    app.add(None, entry("Faible", "password")).await.unwrap();
    app.lock().await;
    assert!(matches!(app.hibp_check().await, Err(AppError::Locked)));
    assert!(matches!(app.health_report().await, Err(AppError::Locked)));
    assert!(log.requests.lock().unwrap().is_empty(), "aucune requête coffre verrouillé");
}

#[tokio::test(flavor = "multi_thread")]
async fn health_report_through_app() {
    let s = server().await;
    let (app, _, _) = first_device(&s).await;
    let weak = app.add(None, entry("Faible", "secret1")).await.unwrap();
    app.add(None, entry("Copie 1", "Secret-Partage-2024!xyz")).await.unwrap();
    app.add(None, entry("Copie 2", "Secret-Partage-2024!xyz")).await.unwrap();
    app.add(None, entry("Saine", "q7#Vt9!mZ2@wL4$kR8%xN")).await.unwrap();

    let r = app.health_report().await.unwrap();
    assert_eq!(r.checked, 4);
    assert_eq!(r.items.len(), 3);
    assert_eq!(r.items[0].entry.id, weak);
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("secret1") && !json.contains("Secret-Partage"), "{json}");
    assert!(json.contains(r#""quality":"poor""#), "{json}");

    // L'exclusion est enregistrée et survit au verrouillage.
    app.set_excluded_from_reports(&weak, true).await.unwrap();
    app.lock().await;
    app.unlock(PW).await.unwrap();
    assert!(app.excluded_from_reports(&weak).await.unwrap());
    let r = app.health_report().await.unwrap();
    assert_eq!(r.excluded, 1);
    assert!(r.items.iter().find(|i| i.entry.id == weak).unwrap().excluded);

    // Jauge de l'éditeur : le contexte de l'entrée pénalise.
    let st = |pw: &str, user: &str| {
        app.strength(&kittypass_app::StrengthInput {
            password: Zeroizing::new(pw.into()),
            title: String::new(),
            username: user.into(),
            url: String::new(),
        })
    };
    assert_eq!(st("", "").quality, kittypass_app::QualityView::Bad);
    assert!(st("Zorglub-Marseille-1987", "Zorglub-Marseille-1987").bits < st("Zorglub-Marseille-1987", "").bits);
    assert_eq!(st("q7#Vt9!mZ2@wL4$kR8%xN", "").quality, kittypass_app::QualityView::Excellent);
}

// ---------------------------------------------------------------- fichier clé

fn key_req(s: &Srv, mode: SetupMode, invite: Option<String>, key: &std::path::Path, remember: bool) -> SetupRequest {
    SetupRequest { key_file: Some(key.to_path_buf()), remember_key_file: remember, ..req(s, mode, invite) }
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_created_with_keyfile() {
    let s = server().await;
    let dir = tmpdir("kf-a");
    let app = App::open(dir.clone(), Arc::new(MemoryStore::default())).unwrap();
    let key = tmpdir("kf-file").with_extension("keyx");
    app.generate_key_file(&key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Jamais d'écrasement d'un fichier existant.
    let before = std::fs::read(&key).unwrap();
    assert_eq!(app.generate_key_file(&key).unwrap_err().code(), "io");
    assert_eq!(std::fs::read(&key).unwrap(), before);

    let invite = new_invite(&s.state.db(), &s.state, false, 1).unwrap();
    app.setup(key_req(&s, SetupMode::Create, Some(invite), &key, true)).await.unwrap();
    app.add(None, entry("Protégée", "x")).await.unwrap();
    let st = app.status().await;
    assert!(st.has_key_file);
    assert_eq!(st.key_file.as_deref(), Some(key.to_str().unwrap()));
    // Le profil retient le chemin, jamais le contenu.
    let profile = std::fs::read_to_string(dir.join("profile.json")).unwrap();
    assert!(profile.contains("key_file"));
    let key_text = String::from_utf8(before).unwrap();
    let data_line = key_text.lines().find(|l| l.trim().len() == 35).unwrap().trim().to_owned();
    for f in std::fs::read_dir(&dir).unwrap() {
        let content = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&content).contains(&data_line), "contenu du fichier clé écrit sur le disque");
    }

    app.lock().await;
    assert_eq!(app.unlock_with_key_file(PW, None, true).await.unwrap_err().code(), "invalid_password");
    let other = tmpdir("kf-other").with_extension("keyx");
    app.generate_key_file(&other).unwrap();
    assert_eq!(app.unlock_with_key_file(PW, Some(&other), false).await.unwrap_err().code(), "invalid_password");
    assert_eq!(app.remembered_key_file().await.as_deref(), Some(key.as_path()), "un échec ne change pas le chemin retenu");
    app.unlock(PW).await.unwrap();
    assert!(app.status().await.has_key_file);

    app.sync().await.unwrap();
    // Un nouvel appareil doit fournir le fichier pour rejoindre.
    let b = App::open(tmpdir("kf-b"), Arc::new(MemoryStore::default())).unwrap();
    assert_eq!(b.setup(req(&s, SetupMode::Join, None)).await.unwrap_err().code(), "invalid_password");
    let b = App::open(tmpdir("kf-b2"), Arc::new(MemoryStore::default())).unwrap();
    b.setup(key_req(&s, SetupMode::Join, None, &key, false)).await.unwrap();
    assert!(b.status().await.key_file.is_none(), "chemin non retenu à la demande");
    assert_eq!(b.entries("", None).await.unwrap().items.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn keyfile_added_on_one_device_adopted_on_the_other() {
    let s = server().await;
    let (a, _, dir_a) = first_device(&s).await;
    a.add(None, entry("Commune", "x")).await.unwrap();
    a.sync().await.unwrap();
    let b = second_device(&s).await;
    b.add(None, entry("Hors ligne sur B", "y")).await.unwrap();

    let key = tmpdir("kf-shared").with_extension("keyx");
    a.generate_key_file(&key).unwrap();
    assert_eq!(a.set_key_file("mauvais", Some(&key), true).await.unwrap_err().code(), "invalid_password");
    assert!(!a.status().await.has_key_file);
    a.set_key_file(PW, Some(&key), true).await.unwrap();
    assert!(a.status().await.has_key_file);
    // Le fichier local est re-chiffré : le mot de passe seul ne suffit plus.
    a.lock().await;
    assert!(a.unlock_with_key_file(PW, None, false).await.is_err());
    a.unlock_with_key_file(PW, Some(&key), true).await.unwrap();
    let _ = dir_a;

    // B ne peut plus synchroniser sans le fichier, puis l'adopte.
    assert_eq!(b.sync().await.unwrap_err().code(), "invalid_password");
    b.set_key_file(PW, Some(&key), true).await.unwrap();
    let titles: Vec<String> = b.entries("", None).await.unwrap().items.into_iter().map(|i| i.title).collect();
    assert!(titles.contains(&"Commune".to_string()) && titles.contains(&"Hors ligne sur B".to_string()));
    a.sync().await.unwrap();
    assert_eq!(a.entries("", None).await.unwrap().items.len(), 2);

    // Retirer le fichier clé, puis B suit.
    a.set_key_file(PW, None, true).await.unwrap();
    assert!(a.remembered_key_file().await.is_none());
    assert!(b.sync().await.is_err());
    b.set_key_file(PW, None, true).await.unwrap();
    b.lock().await;
    b.unlock(PW).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keyfile_change_offline_changes_nothing() {
    let s = server().await;
    let (a, _, dir) = first_device(&s).await;
    a.add(None, entry("Une", "x")).await.unwrap();
    drop(a);
    // Même appareil, serveur injoignable.
    let profile = std::fs::read_to_string(dir.join("profile.json")).unwrap();
    std::fs::write(dir.join("profile.json"), profile.replace(&s.url, "http://127.0.0.1:9")).unwrap();
    let a = App::open(dir.clone(), Arc::new(MemoryStore::default())).unwrap();
    a.unlock(PW).await.unwrap();
    let before = std::fs::read(dir.join("vault.kdbx")).unwrap();
    let key = tmpdir("kf-offline").with_extension("keyx");
    a.generate_key_file(&key).unwrap();
    assert_eq!(a.set_key_file(PW, Some(&key), true).await.unwrap_err().code(), "network");
    assert!(!a.status().await.has_key_file);
    assert!(a.remembered_key_file().await.is_none());
    assert_eq!(std::fs::read(dir.join("vault.kdbx")).unwrap(), before);
    a.lock().await;
    a.unlock(PW).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn odd_keyfile_paths_are_refused() {
    let s = server().await;
    let (a, _, _) = first_device(&s).await;
    let d = tmpdir("kf-dir");
    std::fs::create_dir_all(&d).unwrap();
    assert_eq!(a.set_key_file(PW, Some(&d), true).await.unwrap_err().code(), "key_file");
    assert_eq!(a.set_key_file(PW, Some(&d.join("absent")), true).await.unwrap_err().code(), "key_file");
    let empty = d.join("vide");
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(a.set_key_file(PW, Some(&empty), true).await.unwrap_err().code(), "key_file");
    #[cfg(unix)]
    {
        // Un tube nommé bloquerait la lecture : refusé sans l'ouvrir.
        let fifo = d.join("tube");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let r = tokio::time::timeout(Duration::from_secs(5), a.set_key_file(PW, Some(&fifo), true)).await;
        assert_eq!(r.expect("bloqué sur le tube").unwrap_err().code(), "key_file");
    }
    assert!(!a.status().await.has_key_file);
}

// ---------------------------------------------------------- import / export

#[tokio::test(flavor = "multi_thread")]
async fn import_and_export_through_app() {
    use kittypass_app::{ExportFormat, ExportRequest, ImportFormat, ImportRequest};
    let s = server().await;
    let (a, _, dir) = first_device(&s).await;
    let work = tmpdir("transfer");
    std::fs::create_dir_all(&work).unwrap();
    let root = a.groups().await.unwrap().id;

    // CSV → nouveau groupe nommé d'après le fichier.
    let csv = work.join("chrome.csv");
    std::fs::write(&csv, "name,url,username,password\nSite,https://s.example,bob,pw-importé\n").unwrap();
    let req = |format, path: &std::path::Path| ImportRequest {
        format,
        path: path.to_owned(),
        parent: root.clone(),
        name: None,
        password: None,
        key_file: None,
    };
    let r = a.import_file(req(ImportFormat::Csv, &csv)).await.unwrap();
    assert_eq!((r.imported, r.skipped), (1, 0));
    let g = a.groups().await.unwrap();
    assert!(g.children.iter().any(|c| c.id == r.group_id && c.name == "chrome"));
    let listed = a.entries("", Some(&r.group_id)).await.unwrap();
    assert_eq!(listed.items.len(), 1);
    // Enregistré sur le disque : survit au verrouillage.
    a.lock().await;
    a.unlock(PW).await.unwrap();
    assert_eq!(a.entries("", Some(&r.group_id)).await.unwrap().items.len(), 1);

    // Copie .kdbx exportée puis réimportée avec son propre mot de passe.
    let copy = work.join("copie.kdbx");
    let exp = ExportRequest { format: ExportFormat::Kdbx, password: Some(Zeroizing::new("mot-de-passe-copie".into())), key_file: None };
    a.export_to(&copy, &exp).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let mut kreq = req(ImportFormat::Kdbx, &copy);
    kreq.password = Some(Zeroizing::new(PW.into()));
    assert_eq!(a.import_file(kreq).await.unwrap_err().code(), "invalid_password");
    let mut kreq = req(ImportFormat::Kdbx, &copy);
    kreq.password = Some(Zeroizing::new("mot-de-passe-copie".into()));
    kreq.name = Some("Copie".into());
    assert_eq!(a.import_file(kreq).await.unwrap().imported, 1);

    // Copie sans mot de passe ou trop faible : refusée.
    let weak = ExportRequest { format: ExportFormat::Kdbx, password: Some(Zeroizing::new("court".into())), key_file: None };
    assert!(a.export_to(&work.join("faible.kdbx"), &weak).await.is_err());
    let none = ExportRequest { format: ExportFormat::Kdbx, password: None, key_file: None };
    assert!(a.export_to(&work.join("rien.kdbx"), &none).await.is_err());

    // Exports en clair.
    for (fmt, needle) in [(ExportFormat::Csv, "pw-importé"), (ExportFormat::Xml, "pw-importé"), (ExportFormat::Html, "pw-importé")] {
        let p = work.join(format!("export.{}", fmt.extension()));
        a.export_to(&p, &ExportRequest { format: fmt, password: None, key_file: None }).await.unwrap();
        assert!(String::from_utf8(std::fs::read(&p).unwrap()).unwrap().contains(needle));
    }

    // Jamais dans le dossier de KittyPass (ni par un lien symbolique).
    let csv_req = ExportRequest { format: ExportFormat::Csv, password: None, key_file: None };
    let before = std::fs::read(dir.join("vault.kdbx")).unwrap();
    assert_eq!(a.export_to(&dir.join("vault.kdbx"), &csv_req).await.unwrap_err().code(), "io");
    assert_eq!(a.export_to(&dir.join("nouveau.csv"), &csv_req).await.unwrap_err().code(), "io");
    #[cfg(unix)]
    {
        let link = work.join("lien.csv");
        std::os::unix::fs::symlink(dir.join("vault.kdbx"), &link).unwrap();
        assert_eq!(a.export_to(&link, &csv_req).await.unwrap_err().code(), "io");
        let link_dir = work.join("lien-dossier");
        std::os::unix::fs::symlink(&dir, &link_dir).unwrap();
        assert_eq!(a.export_to(&link_dir.join("x.csv"), &csv_req).await.unwrap_err().code(), "io");
    }
    assert_eq!(std::fs::read(dir.join("vault.kdbx")).unwrap(), before);

    // Fichiers d'import impossibles : dossier, absent, tube, trop gros.
    assert_eq!(a.import_file(req(ImportFormat::Csv, &work)).await.unwrap_err().code(), "io");
    assert_eq!(a.import_file(req(ImportFormat::Csv, &work.join("absent.csv"))).await.unwrap_err().code(), "io");
    #[cfg(unix)]
    {
        let fifo = work.join("tube");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let r = tokio::time::timeout(Duration::from_secs(5), a.import_file(req(ImportFormat::Csv, &fifo))).await;
        assert_eq!(r.expect("bloqué sur le tube").unwrap_err().code(), "io");
    }
    let big = work.join("gros.csv");
    std::fs::File::create(&big).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap();
    assert!(a.import_file(req(ImportFormat::Csv, &big)).await.is_err());

    // Verrouillé : rien.
    a.lock().await;
    assert_eq!(a.import_file(req(ImportFormat::Csv, &csv)).await.unwrap_err().code(), "locked");
    assert_eq!(a.export_to(&work.join("v.csv"), &csv_req).await.unwrap_err().code(), "locked");
    assert!(!work.join("v.csv").exists());
}

/// Formats JSON de l'interface pour l'import et l'export.
#[test]
fn transfer_json_formats() {
    use kittypass_app::{ExportRequest, ImportFormat, ImportRequest};
    let r: ImportRequest = serde_json::from_str(r#"{"format":"1pux","path":"/tmp/x.1pux","parent":"p"}"#).unwrap();
    assert_eq!(r.format, ImportFormat::OnePux);
    let r: ImportRequest =
        serde_json::from_str(r#"{"format":"kdbx","path":"x","parent":"p","name":"N","password":"pw","key_file":null}"#).unwrap();
    assert_eq!(r.format, ImportFormat::Kdbx);
    assert!(serde_json::from_str::<ImportRequest>(r#"{"format":"exe","path":"x","parent":"p"}"#).is_err());
    let e: ExportRequest = serde_json::from_str(r#"{"format":"html"}"#).unwrap();
    assert!(e.format.is_cleartext());
}

/// Invitation déjà utilisée ou identifiant pris : messages clairs, pas un
/// simple code HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn used_invite_and_taken_username_have_clear_errors() {
    let s = server().await;
    let invite = new_invite(&s.state.db(), &s.state, false, 1).unwrap();
    let a = App::open(tmpdir("inv-a"), Arc::new(MemoryStore::default())).unwrap();
    a.setup(req(&s, SetupMode::Create, Some(invite.clone()))).await.unwrap();
    let b = App::open(tmpdir("inv-b"), Arc::new(MemoryStore::default())).unwrap();
    let mut r = req(&s, SetupMode::Create, Some(invite));
    r.username = "bob".into();
    assert_eq!(b.setup(r).await.unwrap_err().code(), "invalid_invite");
    let fresh = new_invite(&s.state.db(), &s.state, false, 1).unwrap();
    let e = b.setup(req(&s, SetupMode::Create, Some(fresh))).await.unwrap_err();
    assert_eq!(e.code(), "username_taken");
    assert!(!e.to_string().contains("409"));
    assert!(!b.status().await.configured);
}
