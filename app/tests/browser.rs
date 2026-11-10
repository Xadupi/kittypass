//! Intégration navigateur : l'application face à une fausse extension
//! KeePassXC-Browser qui parle le vrai protocole (NaCl, nonces, actions).

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use kittypass_app::{Answer, App, BrowserConnection, MemoryStore, Prompt, Prompter};
use kittypass_core::{
    browser::crypto::{Session, increment_nonce, random_nonce},
    vault::{CustomField, EntryData, MasterKey, Vault},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-application";

/// Répond aux questions dans l'ordre prévu et garde ce qui a été demandé.
#[derive(Default)]
struct Script {
    answers: Mutex<VecDeque<Option<Answer>>>,
    asked: Mutex<Vec<Prompt>>,
    unlock: AtomicUsize,
}

impl Script {
    fn then(&self, a: Option<Answer>) -> &Self {
        self.answers.lock().unwrap().push_back(a);
        self
    }
    fn asked(&self) -> Vec<Prompt> {
        self.asked.lock().unwrap().clone()
    }
}

impl Prompter for Script {
    async fn ask(&self, prompt: Prompt) -> Option<Answer> {
        self.asked.lock().unwrap().push(prompt);
        self.answers.lock().unwrap().pop_front().flatten()
    }
    fn unlock_requested(&self) {
        self.unlock.fetch_add(1, Ordering::SeqCst);
    }
}

/// Fausse extension : sa paire de clés, son identifiant et ses associations.
struct Ext {
    s: Session,
    client_id: String,
    keys: Vec<(String, String)>,
    id_key: String,
}

impl Ext {
    fn new() -> Self {
        Self {
            s: Session::new().unwrap(),
            client_id: B64.encode([9u8; 24]),
            keys: vec![],
            id_key: B64.encode(&random_nonce().unwrap()[..].repeat(2)[..32]),
        }
    }

    async fn connect(&mut self, app: &App, conn: &mut BrowserConnection, p: &Script) -> Value {
        let n = random_nonce().unwrap();
        let req = json!({"action": "change-public-keys", "publicKey": self.s.public_key_b64(), "nonce": B64.encode(n), "clientID": self.client_id});
        let r = app.browser_request(conn, req.to_string().as_bytes(), p).await;
        assert_eq!(r["success"], "true", "{r}");
        assert_eq!(r["nonce"], B64.encode(increment_nonce(&n)));
        self.s.set_peer(r["publicKey"].as_str().unwrap()).unwrap();
        r
    }

    fn envelope(&self, action: &str, mut body: Value) -> (Value, [u8; 24]) {
        let n = random_nonce().unwrap();
        body["action"] = action.into();
        let msg = self.s.encrypt(body.to_string().as_bytes(), &n).unwrap();
        (json!({"action": action, "message": msg, "nonce": B64.encode(n), "clientID": self.client_id}), n)
    }

    /// Envoie une requête chiffrée ; renvoie la réponse déchiffrée, ou
    /// l'erreur en clair.
    async fn call(&mut self, app: &App, conn: &mut BrowserConnection, p: &Script, action: &str, body: Value) -> Value {
        let (env, n) = self.envelope(action, body);
        let r = app.browser_request(conn, env.to_string().as_bytes(), p).await;
        self.open(r, &n)
    }

    fn open(&mut self, r: Value, n: &[u8; 24]) -> Value {
        if r.get("errorCode").is_some() {
            return r;
        }
        let inc = increment_nonce(n);
        assert_eq!(r["nonce"], B64.encode(inc));
        let plain = self.s.decrypt(r["message"].as_str().unwrap(), &inc).unwrap();
        let v: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["nonce"], B64.encode(inc));
        assert_eq!(v["success"], "true");
        v
    }

    fn keys(&self) -> Value {
        json!(self.keys.iter().map(|(id, key)| json!({"id": id, "key": key})).collect::<Vec<_>>())
    }

    async fn associate(&mut self, app: &App, conn: &mut BrowserConnection, p: &Script, name: &str) -> Value {
        p.then(Some(Answer::Associate { name: name.into() }));
        let r = self.call(app, conn, p, "associate", json!({"key": self.s.public_key_b64(), "idKey": self.id_key})).await;
        if r["id"] == name {
            self.keys.push((name.into(), self.id_key.clone()));
        }
        r
    }

    async fn logins(&mut self, app: &App, conn: &mut BrowserConnection, p: &Script, url: &str) -> Value {
        let keys = self.keys();
        self.call(app, conn, p, "get-logins", json!({"url": url, "submitUrl": url, "keys": keys})).await
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("kp-browser-{}-{name}-{t}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn entry(title: &str, user: &str, pw: &str, url: &str) -> EntryData {
    EntryData {
        title: title.into(),
        username: user.into(),
        password: Zeroizing::new(pw.into()),
        url: url.into(),
        ..Default::default()
    }
}

/// Application déverrouillée, hors ligne, avec quelques entrées.
async fn app(name: &str) -> (App, Vec<String>) {
    let dir = tmpdir(name);
    let mut v = Vault::create_with_key(&MasterKey::new(PW, None)).unwrap();
    let mut ids = vec![];
    ids.push(v.add(&entry("Exemple", "alice", "pw-exemple", "https://example.com/login")).unwrap());
    ids.push(v.add(&entry("Exemple bis", "bob", "pw-bob", "example.com")).unwrap());
    let mut t = entry("Avec 2FA", "carol", "pw-carol", "https://secure.example.org");
    t.otp = Some(Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()));
    ids.push(v.add(&t).unwrap());
    ids.push(v.add(&entry("Autre site", "dave", "pw-autre", "https://other.net")).unwrap());
    std::fs::write(dir.join("vault.kdbx"), v.save().unwrap()).unwrap();
    let profile = json!({"server_url": "http://127.0.0.1:9", "username": "alice", "vault_id": "v", "device": "test", "last_seen": 0});
    std::fs::write(dir.join("profile.json"), profile.to_string()).unwrap();
    let app = App::open(dir, Arc::new(MemoryStore::default())).unwrap();
    app.unlock(PW).await.unwrap();
    (app, ids)
}

fn simple(id: &str) -> String {
    id.replace('-', "")
}

fn logins_of(r: &Value) -> Vec<String> {
    let mut v: Vec<String> =
        r["entries"].as_array().into_iter().flatten().map(|e| e["login"].as_str().unwrap().to_owned()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn full_flow_like_the_extension() {
    let (app, ids) = app("flow").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;

    let h = ext.call(&app, &mut conn, &p, "get-databasehash", json!({})).await;
    assert_eq!(h["hash"].as_str().unwrap().len(), 64);
    assert_eq!(h["version"], "2.7.10");

    let a = ext.associate(&app, &mut conn, &p, "Firefox perso").await;
    assert_eq!(a["id"], "Firefox perso");
    assert_eq!(a["hash"], h["hash"]);
    assert_eq!(p.asked(), vec![Prompt::Associate]);

    let t = ext.call(&app, &mut conn, &p, "test-associate", json!({"id": "Firefox perso", "key": ext.id_key})).await;
    assert_eq!(t["id"], "Firefox perso");

    // Première demande : confirmation ; l'utilisateur n'autorise qu'alice et
    // demande de s'en souvenir.
    p.then(Some(Answer::Access { allowed: vec![ids[0].clone()], remember: true }));
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login?next=/").await;
    assert_eq!(logins_of(&r), vec!["alice"]);
    assert_eq!(r["entries"][0]["password"], "pw-exemple");
    assert_eq!(r["entries"][0]["uuid"], simple(&ids[0]));
    let Prompt::Access { host, entries, .. } = &p.asked()[1] else { panic!() };
    assert_eq!(host, "example.com");
    assert_eq!(entries.len(), 2, "les deux entrées du site sont proposées");
    assert!(!serde_json::to_string(&p.asked()).unwrap().contains("pw-"), "un mot de passe est parti dans la question");

    // Seconde fois : alice sans question, bob refusé et retenu.
    let before = p.asked().len();
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(logins_of(&r), vec!["alice"]);
    assert_eq!(p.asked().len(), before, "question reposée malgré « Se souvenir »");

    // 2FA d'une entrée remise.
    p.then(Some(Answer::Access { allowed: vec![ids[2].clone()], remember: false }));
    let r = ext.logins(&app, &mut conn, &p, "https://secure.example.org/").await;
    assert_eq!(r["entries"][0]["totp"].as_str().unwrap().len(), 6);
    let code = ext.call(&app, &mut conn, &p, "get-totp", json!({"uuid": simple(&ids[2])})).await;
    assert_eq!(code["totp"].as_str().unwrap().len(), 6);

    // Générateur.
    let g = ext.call(&app, &mut conn, &p, "generate-password", json!({})).await;
    assert!(g["password"].as_str().unwrap().len() >= 20);
    assert!(g.get("entries").is_none());

    // Nouvel identifiant : groupe du navigateur, URL sans requête.
    let s = ext
        .call(
            &app,
            &mut conn,
            &p,
            "set-login",
            json!({"id": "Firefox perso", "login": "neo", "password": "nouveau-pw", "url": "https://new.example.net/signup?token=SECRET", "submitUrl": ""}),
        )
        .await;
    assert_eq!(s["error"], "success");
    let found = app.entries("neo", None).await.unwrap();
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].url, "https://new.example.net/signup");
    assert_eq!(found.items[0].title, "new.example.net");
    let groups = app.groups().await.unwrap();
    assert!(groups.children.iter().any(|g| g.name == kittypass_app::BROWSER_GROUP));

    // Mise à jour confirmée d'une entrée remise.
    p.then(Some(Answer::Confirm { ok: true }));
    let u = ext
        .call(
            &app,
            &mut conn,
            &p,
            "set-login",
            json!({"id": "Firefox perso", "login": "alice", "password": "pw-change", "url": "https://example.com/login", "uuid": simple(&ids[0])}),
        )
        .await;
    assert_eq!(u["error"], "success");
    assert!(matches!(p.asked().last(), Some(Prompt::UpdateLogin { .. })));
    let pw = app.secret(&ids[0], kittypass_app::SecretField::Password, None).await.unwrap();
    assert_eq!(pw.as_str(), "pw-change");
    assert_eq!(app.entry(&ids[0]).await.unwrap().history.len(), 1, "l'ancien mot de passe n'est pas dans l'historique");

    // Groupes : arborescence sans corbeille ; création d'un chemin.
    let gr = ext.call(&app, &mut conn, &p, "get-database-groups", json!({})).await;
    assert!(gr["groups"]["groups"][0]["children"].is_array());
    let c = ext.call(&app, &mut conn, &p, "create-new-group", json!({"groupName": "Web/Forums"})).await;
    assert_eq!(c["name"], "Web/Forums");
    assert_eq!(c["uuid"].as_str().unwrap().len(), 32);

    // Verrouillage demandé par le navigateur.
    let l = ext.call(&app, &mut conn, &p, "lock-database", json!({})).await;
    assert_eq!(l["success"], "true");
    assert!(!app.status().await.unlocked);
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(r["errorCode"], "1");
}

#[tokio::test]
async fn nothing_without_a_proven_association() {
    let (app, ids) = app("noassoc").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;

    // Clé inventée.
    ext.keys = vec![("Firefox".into(), B64.encode([1u8; 32]))];
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(r["errorCode"], "8");
    for (action, body) in [
        ("set-login", json!({"id": "Firefox", "login": "x", "password": "y", "url": "https://example.com"})),
        ("get-totp", json!({"uuid": simple(&ids[2])})),
        ("get-database-groups", json!({})),
        ("create-new-group", json!({"groupName": "x"})),
        ("lock-database", json!({})),
        ("passkeys-get", json!({"publicKey": {}, "origin": "https://example.com"})),
    ] {
        let r = ext.call(&app, &mut conn, &p, action, body).await;
        assert_eq!(r["errorCode"], "8", "{action} accepté sans association");
    }
    assert!(app.status().await.unlocked);
    assert!(app.entries("", None).await.unwrap().items.len() == 4, "entrée créée sans association");
    assert!(p.asked().is_empty());

    // test-associate avec une mauvaise clé, ou un nom inconnu.
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    let mut conn2 = BrowserConnection::new().unwrap();
    let mut other = Ext::new();
    other.connect(&app, &mut conn2, &p).await;
    let r = other.call(&app, &mut conn2, &p, "test-associate", json!({"id": "Firefox", "key": B64.encode([2u8; 32])})).await;
    assert_eq!(r["errorCode"], "8");
    let r = other.call(&app, &mut conn2, &p, "test-associate", json!({"id": "Inconnu", "key": ext.id_key})).await;
    assert_eq!(r["errorCode"], "8");
    // L'association est liée au coffre, pas à la connexion : la bonne clé
    // marche depuis une autre connexion.
    let r = other.call(&app, &mut conn2, &p, "test-associate", json!({"id": "Firefox", "key": ext.id_key})).await;
    assert_eq!(r["id"], "Firefox");
}

#[tokio::test]
async fn association_needs_user_and_own_key() {
    let (app, _) = app("assoc").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    // Refus de l'utilisateur.
    p.then(None);
    let r = ext.call(&app, &mut conn, &p, "associate", json!({"key": ext.s.public_key_b64(), "idKey": ext.id_key})).await;
    assert_eq!(r["errorCode"], "6");
    // Clé annoncée qui n'est pas celle de la connexion : pas de question.
    let before = p.asked().len();
    let r = ext.call(&app, &mut conn, &p, "associate", json!({"key": B64.encode([3u8; 32]), "idKey": ext.id_key})).await;
    assert_eq!(r["errorCode"], "8");
    assert_eq!(p.asked().len(), before);
    // Un nom déjà pris ne remplace pas la clé existante.
    ext.associate(&app, &mut conn, &p, "Chromium").await;
    let mut conn2 = BrowserConnection::new().unwrap();
    let mut thief = Ext::new();
    thief.connect(&app, &mut conn2, &p).await;
    let r = thief.associate(&app, &mut conn2, &p, "Chromium").await;
    assert_eq!(r["errorCode"], "8");
    let r = ext.call(&app, &mut conn, &p, "test-associate", json!({"id": "Chromium", "key": ext.id_key})).await;
    assert_eq!(r["id"], "Chromium");
}

#[tokio::test]
async fn protocol_abuse_is_rejected() {
    let (app, _) = app("abuse").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();

    // Avant l'échange de clés.
    let mut early = Ext::new();
    early.s.set_peer(&Session::new().unwrap().public_key_b64()).unwrap();
    let (env, _) = early.envelope("get-databasehash", json!({}));
    let r = app.browser_request(&mut conn, env.to_string().as_bytes(), &p).await;
    assert_eq!(r["errorCode"], "3");
    ext.connect(&app, &mut conn, &p).await;

    // Rejeu d'une requête chiffrée.
    let (env, n) = ext.envelope("get-databasehash", json!({}));
    let raw = env.to_string();
    let first = app.browser_request(&mut conn, raw.as_bytes(), &p).await;
    assert!(ext.open(first, &n).get("hash").is_some());
    let again = app.browser_request(&mut conn, raw.as_bytes(), &p).await;
    assert_eq!(again["errorCode"], "4");

    // Action de l'enveloppe différente de celle du message chiffré.
    let (mut env, _) = ext.envelope("get-databasehash", json!({}));
    env["action"] = "lock-database".into();
    let r = app.browser_request(&mut conn, env.to_string().as_bytes(), &p).await;
    assert_eq!(r["errorCode"], "4");
    assert!(app.status().await.unlocked);

    // Autre clientID sur la même connexion.
    let (mut env, _) = ext.envelope("get-databasehash", json!({}));
    env["clientID"] = "autre".into();
    let r = app.browser_request(&mut conn, env.to_string().as_bytes(), &p).await;
    assert_eq!(r["errorCode"], "10");

    // Message chiffré pour quelqu'un d'autre.
    let mut stranger = Session::new().unwrap();
    stranger.set_peer(&Session::new().unwrap().public_key_b64()).unwrap();
    let n = random_nonce().unwrap();
    let bogus = json!({"action": "get-databasehash", "message": stranger.encrypt(b"{}", &n).unwrap(), "nonce": B64.encode(n), "clientID": ext.client_id});
    let r = app.browser_request(&mut conn, bogus.to_string().as_bytes(), &p).await;
    assert_eq!(r["errorCode"], "4");

    // JSON invalide, énorme, clé publique piégée, action inconnue.
    assert_eq!(app.browser_request(&mut conn, b"{pas du json", &p).await["errorCode"], "13");
    let huge = vec![b'a'; 2 * 1024 * 1024];
    assert_eq!(app.browser_request(&mut conn, &huge, &p).await["errorCode"], "13");
    let weak = json!({"action": "change-public-keys", "publicKey": B64.encode([0u8; 32]), "nonce": B64.encode([0u8; 24]), "clientID": "x"});
    assert_eq!(app.browser_request(&mut conn, weak.to_string().as_bytes(), &p).await["errorCode"], "9");
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    let r = ext.call(&app, &mut conn, &p, "request-autotype", json!({})).await;
    assert_eq!(r["errorCode"], "12");
}

#[tokio::test]
async fn sites_only_get_their_own_entries() {
    let (app, ids) = app("sites").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    ext.associate(&app, &mut conn, &p, "Firefox").await;

    for url in [
        "https://evilexample.com/",
        "https://example.com.evil.net/",
        "http://example.com/login",
        "https://example.com:8443/login",
        "javascript:alert(1)",
        "",
    ] {
        let before = p.asked().len();
        let r = ext.logins(&app, &mut conn, &p, url).await;
        assert!(r.get("entries").is_none() || logins_of(&r).is_empty(), "{url} a reçu {r}");
        assert_eq!(p.asked().len(), before, "{url} a déclenché une question");
    }

    // Refus de l'utilisateur : rien n'est remis.
    p.then(Some(Answer::Access { allowed: vec![], remember: false }));
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(r["errorCode"], "15");
    // Délai dépassé / fenêtre fermée : pareil.
    p.then(None);
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(r["errorCode"], "15");
    // Un identifiant choisi qui n'était pas proposé est ignoré.
    p.then(Some(Answer::Access { allowed: vec![ids[3].clone()], remember: false }));
    let r = ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    assert_eq!(r["errorCode"], "15");

    // Formulaire envoyé vers un autre hôte : l'autorisation de la page ne
    // suffit pas.
    p.then(Some(Answer::Access { allowed: vec![ids[0].clone()], remember: true }));
    ext.logins(&app, &mut conn, &p, "https://example.com/login").await;
    let before = p.asked().len();
    p.then(Some(Answer::Access { allowed: vec![], remember: false }));
    let keys = ext.keys();
    let r = ext
        .call(&app, &mut conn, &p, "get-logins", json!({"url": "https://example.com/login", "submitUrl": "https://collect.evil.net/", "keys": keys}))
        .await;
    assert_eq!(p.asked().len(), before + 1, "pas de question pour un envoi vers un autre hôte");
    let Some(Prompt::Access { submit_host, .. }) = p.asked().last().cloned() else { panic!() };
    assert_eq!(submit_host.as_deref(), Some("collect.evil.net"));
    assert!(logins_of(&r).is_empty());

    // 2FA et mise à jour : seulement pour des entrées remises ici.
    let r = ext.call(&app, &mut conn, &p, "get-totp", json!({"uuid": simple(&ids[2])})).await;
    assert_eq!(r["errorCode"], "18");
    let r = ext
        .call(
            &app,
            &mut conn,
            &p,
            "set-login",
            json!({"id": "Firefox", "login": "dave", "password": "vole", "url": "https://other.net", "uuid": simple(&ids[3])}),
        )
        .await;
    assert_eq!(r["errorCode"], "18");
    // Entrée remise, mais pour un autre site.
    let r = ext
        .call(
            &app,
            &mut conn,
            &p,
            "set-login",
            json!({"id": "Firefox", "login": "alice", "password": "vole", "url": "https://other.net", "uuid": simple(&ids[0])}),
        )
        .await;
    assert_eq!(r["errorCode"], "18");
    // Mise à jour refusée par l'utilisateur.
    p.then(Some(Answer::Confirm { ok: false }));
    let r = ext
        .call(
            &app,
            &mut conn,
            &p,
            "set-login",
            json!({"id": "Firefox", "login": "alice", "password": "vole", "url": "https://example.com/", "uuid": simple(&ids[0])}),
        )
        .await;
    assert_eq!(r["errorCode"], "6");
    let pw = app.secret(&ids[0], kittypass_app::SecretField::Password, None).await.unwrap();
    assert_eq!(pw.as_str(), "pw-exemple");

    // Une nouvelle connexion (nouvelle clé) ne garde pas les entrées remises.
    let mut conn2 = BrowserConnection::new().unwrap();
    let keys = ext.keys.clone();
    let mut ext2 = Ext::new();
    ext2.keys = keys;
    ext2.connect(&app, &mut conn2, &p).await;
    ext2.call(&app, &mut conn2, &p, "test-associate", json!({"id": "Firefox", "key": ext.id_key})).await;
    let r = ext2.call(&app, &mut conn2, &p, "get-totp", json!({"uuid": simple(&ids[0])})).await;
    assert_eq!(r["errorCode"], "18");
}

#[tokio::test]
async fn hidden_and_binned_entries_are_never_offered() {
    let (app, ids) = app("hidden").await;
    app.delete(&ids[1]).await.unwrap();
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    p.then(Some(Answer::Access { allowed: ids.clone(), remember: false }));
    let r = ext.logins(&app, &mut conn, &p, "https://www.example.com/login").await;
    assert_eq!(logins_of(&r), vec!["alice"]);
    let Prompt::Access { entries, .. } = p.asked().last().cloned().unwrap() else { panic!() };
    assert_eq!(entries.len(), 1, "entrée de la corbeille proposée");
}

#[tokio::test]
async fn locked_vault_answers_not_opened_and_can_ask_for_unlock() {
    let (app, _) = app("locked").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    app.lock().await;
    let r = ext.call(&app, &mut conn, &p, "get-databasehash", json!({})).await;
    assert_eq!(r["errorCode"], "1");
    assert_eq!(p.unlock.load(Ordering::SeqCst), 0);
    let (mut env, _) = ext.envelope("get-databasehash", json!({}));
    env["triggerUnlock"] = "true".into();
    let r = app.browser_request(&mut conn, env.to_string().as_bytes(), &p).await;
    assert_eq!(r["errorCode"], "1");
    assert_eq!(p.unlock.load(Ordering::SeqCst), 1);
    // Le générateur marche coffre verrouillé (il ne lit rien).
    let g = ext.call(&app, &mut conn, &p, "generate-password", json!({})).await;
    assert!(g["password"].is_string());
}

#[tokio::test]
async fn browser_requests_do_not_delay_auto_lock() {
    let (app, _) = app("idle").await;
    app.set_auto_lock_after(Some(std::time::Duration::from_millis(200)));
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    ext.call(&app, &mut conn, &p, "get-databasehash", json!({})).await;
    assert!(app.lock_if_idle().await, "l'interrogation du navigateur a repoussé le verrouillage");
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[tokio::test]
async fn passkeys_register_then_sign_in() {
    let (app, _) = app("passkeys").await;
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    let options = json!({
        "rp": {"id": "example.com", "name": "Exemple"},
        "user": {"id": b64url(b"u-42"), "name": "alice@example.com", "displayName": "Alice"},
        "challenge": b64url(&[5u8; 32]),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    });

    // Refus.
    p.then(Some(Answer::Confirm { ok: false }));
    let r = ext.call(&app, &mut conn, &p, "passkeys-register", json!({"publicKey": options, "origin": "https://example.com"})).await;
    assert_eq!(r["response"]["errorCode"], 22);
    // Site qui demande un RP ID qui n'est pas le sien : pas de question.
    let before = p.asked().len();
    let r = ext.call(&app, &mut conn, &p, "passkeys-register", json!({"publicKey": options, "origin": "https://evil.net"})).await;
    assert_eq!(r["response"]["errorCode"], 28);
    assert_eq!(p.asked().len(), before);

    p.then(Some(Answer::Confirm { ok: true }));
    let r = ext.call(&app, &mut conn, &p, "passkeys-register", json!({"publicKey": options, "origin": "https://example.com"})).await;
    let cred = &r["response"];
    assert_eq!(cred["type"], "public-key");
    let cred_id = cred["id"].as_str().unwrap().to_owned();
    let Some(Prompt::CreatePasskey { rp_id, user_name, .. }) = p.asked().last().cloned() else { panic!() };
    assert_eq!((rp_id.as_str(), user_name.as_str()), ("example.com", "alice@example.com"));
    // Enregistrée au format KeePassXC, clé privée protégée et jamais dans la
    // fiche envoyée à l'interface.
    let found = app.entries("Exemple", None).await.unwrap();
    let pk_entry = found.items.iter().find(|e| e.url == "https://example.com").unwrap();
    let view = app.entry(&pk_entry.id).await.unwrap();
    let json_view = serde_json::to_string(&view).unwrap();
    assert!(json_view.contains("KPEX_PASSKEY_CREDENTIAL_ID"));
    assert!(!json_view.contains("BEGIN PRIVATE KEY"), "clé privée envoyée à l'interface");

    // Même compte une deuxième fois : exclu.
    let mut again = options.clone();
    again["excludeCredentials"] = json!([{"type": "public-key", "id": cred_id}]);
    let r = ext.call(&app, &mut conn, &p, "passkeys-register", json!({"publicKey": again, "origin": "https://example.com"})).await;
    assert_eq!(r["response"]["errorCode"], 21);

    // Connexion.
    p.then(Some(Answer::Choose { id: pk_entry.id.clone() }));
    let get = json!({"challenge": b64url(&[6u8; 32]), "rpId": "example.com"});
    let r = ext.call(&app, &mut conn, &p, "passkeys-get", json!({"publicKey": get, "origin": "https://login.example.com"})).await;
    assert_eq!(r["response"]["id"], cred_id);
    assert_eq!(r["response"]["response"]["userHandle"], b64url(b"u-42"));
    // Autre site : aucune passkey, aucune question.
    let before = p.asked().len();
    let r = ext
        .call(&app, &mut conn, &p, "passkeys-get", json!({"publicKey": {"challenge": b64url(&[6u8; 32])}, "origin": "https://other.net"}))
        .await;
    assert_eq!(r["response"]["errorCode"], 15);
    assert_eq!(p.asked().len(), before);
    // Choix d'une entrée qui n'était pas proposée.
    p.then(Some(Answer::Choose { id: "00000000-0000-0000-0000-000000000000".into() }));
    let r = ext.call(&app, &mut conn, &p, "passkeys-get", json!({"publicKey": get, "origin": "https://example.com"})).await;
    assert_eq!(r["response"]["errorCode"], 22);
}

#[tokio::test]
async fn keepassxc_passkey_attributes_are_used() {
    // Passkey créée « ailleurs » (attributs KeePassXC écrits à la main).
    let (app, _) = app("kpxc-passkey").await;
    let pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUTV0sNG+/YrVVXMp\nQVf8sB8o7JaaO5bNEn/9EqyS87GhRANCAAREQc8ZCr7b1mYEsmxp1oSePOKj9sI9\nWr7XuycHsOpQm3PL3KxX2Q4cI8GzC9YfSUSls5mSsuiMOUgn+Ljrd9m0\n-----END PRIVATE KEY-----\n";
    let f = |k: &str, v: &str, protected| CustomField { key: k.into(), value: Zeroizing::new(v.into()), protected };
    let d = EntryData {
        title: "Site".into(),
        url: "https://webauthn.io".into(),
        custom: vec![
            f("KPEX_PASSKEY_CREDENTIAL_ID", "AQIDBA", false),
            f("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem, true),
            f("KPEX_PASSKEY_RELYING_PARTY", "webauthn.io", false),
            f("KPEX_PASSKEY_USERNAME", "zoe", false),
            f("KPEX_PASSKEY_USER_HANDLE", "dXNlcg", false),
        ],
        ..Default::default()
    };
    let custom: Vec<kittypass_app::CustomInput> = d
        .custom
        .iter()
        .map(|c| kittypass_app::CustomInput { key: c.key.clone(), value: Some(c.value.clone()), protected: c.protected, original_key: None })
        .collect();
    let id = app
        .add(
            None,
            kittypass_app::EntryInput {
                title: d.title.clone(),
                username: String::new(),
                password: Zeroizing::new(String::new()),
                url: d.url.clone(),
                notes: Zeroizing::new(String::new()),
                otp: None,
                keep_otp: false,
                tags: vec![],
                expires: None,
                custom: Some(custom),
            },
        )
        .await
        .unwrap();
    let p = Script::default();
    let mut conn = BrowserConnection::new().unwrap();
    let mut ext = Ext::new();
    ext.connect(&app, &mut conn, &p).await;
    ext.associate(&app, &mut conn, &p, "Firefox").await;
    p.then(Some(Answer::Choose { id: id.clone() }));
    let r = ext
        .call(&app, &mut conn, &p, "passkeys-get", json!({"publicKey": {"challenge": b64url(&[1u8; 32])}, "origin": "https://webauthn.io"}))
        .await;
    assert_eq!(r["response"]["id"], "AQIDBA");
    assert!(r["response"]["response"]["signature"].is_string());
    let Some(Prompt::UsePasskey { entries, .. }) = p.asked().last().cloned() else { panic!() };
    assert_eq!(entries[0].username, "zoe");
}
