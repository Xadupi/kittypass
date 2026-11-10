//! Tests offensifs de l'API : chaque test essaie de casser une protection.

use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{Value, json};
use tower::ServiceExt;
use kittypass_server::{
    AppState,
    clock::MockClock,
    config::Config,
    crypto::{ServerKeys, random_bytes},
    new_invite, router, totp,
};

const T0: i64 = 1_800_000_000;

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or_default().to_owned()
    }
}

struct Account {
    username: String,
    key: [u8; 32],
    access: String,
    refresh: String,
}

struct T {
    app: Router,
    clock: Arc<MockClock>,
    state: Arc<AppState>,
}

impl T {
    fn new() -> Self {
        Self::with(Config::default())
    }

    fn with(config: Config) -> Self {
        let clock = Arc::new(MockClock::new(T0));
        let state = Arc::new(
            AppState::new(
                Connection::open_in_memory().unwrap(),
                ServerKeys::from_master(&[42u8; 32]),
                clock.clone(),
                config,
            )
            .unwrap(),
        );
        Self { app: router(state.clone()), clock, state }
    }

    async fn call_from(
        &self,
        ip: [u8; 4],
        method: &str,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Body,
    ) -> Resp {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(body).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from((ip, 40000))));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        Resp { status, headers, body }
    }

    async fn call(&self, method: &str, path: &str, token: Option<&str>, headers: &[(&str, &str)], body: Body) -> Resp {
        self.call_from([10, 0, 0, 1], method, path, token, headers, body).await
    }

    async fn post(&self, path: &str, token: Option<&str>, v: Value) -> Resp {
        self.call("POST", path, token, &[("content-type", "application/json")], Body::from(v.to_string())).await
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Resp {
        self.call("GET", path, token, &[], Body::empty()).await
    }

    async fn put_vault(&self, id: &str, token: &str, if_match: Option<&str>, data: Vec<u8>) -> Resp {
        let h: Vec<(&str, &str)> = if_match.map(|m| vec![("if-match", m)]).unwrap_or_default();
        self.call("PUT", &format!("/api/v1/vaults/{id}"), Some(token), &h, Body::from(data)).await
    }

    fn invite(&self, admin: bool) -> String {
        new_invite(&self.state.db(), &self.state, admin, 72).unwrap()
    }

    fn register_body(invite: &str, username: &str, key: &[u8; 32]) -> Value {
        json!({
            "invite": invite,
            "username": username,
            "kdf": {"salt": STANDARD.encode(random_bytes::<32>()), "memory_kib": 65536, "iterations": 3, "parallelism": 4},
            "auth_key": STANDARD.encode(key),
        })
    }

    async fn login(&self, username: &str, key: &[u8; 32], extra: Value) -> Resp {
        let mut body = json!({"username": username, "auth_key": STANDARD.encode(key), "device": "test"});
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        self.post("/api/v1/login", None, body).await
    }

    async fn account_with(&self, username: &str, admin: bool) -> Account {
        let key = random_bytes::<32>();
        let invite = self.invite(admin);
        let r = self.post("/api/v1/register", None, Self::register_body(&invite, username, &key)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
        let r = self.login(username, &key, json!({})).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
        let j = r.json();
        Account {
            username: username.into(),
            key,
            access: j["access_token"].as_str().unwrap().into(),
            refresh: j["refresh_token"].as_str().unwrap().into(),
        }
    }

    async fn account(&self, username: &str) -> Account {
        self.account_with(username, false).await
    }

    async fn new_vault(&self, a: &Account) -> String {
        let r = self.post("/api/v1/vaults", Some(&a.access), json!({"name": "Perso"})).await;
        assert_eq!(r.status, StatusCode::CREATED);
        r.json()["id"].as_str().unwrap().into()
    }

    fn current_totp(&self, secret_b32: &str) -> String {
        format!("{:06}", totp::code_at(&base32_decode(secret_b32), self.clock.now_step()))
    }
}

trait Step {
    fn now_step(&self) -> i64;
}
impl Step for MockClock {
    fn now_step(&self) -> i64 {
        use kittypass_server::clock::Clock;
        self.now() / totp::STEP
    }
}

fn base32_decode(s: &str) -> Vec<u8> {
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

/// Un vrai fichier KDBX 4 (généré une seule fois, Argon2 est coûteux).
fn kdbx() -> Vec<u8> {
    static F: OnceLock<Vec<u8>> = OnceLock::new();
    F.get_or_init(|| kittypass_core::vault::Vault::create("mot-de-passe-test").unwrap().save().unwrap()).clone()
}

// =====================================================================
// Parcours normal
// =====================================================================

#[tokio::test]
async fn full_flow() {
    let t = T::new();
    let a = t.account("alice").await;
    let id = t.new_vault(&a).await;

    let r = t.get(&format!("/api/v1/vaults/{id}"), Some(&a.access)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(r.headers["etag"], "\"0\"");

    let r = t.put_vault(&id, &a.access, Some("\"0\""), kdbx()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["version"], 1);

    let r = t.get(&format!("/api/v1/vaults/{id}"), Some(&a.access)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["etag"], "\"1\"");
    assert_eq!(r.body, kdbx());

    let r = t.get("/api/v1/vaults", Some(&a.access)).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
}

/// De bout en bout avec la vraie dérivation de clé et un vrai coffre chiffré.
#[tokio::test]
async fn end_to_end_with_real_crypto() {
    use kittypass_core::{account::{KdfParams, derive_auth_key, new_account_salt}, header::OpenLimits, vault::{EntryData, Vault}};
    let t = T::new();
    let pw = "phrase-de-passe-très-longue";
    let salt = new_account_salt().unwrap();
    let key = derive_auth_key(pw, &salt, &KdfParams::DEFAULT).unwrap();
    let mut body = T::register_body(&t.invite(false), "bob", key.as_bytes());
    body["kdf"]["salt"] = json!(STANDARD.encode(salt));
    assert_eq!(t.post("/api/v1/register", None, body).await.status, StatusCode::CREATED);

    // Un nouvel appareil : pré-login → dérivation → connexion.
    let pre = t.post("/api/v1/prelogin", None, json!({"username": "bob"})).await.json();
    let salt2 = STANDARD.decode(pre["salt"].as_str().unwrap()).unwrap();
    let params = KdfParams {
        memory_kib: pre["memory_kib"].as_u64().unwrap() as u32,
        iterations: pre["iterations"].as_u64().unwrap() as u32,
        parallelism: pre["parallelism"].as_u64().unwrap() as u32,
    };
    let key2 = derive_auth_key(pw, &salt2, &params).unwrap();
    let r = t.login("bob", key2.as_bytes(), json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    let access = r.json()["access_token"].as_str().unwrap().to_owned();

    let mut v = Vault::create(pw).unwrap();
    v.add(&EntryData { title: "Banque".into(), ..Default::default() }).unwrap();
    let id = t.post("/api/v1/vaults", Some(&access), json!({"name": "Perso"})).await.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(t.put_vault(&id, &access, Some("0"), v.save().unwrap()).await.status, StatusCode::OK);
    let data = t.get(&format!("/api/v1/vaults/{id}"), Some(&access)).await.body;
    let v2 = Vault::open(&data, pw, &OpenLimits::default()).unwrap();
    assert_eq!(v2.list()[0].title, "Banque");
}

// =====================================================================
// Énumération de comptes
// =====================================================================

#[tokio::test]
async fn prelogin_does_not_reveal_accounts() {
    let t = T::new();
    t.account("alice").await;
    let real = t.post("/api/v1/prelogin", None, json!({"username": "alice"})).await;
    let fake = t.post("/api/v1/prelogin", None, json!({"username": "alicf"})).await;
    let fake2 = t.post("/api/v1/prelogin", None, json!({"username": "alicf"})).await;
    assert_eq!(real.status, fake.status);
    let (r, f) = (real.json(), fake.json());
    for k in ["memory_kib", "iterations", "parallelism"] {
        assert_eq!(r[k], f[k], "paramètre {k} différent : énumération possible");
    }
    assert_eq!(r["salt"].as_str().unwrap().len(), f["salt"].as_str().unwrap().len());
    assert_eq!(f["salt"], fake2.json()["salt"], "sel factice instable : énumération possible");
    let mut keys_r: Vec<_> = r.as_object().unwrap().keys().collect();
    let mut keys_f: Vec<_> = f.as_object().unwrap().keys().collect();
    keys_r.sort();
    keys_f.sort();
    assert_eq!(keys_r, keys_f);
}

#[tokio::test]
async fn login_errors_are_indistinguishable() {
    let t = T::new();
    let a = t.account("alice").await;
    t.account("carol").await;
    t.state.db().execute("UPDATE users SET disabled = 1 WHERE username = 'carol'", []).unwrap();
    let wrong_pw = t.login("alice", &[0u8; 32], json!({})).await;
    let unknown = t.login("nobody", &a.key, json!({})).await;
    let disabled = t.login("carol", &[0u8; 32], json!({})).await;
    let invalid_name = t.login("x", &a.key, json!({})).await;
    for r in [&wrong_pw, &unknown, &disabled, &invalid_name] {
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(r.body, wrong_pw.body, "réponses différentes : énumération possible");
    }
}

// =====================================================================
// Inscription
// =====================================================================

#[tokio::test]
async fn register_requires_valid_single_use_invite() {
    let t = T::new();
    let key = random_bytes::<32>();
    for bad in ["", "nope", &"A".repeat(500)] {
        let r = t.post("/api/v1/register", None, T::register_body(bad, "eve", &key)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let inv = t.invite(false);
    assert_eq!(t.post("/api/v1/register", None, T::register_body(&inv, "eve", &key)).await.status, StatusCode::CREATED);
    let r = t.post("/api/v1/register", None, T::register_body(&inv, "eve2", &key)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "invitation réutilisable");

    let inv = t.invite(false);
    t.clock.advance(73 * 3600);
    let r = t.post("/api/v1/register", None, T::register_body(&inv, "late", &key)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "invitation expirée acceptée");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_race_only_one_wins() {
    let t = T::new();
    let inv = t.invite(false);
    let key = random_bytes::<32>();
    let futs: Vec<_> = (0..8)
        .map(|i| Box::pin(t.post("/api/v1/register", None, T::register_body(&inv, &format!("racer{i}"), &key))))
        .collect();
    let results = futures_poll_all(futs).await;
    let ok = results.iter().filter(|r| r.status == StatusCode::CREATED).count();
    assert_eq!(ok, 1, "une invitation a servi {ok} fois");
}

/// Exécute des futures de façon concurrente, sans dépendance supplémentaire.
async fn futures_poll_all<F: std::future::Future + Unpin>(mut futs: Vec<F>) -> Vec<F::Output> {
    use std::task::Poll;
    let mut results: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in futs.iter_mut().enumerate() {
            if results[i].is_none() {
                match std::pin::Pin::new(f).poll(cx) {
                    Poll::Ready(v) => results[i] = Some(v),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending { Poll::Pending } else { Poll::Ready(()) }
    })
    .await;
    results.into_iter().map(Option::unwrap).collect()
}

#[tokio::test]
async fn register_rejects_mass_assignment_and_bad_input() {
    let t = T::new();
    let key = random_bytes::<32>();
    // Tentative d'élévation de privilèges par champ supplémentaire.
    let mut b = T::register_body(&t.invite(false), "mallory", &key);
    b["is_admin"] = json!(true);
    let r = t.post("/api/v1/register", None, b).await;
    assert!(r.status.is_client_error(), "champ inconnu accepté");
    let admin: Option<bool> = t
        .state
        .db()
        .query_row("SELECT is_admin FROM users WHERE username = 'mallory'", [], |r| r.get(0))
        .ok();
    assert_ne!(admin, Some(true));

    // Paramètres KDF affaiblis par un client malveillant.
    let mut b = T::register_body(&t.invite(false), "weak", &key);
    b["kdf"]["memory_kib"] = json!(8);
    assert_eq!(t.post("/api/v1/register", None, b).await.status, StatusCode::BAD_REQUEST);
    let mut b = T::register_body(&t.invite(false), "weak", &key);
    b["kdf"]["salt"] = json!(STANDARD.encode([0u8; 16]));
    assert_eq!(t.post("/api/v1/register", None, b).await.status, StatusCode::BAD_REQUEST);
    let mut b = T::register_body(&t.invite(false), "weak", &key);
    b["auth_key"] = json!(STANDARD.encode([0u8; 31]));
    assert_eq!(t.post("/api/v1/register", None, b).await.status, StatusCode::BAD_REQUEST);

    for name in ["admin' OR '1'='1", "аdmin", "a", "ab\u{0}c", "../../etc"] {
        let r = t.post("/api/v1/register", None, T::register_body(&t.invite(false), name, &key)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name:?}");
    }
}

#[tokio::test]
async fn username_case_and_duplicates() {
    let t = T::new();
    let a = t.account("alice").await;
    let r = t.post("/api/v1/register", None, T::register_body(&t.invite(false), "ALICE", &a.key)).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "doublon par la casse");
    assert_eq!(t.login("Alice", &a.key, json!({})).await.status, StatusCode::OK);
}

// =====================================================================
// Force brute et limitation du débit
// =====================================================================

#[tokio::test]
async fn progressive_lockout() {
    let t = T::new();
    let a = t.account("alice").await;
    for _ in 0..5 {
        assert_eq!(t.login("alice", &[1u8; 32], json!({})).await.status, StatusCode::UNAUTHORIZED);
    }
    // Verrouillé : même le bon mot de passe échoue, sans le dire.
    let r = t.login("alice", &a.key, json!({})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error(), "invalid_credentials");
    t.clock.advance(31);
    assert_eq!(t.login("alice", &a.key, json!({})).await.status, StatusCode::OK);
}

#[tokio::test]
async fn per_user_rate_limit() {
    let t = T::new();
    t.account("alice").await;
    let mut limited = false;
    for i in 0..15u8 {
        // IP différente à chaque essai : la limite par compte doit tenir.
        let body = json!({"username": "alice", "auth_key": STANDARD.encode([9u8; 32]), "device": "x"});
        let r = t
            .call_from([10, 9, 9, i], "POST", "/api/v1/login", None, &[("content-type", "application/json")], Body::from(body.to_string()))
            .await;
        limited |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "pas de limite par compte : force brute distribuée possible");
}

#[tokio::test]
async fn spoofed_forwarded_for_is_ignored_from_untrusted_peer() {
    let t = T::new();
    let mut limited = false;
    for i in 0..40 {
        let ip = format!("192.0.2.{i}");
        let body = json!({"username": format!("user{i}"), "auth_key": STANDARD.encode([9u8; 32]), "device": "x"});
        let r = t
            .call("POST", "/api/v1/login", None, &[("content-type", "application/json"), ("x-forwarded-for", &ip)], Body::from(body.to_string()))
            .await;
        limited |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "X-Forwarded-For falsifié contourne la limite par IP");
}

#[tokio::test]
async fn trusted_proxy_uses_last_forwarded_hop() {
    let proxy = [10, 0, 0, 254];
    let t = T::with(Config { trusted_proxies: vec![proxy.into()], ..Config::default() });
    let mut limited = false;
    for i in 0..40 {
        // Le client invente la première valeur ; le proxy ajoute la vraie en dernier.
        let xff = format!("198.51.100.{i}, 203.0.113.7");
        let body = json!({"username": format!("user{i}"), "auth_key": STANDARD.encode([9u8; 32]), "device": "x"});
        let r = t
            .call_from(proxy, "POST", "/api/v1/login", None, &[("content-type", "application/json"), ("x-forwarded-for", &xff)], Body::from(body.to_string()))
            .await;
        limited |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "la valeur falsifiée par le client a été utilisée");
}

// =====================================================================
// Jetons et sessions
// =====================================================================

#[tokio::test]
async fn bad_tokens_are_rejected() {
    let t = T::new();
    let a = t.account("alice").await;
    let long = "A".repeat(10_000);
    for tok in ["", "x", a.refresh.as_str(), long.as_str(), "' OR 1=1 --"] {
        let r = t.get("/api/v1/vaults", Some(tok)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "jeton {:.20}… accepté", tok);
    }
    let r = t.call("GET", "/api/v1/vaults", None, &[("authorization", &format!("Basic {}", a.access))], Body::empty()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.get("/api/v1/vaults", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn access_token_expires() {
    let t = T::new();
    let a = t.account("alice").await;
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::OK);
    t.clock.advance(15 * 60 + 1);
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rotation_and_theft_detection() {
    let t = T::new();
    let a = t.account("alice").await;
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": a.refresh})).await;
    assert_eq!(r.status, StatusCode::OK);
    let new_access = r.json()["access_token"].as_str().unwrap().to_owned();
    let new_refresh = r.json()["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(new_refresh, a.refresh);

    // Un voleur rejoue l'ancien jeton : refusé, et la session entière tombe.
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": a.refresh})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.get("/api/v1/vaults", Some(&new_access)).await.status, StatusCode::UNAUTHORIZED);
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": new_refresh})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Un jeton d'accès ne sert pas de jeton de rafraîchissement.
    let b = t.account("bob").await;
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": b.access})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_expires() {
    let t = T::new();
    let a = t.account("alice").await;
    t.clock.advance(30 * 24 * 3600 + 1);
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": a.refresh})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_and_session_revocation() {
    let t = T::new();
    let a = t.account("alice").await;
    let r = t.login("alice", &a.key, json!({})).await;
    let other = r.json()["access_token"].as_str().unwrap().to_owned();

    let sessions = t.get("/api/v1/sessions", Some(&a.access)).await.json();
    assert_eq!(sessions.as_array().unwrap().len(), 2);
    let other_id = sessions.as_array().unwrap().iter().find(|s| s["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = t.call("DELETE", &format!("/api/v1/sessions/{other_id}"), Some(&a.access), &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.get("/api/v1/vaults", Some(&other)).await.status, StatusCode::UNAUTHORIZED);

    assert_eq!(t.post("/api/v1/logout", Some(&a.access), json!({})).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabled_account_loses_access_immediately() {
    let t = T::new();
    let a = t.account("alice").await;
    t.state.db().execute("UPDATE users SET disabled = 1 WHERE username = 'alice'", []).unwrap();
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::UNAUTHORIZED);
    let r = t.post("/api/v1/token/refresh", None, json!({"refresh_token": a.refresh})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn secrets_are_not_stored_in_clear() {
    let t = T::new();
    let a = t.account("alice").await;
    let conn = t.state.db();
    let tokens: Vec<Vec<u8>> =
        conn.prepare("SELECT hash FROM tokens").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    for h in &tokens {
        assert_ne!(h.as_slice(), a.access.as_bytes());
        assert_ne!(h.as_slice(), a.refresh.as_bytes());
    }
    let stored: Vec<u8> = conn.query_row("SELECT auth_hash FROM users", [], |r| r.get(0)).unwrap();
    assert_ne!(stored, a.key, "clé d'authentification stockée telle quelle");
}

// =====================================================================
// Contrôle d'accès entre utilisateurs (IDOR)
// =====================================================================

#[tokio::test]
async fn users_cannot_touch_each_others_data() {
    let t = T::new();
    let a = t.account("alice").await;
    let b = t.account("bob").await;
    let id = t.new_vault(&a).await;
    t.put_vault(&id, &a.access, Some("0"), kdbx()).await;

    let paths = [
        format!("/api/v1/vaults/{id}"),
        format!("/api/v1/vaults/{id}/versions"),
        format!("/api/v1/vaults/{id}/versions/1"),
    ];
    for p in &paths {
        let r = t.get(p, Some(&b.access)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{p} lisible par un autre compte");
    }
    let r = t.put_vault(&id, &b.access, Some("1"), kdbx()).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "écriture dans le coffre d'autrui");
    let r = t.call("DELETE", &format!("/api/v1/vaults/{id}"), Some(&b.access), &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "suppression du coffre d'autrui");
    assert!(t.get("/api/v1/vaults", Some(&b.access)).await.json().as_array().unwrap().is_empty());

    // Sessions d'autrui.
    let a_sessions = t.get("/api/v1/sessions", Some(&a.access)).await.json();
    let a_sid = a_sessions[0]["id"].as_str().unwrap();
    let r = t.call("DELETE", &format!("/api/v1/sessions/{a_sid}"), Some(&b.access), &[], Body::empty()).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::OK);

    // Le coffre d'Alice est intact.
    assert_eq!(t.get(&paths[0], Some(&a.access)).await.headers["etag"], "\"1\"");
}

#[tokio::test]
async fn malicious_ids_in_paths() {
    let t = T::new();
    let a = t.account("alice").await;
    for id in ["1'%20OR%20'1'='1", "..%2F..%2Fetc%2Fpasswd", "%00", "00000000-0000-0000-0000-000000000000"] {
        let r = t.get(&format!("/api/v1/vaults/{id}"), Some(&a.access)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{id}");
    }
    let id = t.new_vault(&a).await;
    let r = t.get(&format!("/api/v1/vaults/{id}/versions/-1"), Some(&a.access)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.get(&format!("/api/v1/vaults/{id}/versions/abc"), Some(&a.access)).await;
    assert!(r.status.is_client_error());
}

// =====================================================================
// Synchronisation
// =====================================================================

#[tokio::test]
async fn upload_preconditions_and_validation() {
    let t = T::new();
    let a = t.account("alice").await;
    let id = t.new_vault(&a).await;

    assert_eq!(t.put_vault(&id, &a.access, None, kdbx()).await.status, StatusCode::PRECONDITION_REQUIRED);
    for bad in ["-1", "abc", "\"\"", "1e9", "99999999999999999999999"] {
        assert_eq!(t.put_vault(&id, &a.access, Some(bad), kdbx()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = t.put_vault(&id, &a.access, Some("5"), kdbx()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.json()["current_version"], 0);

    // Le serveur refuse ce qui n'est pas un KDBX 4 sain.
    for body in [vec![], b"hello".to_vec(), vec![0u8; 4096]] {
        assert_eq!(t.put_vault(&id, &a.access, Some("0"), body).await.status, StatusCode::BAD_REQUEST);
    }
    let mut bomb = kdbx();
    let pos = bomb.windows(8).position(|w| w == (64u64 << 20).to_le_bytes()).unwrap();
    bomb[pos..pos + 8].copy_from_slice(&(16u64 << 30).to_le_bytes());
    let r = t.put_vault(&id, &a.access, Some("0"), bomb).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "fichier piégé accepté : il bloquerait les autres appareils");
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let t = T::with(Config { max_vault_bytes: 100_000, ..Config::default() });
    let a = t.account("alice").await;
    let id = t.new_vault(&a).await;
    let r = t.put_vault(&id, &a.access, Some("0"), vec![0u8; 200_000]).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = t.post("/api/v1/prelogin", None, json!({"username": "x".repeat(100_000)})).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_uploads_cannot_both_win() {
    let t = T::new();
    let a = t.account("alice").await;
    let id = t.new_vault(&a).await;
    let futs: Vec<_> = (0..6).map(|_| Box::pin(t.put_vault(&id, &a.access, Some("0"), kdbx()))).collect();
    let results = futures_poll_all(futs).await;
    let ok = results.iter().filter(|r| r.status == StatusCode::OK).count();
    let conflicts = results.iter().filter(|r| r.status == StatusCode::CONFLICT).count();
    assert_eq!((ok, conflicts), (1, 5), "écritures concurrentes : modifications perdues");
}

#[tokio::test]
async fn old_versions_are_kept_then_pruned() {
    let t = T::with(Config { versions_kept: 3, ..Config::default() });
    let a = t.account("alice").await;
    let id = t.new_vault(&a).await;
    for v in 0..5 {
        assert_eq!(t.put_vault(&id, &a.access, Some(&v.to_string()), kdbx()).await.status, StatusCode::OK);
    }
    let list = t.get(&format!("/api/v1/vaults/{id}/versions"), Some(&a.access)).await.json();
    let versions: Vec<i64> = list.as_array().unwrap().iter().map(|v| v["version"].as_i64().unwrap()).collect();
    assert_eq!(versions, vec![5, 4, 3]);
    assert_eq!(t.get(&format!("/api/v1/vaults/{id}/versions/3"), Some(&a.access)).await.status, StatusCode::OK);
    assert_eq!(t.get(&format!("/api/v1/vaults/{id}/versions/1"), Some(&a.access)).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn vault_limits_and_names() {
    let t = T::with(Config { max_vaults_per_user: 2, ..Config::default() });
    let a = t.account("alice").await;
    t.new_vault(&a).await;
    t.new_vault(&a).await;
    let r = t.post("/api/v1/vaults", Some(&a.access), json!({"name": "trop"})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let b = t.account("bob").await;
    for name in ["", "a\nb", "\u{202e}fdp.exe", &"x".repeat(65)] {
        let r = t.post("/api/v1/vaults", Some(&b.access), json!({"name": name})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name:?}");
    }
}

// =====================================================================
// 2FA
// =====================================================================

async fn enable_2fa(t: &T, a: &Account) -> (String, Vec<String>) {
    let r = t.post("/api/v1/2fa/setup", Some(&a.access), json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    let secret = r.json()["secret"].as_str().unwrap().to_owned();
    assert!(r.json()["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/KittyPass:"));
    let r = t.post("/api/v1/2fa/enable", Some(&a.access), json!({"code": t.current_totp(&secret)})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let codes = r.json()["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect();
    (secret, codes)
}

#[tokio::test]
async fn totp_flow_replay_and_recovery_codes() {
    let t = T::new();
    let a = t.account("alice").await;
    let r = t.post("/api/v1/2fa/setup", Some(&a.access), json!({})).await;
    let secret = r.json()["secret"].as_str().unwrap().to_owned();
    let r = t.post("/api/v1/2fa/enable", Some(&a.access), json!({"code": "000000"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "code faux accepté à l'activation");
    let r = t.post("/api/v1/2fa/enable", Some(&a.access), json!({"code": t.current_totp(&secret)})).await;
    let codes: Vec<String> =
        r.json()["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(codes.iter().collect::<std::collections::HashSet<_>>().len(), 10);

    // Sans code : demandé ; code faux : refusé.
    assert_eq!(t.login("alice", &a.key, json!({})).await.error(), "totp_required");
    assert_eq!(t.login("alice", &a.key, json!({"totp": "123456"})).await.status, StatusCode::UNAUTHORIZED);

    // Le code utilisé à l'activation ne peut pas resservir.
    assert_eq!(t.login("alice", &a.key, json!({"totp": t.current_totp(&secret)})).await.status, StatusCode::UNAUTHORIZED);
    t.clock.advance(30);
    let code = t.current_totp(&secret);
    assert_eq!(t.login("alice", &a.key, json!({"totp": code})).await.status, StatusCode::OK);
    assert_eq!(t.login("alice", &a.key, json!({"totp": code})).await.status, StatusCode::UNAUTHORIZED, "code TOTP rejoué");

    // Code de secours : une seule fois, insensible à la casse et aux tirets.
    let rc = codes[0].to_lowercase().replace('-', "");
    assert_eq!(t.login("alice", &a.key, json!({"recovery_code": rc})).await.status, StatusCode::OK);
    assert_eq!(t.login("alice", &a.key, json!({"recovery_code": codes[0]})).await.status, StatusCode::UNAUTHORIZED);

    // Bon code TOTP mais mauvais mot de passe : refusé.
    t.clock.advance(30);
    assert_eq!(t.login("alice", &[3u8; 32], json!({"totp": t.current_totp(&secret)})).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabling_2fa_logs_out_other_devices() {
    let t = T::new();
    let a = t.account("alice").await;
    let other = t.login("alice", &a.key, json!({})).await.json()["access_token"].as_str().unwrap().to_owned();
    enable_2fa(&t, &a).await;
    assert_eq!(t.get("/api/v1/vaults", Some(&other)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn totp_secret_encrypted_at_rest() {
    let t = T::new();
    let a = t.account("alice").await;
    let (secret, _) = enable_2fa(&t, &a).await;
    let raw = base32_decode(&secret);
    let stored: Vec<u8> = t.state.db().query_row("SELECT totp_secret FROM users", [], |r| r.get(0)).unwrap();
    assert!(!stored.windows(raw.len()).any(|w| w == raw.as_slice()), "secret TOTP en clair dans la base");
}

#[tokio::test]
async fn disabling_2fa_needs_password_and_code() {
    let t = T::new();
    let a = t.account("alice").await;
    let (secret, _) = enable_2fa(&t, &a).await;
    t.clock.advance(30);
    let code = t.current_totp(&secret);
    // Voleur de jeton sans le mot de passe.
    let r = t.post("/api/v1/2fa/disable", Some(&a.access), json!({"auth_key": STANDARD.encode([0u8; 32]), "code": code})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t.post("/api/v1/2fa/disable", Some(&a.access), json!({"auth_key": STANDARD.encode(a.key), "code": "000000"})).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t.post("/api/v1/2fa/disable", Some(&a.access), json!({"auth_key": STANDARD.encode(a.key), "code": code})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.login("alice", &a.key, json!({})).await.status, StatusCode::OK);
}

#[tokio::test]
async fn totp_brute_force_triggers_lockout() {
    let t = T::new();
    let a = t.account("alice").await;
    enable_2fa(&t, &a).await;
    for i in 0..5 {
        t.login("alice", &a.key, json!({"totp": format!("{i:06}")})).await;
    }
    let locked: i64 = t.state.db().query_row("SELECT locked_until FROM users", [], |r| r.get(0)).unwrap();
    assert!(locked > T0, "les codes TOTP faux ne verrouillent pas le compte");
}

#[tokio::test]
async fn server_can_require_2fa() {
    let t = T::with(Config { require_2fa: true, ..Config::default() });
    let a = t.account("alice").await;
    let r = t.login("alice", &a.key, json!({})).await;
    assert_eq!(r.json()["must_setup_2fa"], true);
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::FORBIDDEN);
    let (secret, _) = enable_2fa(&t, &a).await;
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::OK);
    t.clock.advance(30);
    let r = t.post("/api/v1/2fa/disable", Some(&a.access), json!({"auth_key": STANDARD.encode(a.key), "code": t.current_totp(&secret)})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "2FA désactivable alors qu'elle est imposée");
}

// =====================================================================
// Administration, mot de passe
// =====================================================================

#[tokio::test]
async fn only_admins_create_invites() {
    let t = T::new();
    let user = t.account("alice").await;
    let admin = t.account_with("root", true).await;
    let r = t.post("/api/v1/admin/invites", Some(&user.access), json!({})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.post("/api/v1/admin/invites", Some(&admin.access), json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t.post("/api/v1/admin/invites", Some(&admin.access), json!({"admin": true})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "admin sans 2FA peut créer des admins");
    for hours in [0, -5, 100_000] {
        let r = t.post("/api/v1/admin/invites", Some(&admin.access), json!({"hours": hours})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn change_password() {
    let t = T::new();
    let a = t.account("alice").await;
    let other = t.login("alice", &a.key, json!({})).await.json()["access_token"].as_str().unwrap().to_owned();
    let new_key = random_bytes::<32>();
    let body = |current: &[u8; 32]| {
        json!({
            "current_auth_key": STANDARD.encode(current),
            "kdf": {"salt": STANDARD.encode(random_bytes::<32>()), "memory_kib": 65536, "iterations": 3, "parallelism": 4},
            "new_auth_key": STANDARD.encode(new_key),
        })
    };
    let r = t.post("/api/v1/account/password", Some(&a.access), body(&[0u8; 32])).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t.post("/api/v1/account/password", Some(&a.access), body(&a.key)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.get("/api/v1/vaults", Some(&other)).await.status, StatusCode::UNAUTHORIZED, "autres sessions conservées");
    assert_eq!(t.get("/api/v1/vaults", Some(&a.access)).await.status, StatusCode::OK);
    assert_eq!(t.login(&a.username, &a.key, json!({})).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(t.login(&a.username, &new_key, json!({})).await.status, StatusCode::OK);
}

// =====================================================================
// En-têtes et robustesse
// =====================================================================

#[tokio::test]
async fn security_headers_everywhere() {
    let t = T::new();
    for r in [t.get("/health", None).await, t.get("/api/v1/vaults", None).await, t.get("/nope", None).await] {
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["x-content-type-options"], "nosniff");
        assert_eq!(r.headers["x-frame-options"], "DENY");
        assert!(r.headers.contains_key("strict-transport-security"));
        assert!(r.headers.contains_key("content-security-policy"));
    }
}

#[tokio::test]
async fn malformed_requests_do_not_crash() {
    let t = T::new();
    let cases: &[(&str, &str, &str)] = &[
        ("POST", "/api/v1/login", "{"),
        ("POST", "/api/v1/login", "null"),
        ("POST", "/api/v1/login", "[]"),
        ("POST", "/api/v1/login", r#"{"username": 1, "auth_key": [], "device": {}}"#),
        ("POST", "/api/v1/register", r#"{"invite": "x", "username": "abc", "kdf": null, "auth_key": "x"}"#),
        ("POST", "/api/v1/prelogin", "\u{0}\u{0}\u{0}"),
        ("POST", "/api/v1/token/refresh", r#"{"refresh_token": "\ud800"}"#),
    ];
    for (m, p, body) in cases {
        let r = t.call(m, p, None, &[("content-type", "application/json")], Body::from(*body)).await;
        assert!(r.status.is_client_error(), "{m} {p} {body} → {}", r.status);
    }
    // Le serveur répond toujours après ces requêtes.
    assert_eq!(t.get("/health", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn account_summary_follows_2fa() {
    let t = T::new();
    let a = t.account("alice").await;
    let r = t.get("/api/v1/account", Some(&a.access)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), json!({"username": "alice", "totp_enabled": false, "require_2fa": false, "is_admin": false}));
    enable_2fa(&t, &a).await;
    assert_eq!(t.get("/api/v1/account", Some(&a.access)).await.json()["totp_enabled"], true);
    assert_eq!(t.get("/api/v1/account", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_lists_and_disables_users() {
    let t = T::new();
    let admin = t.account_with("root", true).await;
    let bob = t.account("bob").await;
    // Réservé aux admins.
    assert_eq!(t.get("/api/v1/admin/users", Some(&bob.access)).await.status, StatusCode::FORBIDDEN);
    let r = t.post("/api/v1/admin/users/root/disabled", Some(&bob.access), json!({"disabled": true})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let list = t.get("/api/v1/admin/users", Some(&admin.access)).await.json();
    let names: Vec<_> = list.as_array().unwrap().iter().map(|u| u["username"].as_str().unwrap()).collect();
    assert_eq!(names, ["bob", "root"]);
    assert_eq!(list[1]["current"], true);
    assert_eq!(list[1]["is_admin"], true);
    assert!(list[0].get("auth_hash").is_none());
    assert_eq!(t.get("/api/v1/account", Some(&admin.access)).await.json()["is_admin"], true);

    // Pas soi-même, pas un inconnu.
    let r = t.post("/api/v1/admin/users/root/disabled", Some(&admin.access), json!({"disabled": true})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t.post("/api/v1/admin/users/nobody/disabled", Some(&admin.access), json!({"disabled": true})).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Désactivé : sessions fermées, connexion refusée ; réactivé : connexion possible.
    let r = t.post("/api/v1/admin/users/bob/disabled", Some(&admin.access), json!({"disabled": true})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.get("/api/v1/vaults", Some(&bob.access)).await.status, StatusCode::UNAUTHORIZED);
    assert_ne!(t.login("bob", &bob.key, json!({})).await.status, StatusCode::OK);
    assert_eq!(t.get("/api/v1/admin/users", Some(&admin.access)).await.json()[0]["disabled"], true);
    let r = t.post("/api/v1/admin/users/bob/disabled", Some(&admin.access), json!({"disabled": false})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.login("bob", &bob.key, json!({})).await.status, StatusCode::OK);
}

#[tokio::test]
async fn storage_quota_per_account() {
    let size = kdbx().len() as i64;
    let t = T::with(Config { max_user_bytes: size * 3, versions_kept: 50, ..Config::default() });
    let a = t.account("alice").await;
    let b = t.account("bob").await;
    let v1 = t.new_vault(&a).await;
    let v2 = t.new_vault(&a).await;
    assert_eq!(t.put_vault(&v1, &a.access, Some("0"), kdbx()).await.status, StatusCode::OK);
    assert_eq!(t.put_vault(&v1, &a.access, Some("1"), kdbx()).await.status, StatusCode::OK);
    assert_eq!(t.put_vault(&v2, &a.access, Some("0"), kdbx()).await.status, StatusCode::OK);
    // Quota atteint, tous coffres et versions confondus ; rien n'est enregistré.
    let r = t.put_vault(&v2, &a.access, Some("1"), kdbx()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.json()["error"], "storage_quota_exceeded");
    assert_eq!(t.get(&format!("/api/v1/vaults/{v2}/versions"), Some(&a.access)).await.json().as_array().unwrap().len(), 1);
    // Le quota est propre à chaque compte.
    let vb = t.new_vault(&b).await;
    assert_eq!(t.put_vault(&vb, &b.access, Some("0"), kdbx()).await.status, StatusCode::OK);
}

#[test]
fn rate_limit_key_groups_ipv6_by_64() {
    use kittypass_server::rate_key;
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert_eq!(rate_key(ip("2001:db8:1:2:aaaa::1")), rate_key(ip("2001:db8:1:2:ffff::9")));
    assert_ne!(rate_key(ip("2001:db8:1:2::1")), rate_key(ip("2001:db8:1:3::1")));
    assert_eq!(rate_key(ip("::ffff:192.0.2.7")), rate_key(ip("192.0.2.7")));
    assert_ne!(rate_key(ip("192.0.2.7")), rate_key(ip("192.0.2.8")));
}

#[tokio::test]
async fn trusted_device_skips_2fa_after_first_login() {
    let t = T::new();
    let a = t.account("alice").await;
    let (secret, _) = enable_2fa(&t, &a).await;
    t.clock.advance(30);

    // Première connexion : code 2FA ; l'appareil reçoit un jeton de confiance.
    let r = t.login("alice", &a.key, json!({"totp": t.current_totp(&secret)})).await;
    assert_eq!(r.status, StatusCode::OK);
    let tok1 = r.json()["device_token"].as_str().unwrap().to_owned();

    // Ensuite : plus de code, le jeton suffit, et il est renouvelé.
    let r = t.login("alice", &a.key, json!({"device_token": tok1})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let tok2 = r.json()["device_token"].as_str().unwrap().to_owned();
    assert_ne!(tok1, tok2);
    // L'ancien jeton ne resert pas ; un faux non plus.
    assert_eq!(t.login("alice", &a.key, json!({"device_token": tok1})).await.error(), "totp_required");
    assert_eq!(t.login("alice", &a.key, json!({"device_token": "faux"})).await.error(), "totp_required");
    // Le jeton ne remplace pas le mot de passe.
    assert_eq!(t.login("alice", &[3u8; 32], json!({"device_token": tok2})).await.status, StatusCode::UNAUTHORIZED);

    // Un an sans connexion : oublié.
    let r = t.login("alice", &a.key, json!({"device_token": tok2})).await;
    let tok3 = r.json()["device_token"].as_str().unwrap().to_owned();
    t.clock.advance(366 * 24 * 3600);
    assert_eq!(t.login("alice", &a.key, json!({"device_token": tok3})).await.error(), "totp_required");
}

#[tokio::test]
async fn revoked_session_loses_device_trust() {
    let t = T::new();
    let a = t.account("alice").await;
    let (secret, _) = enable_2fa(&t, &a).await;
    t.clock.advance(30);
    let r = t.login("alice", &a.key, json!({"totp": t.current_totp(&secret)})).await;
    let tok = r.json()["device_token"].as_str().unwrap().to_owned();
    let access = r.json()["access_token"].as_str().unwrap().to_owned();
    assert_eq!(t.post("/api/v1/logout", Some(&access), json!({})).await.status, StatusCode::NO_CONTENT);
    assert_eq!(t.login("alice", &a.key, json!({"device_token": tok})).await.error(), "totp_required");
}
