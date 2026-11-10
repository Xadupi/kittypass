//! Le vrai client HTTP du cœur contre le vrai serveur, sur une vraie socket.

use std::{net::SocketAddr, sync::Arc};

use rusqlite::Connection;
use kittypass_core::{
    Error,
    client::Client,
    header::OpenLimits,
    sync::{download, sync},
    vault::{EntryData, MasterKey, Vault},
};
use kittypass_server::{AppState, clock::MockClock, config::Config, crypto::ServerKeys, new_invite, router, totp};

const PW: &str = "phrase-de-passe-e2e-longue";

struct Server {
    url: String,
    state: Arc<AppState>,
    clock: Arc<MockClock>,
}

async fn start() -> Server {
    let clock = Arc::new(MockClock::new(1_800_000_000));
    let state = Arc::new(
        AppState::new(Connection::open_in_memory().unwrap(), ServerKeys::from_master(&[7; 32]), clock.clone(), Config::default())
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server { url: format!("http://127.0.0.1:{}", addr.port()), state, clock }
}

impl Server {
    fn invite(&self) -> String {
        new_invite(&self.state.db(), &self.state, false, 1).unwrap()
    }
    async fn user(&self, name: &str) -> Client {
        let c = Client::new(&self.url).unwrap();
        c.register(&self.invite(), name, PW).await.unwrap();
        c.login(name, PW, None, "e2e").await.unwrap();
        c
    }
}

fn entry(title: &str) -> EntryData {
    EntryData { title: title.into(), ..Default::default() }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_sync_through_real_server() {
    let s = start().await;
    let pc = s.user("alice").await;
    let phone = Client::new(&s.url).unwrap();
    phone.login("alice", PW, None, "téléphone").await.unwrap();

    let info = pc.create_vault("Perso").await.unwrap();
    let mut v_pc = Vault::create(PW).unwrap();
    v_pc.add(&entry("Banque")).unwrap();
    let r = sync(&mut v_pc, 0, &OpenLimits::default(), &pc.remote(&info.id).unwrap()).await.unwrap();
    assert_eq!(r.version, 1);

    // Le téléphone télécharge le coffre existant, puis ajoute une entrée.
    let vaults = phone.list_vaults().await.unwrap();
    assert_eq!(vaults.len(), 1);
    let remote = phone.remote(&vaults[0].id).unwrap();
    let (mut v_phone, seen) = download(&remote, &MasterKey::new(PW, None), &OpenLimits::default()).await.unwrap().unwrap();
    v_phone.add(&entry("Mail")).unwrap();
    let r2 = sync(&mut v_phone, seen, &OpenLimits::default(), &remote).await.unwrap();
    assert!(r2.pushed);
    sync(&mut v_pc, r.version, &OpenLimits::default(), &pc.remote(&info.id).unwrap()).await.unwrap();

    let titles = |v: &Vault| v.list().into_iter().map(|e| e.title).collect::<Vec<_>>();
    assert_eq!(titles(&v_pc), ["Banque", "Mail"]);
    assert_eq!(titles(&v_phone), ["Banque", "Mail"]);
    assert_eq!(pc.list_sessions().await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_access_token_is_refreshed_transparently() {
    let s = start().await;
    let c = s.user("bob").await;
    let before = c.tokens().unwrap().refresh_token;
    s.clock.advance(16 * 60);
    assert!(c.list_vaults().await.unwrap().is_empty());
    assert_ne!(c.tokens().unwrap().refresh_token, before, "pas de rotation du jeton");
}

#[tokio::test(flavor = "multi_thread")]
async fn stolen_refresh_token_kills_both_sessions() {
    let s = start().await;
    let victim = s.user("carol").await;
    let thief = Client::new(&s.url).unwrap();
    thief.set_tokens(victim.tokens());
    thief.refresh().await.unwrap(); // le voleur l'utilise en premier
    // La victime tente à son tour : réutilisation détectée, session révoquée.
    assert!(matches!(victim.refresh().await, Err(Error::SessionExpired)));
    assert!(matches!(thief.list_vaults().await, Err(Error::SessionExpired)));
}

#[tokio::test(flavor = "multi_thread")]
async fn totp_through_client() {
    let s = start().await;
    let c = s.user("dave").await;
    let setup = c.setup_2fa().await.unwrap();
    assert!(setup.otpauth_uri.contains(&format!("secret={}", setup.secret.as_str())));
    let secret_b32 = setup.secret.to_string();
    let secret = base32_decode(&secret_b32);
    let step = |s: &Server| kittypass_server::clock::Clock::now(&*s.clock) / totp::STEP;
    let codes = c.enable_2fa(&format!("{:06}", totp::code_at(&secret, step(&s)))).await.unwrap();
    assert_eq!(codes.len(), 10);

    let c2 = Client::new(&s.url).unwrap();
    assert!(matches!(c2.login("dave", PW, None, "x").await, Err(Error::TotpRequired)));
    assert!(matches!(c2.login("dave", "mauvais-mot-de-passe", None, "x").await, Err(Error::InvalidCredentials)));
    s.clock.advance(30);
    c2.login("dave", PW, Some(&format!("{:06}", totp::code_at(&secret, step(&s)))), "x").await.unwrap();
    // Code de secours passé dans le même champ.
    let c3 = Client::new(&s.url).unwrap();
    c3.login("dave", PW, Some(codes[0].as_str()), "x").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_never_sends_usable_key() {
    // L'erreur est la même pour un compte inconnu et un mauvais mot de passe.
    let s = start().await;
    s.user("erin").await;
    let c = Client::new(&s.url).unwrap();
    assert!(matches!(c.login("erin", "pas-le-bon-mdp", None, "x").await, Err(Error::InvalidCredentials)));
    assert!(matches!(c.login("inconnu", PW, None, "x").await, Err(Error::InvalidCredentials)));
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
