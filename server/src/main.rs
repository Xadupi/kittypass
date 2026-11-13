use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::extract::ConnectInfo;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use tower::Service;

/// Connexions simultanées au plus (au-delà, les suivantes attendent).
const MAX_CONNECTIONS: usize = 512;

use rusqlite::Connection;
use kittypass_server::{
    AppState, clock::SystemClock, config::Config, crypto::ServerKeys, db, new_invite, router,
};

const USAGE: &str = "\
Utilisation : kittypass-server <commande>

  serve                     démarre le serveur (par défaut)
  invite [--admin] [HEURES] crée une invitation (72 h par défaut)
  users                     liste les comptes
  disable <utilisateur>     désactive un compte et ferme ses sessions
  enable <utilisateur>      réactive un compte
  --version                 affiche la version

Variables d'environnement :
  KITTYPASS_DATA             dossier des données (./data)
  KITTYPASS_BIND             adresse d'écoute (127.0.0.1:8080)
  KITTYPASS_TRUSTED_PROXIES  IP des reverse proxies, séparées par des virgules
  KITTYPASS_REQUIRE_2FA      true pour imposer la 2FA à tous les comptes";

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn build_state() -> Result<Arc<AppState>, Box<dyn Error>> {
    let data = PathBuf::from(env("KITTYPASS_DATA", "./data"));
    std::fs::create_dir_all(&data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))?;
    }
    let keys = ServerKeys::load_or_create(&data.join("secret.key"))?;
    let conn = Connection::open(data.join("kittypass.db"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    let trusted_proxies = env("KITTYPASS_TRUSTED_PROXIES", "")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let config = Config {
        trusted_proxies,
        require_2fa: env("KITTYPASS_REQUIRE_2FA", "false") == "true",
        ..Config::default()
    };
    Ok(Arc::new(AppState::new(conn, keys, Arc::new(SystemClock), config)?))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().with_target(false).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("--version" | "-V" | "version")) {
        println!("kittypass-server {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let state = build_state()?;

    match args.first().map(String::as_str) {
        None | Some("serve") => serve(state).await?,
        Some("invite") => {
            let admin = args.iter().any(|a| a == "--admin");
            let hours = args.iter().skip(1).find_map(|a| a.parse::<i64>().ok()).unwrap_or(72);
            let code = new_invite(&state.db(), &state, admin, hours)?;
            println!("{code}");
            eprintln!("Invitation{} valable {hours} h.", if admin { " ADMIN" } else { "" });
        }
        Some("users") => {
            let conn = state.db();
            let mut stmt = conn.prepare(
                "SELECT username, is_admin, totp_secret IS NOT NULL, disabled FROM users ORDER BY username",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?, r.get::<_, bool>(2)?, r.get::<_, bool>(3)?))
            })?;
            println!("{:<32} admin  2fa  désactivé", "utilisateur");
            for row in rows {
                let (u, a, t, d) = row?;
                println!("{u:<32} {a:<6} {t:<4} {d}");
            }
        }
        Some(cmd @ ("disable" | "enable")) => {
            let user = args.get(1).ok_or("nom d'utilisateur manquant")?;
            let conn = state.db();
            let disabled = cmd == "disable";
            let n = conn.execute(
                "UPDATE users SET disabled = ?1 WHERE username = ?2",
                rusqlite::params![disabled, user.to_ascii_lowercase()],
            )?;
            if n == 0 {
                return Err("utilisateur introuvable".into());
            }
            if disabled {
                conn.execute(
                    "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?1)",
                    [user.to_ascii_lowercase()],
                )?;
                conn.execute(
                    "DELETE FROM trusted_devices WHERE user_id = (SELECT id FROM users WHERE username = ?1)",
                    [user.to_ascii_lowercase()],
                )?;
            }
            eprintln!("OK");
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}

async fn serve(state: Arc<AppState>) -> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = env("KITTYPASS_BIND", "127.0.0.1:8080").parse()?;

    let purge_state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            tick.tick().await;
            if let Err(e) = db::purge_expired(&purge_state.db(), purge_state.now()) {
                tracing::error!("purge : {e}");
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("KittyPass écoute sur {bind}");
    let app = router(state);
    // Défense en profondeur (Caddy le fait aussi devant) : en-têtes reçus en
    // 10 s au plus et 64 Kio au plus, nombre de connexions borné. Sans cela,
    // des connexions lentes (« slowloris ») resteraient ouvertes sans fin.
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(64 * 1024);
    builder.http2().timer(TokioTimer::new()).max_header_list_size(64 * 1024).keep_alive_interval(Duration::from_secs(30));
    let builder = Arc::new(builder);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            _ = &mut shutdown => break,
            p = slots.clone().acquire_owned() => p?,
        };
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("accept : {e}");
                    continue;
                }
            },
        };
        let app = app.clone();
        let builder = builder.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                let mut app = app.clone();
                async move { app.call(req).await }
            });
            // Connexion entière (requêtes comprises) : 10 minutes au plus.
            let conn = builder.serve_connection(TokioIo::new(stream), svc);
            let _ = tokio::time::timeout(Duration::from_secs(600), conn).await;
            drop(permit);
        });
    }
    Ok(())
}
