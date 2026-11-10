//! Serveur KittyPass : comptes, sessions, 2FA, stockage versionné de fichiers
//! KDBX chiffrés. Le serveur ne voit jamais le contenu des coffres.
#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod ratelimit;
mod routes;
pub mod totp;

use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

pub use routes::{new_invite, rate_key, router};

pub struct AppState {
    db: Mutex<Connection>,
    pub keys: crypto::ServerKeys,
    pub clock: Arc<dyn clock::Clock>,
    pub limiter: ratelimit::Limiter,
    pub config: config::Config,
}

impl AppState {
    pub fn new(
        conn: Connection,
        keys: crypto::ServerKeys,
        clock: Arc<dyn clock::Clock>,
        config: config::Config,
    ) -> rusqlite::Result<Self> {
        db::migrate(&conn)?;
        Ok(Self { db: Mutex::new(conn), keys, clock, limiter: ratelimit::Limiter::default(), config })
    }

    /// Accès à la base. Un verrou empoisonné (panique dans un autre handler)
    /// n'empêche pas le service : SQLite reste cohérent grâce aux transactions.
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }
}
