use rusqlite::Connection;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id               TEXT PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    is_admin         INTEGER NOT NULL DEFAULT 0,
    kdf_salt         BLOB NOT NULL,
    kdf_memory_kib   INTEGER NOT NULL,
    kdf_iterations   INTEGER NOT NULL,
    kdf_parallelism  INTEGER NOT NULL,
    auth_salt        BLOB NOT NULL,
    auth_hash        BLOB NOT NULL,
    totp_secret      BLOB,
    totp_pending     BLOB,
    totp_last_step   INTEGER,
    failed_logins    INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER NOT NULL DEFAULT 0,
    disabled         INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    code_hash   BLOB PRIMARY KEY,
    is_admin    INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL,
    used_by     TEXT
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BLOB NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- Une session = un appareil connecté = une famille de jetons de rafraîchissement.
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    hash        BLOB PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_session ON tokens(session_id);

CREATE TABLE IF NOT EXISTS vaults (
    id          TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS vaults_owner ON vaults(owner_id);

CREATE TABLE IF NOT EXISTS vault_versions (
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    data        BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    session_id  TEXT,
    PRIMARY KEY (vault_id, version)
);

-- Appareils de confiance : après une connexion avec la 2FA, l'appareil reçoit
-- un jeton qui remplace le code aux connexions suivantes (renouvelé à chaque
-- usage, oublié après un an sans usage ou quand la session est révoquée).
CREATE TABLE IF NOT EXISTS trusted_devices (
    hash        BLOB PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_used   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS trusted_devices_user ON trusted_devices(user_id);

CREATE TABLE IF NOT EXISTS audit (
    ts       INTEGER NOT NULL,
    user_id  TEXT,
    event    TEXT NOT NULL,
    ip       TEXT
);
"#;

/// Durée de vie d'un appareil de confiance sans connexion : un an.
pub const TRUST_TTL: i64 = 365 * 24 * 3600;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA secure_delete = ON;",
    )?;
    conn.execute_batch(SCHEMA)
}

/// Purge des jetons et invitations expirés (tâche périodique).
pub fn purge_expired(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM tokens WHERE expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM sessions WHERE id NOT IN (SELECT session_id FROM tokens)", [])?;
    conn.execute("DELETE FROM trusted_devices WHERE last_used <= ?1", [now - TRUST_TTL])?;
    conn.execute("DELETE FROM invites WHERE expires_at <= ?1 AND used_by IS NULL", [now])?;
    conn.execute("DELETE FROM audit WHERE ts <= ?1", [now - 365 * 24 * 3600])?;
    Ok(())
}

pub fn audit(conn: &Connection, now: i64, user_id: Option<&str>, event: &str, ip: &str) {
    if let Err(e) = conn.execute(
        "INSERT INTO audit (ts, user_id, event, ip) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![now, user_id, event, ip],
    ) {
        tracing::error!("journal d'audit : {e}");
    }
    tracing::info!(event, user_id, ip, "audit");
}
