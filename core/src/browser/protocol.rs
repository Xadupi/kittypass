//! Messages du protocole KeePassXC-Browser : enveloppe JSON, codes
//! d'erreur et construction des réponses chiffrées.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::crypto::{Nonce, Session, decode_nonce, increment_nonce};
use crate::{Error, Result};

/// Version annoncée à l'extension : celle de KeePassXC dont on reproduit le
/// comportement. En dessous de 2.7.7, l'extension désactive les passkeys.
pub const VERSION: &str = "2.7.10";

/// Taille maximale d'un message natif (limite des navigateurs vers l'hôte).
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Codes d'erreur compris par l'extension (`kpErrors`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    Unknown = 0,
    DatabaseNotOpened = 1,
    DatabaseHashNotReceived = 2,
    ClientPublicKeyNotReceived = 3,
    CannotDecryptMessage = 4,
    Timeout = 5,
    ActionCancelledOrDenied = 6,
    PublicKeyNotFound = 7,
    AssociationFailed = 8,
    KeyChangeFailed = 9,
    EncryptionKeyUnrecognized = 10,
    NoSavedDatabasesFound = 11,
    IncorrectAction = 12,
    EmptyMessageReceived = 13,
    NoUrlProvided = 14,
    NoLoginsFound = 15,
    NoGroupsFound = 16,
    CannotCreateNewGroup = 17,
    NoValidUuidProvided = 18,
    AccessToAllEntriesDenied = 19,
    PasskeysAttestationNotSupported = 20,
    PasskeysCredentialIsExcluded = 21,
    PasskeysRequestCanceled = 22,
    PasskeysInvalidUserVerification = 23,
    PasskeysEmptyPublicKey = 24,
    PasskeysInvalidUrlProvided = 25,
    PasskeysOriginNotAllowed = 26,
    PasskeysDomainIsNotValid = 27,
    PasskeysDomainRpIdMismatch = 28,
    PasskeysNoSupportedAlgorithms = 29,
    PasskeysWaitForLifetimer = 30,
    PasskeysUnknownError = 31,
    PasskeysInvalidChallenge = 32,
    PasskeysInvalidUserId = 33,
}

impl ErrorCode {
    /// Texte d'erreur (l'extension affiche plutôt sa propre traduction).
    pub fn message(self) -> &'static str {
        use ErrorCode::*;
        match self {
            DatabaseNotOpened => "Database not opened",
            DatabaseHashNotReceived => "Database hash not available",
            ClientPublicKeyNotReceived => "Client public key not received",
            CannotDecryptMessage => "Cannot decrypt message",
            ActionCancelledOrDenied => "Action cancelled or denied",
            PublicKeyNotFound => "Message encryption failed",
            AssociationFailed => "KeePassXC association failed, try again",
            EncryptionKeyUnrecognized => "Encryption key is not recognized",
            IncorrectAction => "Incorrect action",
            EmptyMessageReceived => "Empty message received",
            NoUrlProvided => "No URL provided",
            NoLoginsFound => "No logins found",
            NoGroupsFound => "No groups found",
            CannotCreateNewGroup => "Cannot create new group",
            NoValidUuidProvided => "No valid UUID provided",
            AccessToAllEntriesDenied => "Access to all entries is denied",
            _ => "Unknown error",
        }
    }
}

/// Enveloppe d'une requête de l'extension (non chiffrée).
#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub action: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(rename = "clientID", default)]
    pub client_id: Option<String>,
    #[serde(rename = "requestID", default)]
    pub request_id: Option<String>,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,
    #[serde(rename = "triggerUnlock", default)]
    pub trigger_unlock: Option<Value>,
}

impl Envelope {
    /// Lit une enveloppe JSON, bornée en taille.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_MESSAGE_BYTES {
            return Err(Error::TooLarge);
        }
        serde_json::from_slice(raw).map_err(|_| Error::InvalidArgument("requête illisible"))
    }

    pub fn wants_unlock(&self) -> bool {
        matches!(&self.trigger_unlock, Some(Value::String(s)) if s == "true") || self.trigger_unlock == Some(Value::Bool(true))
    }

    pub fn nonce(&self) -> Result<Nonce> {
        decode_nonce(self.nonce.as_deref().ok_or(Error::InvalidArgument("nonce absent"))?)
    }
}

/// Réponse d'erreur, en clair (l'extension l'associe à la requête par son
/// action, faute de nonce).
pub fn error_reply(action: &str, code: ErrorCode) -> Value {
    json!({ "action": action, "errorCode": (code as u8).to_string(), "error": code.message() })
}

/// Réponse à `change-public-keys`, la seule non chiffrée.
pub fn key_exchange_reply(session: &Session, request_nonce: &Nonce) -> Value {
    json!({
        "action": "change-public-keys",
        "version": VERSION,
        "publicKey": session.public_key_b64(),
        "nonce": B64.encode(increment_nonce(request_nonce)),
        "success": "true",
    })
}

/// Réponse chiffrée : ajoute `version`, `success` et le nonce incrémenté au
/// contenu, chiffré avec ce même nonce.
pub fn encrypted_reply(
    session: &Session,
    action: &str,
    request_nonce: &Nonce,
    request_id: Option<&str>,
    mut inner: Map<String, Value>,
) -> Result<Value> {
    let nonce = increment_nonce(request_nonce);
    let nonce_b64 = B64.encode(nonce);
    inner.insert("version".into(), VERSION.into());
    inner.insert("success".into(), "true".into());
    inner.insert("nonce".into(), nonce_b64.clone().into());
    let plain = Zeroizing::new(serde_json::to_vec(&Value::Object(inner)).map_err(|_| Error::Save)?);
    let message = session.encrypt(&plain, &nonce)?;
    let mut out = json!({ "action": action, "message": message, "nonce": nonce_b64 });
    if let Some(id) = request_id {
        out["requestID"] = id.into();
    }
    if serde_json::to_vec(&out).map(|v| v.len()).unwrap_or(usize::MAX) > MAX_MESSAGE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Message non sollicité (`database-locked`, `database-unlocked`), en
/// clair comme chez KeePassXC : il ne contient rien d'autre que l'action.
pub fn notification(action: &str) -> Value {
    json!({ "action": action })
}

/// Déchiffre le contenu d'une requête et vérifie que son action est celle
/// de l'enveloppe (sinon une requête chiffrée pourrait être « relabellisée »).
pub fn open_request(session: &mut Session, env: &Envelope) -> Result<Map<String, Value>> {
    let nonce = env.nonce()?;
    let message = env.message.as_deref().ok_or(Error::InvalidArgument("message absent"))?;
    let plain = session.decrypt(message, &nonce)?;
    let value: Value = serde_json::from_slice(&plain).map_err(|_| Error::InvalidArgument("message illisible"))?;
    let Value::Object(map) = value else { return Err(Error::InvalidArgument("message illisible")) };
    match map.get("action").and_then(Value::as_str) {
        Some(a) if a == env.action => Ok(map),
        _ => Err(Error::InvalidArgument("action incohérente")),
    }
}

/// Champ texte d'un message déchiffré.
pub fn str_field<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}

/// Clés envoyées par l'extension (`keys: [{id, key}]`), bornées.
pub fn keys_field(m: &Map<String, Value>) -> Vec<(String, String)> {
    m.get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(64)
        .filter_map(|k| Some((k.get("id")?.as_str()?.to_owned(), k.get("key")?.as_str()?.to_owned())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let mut host = Session::new().unwrap();
        let mut ext = Session::new().unwrap();
        host.set_peer(&ext.public_key_b64()).unwrap();
        ext.set_peer(&host.public_key_b64()).unwrap();
        (host, ext)
    }

    fn request(ext: &Session, action: &str, body: Value) -> (Envelope, Nonce) {
        let n = super::super::crypto::random_nonce().unwrap();
        let msg = ext.encrypt(body.to_string().as_bytes(), &n).unwrap();
        let raw = json!({"action": action, "message": msg, "nonce": B64.encode(n), "clientID": "c"}).to_string();
        (Envelope::parse(raw.as_bytes()).unwrap(), n)
    }

    #[test]
    fn reply_carries_incremented_nonce_inside_and_out() {
        let (mut host, mut ext) = pair();
        let (env, n) = request(&ext, "get-databasehash", json!({"action": "get-databasehash"}));
        let m = open_request(&mut host, &env).unwrap();
        assert_eq!(str_field(&m, "action"), Some("get-databasehash"));
        let mut inner = Map::new();
        inner.insert("hash".into(), "abc".into());
        let r = encrypted_reply(&host, "get-databasehash", &n, Some("r1"), inner).unwrap();
        let inc = B64.encode(increment_nonce(&n));
        assert_eq!(r["nonce"], inc);
        assert_eq!(r["requestID"], "r1");
        let plain = ext.decrypt(r["message"].as_str().unwrap(), &increment_nonce(&n)).unwrap();
        let v: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["nonce"], inc);
        assert_eq!(v["success"], "true");
        assert_eq!(v["version"], VERSION);
        assert_eq!(v["hash"], "abc");
    }

    #[test]
    fn relabelled_or_replayed_requests_fail() {
        let (mut host, ext) = pair();
        let (mut env, _) = request(&ext, "get-logins", json!({"action": "get-logins"}));
        env.action = "set-login".into();
        assert!(open_request(&mut host, &env).is_err());
        let (env, _) = request(&ext, "get-logins", json!({"action": "get-logins"}));
        open_request(&mut host, &env).unwrap();
        assert!(open_request(&mut host, &env).is_err(), "rejeu accepté");
        let (env, _) = request(&ext, "get-logins", json!(["pas", "un", "objet"]));
        assert!(open_request(&mut host, &env).is_err());
    }

    #[test]
    fn error_reply_has_no_nonce() {
        let e = error_reply("get-logins", ErrorCode::NoLoginsFound);
        assert_eq!(e["errorCode"], "15");
        assert!(e.get("nonce").is_none());
    }

    #[test]
    fn oversized_envelope_is_refused() {
        let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(Envelope::parse(&big), Err(Error::TooLarge)));
        assert!(Envelope::parse(b"{\"action\": 3}").is_err());
    }

    #[test]
    fn keys_are_bounded() {
        let keys: Vec<Value> = (0..500).map(|i| json!({"id": format!("k{i}"), "key": "x"})).collect();
        let m = json!({"keys": keys}).as_object().unwrap().clone();
        assert_eq!(keys_field(&m).len(), 64);
    }
}
