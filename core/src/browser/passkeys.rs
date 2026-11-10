//! Passkeys (WebAuthn) au format de KeePassXC : KittyPass joue
//! l'authentificateur pour l'extension KeePassXC-Browser.
//!
//! Les clés sont stockées dans l'entrée comme le fait KeePassXC (attributs
//! `KPEX_PASSKEY_*`, clé privée PKCS#8 PEM protégée), donc une passkey créée
//! ici marche dans KeePassXC et inversement. Algorithmes : ES256 et EdDSA
//! (RSA écarté : la seule implémentation Rust pure a une faille de timing
//! connue, RUSTSEC-2023-0071).
//!
//! Vérifications faites avant toute signature :
//! - l'origine est en `https` (ou `http://localhost`) ;
//! - le RP ID est l'hôte de l'origine ou un de ses domaines parents, jamais
//!   un suffixe public (`com`, `github.io`…), sauf origine liée annoncée par
//!   le site (`/.well-known/webauthn`, lu par l'extension) ;
//! - défi d'au moins 16 octets, identifiant utilisateur de 1 à 64 octets.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ciborium::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::protocol::ErrorCode;
use crate::{
    rng,
    vault::{CustomField, EntryData},
};

/// AAGUID de KeePassXC : les sites qui affichent l'authentificateur
/// reconnaissent ainsi un gestionnaire compatible.
pub const AAGUID: [u8; 16] = [
    0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e, 0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02,
];

pub const ATTR_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const ATTR_PRIVATE_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const ATTR_RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const ATTR_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const ATTR_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";

const CREDENTIAL_ID_BYTES: usize = 32;
const MIN_CHALLENGE_BYTES: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 1024;
const MAX_USER_ID_BYTES: usize = 64;
const MAX_LISTED_CREDENTIALS: usize = 256;
const MAX_RELATED_ORIGINS: usize = 100;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

type Res<T> = std::result::Result<T, ErrorCode>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    EdDsa,
}

impl Alg {
    fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
        }
    }
}

/// Origine vérifiée d'une requête.
#[derive(Debug, Clone)]
struct Origin {
    /// Sérialisation normalisée (`https://exemple.fr`).
    text: String,
    host: String,
}

fn check_origin(origin: &str) -> Res<Origin> {
    let u = Url::parse(origin).map_err(|_| ErrorCode::PasskeysInvalidUrlProvided)?;
    let host = u.host_str().ok_or(ErrorCode::PasskeysInvalidUrlProvided)?.trim_end_matches('.').to_ascii_lowercase();
    let local = host == "localhost" || host.ends_with(".localhost");
    match u.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return Err(ErrorCode::PasskeysOriginNotAllowed),
    }
    Ok(Origin { text: u.origin().ascii_serialization(), host })
}

/// Nom de domaine ASCII valide (le RP ID n'a ni port, ni chemin).
fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// RP ID effectif : celui demandé (ou l'hôte de l'origine), vérifié.
fn check_rp_id(rp_id: Option<&str>, origin: &Origin, related: &[String]) -> Res<String> {
    let rp = match rp_id {
        Some(r) if !r.is_empty() => r.trim_end_matches('.').to_ascii_lowercase(),
        _ => origin.host.clone(),
    };
    if !valid_domain(&rp) {
        return Err(ErrorCode::PasskeysDomainIsNotValid);
    }
    // Un suffixe public n'est jamais un RP ID (sauf `localhost` exact, pour
    // le développement).
    let is_suffix = psl::suffix_str(&rp).is_none_or(|s| s == rp);
    if is_suffix && !(rp == "localhost" && origin.host == rp) {
        return Err(ErrorCode::PasskeysDomainIsNotValid);
    }
    let same_site = origin.host == rp || origin.host.ends_with(&format!(".{rp}"));
    if !same_site {
        let listed = related.iter().take(MAX_RELATED_ORIGINS).any(|r| check_origin(r).is_ok_and(|r| r.text == origin.text));
        if !listed {
            return Err(ErrorCode::PasskeysDomainRpIdMismatch);
        }
    }
    Ok(rp)
}

fn b64url(v: &Value, err: ErrorCode, min: usize, max: usize) -> Res<Vec<u8>> {
    let s = v.as_str().ok_or(err)?;
    let bytes = B64URL.decode(s.trim_end_matches('=')).map_err(|_| err)?;
    (min..=max).contains(&bytes.len()).then_some(bytes).ok_or(err)
}

fn text(v: &Value, max: usize) -> String {
    v.as_str().unwrap_or_default().chars().take(max).collect()
}

/// Identifiants de credential listés par le site (exclusion ou autorisation).
fn credential_list(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .take(MAX_LISTED_CREDENTIALS)
        .filter(|c| c.get("type").and_then(Value::as_str).is_none_or(|t| t == "public-key"))
        .filter_map(|c| c.get("id")?.as_str().map(|s| s.trim_end_matches('=').to_owned()))
        .collect()
}

/// Demande de création vérifiée, prête à être confirmée par l'utilisateur.
#[derive(Debug, Clone)]
pub struct CreatePlan {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// Identifiant utilisateur du site, base64url.
    pub user_handle: String,
    /// Credentials déjà connus du site pour ce compte : en créer une de plus
    /// pour l'un d'eux est refusé (`excludeCredentials`).
    pub exclude: Vec<String>,
    challenge: String,
    origin: String,
    alg: Alg,
    cred_props: bool,
}

pub fn plan_create(options: &Value, origin: &str, related: &[String]) -> Res<CreatePlan> {
    if !options.is_object() {
        return Err(ErrorCode::PasskeysEmptyPublicKey);
    }
    let origin = check_origin(origin)?;
    let rp = options.get("rp").ok_or(ErrorCode::PasskeysEmptyPublicKey)?;
    let rp_id = check_rp_id(rp.get("id").and_then(Value::as_str), &origin, related)?;
    let challenge = b64url(&options["challenge"], ErrorCode::PasskeysInvalidChallenge, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES)?;
    let user = options.get("user").ok_or(ErrorCode::PasskeysInvalidUserId)?;
    let user_id = b64url(&user["id"], ErrorCode::PasskeysInvalidUserId, 1, MAX_USER_ID_BYTES)?;
    let params = options.get("pubKeyCredParams").and_then(Value::as_array).cloned().unwrap_or_default();
    let alg = if params.is_empty() {
        Alg::Es256
    } else {
        params
            .iter()
            .filter(|p| p.get("type").and_then(Value::as_str).is_none_or(|t| t == "public-key"))
            .find_map(|p| match p.get("alg").and_then(Value::as_i64) {
                Some(-7) => Some(Alg::Es256),
                Some(-8) => Some(Alg::EdDsa),
                _ => None,
            })
            .ok_or(ErrorCode::PasskeysNoSupportedAlgorithms)?
    };
    let cred_props = options.pointer("/extensions/credProps").and_then(Value::as_bool).unwrap_or(false);
    let user_name = text(&user["name"], 256);
    Ok(CreatePlan {
        rp_name: match text(&rp["name"], 256) {
            n if n.is_empty() => rp_id.clone(),
            n => n,
        },
        rp_id,
        user_display_name: match text(&user["displayName"], 256) {
            n if n.is_empty() => user_name.clone(),
            n => n,
        },
        user_name,
        user_handle: B64URL.encode(user_id),
        exclude: credential_list(&options["excludeCredentials"]),
        challenge: B64URL.encode(challenge),
        origin: origin.text,
        alg,
        cred_props,
    })
}

/// Demande d'authentification vérifiée.
#[derive(Debug, Clone)]
pub struct GetPlan {
    pub rp_id: String,
    /// Credentials acceptés par le site ; vide = toutes celles du RP.
    pub allow: Vec<String>,
    challenge: String,
    origin: String,
}

pub fn plan_get(options: &Value, origin: &str, related: &[String]) -> Res<GetPlan> {
    if !options.is_object() {
        return Err(ErrorCode::PasskeysEmptyPublicKey);
    }
    let origin = check_origin(origin)?;
    let rp_id = check_rp_id(options.get("rpId").and_then(Value::as_str), &origin, related)?;
    let challenge = b64url(&options["challenge"], ErrorCode::PasskeysInvalidChallenge, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES)?;
    Ok(GetPlan { rp_id, allow: credential_list(&options["allowCredentials"]), challenge: B64URL.encode(challenge), origin: origin.text })
}

impl GetPlan {
    /// La passkey stockée peut-elle répondre à cette demande ?
    pub fn accepts(&self, p: &Passkey) -> bool {
        p.rp_id == self.rp_id && (self.allow.is_empty() || self.allow.contains(&p.credential_id))
    }
}

/// Passkey telle que stockée dans une entrée.
#[derive(Clone)]
pub struct Passkey {
    pub credential_id: String,
    pub private_key_pem: Zeroizing<String>,
    pub rp_id: String,
    pub username: String,
    pub user_handle: String,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("credential_id", &self.credential_id)
            .field("rp_id", &self.rp_id)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Passkey {
    /// Lit la passkey d'une entrée, si elle en a une.
    pub fn from_entry(d: &EntryData) -> Option<Self> {
        let get = |k: &str| d.custom.iter().find(|c| c.key == k).map(|c| c.value.as_str());
        Some(Self {
            credential_id: get(ATTR_CREDENTIAL_ID)?.trim_end_matches('=').to_owned(),
            private_key_pem: Zeroizing::new(get(ATTR_PRIVATE_KEY)?.to_owned()),
            rp_id: get(ATTR_RELYING_PARTY)?.to_owned(),
            username: get(ATTR_USERNAME).unwrap_or_default().to_owned(),
            user_handle: get(ATTR_USER_HANDLE).unwrap_or_default().trim_end_matches('=').to_owned(),
        })
    }

    /// Attributs à écrire dans l'entrée (format KeePassXC).
    pub fn fields(&self) -> Vec<CustomField> {
        let f = |key: &str, value: &str, protected| CustomField { key: key.into(), value: Zeroizing::new(value.into()), protected };
        vec![
            f(ATTR_CREDENTIAL_ID, &self.credential_id, false),
            f(ATTR_PRIVATE_KEY, &self.private_key_pem, true),
            f(ATTR_RELYING_PARTY, &self.rp_id, false),
            f(ATTR_USERNAME, &self.username, false),
            f(ATTR_USER_HANDLE, &self.user_handle, false),
        ]
    }

    /// Entrée complète pour une nouvelle passkey.
    pub fn entry_data(&self, title: &str) -> EntryData {
        EntryData {
            title: title.to_owned(),
            username: self.username.clone(),
            url: format!("https://{}", self.rp_id),
            custom: self.fields(),
            ..Default::default()
        }
    }
}

enum Key {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

impl Key {
    fn generate(alg: Alg) -> Res<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        match alg {
            Alg::Es256 => loop {
                rng::fill(seed.as_mut()).map_err(|_| ErrorCode::PasskeysUnknownError)?;
                // Rejet des scalaires hors intervalle (probabilité ~2^-32).
                if let Ok(k) = p256::ecdsa::SigningKey::from_slice(seed.as_ref()) {
                    return Ok(Key::Es256(k));
                }
            },
            Alg::EdDsa => {
                rng::fill(seed.as_mut()).map_err(|_| ErrorCode::PasskeysUnknownError)?;
                Ok(Key::EdDsa(ed25519_dalek::SigningKey::from_bytes(&seed)))
            }
        }
    }

    fn from_pem(pem: &str) -> Res<Self> {
        use p256::pkcs8::DecodePrivateKey;
        if let Ok(k) = p256::SecretKey::from_pkcs8_pem(pem) {
            return Ok(Key::Es256(k.into()));
        }
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem).map(Key::EdDsa).map_err(|_| ErrorCode::PasskeysUnknownError)
    }

    fn to_pem(&self) -> Res<Zeroizing<String>> {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        match self {
            Key::Es256(k) => p256::SecretKey::from(k).to_pkcs8_pem(LineEnding::LF),
            Key::EdDsa(k) => k.to_pkcs8_pem(LineEnding::LF),
        }
        .map_err(|_| ErrorCode::PasskeysUnknownError)
    }

    fn alg(&self) -> Alg {
        match self {
            Key::Es256(_) => Alg::Es256,
            Key::EdDsa(_) => Alg::EdDsa,
        }
    }

    /// Clé publique COSE (RFC 9053), clés en ordre canonique CTAP2.
    fn cose(&self) -> Vec<u8> {
        let i = |n: i64| Cbor::Integer(n.into());
        let map = match self {
            Key::Es256(k) => {
                let p = k.verifying_key().to_sec1_point(false);
                vec![
                    (i(1), i(2)),
                    (i(3), i(-7)),
                    (i(-1), i(1)),
                    (i(-2), Cbor::Bytes(p.x().map(|x| x.to_vec()).unwrap_or_default())),
                    (i(-3), Cbor::Bytes(p.y().map(|y| y.to_vec()).unwrap_or_default())),
                ]
            }
            Key::EdDsa(k) => vec![(i(1), i(1)), (i(3), i(-8)), (i(-1), i(6)), (i(-2), Cbor::Bytes(k.verifying_key().to_bytes().to_vec()))],
        };
        cbor(&Cbor::Map(map))
    }

    /// Clé publique SubjectPublicKeyInfo (DER), pour `getPublicKey()`.
    fn spki(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        match self {
            Key::Es256(k) => k.verifying_key().to_public_key_der().map(|d| d.into_vec()),
            Key::EdDsa(k) => k.verifying_key().to_public_key_der().map(|d| d.into_vec()),
        }
        .unwrap_or_default()
    }

    /// Signature WebAuthn : ECDSA en DER, Ed25519 brute.
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        match self {
            Key::Es256(k) => {
                let s: p256::ecdsa::Signature = k.sign(msg);
                s.to_der().as_bytes().to_vec()
            }
            Key::EdDsa(k) => k.sign(msg).to_bytes().to_vec(),
        }
    }
}

fn cbor(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    // Écrire dans un Vec ne peut pas échouer.
    let _ = ciborium::into_writer(v, &mut out);
    out
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    // Ordre des champs de la spécification (certains serveurs le vérifient).
    let s = |x: &str| Value::String(x.to_owned()).to_string();
    format!("{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}", s(kind), s(challenge), s(origin)).into_bytes()
}

fn auth_data(rp_id: &str, flags: u8, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut d = Sha256::digest(rp_id.as_bytes()).to_vec();
    d.push(flags);
    // Compteur de signatures à 0 : la passkey est synchronisée entre
    // appareils, un compteur ne pourrait pas rester croissant.
    d.extend_from_slice(&0u32.to_be_bytes());
    if let Some((cred_id, cose)) = attested {
        d.extend_from_slice(&AAGUID);
        d.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        d.extend_from_slice(cred_id);
        d.extend_from_slice(cose);
    }
    d
}

/// Crée la passkey (après confirmation) : la passkey à enregistrer et la
/// réponse `PublicKeyCredential` (JSON) pour le site.
pub fn create(plan: &CreatePlan) -> Res<(Passkey, Value)> {
    let key = Key::generate(plan.alg)?;
    let mut cred_id = [0u8; CREDENTIAL_ID_BYTES];
    rng::fill(&mut cred_id).map_err(|_| ErrorCode::PasskeysUnknownError)?;
    let cdj = client_data("webauthn.create", &plan.challenge, &plan.origin);
    let cose = key.cose();
    let ad = auth_data(&plan.rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, Some((&cred_id, &cose)));
    let att = cbor(&Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(ad.clone())),
    ]));
    let id = B64URL.encode(cred_id);
    let mut ext = json!({});
    if plan.cred_props {
        ext["credProps"] = json!({ "rk": true });
    }
    let response = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": B64URL.encode(&cdj),
            "authenticatorData": B64URL.encode(&ad),
            "attestationObject": B64URL.encode(&att),
            "publicKey": B64URL.encode(key.spki()),
            "publicKeyAlgorithm": key.alg().cose(),
            "transports": ["internal", "hybrid"],
            "clientExtensionResults": ext,
        },
    });
    let passkey = Passkey {
        credential_id: id,
        private_key_pem: key.to_pem()?,
        rp_id: plan.rp_id.clone(),
        username: plan.user_name.clone(),
        user_handle: plan.user_handle.clone(),
    };
    Ok((passkey, response))
}

/// Signe une demande d'authentification avec la passkey choisie.
pub fn assert(plan: &GetPlan, passkey: &Passkey) -> Res<Value> {
    if !plan.accepts(passkey) {
        return Err(ErrorCode::PasskeysDomainRpIdMismatch);
    }
    let key = Key::from_pem(&passkey.private_key_pem)?;
    let cdj = client_data("webauthn.get", &plan.challenge, &plan.origin);
    let ad = auth_data(&plan.rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS, None);
    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig = key.sign(&signed);
    let mut response = json!({
        "clientDataJSON": B64URL.encode(&cdj),
        "authenticatorData": B64URL.encode(&ad),
        "signature": B64URL.encode(sig),
        "clientExtensionResults": {},
    });
    if !passkey.user_handle.is_empty() {
        response["userHandle"] = passkey.user_handle.clone().into();
    }
    Ok(json!({
        "id": passkey.credential_id,
        "rawId": passkey.credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> String {
        B64URL.encode([7u8; 32])
    }

    fn create_options(rp: &str, algs: &[i64]) -> Value {
        json!({
            "rp": {"id": rp, "name": "Exemple"},
            "user": {"id": B64URL.encode(b"user-1"), "name": "alice", "displayName": "Alice"},
            "challenge": challenge(),
            "pubKeyCredParams": algs.iter().map(|a| json!({"type": "public-key", "alg": a})).collect::<Vec<_>>(),
            "extensions": {"credProps": true},
        })
    }

    #[test]
    fn origin_and_rp_id_rules() {
        let ok = |o: &str, rp: &str| plan_create(&create_options(rp, &[-7]), o, &[]).map(|p| p.rp_id);
        assert_eq!(ok("https://example.com", "example.com").unwrap(), "example.com");
        assert_eq!(ok("https://login.example.com", "example.com").unwrap(), "example.com");
        assert_eq!(ok("https://example.com:8443", "example.com").unwrap(), "example.com");
        assert_eq!(ok("http://localhost:3000", "localhost").unwrap(), "localhost");
        assert_eq!(ok("http://example.com", "example.com").unwrap_err(), ErrorCode::PasskeysOriginNotAllowed);
        assert_eq!(ok("ftp://example.com", "example.com").unwrap_err(), ErrorCode::PasskeysOriginNotAllowed);
        assert_eq!(ok("pas une url", "example.com").unwrap_err(), ErrorCode::PasskeysInvalidUrlProvided);
        assert_eq!(ok("https://example.com", "other.com").unwrap_err(), ErrorCode::PasskeysDomainRpIdMismatch);
        assert_eq!(ok("https://example.com", "login.example.com").unwrap_err(), ErrorCode::PasskeysDomainRpIdMismatch);
        assert_eq!(ok("https://evilexample.com", "example.com").unwrap_err(), ErrorCode::PasskeysDomainRpIdMismatch);
        assert_eq!(ok("https://a.github.io", "github.io").unwrap_err(), ErrorCode::PasskeysDomainIsNotValid);
        assert_eq!(ok("https://a.co.uk", "co.uk").unwrap_err(), ErrorCode::PasskeysDomainIsNotValid);
        assert_eq!(ok("https://example.com", "com").unwrap_err(), ErrorCode::PasskeysDomainIsNotValid);
        assert_eq!(ok("https://example.com", "exa mple.com").unwrap_err(), ErrorCode::PasskeysDomainIsNotValid);
        assert_eq!(ok("https://example.com", "example.com:443").unwrap_err(), ErrorCode::PasskeysDomainIsNotValid);
        // RP ID absent : l'hôte de l'origine.
        let mut o = create_options("x", &[-7]);
        o["rp"].as_object_mut().unwrap().remove("id");
        assert_eq!(plan_create(&o, "https://www.example.com", &[]).unwrap().rp_id, "www.example.com");
    }

    #[test]
    fn related_origins_allow_cross_site_rp() {
        let o = create_options("example.com", &[-7]);
        let related = vec!["https://example.fr".to_owned()];
        assert_eq!(plan_create(&o, "https://example.fr", &related).unwrap().rp_id, "example.com");
        assert!(plan_create(&o, "https://example.de", &related).is_err());
        // Une origine liée en http ne vaut rien.
        assert!(plan_create(&o, "https://example.fr", &["http://example.fr".to_owned()]).is_err());
    }

    #[test]
    fn challenge_user_and_algorithms_are_checked() {
        let mut o = create_options("example.com", &[-7]);
        o["challenge"] = B64URL.encode([1u8; 8]).into();
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysInvalidChallenge);
        o["challenge"] = "%%%".into();
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysInvalidChallenge);
        let mut o = create_options("example.com", &[-7]);
        o["user"]["id"] = B64URL.encode([1u8; 65]).into();
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysInvalidUserId);
        o["user"]["id"] = "".into();
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysInvalidUserId);
        let o = create_options("example.com", &[-257, -37]);
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysNoSupportedAlgorithms);
        let o = create_options("example.com", &[-257, -8, -7]);
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap().alg, Alg::EdDsa);
        let o = create_options("example.com", &[]);
        assert_eq!(plan_create(&o, "https://example.com", &[]).unwrap().alg, Alg::Es256);
        assert_eq!(plan_create(&Value::Null, "https://example.com", &[]).unwrap_err(), ErrorCode::PasskeysEmptyPublicKey);
    }

    fn parse_auth_data(ad: &[u8]) -> (&[u8], u8, u32) {
        (&ad[..32], ad[32], u32::from_be_bytes(ad[33..37].try_into().unwrap()))
    }

    #[test]
    fn create_then_assert_es256_verifies() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let plan = plan_create(&create_options("example.com", &[-7]), "https://login.example.com", &[]).unwrap();
        let (pk, resp) = create(&plan).unwrap();
        assert!(pk.private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(resp["response"]["clientExtensionResults"]["credProps"]["rk"], true);
        let ad = B64URL.decode(resp["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        let (rp_hash, flags, count) = parse_auth_data(&ad);
        assert_eq!(rp_hash, Sha256::digest(b"example.com").as_slice());
        assert_eq!(flags, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        assert_eq!(count, 0);
        assert_eq!(&ad[37..53], &AAGUID);
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        assert_eq!(B64URL.encode(&ad[55..55 + cred_len]), pk.credential_id);
        let cose: Cbor = ciborium::from_reader(&ad[55 + cred_len..]).unwrap();
        assert!(matches!(cose, Cbor::Map(ref m) if m.len() == 5));
        // Objet d'attestation « none » lisible.
        let att: Cbor = ciborium::from_reader(
            B64URL.decode(resp["response"]["attestationObject"].as_str().unwrap()).unwrap().as_slice(),
        )
        .unwrap();
        let Cbor::Map(att) = att else { panic!() };
        assert_eq!(att[0], (Cbor::Text("fmt".into()), Cbor::Text("none".into())));
        let cdj: Value =
            serde_json::from_slice(&B64URL.decode(resp["response"]["clientDataJSON"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(cdj["type"], "webauthn.create");
        assert_eq!(cdj["origin"], "https://login.example.com");
        assert_eq!(cdj["challenge"], challenge());

        // Assertion, vérifiée avec la clé publique renvoyée à la création.
        let get = plan_get(&json!({"rpId": "example.com", "challenge": challenge()}), "https://example.com", &[]).unwrap();
        let a = assert(&get, &pk).unwrap();
        let spki = B64URL.decode(resp["response"]["publicKey"].as_str().unwrap()).unwrap();
        use p256::pkcs8::DecodePublicKey;
        let vk = VerifyingKey::from_public_key_der(&spki).unwrap();
        let ad = B64URL.decode(a["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        let cdj = B64URL.decode(a["response"]["clientDataJSON"].as_str().unwrap()).unwrap();
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig = Signature::from_der(&B64URL.decode(a["response"]["signature"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(&signed, &sig).unwrap();
        assert_eq!(parse_auth_data(&ad).1, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
        assert_eq!(a["response"]["userHandle"], B64URL.encode(b"user-1"));
        // Le défi est bien lié à la signature.
        signed[40] ^= 1;
        assert!(vk.verify(&signed, &sig).is_err());
    }

    #[test]
    fn create_then_assert_eddsa_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey, pkcs8::DecodePublicKey};
        let plan = plan_create(&create_options("example.com", &[-8]), "https://example.com", &[]).unwrap();
        let (pk, resp) = create(&plan).unwrap();
        assert_eq!(resp["response"]["publicKeyAlgorithm"], -8);
        let vk = VerifyingKey::from_public_key_der(&B64URL.decode(resp["response"]["publicKey"].as_str().unwrap()).unwrap()).unwrap();
        let get = plan_get(&json!({"challenge": challenge()}), "https://example.com", &[]).unwrap();
        let a = assert(&get, &pk).unwrap();
        let mut signed = B64URL.decode(a["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        signed.extend_from_slice(&Sha256::digest(B64URL.decode(a["response"]["clientDataJSON"].as_str().unwrap()).unwrap()));
        let sig = Signature::from_slice(&B64URL.decode(a["response"]["signature"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(&signed, &sig).unwrap();
    }

    #[test]
    fn passkey_is_bound_to_its_rp_and_allow_list() {
        let plan = plan_create(&create_options("example.com", &[-7]), "https://example.com", &[]).unwrap();
        let (pk, _) = create(&plan).unwrap();
        let other = plan_get(&json!({"challenge": challenge()}), "https://other.com", &[]).unwrap();
        assert!(!other.accepts(&pk));
        assert_eq!(assert(&other, &pk).unwrap_err(), ErrorCode::PasskeysDomainRpIdMismatch);
        let allow_other = plan_get(
            &json!({"challenge": challenge(), "allowCredentials": [{"type": "public-key", "id": "AAAA"}]}),
            "https://example.com",
            &[],
        )
        .unwrap();
        assert!(!allow_other.accepts(&pk));
        let allow_it = plan_get(
            &json!({"challenge": challenge(), "allowCredentials": [{"type": "public-key", "id": pk.credential_id}]}),
            "https://example.com",
            &[],
        )
        .unwrap();
        assert!(allow_it.accepts(&pk));
    }

    #[test]
    fn stored_round_trip_through_entry_fields() {
        let plan = plan_create(&create_options("example.com", &[-7]), "https://example.com", &[]).unwrap();
        let (pk, _) = create(&plan).unwrap();
        let d = pk.entry_data("Exemple");
        assert!(d.custom.iter().find(|c| c.key == ATTR_PRIVATE_KEY).unwrap().protected);
        let back = Passkey::from_entry(&d).unwrap();
        assert_eq!(back.credential_id, pk.credential_id);
        assert_eq!(back.rp_id, "example.com");
        assert_eq!(back.username, "alice");
        // Le Debug ne montre pas la clé privée.
        assert!(!format!("{back:?}").contains("PRIVATE"));
        // Clé privée abîmée : erreur, pas de panique.
        let mut broken = back.clone();
        broken.private_key_pem = Zeroizing::new("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into());
        let get = plan_get(&json!({"challenge": challenge()}), "https://example.com", &[]).unwrap();
        assert_eq!(assert(&get, &broken).unwrap_err(), ErrorCode::PasskeysUnknownError);
    }

    #[test]
    fn client_data_escapes_origin() {
        let c = client_data("webauthn.get", "abc", "https://x\"y");
        let v: Value = serde_json::from_slice(&c).unwrap();
        assert_eq!(v["origin"], "https://x\"y");
    }
}
