//! Primitives côté serveur : jetons, empreintes, chiffrement des secrets TOTP.

use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Clés du serveur, dérivées d'un unique secret maître stocké **hors** de la
/// base. Une fuite de la base seule ne donne donc ni les empreintes
/// exploitables, ni les secrets TOTP.
#[derive(Clone)]
pub struct ServerKeys {
    pepper: [u8; 32],
    totp_key: [u8; 32],
    fake_salt_key: [u8; 32],
}

impl std::fmt::Debug for ServerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerKeys(<masquées>)")
    }
}

impl ServerKeys {
    pub fn from_master(master: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"kittypass-server"), master);
        let mut k = Self { pepper: [0; 32], totp_key: [0; 32], fake_salt_key: [0; 32] };
        // Les longueurs sont fixes et valides : expand ne peut pas échouer.
        hk.expand(b"pepper/v1", &mut k.pepper).expect("hkdf");
        hk.expand(b"totp/v1", &mut k.totp_key).expect("hkdf");
        hk.expand(b"fake-salt/v1", &mut k.fake_salt_key).expect("hkdf");
        k
    }

    /// Lit le secret maître, ou le crée (permissions 0600) au premier lancement.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        let master: [u8; 32] = if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(std::io::Error::other(format!(
                        "{} est lisible par d'autres utilisateurs (mode {:o}) : chmod 600",
                        path.display(),
                        mode & 0o777
                    )));
                }
            }
            std::fs::read(path)?
                .try_into()
                .map_err(|_| std::io::Error::other("secret maître corrompu (32 octets attendus)"))?
        } else {
            let m = random_bytes::<32>();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            opts.open(path)?.write_all(&m)?;
            m
        };
        Ok(Self::from_master(&master))
    }

    /// Empreinte stockée de la clé d'authentification du client.
    /// `auth_key` a 256 bits d'entropie (sortie d'Argon2id côté client) : un
    /// HMAC avec poivre suffit, et évite qu'un attaquant épuise le CPU du
    /// serveur à coups de connexions.
    pub fn auth_hash(&self, salt: &[u8], auth_key: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.pepper).expect("hmac");
        m.update(&(salt.len() as u32).to_be_bytes());
        m.update(salt);
        m.update(auth_key);
        m.finalize().into_bytes().into()
    }

    /// Sel factice et stable pour un identifiant inexistant : le pré-login ne
    /// révèle pas si un compte existe.
    pub fn fake_salt(&self, username: &str) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.fake_salt_key).expect("hmac");
        m.update(username.as_bytes());
        m.finalize().into_bytes().into()
    }

    /// Chiffre un secret TOTP, lié à l'utilisateur (données associées) : on ne
    /// peut pas copier le secret chiffré d'un compte vers un autre.
    pub fn seal(&self, user_id: &str, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&self.totp_key.into());
        let nonce = random_bytes::<24>();
        let ct = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: user_id.as_bytes() })
            .expect("chiffrement");
        [nonce.as_slice(), &ct].concat()
    }

    pub fn open(&self, user_id: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 24 + 16 {
            return None;
        }
        let (nonce, ct) = sealed.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().ok()?;
        XChaCha20Poly1305::new(&self.totp_key.into())
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: user_id.as_bytes() })
            .ok()
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("générateur aléatoire du système indisponible");
    b
}

/// Jeton opaque de 256 bits.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Seule l'empreinte des jetons est stockée.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ServerKeys {
        ServerKeys::from_master(&[1u8; 32])
    }

    #[test]
    fn derived_keys_are_distinct() {
        let k = keys();
        assert_ne!(k.pepper, k.totp_key);
        assert_ne!(k.pepper, k.fake_salt_key);
        assert_ne!(k.totp_key, k.fake_salt_key);
    }

    #[test]
    fn auth_hash_depends_on_everything() {
        let k = keys();
        let h = k.auth_hash(b"salt", b"key");
        assert_ne!(h, k.auth_hash(b"salt", b"kez"));
        assert_ne!(h, k.auth_hash(b"salu", b"key"));
        assert_ne!(h, ServerKeys::from_master(&[2u8; 32]).auth_hash(b"salt", b"key"));
        // Le préfixe de longueur empêche (sel="ab", clé="c") == (sel="a", clé="bc").
        assert_ne!(k.auth_hash(b"ab", b"c"), k.auth_hash(b"a", b"bc"));
    }

    #[test]
    fn seal_roundtrip_and_binding() {
        let k = keys();
        let s = k.seal("alice", b"secret-totp");
        assert_eq!(k.open("alice", &s).unwrap(), b"secret-totp");
        assert!(k.open("bob", &s).is_none(), "secret transplantable d'un compte à l'autre");
        let mut t = s.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(k.open("alice", &t).is_none());
        assert!(k.open("alice", &s[..10]).is_none());
        assert!(ServerKeys::from_master(&[9; 32]).open("alice", &s).is_none());
        assert_ne!(k.seal("alice", b"x"), k.seal("alice", b"x"), "nonce réutilisé");
    }

    #[test]
    fn fake_salt_is_stable_and_per_user() {
        let k = keys();
        assert_eq!(k.fake_salt("eve"), k.fake_salt("eve"));
        assert_ne!(k.fake_salt("eve"), k.fake_salt("eva"));
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_token());
    }

    #[test]
    fn secret_file_permissions() {
        let dir = std::env::temp_dir().join(format!("vs-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret.key");
        let a = ServerKeys::load_or_create(&p).unwrap();
        let b = ServerKeys::load_or_create(&p).unwrap();
        assert_eq!(a.pepper, b.pepper, "le secret doit persister");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ServerKeys::load_or_create(&p).is_err(), "secret lisible par tous accepté");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn debug_hides_keys() {
        assert_eq!(format!("{:?}", keys()), "ServerKeys(<masquées>)");
    }
}
