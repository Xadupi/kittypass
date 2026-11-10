//! Dérivation de la clé d'authentification envoyée au serveur.
//!
//! ```text
//! master_key = Argon2id(mot_de_passe, sel_compte, params)
//! auth_key   = HKDF-SHA256(master_key, info = "kittypass/auth/v1")
//! ```
//!
//! Les paramètres viennent du serveur (pré-login). Un serveur malveillant
//! pourrait envoyer des paramètres très faibles pour rendre `auth_key` facile à
//! casser, ou énormes pour bloquer l'appareil : ils sont donc bornés ici,
//! côté client, et jamais crus aveuglément.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

const AUTH_INFO: &[u8] = b"kittypass/auth/v1";

/// Paramètres Argon2id de la clé de compte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Valeurs par défaut pour un nouveau compte (64 MiB, t=3, p=4).
    pub const DEFAULT: Self = Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 };

    /// Minimum accepté : recommandation OWASP (19 MiB, t=2).
    pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
    pub const MIN_ITERATIONS: u32 = 2;
    /// Maximum accepté : au-delà, un téléphone peut manquer de mémoire.
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    pub const MAX_ITERATIONS: u32 = 20;
    pub const MAX_PARALLELISM: u32 = 16;

    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::MIN_MEMORY_KIB {
            return Err(Error::KdfOutOfBounds("mémoire trop faible"));
        }
        if self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(Error::KdfOutOfBounds("mémoire trop élevée"));
        }
        if self.iterations < Self::MIN_ITERATIONS {
            return Err(Error::KdfOutOfBounds("itérations trop faibles"));
        }
        if self.iterations > Self::MAX_ITERATIONS {
            return Err(Error::KdfOutOfBounds("itérations trop élevées"));
        }
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(Error::KdfOutOfBounds("parallélisme invalide"));
        }
        Ok(())
    }
}

/// Clé envoyée au serveur pour s'authentifier. Effacée de la mémoire à la
/// destruction, et jamais affichée par `Debug`.
pub struct AuthKey(Zeroizing<[u8; 32]>);

impl AuthKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthKey(<masquée>)")
    }
}

pub const MIN_SALT_LEN: usize = 16;
pub const MAX_SALT_LEN: usize = 64;

/// Génère un sel de compte aléatoire (à l'inscription).
pub fn new_account_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    crate::rng::fill(&mut salt)?;
    Ok(salt)
}

pub fn derive_auth_key(password: &str, account_salt: &[u8], params: &KdfParams) -> Result<AuthKey> {
    if password.is_empty() {
        return Err(Error::InvalidArgument("mot de passe vide"));
    }
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&account_salt.len()) {
        return Err(Error::InvalidArgument("longueur de sel invalide"));
    }
    params.validate()?;

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
            .map_err(|_| Error::KdfOutOfBounds("paramètres Argon2 refusés"))?,
    );
    let mut master = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), account_salt, master.as_mut())
        .map_err(|_| Error::KdfOutOfBounds("échec Argon2"))?;

    let hk = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(AUTH_INFO, out.as_mut())
        .map_err(|_| Error::InvalidArgument("HKDF"))?;
    Ok(AuthKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Paramètres minimaux autorisés, pour que les tests restent rapides.
    const FAST: KdfParams = KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: 1,
    };
    const SALT: [u8; 16] = [7u8; 16];

    #[test]
    fn deterministic() {
        let a = derive_auth_key("correct horse", &SALT, &FAST).unwrap();
        let b = derive_auth_key("correct horse", &SALT, &FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn depends_on_password_salt_and_params() {
        let base = derive_auth_key("correct horse", &SALT, &FAST).unwrap();
        let other_pw = derive_auth_key("correct horsf", &SALT, &FAST).unwrap();
        let other_salt = derive_auth_key("correct horse", &[8u8; 16], &FAST).unwrap();
        let other_params =
            derive_auth_key("correct horse", &SALT, &KdfParams { iterations: 3, ..FAST }).unwrap();
        assert_ne!(base.as_bytes(), other_pw.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_params.as_bytes());
    }

    /// Recalcule la dérivation avec une **autre** implémentation d'Argon2
    /// (rust-argon2) et un HKDF écrit à la main avec HMAC (RFC 5869). Les deux
    /// chemins doivent donner exactement le même résultat.
    #[test]
    fn matches_independent_implementation() {
        use hmac::{KeyInit, Mac};
        let cfg = kdbx_argon2::Config {
            variant: kdbx_argon2::Variant::Argon2id,
            version: kdbx_argon2::Version::Version13,
            mem_cost: FAST.memory_kib,
            time_cost: FAST.iterations,
            lanes: FAST.parallelism,
            hash_length: 32,
            ..Default::default()
        };
        let master = kdbx_argon2::hash_raw(b"kittypass", &SALT, &cfg).unwrap();
        type H = hmac::Hmac<Sha256>;
        let prk = H::new_from_slice(&[0u8; 32]).unwrap().chain_update(&master).finalize().into_bytes();
        let okm = H::new_from_slice(&prk)
            .unwrap()
            .chain_update(b"kittypass/auth/v1\x01")
            .finalize()
            .into_bytes();
        let k = derive_auth_key("kittypass", &SALT, &FAST).unwrap();
        assert_eq!(k.as_bytes().as_slice(), okm.as_slice());
    }

    /// Vecteur figé : si ce test casse, tous les comptes existants deviennent
    /// inaccessibles. Ne jamais modifier la valeur attendue sans migration.
    #[test]
    fn known_answer_is_stable() {
        let k = derive_auth_key("kittypass", &SALT, &FAST).unwrap();
        let hex: String = k.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, KAT_HEX.trim());
    }
    const KAT_HEX: &str = include_str!("../tests/data/auth_kat.hex");

    #[test]
    fn auth_key_is_not_the_raw_argon_output() {
        // La clé envoyée ne doit pas être master_key elle-même : on recalcule
        // Argon2 seul et on vérifie que c'est différent.
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(FAST.memory_kib, FAST.iterations, FAST.parallelism, Some(32)).unwrap(),
        );
        let mut master = [0u8; 32];
        argon.hash_password_into(b"pw-test", &SALT, &mut master).unwrap();
        let k = derive_auth_key("pw-test", &SALT, &FAST).unwrap();
        assert_ne!(&master, k.as_bytes());
    }

    #[test]
    fn rejects_weak_params_from_malicious_server() {
        for p in [
            KdfParams { memory_kib: 8, ..FAST },
            KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB - 1, ..FAST },
            KdfParams { iterations: 1, ..FAST },
            KdfParams { iterations: 0, ..FAST },
            KdfParams { parallelism: 0, ..FAST },
        ] {
            assert!(
                matches!(derive_auth_key("x", &SALT, &p), Err(Error::KdfOutOfBounds(_))),
                "paramètres faibles acceptés : {p:?}"
            );
        }
    }

    #[test]
    fn rejects_huge_params_dos() {
        for p in [
            KdfParams { memory_kib: u32::MAX, ..FAST },
            KdfParams { iterations: u32::MAX, ..FAST },
            KdfParams { parallelism: u32::MAX, ..FAST },
        ] {
            assert!(matches!(derive_auth_key("x", &SALT, &p), Err(Error::KdfOutOfBounds(_))));
        }
    }

    #[test]
    fn rejects_bad_salt_and_empty_password() {
        assert!(derive_auth_key("x", &[], &FAST).is_err());
        assert!(derive_auth_key("x", &[0u8; 15], &FAST).is_err());
        assert!(derive_auth_key("x", &[0u8; 65], &FAST).is_err());
        assert!(derive_auth_key("", &SALT, &FAST).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let k = derive_auth_key("secret", &SALT, &FAST).unwrap();
        let dbg = format!("{k:?}");
        let hex: String = k.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex[..8]));
        assert_eq!(dbg, "AuthKey(<masquée>)");
    }

    #[test]
    fn salts_are_random() {
        assert_ne!(new_account_salt().unwrap(), new_account_salt().unwrap());
    }

    #[test]
    fn default_params_are_valid() {
        KdfParams::DEFAULT.validate().unwrap();
    }
}
