//! Canal chiffré du protocole KeePassXC-Browser : NaCl `crypto_box`
//! (X25519 + XSalsa20-Poly1305), nonces de 24 octets, réponse chiffrée avec
//! le nonce de la requête incrémenté (comme `sodium_increment`).

use std::collections::{HashSet, VecDeque};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto_box::{PublicKey, SalsaBox, SecretKey, aead::Aead};
use zeroize::Zeroizing;

use crate::{Error, Result, rng};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Nonces déjà vus gardés par session, contre le rejeu d'une requête.
const MAX_SEEN_NONCES: usize = 4096;

pub type Nonce = [u8; NONCE_LEN];

/// Incrémente le nonce en petit-boutiste avec retenue (libsodium).
pub fn increment_nonce(nonce: &Nonce) -> Nonce {
    let mut out = *nonce;
    let mut carry: u16 = 1;
    for b in out.iter_mut() {
        carry += u16::from(*b);
        *b = carry as u8;
        carry >>= 8;
    }
    out
}

pub fn decode_nonce(b64: &str) -> Result<Nonce> {
    let bytes = B64.decode(b64).map_err(|_| Error::InvalidArgument("nonce illisible"))?;
    bytes.try_into().map_err(|_| Error::InvalidArgument("nonce de mauvaise longueur"))
}

pub fn decode_key(b64: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = Zeroizing::new(B64.decode(b64).map_err(|_| Error::InvalidArgument("clé illisible"))?);
    bytes.as_slice().try_into().map_err(|_| Error::InvalidArgument("clé de mauvaise longueur"))
}

/// Points d'ordre faible de Curve25519 (liste de libsodium), bit de poids
/// fort masqué : le secret partagé serait prévisible.
const LOW_ORDER: [[u8; KEY_LEN]; 7] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb,
        0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4,
        0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ],
];

fn is_low_order(key: &[u8; KEY_LEN]) -> bool {
    let mut k = *key;
    k[31] &= 0x7f;
    LOW_ORDER.contains(&k)
}

/// Clé publique au hasard (identifiants d'association, nonces de test).
pub fn random_key_b64() -> Result<String> {
    let mut k = [0u8; KEY_LEN];
    rng::fill(&mut k)?;
    Ok(B64.encode(k))
}

pub fn random_nonce() -> Result<Nonce> {
    let mut n = [0u8; NONCE_LEN];
    rng::fill(&mut n)?;
    Ok(n)
}

/// Session avec une instance de l'extension : notre paire de clés
/// éphémère, la clé publique de l'extension et les nonces déjà reçus.
pub struct Session {
    secret: SecretKey,
    peer: Option<(PublicKey, SalsaBox)>,
    seen: HashSet<Nonce>,
    seen_order: VecDeque<Nonce>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new().expect("aléa du système indisponible")
    }
}

impl Session {
    pub fn new() -> Result<Self> {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        rng::fill(k.as_mut())?;
        Ok(Self { secret: SecretKey::from_bytes(*k), peer: None, seen: HashSet::new(), seen_order: VecDeque::new() })
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.secret.public_key().as_bytes())
    }

    /// Clé publique de l'extension, si l'échange a eu lieu.
    pub fn peer_public_key_b64(&self) -> Option<String> {
        self.peer.as_ref().map(|(pk, _)| B64.encode(pk.as_bytes()))
    }

    pub fn has_peer(&self) -> bool {
        self.peer.is_some()
    }

    /// Clé publique de l'extension (`change-public-keys`). Une nouvelle clé
    /// remplace l'ancienne : l'extension en change à chaque redémarrage.
    pub fn set_peer(&mut self, public_key_b64: &str) -> Result<()> {
        let bytes = decode_key(public_key_b64)?;
        if is_low_order(&bytes) {
            return Err(Error::InvalidArgument("clé publique invalide"));
        }
        let pk = PublicKey::from_bytes(bytes);
        let b = SalsaBox::new(&pk, &self.secret);
        self.peer = Some((pk, b));
        self.seen.clear();
        self.seen_order.clear();
        Ok(())
    }

    /// Note un nonce de requête ; refuse un nonce déjà utilisé (rejeu).
    pub fn check_fresh(&mut self, nonce: &Nonce) -> Result<()> {
        if !self.seen.insert(*nonce) {
            return Err(Error::InvalidArgument("nonce déjà utilisé"));
        }
        self.seen_order.push_back(*nonce);
        if self.seen_order.len() > MAX_SEEN_NONCES
            && let Some(old) = self.seen_order.pop_front()
        {
            self.seen.remove(&old);
        }
        Ok(())
    }

    /// Déchiffre un message de l'extension (et vérifie son authenticité).
    pub fn decrypt(&mut self, message_b64: &str, nonce: &Nonce) -> Result<Zeroizing<Vec<u8>>> {
        let (_, b) = self.peer.as_ref().ok_or(Error::InvalidArgument("pas de clé publique"))?;
        let cipher = B64.decode(message_b64).map_err(|_| Error::InvalidArgument("message illisible"))?;
        let plain = b
            .decrypt(nonce.into(), cipher.as_slice())
            .map_err(|_| Error::InvalidArgument("message indéchiffrable"))?;
        self.check_fresh(nonce)?;
        Ok(Zeroizing::new(plain))
    }

    pub fn encrypt(&self, plain: &[u8], nonce: &Nonce) -> Result<String> {
        let (_, b) = self.peer.as_ref().ok_or(Error::InvalidArgument("pas de clé publique"))?;
        let cipher = b.encrypt(nonce.into(), plain).map_err(|_| Error::InvalidArgument("chiffrement impossible"))?;
        Ok(B64.encode(cipher))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_increment_carries_little_endian() {
        let mut n = [0u8; 24];
        assert_eq!(increment_nonce(&n)[0], 1);
        n[0] = 0xff;
        n[1] = 0xff;
        let i = increment_nonce(&n);
        assert_eq!((i[0], i[1], i[2]), (0, 0, 1));
        assert_eq!(increment_nonce(&[0xff; 24]), [0u8; 24]);
    }

    #[test]
    fn round_trip_between_two_sessions() {
        let mut a = Session::new().unwrap();
        let mut b = Session::new().unwrap();
        a.set_peer(&b.public_key_b64()).unwrap();
        b.set_peer(&a.public_key_b64()).unwrap();
        let n = random_nonce().unwrap();
        let c = a.encrypt(b"{\"x\":1}", &n).unwrap();
        assert_eq!(b.decrypt(&c, &n).unwrap().as_slice(), b"{\"x\":1}");
        // Rejeu refusé.
        assert!(b.decrypt(&c, &n).is_err());
    }

    #[test]
    fn tampered_or_foreign_messages_are_rejected() {
        let mut a = Session::new().unwrap();
        let mut b = Session::new().unwrap();
        a.set_peer(&b.public_key_b64()).unwrap();
        b.set_peer(&a.public_key_b64()).unwrap();
        let n = random_nonce().unwrap();
        let c = a.encrypt(b"secret", &n).unwrap();
        let mut raw = B64.decode(&c).unwrap();
        raw[20] ^= 1;
        assert!(b.decrypt(&B64.encode(&raw), &n).is_err());
        assert!(b.decrypt(&c, &increment_nonce(&n)).is_err());
        // Un message chiffré pour un autre destinataire ne se déchiffre pas.
        let mut other = Session::new().unwrap();
        other.set_peer(&a.public_key_b64()).unwrap();
        let foreign = other.encrypt(b"x", &n).unwrap();
        assert!(b.decrypt(&foreign, &n).is_err());
        // Un échec de déchiffrement ne « consomme » pas le nonce.
        assert_eq!(b.decrypt(&c, &n).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn low_order_and_malformed_keys_are_refused() {
        let mut s = Session::new().unwrap();
        for k in LOW_ORDER {
            assert!(s.set_peer(&B64.encode(k)).is_err());
            let mut high = k;
            high[31] |= 0x80;
            assert!(s.set_peer(&B64.encode(high)).is_err());
        }
        assert!(s.set_peer("pas du base64").is_err());
        assert!(s.set_peer(&B64.encode([7u8; 31])).is_err());
        assert!(!s.has_peer());
        assert!(decode_nonce(&B64.encode([0u8; 23])).is_err());
    }
}
