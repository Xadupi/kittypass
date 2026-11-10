//! Lecture défensive de l'en-tête KDBX, **avant** tout déchiffrement.
//!
//! Un fichier KDBX annonce lui-même ses paramètres de dérivation de clé. Un
//! fichier piégé (envoyé par un serveur compromis, par exemple) peut demander
//! 4 Go de mémoire Argon2 ou 2^64 tours AES et bloquer l'appareil. On vérifie
//! donc ces paramètres contre des limites avant de passer le fichier à la
//! bibliothèque KDBX.

use crate::{Error, Result};

const SIG1: u32 = 0x9AA2_D903;
const SIG2_KDBX: u32 = 0xB54B_FB67;

const HDR_END: u8 = 0;
const HDR_TRANSFORM_ROUNDS_V3: u8 = 6;
const HDR_KDF_PARAMETERS_V4: u8 = 11;

const UUID_AES_KDF: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const UUID_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const UUID_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

/// Paramètres de dérivation annoncés par le fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Aes { rounds: u64 },
    Argon2d { memory_bytes: u64, iterations: u64, parallelism: u32 },
    Argon2id { memory_bytes: u64, iterations: u64, parallelism: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    pub major: u16,
    pub minor: u16,
    pub kdf: Kdf,
}

/// Limites appliquées à l'ouverture d'un fichier.
#[derive(Debug, Clone, Copy)]
pub struct OpenLimits {
    pub max_file_bytes: usize,
    pub max_argon2_memory_bytes: u64,
    pub max_argon2_iterations: u64,
    pub max_argon2_parallelism: u32,
    /// Coût total mémoire × itérations (en octets), pour borner le temps.
    pub max_argon2_cost: u128,
    pub max_aes_rounds: u64,
}

impl Default for OpenLimits {
    fn default() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            // 1 GiB : valeur par défaut de certains clients KeePass.
            max_argon2_memory_bytes: GIB,
            max_argon2_iterations: 10_000,
            max_argon2_parallelism: 64,
            max_argon2_cost: 64 * GIB as u128,
            max_aes_rounds: 200_000_000,
        }
    }
}

/// Taille maximale cumulée des champs d'en-tête.
const MAX_HEADER_BYTES: usize = 1024 * 1024;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedHeader("débordement"))?;
        let s = self.data.get(self.pos..end).ok_or(Error::MalformedHeader("tronqué"))?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap_or_default()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap_or_default()))
    }
}

fn le_u64(b: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(b.try_into().map_err(|_| Error::MalformedHeader("entier u64 attendu"))?))
}
fn le_u32(b: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(b.try_into().map_err(|_| Error::MalformedHeader("entier u32 attendu"))?))
}

/// Lit l'en-tête et renvoie la version et la KDF, sans rien déchiffrer.
pub fn inspect(data: &[u8]) -> Result<HeaderInfo> {
    let mut r = Reader { data, pos: 0 };
    if r.u32()? != SIG1 || r.u32()? != SIG2_KDBX {
        return Err(Error::UnsupportedFormat);
    }
    let minor = r.u16()?;
    let major = r.u16()?;
    if major != 3 && major != 4 {
        return Err(Error::UnsupportedFormat);
    }

    let mut kdf = None;
    loop {
        if r.pos > MAX_HEADER_BYTES {
            return Err(Error::MalformedHeader("en-tête trop grand"));
        }
        let id = r.u8()?;
        let len = if major == 4 { r.u32()? as usize } else { r.u16()? as usize };
        let value = r.take(len)?;
        match (major, id) {
            (_, HDR_END) => break,
            (3, HDR_TRANSFORM_ROUNDS_V3) => {
                if kdf.is_some() {
                    return Err(Error::MalformedHeader("KDF en double"));
                }
                kdf = Some(Kdf::Aes { rounds: le_u64(value)? });
            }
            (4, HDR_KDF_PARAMETERS_V4) => {
                if kdf.is_some() {
                    return Err(Error::MalformedHeader("KDF en double"));
                }
                kdf = Some(parse_kdf_dictionary(value)?);
            }
            _ => {}
        }
    }
    let kdf = kdf.ok_or(Error::MalformedHeader("paramètres KDF absents"))?;
    Ok(HeaderInfo { major, minor, kdf })
}

/// Lit un « VariantDictionary » KDBX 4 et en extrait les paramètres de KDF.
fn parse_kdf_dictionary(data: &[u8]) -> Result<Kdf> {
    let mut r = Reader { data, pos: 0 };
    let version = r.u16()?;
    if version >> 8 != 1 {
        return Err(Error::MalformedHeader("version de dictionnaire inconnue"));
    }
    let (mut uuid, mut mem, mut iter, mut par, mut rounds) = (None, None, None, None, None);
    loop {
        let ty = r.u8()?;
        if ty == 0 {
            break;
        }
        let klen = r.u32()? as usize;
        let key = r.take(klen)?;
        let vlen = r.u32()? as usize;
        let val = r.take(vlen)?;
        let slot = match key {
            b"$UUID" => &mut uuid,
            b"M" => &mut mem,
            b"I" => &mut iter,
            b"P" => &mut par,
            b"R" => &mut rounds,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::MalformedHeader("clé de dictionnaire en double"));
        }
        *slot = Some((ty, val));
    }

    // Vérifie le type déclaré avant de lire la valeur (0x04 = u32, 0x05 = u64,
    // 0x42 = octets).
    let get_u64 = |v: Option<(u8, &[u8])>| match v {
        Some((0x05, b)) => le_u64(b),
        _ => Err(Error::MalformedHeader("paramètre KDF u64 manquant")),
    };
    let get_u32 = |v: Option<(u8, &[u8])>| match v {
        Some((0x04, b)) => le_u32(b),
        _ => Err(Error::MalformedHeader("paramètre KDF u32 manquant")),
    };
    let uuid: [u8; 16] = match uuid {
        Some((0x42, b)) => b.try_into().map_err(|_| Error::MalformedHeader("UUID KDF"))?,
        _ => return Err(Error::MalformedHeader("UUID KDF manquant")),
    };

    match uuid {
        UUID_AES_KDF => Ok(Kdf::Aes { rounds: get_u64(rounds)? }),
        UUID_ARGON2D => Ok(Kdf::Argon2d {
            memory_bytes: get_u64(mem)?,
            iterations: get_u64(iter)?,
            parallelism: get_u32(par)?,
        }),
        UUID_ARGON2ID => Ok(Kdf::Argon2id {
            memory_bytes: get_u64(mem)?,
            iterations: get_u64(iter)?,
            parallelism: get_u32(par)?,
        }),
        _ => Err(Error::UnsupportedFormat),
    }
}

/// Vérifie la taille et les paramètres KDF d'un fichier contre `limits`.
pub fn check(data: &[u8], limits: &OpenLimits) -> Result<HeaderInfo> {
    if data.len() > limits.max_file_bytes {
        return Err(Error::TooLarge);
    }
    let info = inspect(data)?;
    match info.kdf {
        Kdf::Aes { rounds } => {
            if rounds == 0 {
                return Err(Error::KdfOutOfBounds("tours AES nuls"));
            }
            if rounds > limits.max_aes_rounds {
                return Err(Error::KdfOutOfBounds("trop de tours AES"));
            }
        }
        Kdf::Argon2d { memory_bytes, iterations, parallelism }
        | Kdf::Argon2id { memory_bytes, iterations, parallelism } => {
            if memory_bytes < 8 * 1024 || iterations == 0 || parallelism == 0 {
                return Err(Error::KdfOutOfBounds("paramètres Argon2 nuls"));
            }
            if memory_bytes > limits.max_argon2_memory_bytes {
                return Err(Error::KdfOutOfBounds("mémoire Argon2 trop élevée"));
            }
            if iterations > limits.max_argon2_iterations {
                return Err(Error::KdfOutOfBounds("itérations Argon2 trop élevées"));
            }
            if parallelism > limits.max_argon2_parallelism {
                return Err(Error::KdfOutOfBounds("parallélisme Argon2 trop élevé"));
            }
            if memory_bytes as u128 * iterations as u128 > limits.max_argon2_cost {
                return Err(Error::KdfOutOfBounds("coût Argon2 total trop élevé"));
            }
        }
    }
    Ok(info)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Construit un en-tête KDBX 4 minimal avec le dictionnaire KDF donné.
    pub(crate) fn kdbx4_header(dict: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&SIG1.to_le_bytes());
        v.extend_from_slice(&SIG2_KDBX.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.push(HDR_KDF_PARAMETERS_V4);
        v.extend_from_slice(&(dict.len() as u32).to_le_bytes());
        v.extend_from_slice(dict);
        v.push(HDR_END);
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(b"\r\n\r\n");
        v
    }

    pub(crate) fn dict(items: &[(u8, &str, Vec<u8>)]) -> Vec<u8> {
        let mut v = 0x0100u16.to_le_bytes().to_vec();
        for (ty, k, val) in items {
            v.push(*ty);
            v.extend_from_slice(&(k.len() as u32).to_le_bytes());
            v.extend_from_slice(k.as_bytes());
            v.extend_from_slice(&(val.len() as u32).to_le_bytes());
            v.extend_from_slice(val);
        }
        v.push(0);
        v
    }

    fn argon2id(mem: u64, iter: u64, par: u32) -> Vec<u8> {
        kdbx4_header(&dict(&[
            (0x42, "$UUID", UUID_ARGON2ID.to_vec()),
            (0x05, "M", mem.to_le_bytes().to_vec()),
            (0x05, "I", iter.to_le_bytes().to_vec()),
            (0x04, "P", par.to_le_bytes().to_vec()),
        ]))
    }

    #[test]
    fn parses_valid_argon2id() {
        let info = check(&argon2id(64 << 20, 10, 2), &OpenLimits::default()).unwrap();
        assert_eq!(info.major, 4);
        assert_eq!(
            info.kdf,
            Kdf::Argon2id { memory_bytes: 64 << 20, iterations: 10, parallelism: 2 }
        );
    }

    #[test]
    fn rejects_memory_bomb() {
        let r = check(&argon2id(u64::MAX, 1, 1), &OpenLimits::default());
        assert!(matches!(r, Err(Error::KdfOutOfBounds(_))));
        let r = check(&argon2id(4 << 30, 1, 1), &OpenLimits::default());
        assert!(matches!(r, Err(Error::KdfOutOfBounds(_))));
    }

    #[test]
    fn rejects_time_bomb() {
        assert!(check(&argon2id(64 << 20, u64::MAX, 1), &OpenLimits::default()).is_err());
        // Chaque paramètre est dans les limites, mais le produit est énorme.
        assert!(check(&argon2id(1 << 30, 5_000, 1), &OpenLimits::default()).is_err());
        let aes = kdbx4_header(&dict(&[
            (0x42, "$UUID", UUID_AES_KDF.to_vec()),
            (0x05, "R", u64::MAX.to_le_bytes().to_vec()),
        ]));
        assert!(check(&aes, &OpenLimits::default()).is_err());
    }

    #[test]
    fn rejects_zero_params() {
        assert!(check(&argon2id(0, 10, 1), &OpenLimits::default()).is_err());
        assert!(check(&argon2id(64 << 20, 0, 1), &OpenLimits::default()).is_err());
        assert!(check(&argon2id(64 << 20, 10, 0), &OpenLimits::default()).is_err());
    }

    #[test]
    fn rejects_wrong_value_types() {
        // « M » déclaré en u32 au lieu de u64 : type confusion refusée.
        let h = kdbx4_header(&dict(&[
            (0x42, "$UUID", UUID_ARGON2ID.to_vec()),
            (0x04, "M", 1u32.to_le_bytes().to_vec()),
            (0x05, "I", 1u64.to_le_bytes().to_vec()),
            (0x04, "P", 1u32.to_le_bytes().to_vec()),
        ]));
        assert!(inspect(&h).is_err());
        // Bon type mais mauvaise longueur.
        let h = kdbx4_header(&dict(&[
            (0x42, "$UUID", UUID_ARGON2ID.to_vec()),
            (0x05, "M", vec![1, 2, 3]),
            (0x05, "I", 1u64.to_le_bytes().to_vec()),
            (0x04, "P", 1u32.to_le_bytes().to_vec()),
        ]));
        assert!(inspect(&h).is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        // Doublon : un attaquant pourrait espérer que le contrôle lise la
        // première valeur et la bibliothèque la seconde.
        let h = kdbx4_header(&dict(&[
            (0x42, "$UUID", UUID_ARGON2ID.to_vec()),
            (0x05, "M", (64u64 << 20).to_le_bytes().to_vec()),
            (0x05, "M", u64::MAX.to_le_bytes().to_vec()),
            (0x05, "I", 1u64.to_le_bytes().to_vec()),
            (0x04, "P", 1u32.to_le_bytes().to_vec()),
        ]));
        assert!(inspect(&h).is_err());
    }

    #[test]
    fn rejects_unknown_kdf_and_formats() {
        let h = kdbx4_header(&dict(&[(0x42, "$UUID", vec![0u8; 16])]));
        assert!(matches!(inspect(&h), Err(Error::UnsupportedFormat)));
        assert!(matches!(inspect(b"PK\x03\x04 not a kdbx"), Err(Error::UnsupportedFormat)));
        let mut h = argon2id(64 << 20, 1, 1);
        h[10] = 5; // version majeure 5
        assert!(matches!(inspect(&h), Err(Error::UnsupportedFormat)));
    }

    #[test]
    fn rejects_oversized_file() {
        let limits = OpenLimits { max_file_bytes: 10, ..Default::default() };
        assert!(matches!(check(&argon2id(64 << 20, 1, 1), &limits), Err(Error::TooLarge)));
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let h = argon2id(64 << 20, 10, 2);
        for n in 0..h.len() - 4 {
            assert!(inspect(&h[..n]).is_err(), "tronqué à {n} accepté");
        }
    }

    #[test]
    fn huge_declared_lengths_do_not_panic() {
        let mut h = argon2id(64 << 20, 10, 2);
        h[13..17].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect(&h).is_err());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20_000))]
        /// Fuzzing léger : aucune entrée ne doit provoquer de panique.
        #[test]
        fn never_panics_on_random_input(data in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let _ = check(&data, &OpenLimits::default());
        }

        /// Entrées aléatoires derrière un en-tête valide : on teste le parseur
        /// de dictionnaire en profondeur.
        #[test]
        fn never_panics_on_random_dictionary(body in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
            let _ = check(&kdbx4_header(&body), &OpenLimits::default());
        }
    }
}
