//! Fichier clé KeePass : second facteur du coffre, jamais envoyé au serveur.
//!
//! Formats acceptés, comme KeePass et KeePassXC : XML 2.0 (`.keyx`, avec
//! somme de contrôle vérifiée), XML 1.0, 32 octets bruts, 64 caractères
//! hexadécimaux, ou n'importe quel fichier (son SHA-256). Les fichiers créés
//! ici sont au format XML 2.0 de KeePassXC.

use std::io::Read;

use keepass::DatabaseKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result, rng};

/// Au-delà, le fichier est haché au fil de la lecture au lieu d'être gardé
/// en mémoire (même résultat : la bibliothèque hacherait le fichier entier).
const INLINE_MAX_BYTES: usize = 1024 * 1024;
/// Plafond de lecture : un périphérique sans fin (/dev/zero) ou un fichier
/// géant ne bloque pas l'application.
pub const MAX_KEY_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Contenu d'un fichier clé, tel que transmis à la bibliothèque KeePass.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyFile {
    data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyFile(<masqué>)")
    }
}

impl KeyFile {
    /// Lit un fichier clé. Refuse un fichier vide ou un XML 2.0 abîmé.
    pub fn from_reader(reader: impl Read) -> Result<Self> {
        let mut reader = reader.take(MAX_KEY_FILE_BYTES + 1);
        let mut head = Zeroizing::new(Vec::new());
        (&mut reader).take(INLINE_MAX_BYTES as u64 + 1).read_to_end(&mut head).map_err(|_| Error::KeyFile("illisible"))?;
        if head.is_empty() {
            return Err(Error::KeyFile("fichier vide"));
        }
        if head.len() <= INLINE_MAX_BYTES {
            DatabaseKey::check_keyfile(&head).map_err(|_| Error::KeyFile("fichier clé XML corrompu"))?;
            return Ok(Self { data: head });
        }
        let mut hasher = Sha256::new();
        hasher.update(&head[..]);
        let mut total = head.len() as u64;
        let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
        loop {
            let n = reader.read(&mut buf).map_err(|_| Error::KeyFile("illisible"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_KEY_FILE_BYTES {
                return Err(Error::KeyFile("fichier trop volumineux (512 Mio au plus)"));
            }
            hasher.update(&buf[..n]);
        }
        // 32 octets : la bibliothèque les prend tels quels, ce qui équivaut au
        // SHA-256 du fichier entier qu'elle aurait calculé.
        Ok(Self { data: Zeroizing::new(hasher.finalize().to_vec()) })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::from_reader(data)
    }

    /// Nouveau fichier clé aléatoire (256 bits), au format XML 2.0 de
    /// KeePassXC. Renvoie la clé et le contenu à écrire sur le disque.
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let mut key = Zeroizing::new([0u8; 32]);
        rng::fill(&mut key[..])?;
        let hex: Zeroizing<String> = Zeroizing::new(key.iter().map(|b| format!("{b:02X}")).collect());
        let hash: String = Sha256::digest(&key[..])[..4].iter().map(|b| format!("{b:02X}")).collect();
        let mut groups = Zeroizing::new(String::new());
        for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
            if i % 4 == 0 {
                groups.push_str("\n            ");
            } else {
                groups.push(' ');
            }
            groups.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        }
        let xml = Zeroizing::new(
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    \
                 <Key>\n        <Data Hash=\"{hash}\">{}\n        </Data>\n    </Key>\n</KeyFile>\n",
                groups.as_str()
            )
            .into_bytes(),
        );
        Ok((Self::from_bytes(&xml)?, xml))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_file_is_valid_v2() {
        let (k, xml) = KeyFile::generate().unwrap();
        let text = std::str::from_utf8(&xml).unwrap();
        assert!(text.contains("<Version>2.0</Version>") && text.contains("Hash=\""));
        assert_eq!(KeyFile::from_bytes(&xml).unwrap(), k);
        // Deux fichiers générés diffèrent.
        assert_ne!(KeyFile::generate().unwrap().0, k);
        // Altérer un chiffre casse la somme de contrôle.
        let i = text.find("Hash=").unwrap() + 30;
        let mut bad = xml.to_vec();
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(KeyFile::from_bytes(&bad).is_err());
    }

    #[test]
    fn empty_and_endless_files_are_refused() {
        assert!(KeyFile::from_bytes(b"").is_err());
        let endless = std::io::repeat(0);
        assert!(matches!(KeyFile::from_reader(endless), Err(Error::KeyFile(_))));
    }

    #[test]
    fn large_file_equals_hash_of_whole_file() {
        let big: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i * 7 % 251) as u8).collect();
        let k = KeyFile::from_bytes(&big).unwrap();
        assert_eq!(k.bytes(), Sha256::digest(&big).as_slice());
        assert!(format!("{k:?}").contains("masqué"));
    }
}
