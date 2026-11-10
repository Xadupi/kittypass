//! Codes TOTP des entrées (URI `otpauth://totp/...`).
//!
//! Implémentation propre plutôt que celle de la bibliothèque KeePass : cette
//! dernière ne valide pas `period` ni `digits`, et un lien piégé
//! (`period=0`, `digits=99`) fait planter l'application.

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Totp({:?}, {} chiffres, {} s)", self.algorithm, self.digits, self.period)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub code: String,
    /// Secondes avant expiration du code.
    pub remaining: u64,
    pub period: u64,
}

const MAX_URI_LEN: usize = 4096;

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s.bytes().filter(|c| !matches!(c, b' ' | b'-' | b'=')) {
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

impl Totp {
    pub fn parse(uri: &str) -> Result<Self> {
        let bad = |m| Error::InvalidArgument(m);
        if uri.len() > MAX_URI_LEN {
            return Err(bad("URI OTP trop longue"));
        }
        let rest = uri.strip_prefix("otpauth://").ok_or(bad("URI OTP invalide"))?;
        let (kind, rest) = rest.split_once('/').ok_or(bad("URI OTP invalide"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(bad("seul TOTP est pris en charge"));
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let (mut secret, mut period, mut digits, mut algorithm) = (None, 30u64, 6u32, Algorithm::Sha1);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(base32_decode(v).ok_or(bad("secret OTP invalide"))?)),
                "period" => period = v.parse().map_err(|_| bad("période OTP invalide"))?,
                "digits" => digits = v.parse().map_err(|_| bad("nombre de chiffres OTP invalide"))?,
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(bad("algorithme OTP inconnu")),
                    }
                }
                _ => {}
            }
        }
        let secret = secret.ok_or(bad("secret OTP manquant"))?;
        if secret.len() < 10 || secret.len() > 128 {
            return Err(bad("taille du secret OTP invalide"));
        }
        if !(1..=300).contains(&period) {
            return Err(bad("période OTP hors limites"));
        }
        if !(6..=10).contains(&digits) {
            return Err(bad("nombre de chiffres OTP hors limites"));
        }
        Ok(Self { secret, period, digits, algorithm })
    }

    pub fn code_at(&self, unix_time: u64) -> Code {
        let counter = (unix_time / self.period).to_be_bytes();
        let mac = hmac_bytes(self.algorithm, &self.secret, &counter);
        let off = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]) as u64;
        // digits ≤ 10 : 10^10 tient dans un u64.
        let value = bin % 10u64.pow(self.digits);
        Code {
            code: format!("{value:0width$}", width = self.digits as usize),
            remaining: self.period - unix_time % self.period,
            period: self.period,
        }
    }

    pub fn code_now(&self) -> Code {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.code_at(now)
    }
}

fn hmac_bytes(alg: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! mac {
        ($d:ty) => {{
            let mut m = Hmac::<$d>::new_from_slice(key).expect("HMAC accepte toute taille de clé");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        Algorithm::Sha1 => mac!(sha1::Sha1),
        Algorithm::Sha256 => mac!(sha2::Sha256),
        Algorithm::Sha512 => mac!(sha2::Sha512),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0);
        for &b in data {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((buf >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// Annexe B de la RFC 6238 (8 chiffres, trois algorithmes).
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            ("SHA1", b"12345678901234567890".to_vec(), [94287082u64, 7081804, 14050471, 89005924, 69279037, 65353130]),
            ("SHA256", b"12345678901234567890123456789012".to_vec(), [46119246, 68084774, 67062674, 91819424, 90698825, 77737706]),
            ("SHA512", b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(), [90693936, 25091201, 99943326, 93441116, 38618901, 47863826]),
        ];
        let times = [59u64, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
        for (alg, secret, expected) in cases {
            let t = Totp::parse(&format!("otpauth://totp/x?secret={}&digits=8&algorithm={alg}", b32(&secret))).unwrap();
            for (time, exp) in times.iter().zip(expected) {
                assert_eq!(t.code_at(*time).code, format!("{exp:08}"), "{alg} t={time}");
            }
        }
    }

    #[test]
    fn defaults_and_remaining() {
        let t = Totp::parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&issuer=Ex").unwrap();
        assert_eq!((t.period, t.digits, t.algorithm), (30, 6, Algorithm::Sha1));
        let c = t.code_at(999_999_995); // 999 999 995 mod 30 = 5
        assert_eq!((c.code.len(), c.remaining), (6, 25));
    }

    #[test]
    fn malicious_uris_are_errors_not_crashes() {
        for uri in [
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=18446744073709551615",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=-1",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?secret=1!!!",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x?secret=AA",
            "otpauth://totp/x",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "https://evil.org/?secret=JBSWY3DPEHPK3PXP",
            "",
        ] {
            assert!(Totp::parse(uri).is_err(), "{uri} accepté");
        }
        assert!(Totp::parse(&format!("otpauth://totp/x?secret={}", "A".repeat(5000))).is_err());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(q in "[a-zA-Z0-9=&?%/:._-]{0,200}", t in 0u64..u64::MAX / 2) {
            if let Ok(totp) = Totp::parse(&format!("otpauth://totp/x?{q}")) {
                let _ = totp.code_at(t);
            }
        }
    }

    #[test]
    fn debug_hides_secret() {
        let t = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert!(!format!("{t:?}").contains("JBSW"));
    }
}
