//! TOTP (RFC 6238 : HMAC-SHA1, 6 chiffres, pas de 30 s).

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::crypto::ct_eq;

pub const STEP: i64 = 30;
const DIGITS: u32 = 6;

pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac");
    mac.update(&(step as u64).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// Vérifie `code` sur la fenêtre [-1, +1] pas. Renvoie le pas utilisé.
///
/// Anti-rejeu : un pas inférieur ou égal à `last_step` (déjà consommé) est
/// refusé, donc un code intercepté ne peut pas resservir.
pub fn verify(secret: &[u8], code: &str, now: i64, last_step: Option<i64>) -> Option<i64> {
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = now.div_euclid(STEP);
    let mut found = None;
    // On teste toutes les fenêtres sans sortir tôt : temps constant.
    for s in [current - 1, current, current + 1] {
        let fresh = last_step.is_none_or(|l| s > l);
        let ok = ct_eq(format!("{:06}", code_at(secret, s)).as_bytes(), code.as_bytes());
        if ok && fresh && found.is_none() {
            found = Some(s);
        }
    }
    found
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// URI lisible par les applications d'authentification.
pub fn otpauth_uri(secret: &[u8], username: &str) -> String {
    // `username` est restreint à [a-z0-9._-] : pas d'encodage nécessaire.
    format!(
        "otpauth://totp/KittyPass:{username}?secret={}&issuer=KittyPass&algorithm=SHA1&digits=6&period=30",
        base32(secret)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// Vecteurs de l'annexe B de la RFC 6238 (SHA1), tronqués à 6 chiffres.
    #[test]
    fn rfc6238_vectors() {
        for (t, expected) in [
            (59, 287082),
            (1111111109, 81804),
            (1111111111, 50471),
            (1234567890, 5924),
            (2000000000, 279037),
            (20000000000, 353130),
        ] {
            assert_eq!(code_at(RFC_SECRET, t / STEP), expected, "t = {t}");
        }
    }

    #[test]
    fn verify_window_and_replay() {
        let now = 1_000_000_020;
        let step = now / STEP;
        let code = format!("{:06}", code_at(RFC_SECRET, step));
        assert_eq!(verify(RFC_SECRET, &code, now, None), Some(step));
        // Rejeu du même code : refusé.
        assert_eq!(verify(RFC_SECRET, &code, now, Some(step)), None);
        // Code précédent toujours valable une fenêtre, sauf si consommé.
        let prev = format!("{:06}", code_at(RFC_SECRET, step - 1));
        assert_eq!(verify(RFC_SECRET, &prev, now, None), Some(step - 1));
        assert_eq!(verify(RFC_SECRET, &prev, now, Some(step - 1)), None);
        // Trop vieux (2 fenêtres) ou trop futur : refusé.
        let old = format!("{:06}", code_at(RFC_SECRET, step - 2));
        let fut = format!("{:06}", code_at(RFC_SECRET, step + 2));
        assert_eq!(verify(RFC_SECRET, &old, now, None), None);
        assert_eq!(verify(RFC_SECRET, &fut, now, None), None);
    }

    #[test]
    fn rejects_malformed_codes() {
        let now = 1_000_000_020;
        for c in ["", "12345", "1234567", "12345a", " 12345", "١٢٣٤٥٦", "-12345", "+12345"] {
            assert_eq!(verify(RFC_SECRET, c, now, None), None, "{c:?}");
        }
    }

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }
}
