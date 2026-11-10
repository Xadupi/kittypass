//! Vérification Have I Been Pwned par k-anonymat : seuls les 5 premiers
//! caractères hexadécimaux du SHA-1 du mot de passe sont envoyés ; le
//! service renvoie tous les suffixes connus pour ce préfixe (plusieurs
//! centaines) et la comparaison se fait ici. Le mot de passe, son empreinte
//! complète et le résultat ne quittent jamais l'appareil.
//!
//! Les réponses sont demandées avec remplissage (`Add-Padding`) : leur
//! taille ne trahit pas le préfixe demandé.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Service public. Un miroir local (même API) peut être utilisé à la place.
pub const DEFAULT_URL: &str = "https://api.pwnedpasswords.com/range/";
pub const PREFIX_LEN: usize = 5;
const SUFFIX_LEN: usize = 35;
/// Une réponse réelle fait environ 40 Ko (remplissage compris).
#[cfg(feature = "client")]
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// SHA-1 en hexadécimal majuscule (40 caractères).
pub fn sha1_hex(password: &str) -> Zeroizing<String> {
    let digest = Sha1::digest(password.as_bytes());
    let mut out = Zeroizing::new(String::with_capacity(40));
    for b in digest.iter() {
        out.push(char::from(b"0123456789ABCDEF"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789ABCDEF"[usize::from(b & 0xf)]));
    }
    out
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Préfixe envoyé au service, ou erreur si `sha1` n'est pas une empreinte.
pub fn prefix(sha1: &str) -> Result<&str> {
    if sha1.len() != 40 || !is_hex(sha1) {
        return Err(Error::InvalidArgument("empreinte SHA-1"));
    }
    Ok(&sha1[..PREFIX_LEN])
}

/// Cherche le suffixe de `sha1` dans une réponse `SUFFIXE:NOMBRE` par ligne.
/// Renvoie le nombre de fuites (0 si absent ; les lignes de remplissage ont
/// un nombre nul). Une réponse mal formée est refusée en entier.
pub fn count_in_range(body: &str, sha1: &str) -> Result<u64> {
    prefix(sha1)?;
    let suffix = &sha1[PREFIX_LEN..];
    let mut found = 0;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (s, n) = line.split_once(':').ok_or(Error::InvalidArgument("réponse HIBP"))?;
        if s.len() != SUFFIX_LEN || !is_hex(s) || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidArgument("réponse HIBP"));
        }
        if s.eq_ignore_ascii_case(suffix) {
            found = n.parse().unwrap_or(u64::MAX);
        }
    }
    Ok(found)
}

/// Client HTTP du service de plages (HTTPS obligatoire, sauf machine locale).
#[cfg(feature = "client")]
pub struct Client {
    base: reqwest::Url,
    http: reqwest::Client,
}

#[cfg(feature = "client")]
impl Client {
    pub fn new(base_url: &str) -> Result<Self> {
        let base = crate::client::validate_server_url(base_url)?;
        let http = reqwest::Client::builder()
            .https_only(base.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("kittypass/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| Error::Network)?;
        Ok(Self { base, http })
    }

    /// Plage de suffixes pour un préfixe de 5 caractères hexadécimaux.
    pub async fn range(&self, prefix: &str) -> Result<String> {
        if prefix.len() != PREFIX_LEN || !is_hex(prefix) {
            return Err(Error::InvalidArgument("préfixe SHA-1"));
        }
        let url = self.base.join(&prefix.to_ascii_uppercase()).map_err(|_| Error::InvalidArgument("préfixe SHA-1"))?;
        let mut res = self.http.get(url).header("Add-Padding", "true").send().await.map_err(|_| Error::Network)?;
        match res.status() {
            s if s.is_success() => {}
            reqwest::StatusCode::TOO_MANY_REQUESTS => return Err(Error::RateLimited),
            s => return Err(Error::Server(s.as_u16())),
        }
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|_| Error::Network)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Error::InvalidArgument("réponse HIBP trop grande"));
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| Error::InvalidArgument("réponse HIBP"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hash_and_lookup() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let h = sha1_hex("password");
        assert_eq!(h.as_str(), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(prefix(&h).unwrap(), "5BAA6");
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assert_eq!(count_in_range(body, &h).unwrap(), 9_659_365);
        // Comparaison insensible à la casse, absence = 0.
        assert_eq!(count_in_range(&body.to_lowercase(), &h).unwrap(), 9_659_365);
        assert_eq!(count_in_range("0018A45C4D1DEF81644B54AB7F969B88D65:1", &h).unwrap(), 0);
        assert_eq!(count_in_range("", &h).unwrap(), 0);
    }

    #[test]
    fn padding_lines_do_not_count() {
        let h = sha1_hex("password");
        assert_eq!(count_in_range("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n", &h).unwrap(), 0);
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let h = sha1_hex("password");
        for body in [
            "<html>erreur</html>",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD:5",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:-1",
            "ZZ4C9B93F3F0682250B6CF8331B7EE68FD8:1",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1 ",
        ] {
            assert!(count_in_range(body, &h).is_err(), "{body:?}");
        }
        // Un nombre gigantesque sature au lieu de paniquer.
        assert_eq!(count_in_range("1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999999", &h).unwrap(), u64::MAX);
    }

    #[test]
    fn bad_hashes_are_rejected() {
        for h in ["", "5BAA6", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FDZ", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD80"] {
            assert!(prefix(h).is_err());
            assert!(count_in_range("", h).is_err());
        }
    }
}
