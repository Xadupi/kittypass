//! Agent SSH, comme KeePassXC : la clé privée d'une entrée (pièce jointe ou
//! fichier) est ajoutée à l'agent SSH du système au déverrouillage et
//! retirée au verrouillage.
//!
//! Ce module ne fait aucune entrée-sortie : il lit les réglages KeeAgent
//! (pièce jointe `KeeAgent.settings`, format de KeePassXC et du greffon
//! KeeAgent), déchiffre les clés OpenSSH et construit les messages du
//! protocole de l'agent (draft-miller-ssh-agent).

use base64::Engine;
use quick_xml::{escape::escape, events::Event};
use sha2::{Digest, Sha256};
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Pièce jointe des réglages, lue et écrite par KeePassXC.
pub const SETTINGS_ATTACHMENT: &str = "KeeAgent.settings";
/// Plus grand fichier de clé accepté (comme KeePassXC).
pub const MAX_KEY_BYTES: usize = 1024 * 1024;
const MAX_SETTINGS_BYTES: usize = 64 * 1024;
/// Plus longue durée de vie proposée dans l'agent : 30 jours.
pub const MAX_LIFETIME_SECS: u32 = 30 * 24 * 3600;
const MAX_FILE_NAME: usize = 4096;

fn err(m: impl Into<String>) -> Error {
    Error::Ssh(m.into())
}

/// Réglages KeeAgent d'une entrée. Les valeurs par défaut sont celles de
/// KeePassXC : une entrée sans pièce jointe `KeeAgent.settings` les a.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentSettings {
    /// Clé utilisable avec l'agent.
    pub allow: bool,
    /// Ajoutée à l'agent au déverrouillage du coffre.
    pub add_at_open: bool,
    /// Retirée de l'agent au verrouillage.
    pub remove_at_close: bool,
    /// L'agent demande confirmation à chaque usage (ssh-askpass).
    pub confirm: bool,
    pub use_lifetime: bool,
    /// Durée de vie dans l'agent (secondes), si `use_lifetime`.
    pub lifetime_secs: u32,
    /// Clé en pièce jointe (`attachment_name`), sinon dans un fichier.
    pub use_attachment: bool,
    pub attachment_name: String,
    pub file_name: String,
    /// Réglage de KeeAgent (Windows) gardé tel quel, sans effet ici.
    pub save_attachment_to_temp_file: bool,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            allow: false,
            add_at_open: false,
            remove_at_close: false,
            confirm: false,
            use_lifetime: false,
            lifetime_secs: 600,
            use_attachment: false,
            attachment_name: String::new(),
            file_name: String::new(),
            save_attachment_to_temp_file: false,
        }
    }
}

/// Texte du fichier : UTF-8 (KeePassXC) ou UTF-16 avec BOM (KeeAgent).
fn decode_text(data: &[u8]) -> Result<String> {
    let bad = || err("réglages KeeAgent illisibles");
    let utf16 = |bytes: &[u8], le: bool| -> Result<String> {
        if !bytes.len().is_multiple_of(2) {
            return Err(bad());
        }
        let units = bytes.as_chunks::<2>().0.iter().map(|c| if le { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) });
        char::decode_utf16(units).collect::<std::result::Result<String, _>>().map_err(|_| bad())
    };
    match data {
        [0xff, 0xfe, rest @ ..] => utf16(rest, true),
        [0xfe, 0xff, rest @ ..] => utf16(rest, false),
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8(rest.to_vec()).map_err(|_| bad()),
        _ => String::from_utf8(data.to_vec()).map_err(|_| bad()),
    }
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.trim() {
        "true" | "True" | "1" => Ok(true),
        "false" | "False" | "0" | "" => Ok(false),
        _ => Err(err("réglages KeeAgent invalides")),
    }
}

impl AgentSettings {
    /// Lit la pièce jointe `KeeAgent.settings`. Les éléments inconnus sont
    /// ignorés, comme dans KeePassXC.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_SETTINGS_BYTES {
            return Err(Error::TooLarge);
        }
        let text = decode_text(data)?;
        // Une déclaration `encoding="UTF-16"` sur un texte déjà décodé ne
        // gêne pas quick-xml, qui lit une chaîne.
        let mut reader = quick_xml::Reader::from_str(&text);
        let mut s = Self::default();
        let mut path: Vec<String> = Vec::new();
        let mut text_buf = String::new();
        let mut root_seen = false;
        loop {
            match reader.read_event().map_err(|_| err("réglages KeeAgent invalides"))? {
                Event::Start(e) => {
                    let name = e.local_name().as_ref().to_owned();
                    if path.is_empty() {
                        if name != "EntrySettings" || root_seen {
                            return Err(err("réglages KeeAgent invalides"));
                        }
                        root_seen = true;
                    }
                    if path.len() > 8 {
                        return Err(err("réglages KeeAgent invalides"));
                    }
                    path.push(name);
                    text_buf.clear();
                }
                Event::Empty(e) => {
                    let name = e.local_name().as_ref().to_owned();
                    if path.is_empty() {
                        return Err(err("réglages KeeAgent invalides"));
                    }
                    path.push(name);
                    s.set(&path, "")?;
                    path.pop();
                }
                Event::Text(t) => {
                    text_buf.push_str(&t.xml10_content());
                }
                Event::GeneralRef(r) => {
                    if let Ok(Some(c)) = r.resolve_char_ref() {
                        text_buf.push(c);
                        continue;
                    }
                    let c = match r.as_ref() {
                        "lt" => "<",
                        "gt" => ">",
                        "amp" => "&",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(err("réglages KeeAgent invalides")),
                    };
                    text_buf.push_str(c);
                }
                Event::End(_) => {
                    s.set(&path, &text_buf)?;
                    text_buf.clear();
                    path.pop();
                }
                Event::Eof => break,
                Event::DocType(_) => return Err(err("réglages KeeAgent invalides")),
                _ => {}
            }
        }
        if !root_seen || !path.is_empty() {
            return Err(err("réglages KeeAgent invalides"));
        }
        s.check()?;
        Ok(s)
    }

    fn set(&mut self, path: &[String], v: &str) -> Result<()> {
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        match p.as_slice() {
            ["EntrySettings", "AllowUseOfSshKey"] => self.allow = parse_bool(v)?,
            ["EntrySettings", "AddAtDatabaseOpen"] => self.add_at_open = parse_bool(v)?,
            ["EntrySettings", "RemoveAtDatabaseClose"] => self.remove_at_close = parse_bool(v)?,
            ["EntrySettings", "UseConfirmConstraintWhenAdding"] => self.confirm = parse_bool(v)?,
            ["EntrySettings", "UseLifetimeConstraintWhenAdding"] => self.use_lifetime = parse_bool(v)?,
            ["EntrySettings", "LifetimeConstraintDuration"] => {
                self.lifetime_secs = v.trim().parse().map_err(|_| err("durée de vie invalide"))?;
            }
            ["EntrySettings", "Location", "SelectedType"] => self.use_attachment = v.trim() == "attachment",
            ["EntrySettings", "Location", "AttachmentName"] => self.attachment_name = v.to_owned(),
            ["EntrySettings", "Location", "FileName"] => self.file_name = v.to_owned(),
            ["EntrySettings", "Location", "SaveAttachmentToTempFile"] => self.save_attachment_to_temp_file = parse_bool(v)?,
            _ => {}
        }
        Ok(())
    }

    /// Vérifie les valeurs (aussi celles venues d'un autre appareil).
    pub fn check(&self) -> Result<()> {
        if self.use_lifetime && !(1..=MAX_LIFETIME_SECS).contains(&self.lifetime_secs) {
            return Err(err("durée de vie hors limites (1 s à 30 jours)"));
        }
        for name in [&self.attachment_name, &self.file_name] {
            if name.len() > MAX_FILE_NAME || name.chars().any(char::is_control) {
                return Err(err("nom de fichier invalide"));
            }
        }
        Ok(())
    }

    /// XML écrit comme KeePassXC (UTF-8, indentation de 2 espaces).
    pub fn to_xml(&self) -> String {
        let b = |v: bool| if v { "true" } else { "false" };
        let opt = |tag: &str, v: &str| if v.is_empty() { format!("<{tag}/>") } else { format!("<{tag}>{}</{tag}>", escape(v)) };
        format!(
            "<?xml version=\"1.0\"?>\n\
             <EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n  \
             <AllowUseOfSshKey>{}</AllowUseOfSshKey>\n  \
             <AddAtDatabaseOpen>{}</AddAtDatabaseOpen>\n  \
             <RemoveAtDatabaseClose>{}</RemoveAtDatabaseClose>\n  \
             <UseConfirmConstraintWhenAdding>{}</UseConfirmConstraintWhenAdding>\n  \
             <UseLifetimeConstraintWhenAdding>{}</UseLifetimeConstraintWhenAdding>\n  \
             <LifetimeConstraintDuration>{}</LifetimeConstraintDuration>\n  \
             <Location>\n    \
             <SelectedType>{}</SelectedType>\n    \
             {}\n    \
             <SaveAttachmentToTempFile>{}</SaveAttachmentToTempFile>\n    \
             {}\n  \
             </Location>\n\
             </EntrySettings>\n",
            b(self.allow),
            b(self.add_at_open),
            b(self.remove_at_close),
            b(self.confirm),
            b(self.use_lifetime),
            self.lifetime_secs,
            if self.use_attachment { "attachment" } else { "file" },
            opt("AttachmentName", &self.attachment_name),
            b(self.save_attachment_to_temp_file),
            opt("FileName", &self.file_name),
        )
    }

    /// Durée de vie à demander à l'agent.
    pub fn lifetime(&self) -> Option<u32> {
        self.use_lifetime.then_some(self.lifetime_secs)
    }
}

/// Description d'une clé, lisible sans la déchiffrer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeyInfo {
    /// `ssh-ed25519`, `rsa-sha2-512`… (nom de l'algorithme de la clé).
    pub algorithm: String,
    /// `SHA256:…`, comme `ssh-keygen -l`.
    pub fingerprint: String,
    pub comment: String,
    pub encrypted: bool,
    /// Ligne de clé publique (`ssh-ed25519 AAAA… commentaire`).
    pub public_key: String,
}

fn parse_private(data: &[u8]) -> Result<PrivateKey> {
    if data.is_empty() || data.len() > MAX_KEY_BYTES {
        return Err(err("fichier de clé vide ou trop gros"));
    }
    let text = std::str::from_utf8(data).map_err(|_| err("ce n'est pas une clé privée OpenSSH"))?;
    let trimmed = text.trim_start();
    if !trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        if trimmed.starts_with("-----BEGIN ") && trimmed.contains("PRIVATE KEY-----") {
            return Err(err(
                "ancien format PEM non pris en charge : convertissez la clé avec « ssh-keygen -p -f fichier »",
            ));
        }
        return Err(err("ce n'est pas une clé privée OpenSSH"));
    }
    PrivateKey::from_openssh(trimmed).map_err(|_| err("clé privée OpenSSH illisible"))
}

/// Empreinte SHA-256 d'une clé publique au format du protocole.
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// Clé publique (format du protocole), sans déchiffrer la clé privée.
pub fn public_blob(data: &[u8]) -> Result<Vec<u8>> {
    parse_private(data)?.public_key().to_bytes().map_err(|_| err("clé illisible"))
}

pub fn key_info(data: &[u8]) -> Result<KeyInfo> {
    let key = parse_private(data)?;
    let public = key.public_key();
    let blob = public.to_bytes().map_err(|_| err("clé illisible"))?;
    Ok(KeyInfo {
        algorithm: public.algorithm().as_str().to_owned(),
        fingerprint: fingerprint(&blob),
        comment: key.comment().to_owned(),
        encrypted: key.is_encrypted(),
        public_key: public.to_openssh().map_err(|_| err("clé illisible"))?,
    })
}

/// Clé prête pour l'agent.
pub struct AgentKey {
    /// Clé publique au format du protocole (sert à la retirer).
    pub public_blob: Vec<u8>,
    pub fingerprint: String,
    pub comment: String,
    /// Clé privée et commentaire, au format `SSH2_AGENTC_ADD_IDENTITY`.
    private: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey").field("fingerprint", &self.fingerprint).field("comment", &self.comment).finish_non_exhaustive()
    }
}

/// Déchiffre la clé (avec `passphrase`, le mot de passe de l'entrée, si
/// elle est chiffrée). `fallback_comment` remplace un commentaire vide.
pub fn load_key(data: &[u8], passphrase: &str, fallback_comment: &str) -> Result<AgentKey> {
    let key = parse_private(data)?;
    let key = if key.is_encrypted() {
        if passphrase.is_empty() {
            return Err(err("la clé est chiffrée et l'entrée n'a pas de mot de passe"));
        }
        key.decrypt(passphrase).map_err(|_| err("phrase de passe de la clé incorrecte (mot de passe de l'entrée)"))?
    } else {
        key
    };
    let public_blob = key.public_key().to_bytes().map_err(|_| err("clé illisible"))?;
    let comment = if key.comment().trim().is_empty() { fallback_comment.trim() } else { key.comment() };
    let comment: String = comment.chars().filter(|c| !c.is_control()).take(256).collect();
    let data = key.key_data();
    let len = data.encoded_len().and_then(|n| comment.as_str().encoded_len().map(|c| n + c)).map_err(|_| err("clé illisible"))?;
    // Capacité exacte : pas de réallocation qui laisserait des copies de la
    // clé dans la mémoire libérée.
    let mut private = Zeroizing::new(Vec::with_capacity(len));
    data.encode(&mut *private).map_err(|_| err("clé illisible"))?;
    comment.as_str().encode(&mut *private).map_err(|_| err("clé illisible"))?;
    Ok(AgentKey { fingerprint: fingerprint(&public_blob), public_blob, comment, private })
}

/// Messages du protocole de l'agent SSH.
pub mod agent {
    use zeroize::Zeroizing;

    use super::{AgentKey, err};
    use crate::Result;

    const FAILURE: u8 = 5;
    const SUCCESS: u8 = 6;
    const REQUEST_IDENTITIES: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;
    const ADD_IDENTITY: u8 = 17;
    const REMOVE_IDENTITY: u8 = 18;
    const ADD_ID_CONSTRAINED: u8 = 25;
    const CONSTRAIN_LIFETIME: u8 = 1;
    const CONSTRAIN_CONFIRM: u8 = 2;
    /// Plus grande réponse acceptée de l'agent.
    pub const MAX_REPLY: usize = 256 * 1024;
    const MAX_IDENTITIES: u32 = 1024;

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    fn frame(body: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 4));
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Ajout d'une clé, avec confirmation et durée de vie éventuelles.
    pub fn add(key: &AgentKey, confirm: bool, lifetime: Option<u32>) -> Zeroizing<Vec<u8>> {
        let constrained = confirm || lifetime.is_some();
        let mut body = Zeroizing::new(Vec::with_capacity(key.private.len() + 16));
        body.push(if constrained { ADD_ID_CONSTRAINED } else { ADD_IDENTITY });
        body.extend_from_slice(&key.private);
        if let Some(secs) = lifetime {
            body.push(CONSTRAIN_LIFETIME);
            body.extend_from_slice(&secs.to_be_bytes());
        }
        if confirm {
            body.push(CONSTRAIN_CONFIRM);
        }
        frame(body)
    }

    pub fn remove(public_blob: &[u8]) -> Vec<u8> {
        let mut body = vec![REMOVE_IDENTITY];
        put_string(&mut body, public_blob);
        frame(Zeroizing::new(body)).to_vec()
    }

    pub fn request_identities() -> Vec<u8> {
        frame(Zeroizing::new(vec![REQUEST_IDENTITIES])).to_vec()
    }

    /// Longueur annoncée par l'en-tête d'une réponse (4 octets).
    pub fn reply_len(header: [u8; 4]) -> Result<usize> {
        let n = u32::from_be_bytes(header) as usize;
        if n == 0 || n > MAX_REPLY {
            return Err(err("réponse de l'agent invalide"));
        }
        Ok(n)
    }

    /// Réponse à un ajout ou un retrait.
    pub fn parse_status(body: &[u8]) -> Result<bool> {
        match body.first() {
            Some(&SUCCESS) => Ok(true),
            Some(&FAILURE) => Ok(false),
            _ => Err(err("réponse de l'agent inattendue")),
        }
    }

    struct Cursor<'a>(&'a [u8]);

    impl<'a> Cursor<'a> {
        fn u32(&mut self) -> Result<u32> {
            let (h, t) = self.0.split_first_chunk::<4>().ok_or_else(|| err("réponse de l'agent tronquée"))?;
            self.0 = t;
            Ok(u32::from_be_bytes(*h))
        }
        fn string(&mut self) -> Result<&'a [u8]> {
            let n = self.u32()? as usize;
            if n > self.0.len() {
                return Err(err("réponse de l'agent tronquée"));
            }
            let (s, t) = self.0.split_at(n);
            self.0 = t;
            Ok(s)
        }
    }

    /// Clés présentes dans l'agent : (clé publique, commentaire).
    pub fn parse_identities(body: &[u8]) -> Result<Vec<(Vec<u8>, String)>> {
        let Some((&IDENTITIES_ANSWER, rest)) = body.split_first() else {
            return Err(err("réponse de l'agent inattendue"));
        };
        let mut c = Cursor(rest);
        let n = c.u32()?;
        if n > MAX_IDENTITIES {
            return Err(err("réponse de l'agent invalide"));
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let blob = c.string()?.to_vec();
            let comment = String::from_utf8_lossy(c.string()?).into_owned();
            out.push((blob, comment));
        }
        if !c.0.is_empty() {
            return Err(err("réponse de l'agent invalide"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clé de test ed25519 générée pour ces tests (sans valeur ailleurs),
    /// non chiffrée, commentaire « test@kittypass ».
    pub(crate) const ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAl34EQAgeZe7TcXFKcHrF5EJcBJnM7N26NJDNJNwhFHwAAAJiMq6OcjKuj
nAAAAAtzc2gtZWQyNTUxOQAAACAl34EQAgeZe7TcXFKcHrF5EJcBJnM7N26NJDNJNwhFHw
AAAEDRgVcMlytLLcmh6JKuSSEdTklVq1IfDO1CRcQSdJqwbCXfgRACB5l7tNxcUpwesXkQ
lwEmczs3bo0kM0k3CEUfAAAADnRlc3RAa2l0dHlwYXNzAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
";
    /// La même chose, chiffrée (bcrypt) par « phrase de test ».
    pub(crate) const ED25519_ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAeTrlugU
hZH2i/vBKn5WgIAAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIM4EbKTh/J2Js97N
WepQJQads7JoQ0lOBZywvsnvVR4uAAAAkEU1W7As8Z8zm/PVaL7ScIFnUw9myRFyXxxS3q
CRsUmwR7I5/rJYDE8wuDwWzSf068bkwUvNuERuxl4b30vvh7gvSWYcZ27GNTyMaCvg+6fe
Kddn+ftQbt249QI3OfqLn2vr+JkRNQ8JKHhk+1n1zUXmpQ5j88nMaWbK9ketUymLNoFDB5
ACAdqBrDRvTNNVmg==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn settings_roundtrip_and_defaults() {
        let s = AgentSettings {
            allow: true,
            add_at_open: true,
            remove_at_close: true,
            confirm: true,
            use_lifetime: true,
            lifetime_secs: 3600,
            use_attachment: true,
            attachment_name: "id_<ed>&25519".into(),
            ..Default::default()
        };
        let xml = s.to_xml();
        assert!(xml.contains("<AttachmentName>id_&lt;ed&gt;&amp;25519</AttachmentName>"));
        assert!(xml.contains("<FileName/>"));
        assert_eq!(AgentSettings::parse(xml.as_bytes()).unwrap(), s);
        assert_eq!(AgentSettings::parse(AgentSettings::default().to_xml().as_bytes()).unwrap(), AgentSettings::default());
    }

    #[test]
    fn settings_from_keeagent_utf16() {
        // KeeAgent (Windows) écrit en UTF-16 avec BOM.
        let xml = "<?xml version=\"1.0\" encoding=\"utf-16\"?><EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey>\
                   <Unknown><Deep>x</Deep></Unknown><Location><SelectedType>file</SelectedType>\
                   <FileName>~/.ssh/id_rsa</FileName></Location></EntrySettings>";
        let mut data = vec![0xff, 0xfe];
        data.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let s = AgentSettings::parse(&data).unwrap();
        assert!(s.allow && !s.use_attachment && !s.add_at_open);
        assert_eq!(s.file_name, "~/.ssh/id_rsa");
    }

    #[test]
    fn settings_refuse_garbage() {
        for bad in [
            &b"pas du xml"[..],
            b"<Autre/>",
            b"<EntrySettings><AllowUseOfSshKey>peut-etre</AllowUseOfSshKey></EntrySettings>",
            b"<EntrySettings><UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding><LifetimeConstraintDuration>0</LifetimeConstraintDuration></EntrySettings>",
            b"<!DOCTYPE x [<!ENTITY a \"b\">]><EntrySettings>&a;</EntrySettings>",
            b"<EntrySettings><Location><FileName>a\x07b</FileName></Location></EntrySettings>",
            b"<EntrySettings>",
            b"<EntrySettings/><EntrySettings/>",
        ] {
            assert!(AgentSettings::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(matches!(AgentSettings::parse(&vec![b' '; MAX_SETTINGS_BYTES + 1]), Err(Error::TooLarge)));
    }

    #[test]
    fn keys() {
        let info = key_info(ED25519.as_bytes()).unwrap();
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(!info.encrypted);
        // Même empreinte que `ssh-keygen -l`.
        assert_eq!(info.fingerprint, "SHA256:nZCTEhwQZP3QEe/+MB7A/vUy8WXSwqLzYTzL7ziqa9c");
        assert!(info.public_key.starts_with("ssh-ed25519 AAAA"));
        let k = load_key(ED25519.as_bytes(), "", "repli").unwrap();
        assert_eq!(k.comment, "test@kittypass");
        assert_eq!(k.fingerprint, info.fingerprint);
        // Format d'ajout : type, clé publique (32), privée (64), commentaire.
        assert_eq!(&k.private[..15], b"\0\0\0\x0bssh-ed25519");
        assert_eq!(k.private.len(), 15 + 36 + 68 + 4 + "test@kittypass".len());
        assert!(load_key(b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n", "", "")
            .unwrap_err()
            .to_string()
            .contains("ssh-keygen -p"));
        assert!(load_key(b"bonjour", "", "").is_err());
        assert!(load_key(&[0xff; 10], "", "").is_err());
        assert!(load_key(&vec![b'a'; MAX_KEY_BYTES + 1], "", "").is_err());
        let enc = key_info(ED25519_ENCRYPTED.as_bytes()).unwrap();
        assert!(enc.encrypted);
        assert_eq!(enc.comment, "");
        assert_eq!(public_blob(ED25519_ENCRYPTED.as_bytes()).unwrap(), load_key(ED25519_ENCRYPTED.as_bytes(), "phrase de test", "").unwrap().public_blob);
        assert!(load_key(ED25519_ENCRYPTED.as_bytes(), "", "").unwrap_err().to_string().contains("pas de mot de passe"));
        assert!(load_key(ED25519_ENCRYPTED.as_bytes(), "mauvaise", "").unwrap_err().to_string().contains("incorrecte"));
        let k = load_key(ED25519_ENCRYPTED.as_bytes(), "phrase de test", "Serveur\n").unwrap();
        // Le commentaire est dans la partie chiffrée.
        assert_eq!(k.comment, "chiffree");
        assert_eq!(k.fingerprint, enc.fingerprint);
        let truncated = &ED25519[..ED25519.len() / 2];
        assert!(load_key(truncated.as_bytes(), "", "").is_err());
    }

    #[test]
    fn agent_messages() {
        let k = load_key(ED25519.as_bytes(), "", "").unwrap();
        let plain = agent::add(&k, false, None);
        assert_eq!(plain[4], 17);
        assert_eq!(u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize, plain.len() - 4);
        let c = agent::add(&k, true, Some(60));
        assert_eq!(c[4], 25);
        assert_eq!(&c[c.len() - 6..], &[1, 0, 0, 0, 60, 2]);
        let r = agent::remove(&k.public_blob);
        assert_eq!(r[4], 18);
        assert_eq!(&r[9..], &k.public_blob[..]);

        let mut answer = vec![12, 0, 0, 0, 1];
        answer.extend_from_slice(&(k.public_blob.len() as u32).to_be_bytes());
        answer.extend_from_slice(&k.public_blob);
        answer.extend_from_slice(&[0, 0, 0, 2, b'h', b'i']);
        assert_eq!(agent::parse_identities(&answer).unwrap(), vec![(k.public_blob.clone(), "hi".into())]);
        // Tronqué, compte mensonger, octets en trop : refusé.
        assert!(agent::parse_identities(&answer[..answer.len() - 1]).is_err());
        assert!(agent::parse_identities(&[12, 0xff, 0xff, 0xff, 0xff]).is_err());
        let mut extra = answer.clone();
        extra.push(0);
        assert!(agent::parse_identities(&extra).is_err());
        assert!(agent::parse_status(&[6]).unwrap());
        assert!(!agent::parse_status(&[5]).unwrap());
        assert!(agent::parse_status(&[]).is_err());
        assert!(agent::reply_len([0, 0, 0, 0]).is_err());
        assert!(agent::reply_len([0, 0x10, 0, 0]).is_err());
    }
}
