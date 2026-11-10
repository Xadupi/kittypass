//! Coffre KDBX 4 : création, ouverture défensive, entrées, groupes,
//! corbeille, historique, attributs personnalisés et pièces jointes.

mod attachments;
mod autotype;
mod browser;
mod groups;
mod history;
pub mod import;
mod export;
mod report;
mod search;
mod ssh;

pub use browser::{ASSOCIATION_PREFIX, Access, AccessSettings, Association, BrowserCandidate, EXTRA_URL_PREFIX, HIDE_KEY, SETTINGS_KEY};
pub use autotype::{AutoTypeSettings, WindowAssociation};
pub use ssh::{KeySource, SshEntry, SshKeyRef};
pub use attachments::{AttachmentInfo, MAX_ATTACHMENT_BYTES, MAX_TOTAL_ATTACHMENT_BYTES};
pub use groups::{GroupNode, MAX_DEPTH, RECYCLE_BIN_NAME};
pub use history::HistoryItem;
pub use report::{EXCLUDE_FROM_REPORTS, HealthItem, HealthReport, PasswordHash, Quality, Strength, strength};

use chrono::NaiveDateTime;
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig},
    db::{Entry, EntryId, EntryRef, EntryTrack, GroupId, Times, fields},
};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    header::{self, OpenLimits},
    keyfile::KeyFile,
};

/// Longueur minimale du mot de passe maître pour un **nouveau** coffre.
/// Un coffre KeePass existant au mot de passe plus court reste ouvrable.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 10;

/// Paramètres Argon2id des nouveaux coffres : 64 MiB, ouvrable sur téléphone.
const NEW_VAULT_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const NEW_VAULT_ITERATIONS: u64 = 10;
const NEW_VAULT_PARALLELISM: u32 = 2;

/// Champs KeePass standard : gérés par les champs dédiés d'`EntryData`, donc
/// interdits comme noms d'attributs personnalisés.
const STANDARD_FIELDS: [&str; 6] =
    [fields::TITLE, fields::USERNAME, fields::PASSWORD, fields::URL, fields::NOTES, fields::OTP];

/// Attribut personnalisé d'une entrée (« Attributs avancés » de KeePassXC).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CustomField {
    pub key: String,
    pub value: Zeroizing<String>,
    /// Masqué dans l'interface et chiffré en mémoire dans le fichier.
    pub protected: bool,
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomField")
            .field("key", &self.key)
            .field("value", &if self.protected { "<masqué>" } else { self.value.as_str() })
            .field("protected", &self.protected)
            .finish()
    }
}

/// Données d'une entrée, en clair, côté client uniquement.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EntryData {
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: Zeroizing<String>,
    /// URI `otpauth://` (TOTP), protégée comme un mot de passe.
    pub otp: Option<Zeroizing<String>>,
    /// Attributs personnalisés, triés par nom à la lecture.
    pub custom: Vec<CustomField>,
    /// Étiquettes (KeePass 2.x / KeePassXC).
    pub tags: Vec<String>,
    /// Date d'expiration (secondes Unix, UTC), si l'entrée expire.
    pub expires: Option<i64>,
}

impl std::fmt::Debug for EntryData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryData")
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<masqué>")
            .field("url", &self.url)
            .field("notes", &"<masqué>")
            .field("otp", &self.otp.as_ref().map(|_| "<masqué>"))
            .field("custom", &self.custom)
            .field("tags", &self.tags)
            .field("expires", &self.expires)
            .finish()
    }
}

/// Résumé d'une entrée pour les listes : jamais de secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    /// Date d'expiration (secondes Unix, UTC), si l'entrée expire.
    pub expires: Option<i64>,
    pub expired: bool,
    /// Dernière modification (secondes Unix, UTC).
    pub modified: Option<i64>,
}

/// Coffre déverrouillé. Le déposer (`drop`) le verrouille et efface le mot de
/// passe maître de la mémoire.
#[derive(Clone)]
pub struct Vault {
    db: Database,
    key: MasterKey,
    /// Clé d'avant un changement (mot de passe ou fichier clé), gardée en
    /// mémoire seulement, jusqu'à ce que la version distante soit re-chiffrée.
    previous_key: Option<MasterKey>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({} entrées)", self.db.num_entries())
    }
}

/// Clé composite du coffre : mot de passe maître et, en option, fichier clé.
#[derive(Clone)]
pub struct MasterKey {
    password: Zeroizing<String>,
    keyfile: Option<KeyFile>,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey(<masqué>, fichier clé : {})", self.keyfile.is_some())
    }
}

impl MasterKey {
    pub fn new(password: &str, keyfile: Option<KeyFile>) -> Self {
        Self { password: Zeroizing::new(password.to_owned()), keyfile }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn has_keyfile(&self) -> bool {
        self.keyfile.is_some()
    }

    fn database_key(&self) -> DatabaseKey {
        let key = DatabaseKey::new().with_password(&self.password);
        match &self.keyfile {
            // Lire une tranche en mémoire ne peut pas échouer.
            Some(f) => key.with_keyfile(&mut f.bytes()).unwrap_or_default(),
            None => key,
        }
    }
}

fn parse_id(id: &str) -> Result<EntryId> {
    uuid::Uuid::parse_str(id).map(EntryId::from).map_err(|_| Error::InvalidId)
}

fn parse_group_id(id: &str) -> Result<GroupId> {
    uuid::Uuid::parse_str(id).map(GroupId::from).map_err(|_| Error::InvalidId)
}

fn summary(e: &EntryRef<'_>) -> EntrySummary {
    EntrySummary {
        id: e.id().uuid().to_string(),
        group_id: e.parent().id().uuid().to_string(),
        title: e.get_title().unwrap_or_default().to_owned(),
        username: e.get_username().unwrap_or_default().to_owned(),
        url: e.get_url().unwrap_or_default().to_owned(),
        tags: clean_tags(&e.tags),
        expires: expiry(e),
        expired: is_expired(e),
        modified: e.times.last_modification.map(|t| t.and_utc().timestamp()),
    }
}

/// Étiquettes lues d'un fichier : KeePass écrit parfois une balise vide,
/// lue comme une étiquette vide.
fn clean_tags(tags: &[String]) -> Vec<String> {
    tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

fn expiry(e: &Entry) -> Option<i64> {
    (e.times.expires == Some(true)).then(|| e.times.expiry.and_utc().timestamp())
}

fn is_expired(e: &Entry) -> bool {
    e.times.expires == Some(true) && e.times.expiry <= Times::now()
}

/// Bornes des dates KDBX (années 1 à 9999).
const MIN_TIMESTAMP: i64 = -62_135_596_800;
const MAX_TIMESTAMP: i64 = 253_402_300_799;

fn entry_data(e: &Entry) -> EntryData {
    let mut custom: Vec<CustomField> = e
        .fields
        .iter()
        .filter(|(k, _)| !STANDARD_FIELDS.contains(&k.as_str()))
        .map(|(k, v)| CustomField {
            key: k.clone(),
            value: Zeroizing::new(v.get().clone()),
            protected: v.is_protected(),
        })
        .collect();
    custom.sort_by(|a, b| a.key.cmp(&b.key));
    EntryData {
        title: e.get_title().unwrap_or_default().to_owned(),
        username: e.get_username().unwrap_or_default().to_owned(),
        password: Zeroizing::new(e.get_password().unwrap_or_default().to_owned()),
        url: e.get_url().unwrap_or_default().to_owned(),
        notes: Zeroizing::new(e.get(fields::NOTES).unwrap_or_default().to_owned()),
        otp: e.get(fields::OTP).map(|s| Zeroizing::new(s.to_owned())),
        custom,
        tags: clean_tags(&e.tags),
        expires: expiry(e),
    }
}

/// Date de modification strictement postérieure à `prev`. Les dates KDBX sont
/// à la seconde : deux modifications dans la même seconde donneraient deux
/// versions d'historique de même date, ce qui fait échouer la fusion KeePass.
fn next_modification(prev: Option<NaiveDateTime>) -> NaiveDateTime {
    let now = Times::now();
    match prev {
        Some(prev) if prev >= now => prev + chrono::TimeDelta::seconds(1),
        _ => now,
    }
}

fn new_vault_kdf() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: NEW_VAULT_ITERATIONS,
        memory: NEW_VAULT_MEMORY_BYTES,
        parallelism: NEW_VAULT_PARALLELISM,
        version: kdbx_argon2::Version::Version13,
    }
}

/// La bibliothèque n'écrit que le KDBX 4, alors que KeePassXC crée par
/// défaut des fichiers KDBX 3.1 (dérivation AES-KDF) : sans conversion, un
/// tel coffre s'ouvrirait mais ne pourrait jamais être enregistré. On passe
/// au KDBX 4 avec Argon2id (AES-KDF résiste bien moins aux attaques par GPU,
/// et le fichier est stocké sur le serveur) et ChaCha20 pour les champs
/// protégés. KeePassXC lit le résultat sans difficulté.
fn upgrade_format(db: &mut Database) {
    if matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        return;
    }
    db.config.version = DatabaseConfig::default().version;
    db.config.kdf_config = new_vault_kdf();
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
}

impl Vault {
    /// Version du format, pour affichage (« KDBX 4.1 »…).
    pub fn format_version(&self) -> String {
        self.db.config.version.to_string()
    }

    /// Crée un coffre vide, chiffré en Argon2id, avec sa corbeille.
    pub fn create(password: &str) -> Result<Self> {
        Self::create_with_key(&MasterKey::new(password, None))
    }

    /// Crée un coffre protégé par un mot de passe et, en option, un fichier clé.
    pub fn create_with_key(key: &MasterKey) -> Result<Self> {
        if key.password().chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(Error::WeakMasterPassword("10 caractères minimum"));
        }
        let mut db = Database::new();
        db.config.kdf_config = new_vault_kdf();
        db.meta.database_name = Some("KittyPass".into());
        db.meta.history_max_items = Some(history::DEFAULT_MAX_ITEMS as isize);
        db.meta.history_max_size = Some(history::DEFAULT_MAX_BYTES as isize);
        db.root_mut().name = "Racine".into();
        let mut vault = Self { db, key: key.clone(), previous_key: None };
        // Créée dès le départ : les appareils qui rejoignent le coffre
        // partagent ainsi la même corbeille au lieu d'en créer chacun une.
        vault.recycle_bin_id();
        Ok(vault)
    }

    /// Ouvre un fichier KDBX après avoir vérifié sa taille et ses paramètres
    /// de dérivation (protection contre les fichiers piégés).
    pub fn open(data: &[u8], password: &str, limits: &OpenLimits) -> Result<Self> {
        Self::open_with_key(data, &MasterKey::new(password, None), limits)
    }

    /// Comme [`Vault::open`], avec la clé composite complète.
    pub fn open_with_key(data: &[u8], key: &MasterKey, limits: &OpenLimits) -> Result<Self> {
        header::check(data, limits)?;
        // Ceinture et bretelles : une panique de la bibliothèque sur un
        // fichier malformé devient une erreur, pas un plantage.
        let parsed = std::panic::catch_unwind(|| Database::parse(data, key.database_key()))
            .map_err(|_| Error::InvalidKeyOrCorrupted)?;
        let mut db = parsed.map_err(|_| Error::InvalidKeyOrCorrupted)?;
        upgrade_format(&mut db);
        Ok(Self { db, key: key.clone(), previous_key: None })
    }

    /// Sérialise le coffre chiffré (nouveaux sels et IV à chaque appel).
    pub fn save(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.db.save(&mut out, self.key.database_key()).map_err(|_| Error::Save)?;
        Ok(out)
    }

    /// Change le mot de passe maître. Le prochain `save` utilisera le nouveau.
    pub fn change_password(&mut self, current: &str, new: &str) -> Result<()> {
        if !constant_time_eq(current.as_bytes(), self.key.password.as_bytes()) {
            return Err(Error::InvalidKeyOrCorrupted);
        }
        if new.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(Error::WeakMasterPassword("10 caractères minimum"));
        }
        self.remember_previous_key();
        self.key.password = Zeroizing::new(new.to_owned());
        Ok(())
    }

    /// Ajoute, remplace (`Some`) ou retire (`None`) le fichier clé. Le mot de
    /// passe actuel est redemandé. Le prochain `save` utilisera la nouvelle
    /// clé : les autres appareils devront recevoir le même fichier.
    pub fn set_key_file(&mut self, current_password: &str, keyfile: Option<KeyFile>) -> Result<()> {
        if !constant_time_eq(current_password.as_bytes(), self.key.password.as_bytes()) {
            return Err(Error::InvalidKeyOrCorrupted);
        }
        self.remember_previous_key();
        self.key.keyfile = keyfile;
        Ok(())
    }

    /// Garde la clé avec laquelle la version distante est encore chiffrée
    /// (la plus ancienne si plusieurs changements se suivent).
    fn remember_previous_key(&mut self) {
        if self.previous_key.is_none() {
            self.previous_key = Some(self.key.clone());
        }
    }

    /// Clé d'avant le dernier changement, tant qu'il n'est pas synchronisé.
    pub fn previous_master_key(&self) -> Option<&MasterKey> {
        self.previous_key.as_ref()
    }

    /// Le changement de clé est arrivé sur le serveur : l'ancienne est oubliée.
    pub fn forget_previous_key(&mut self) {
        self.previous_key = None;
    }

    /// Annule un changement de clé non synchronisé.
    pub fn revert_key_change(&mut self) {
        if let Some(previous) = self.previous_key.take() {
            self.key = previous;
        }
    }

    pub fn has_key_file(&self) -> bool {
        self.key.has_keyfile()
    }

    /// Clé composite actuelle (pour ouvrir la version distante du coffre).
    pub fn master_key(&self) -> &MasterKey {
        &self.key
    }

    /// Nombre total d'entrées, corbeille comprise.
    pub fn len(&self) -> usize {
        self.db.num_entries()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Toutes les entrées hors corbeille, triées par titre.
    pub fn list(&self) -> Vec<EntrySummary> {
        let bin = self.existing_recycle_bin();
        let mut v: Vec<_> = self
            .db
            .iter_all_entries()
            .filter(|e| bin.is_none_or(|bin| !self.group_is_within(e.parent().id(), bin)))
            .map(|e| summary(&e))
            .collect();
        v.sort_by_key(|a| a.title.to_lowercase());
        v
    }

    /// Étiquettes utilisées hors corbeille, avec leur nombre d'entrées,
    /// triées par nom.
    pub fn tags(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for s in self.list() {
            for t in s.tags {
                *counts.entry(t).or_default() += 1;
            }
        }
        counts.into_iter().collect()
    }

    /// Entrées expirées ou expirant dans les `within_secs` secondes, hors
    /// corbeille, de la plus proche à la plus lointaine.
    pub fn expiring(&self, within_secs: i64) -> Vec<EntrySummary> {
        let limit = Times::now().and_utc().timestamp().saturating_add(within_secs);
        let mut v: Vec<_> = self.list().into_iter().filter(|s| s.expires.is_some_and(|t| t <= limit)).collect();
        v.sort_by_key(|s| s.expires);
        v
    }

    pub fn get(&self, id: &str) -> Result<EntryData> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        Ok(entry_data(&e))
    }

    /// Ajoute une entrée au groupe racine.
    pub fn add(&mut self, data: &EntryData) -> Result<String> {
        let root = self.db.root().id().uuid().to_string();
        self.add_in(&root, data)
    }

    /// Ajoute une entrée dans le groupe `group_id`.
    pub fn add_in(&mut self, group_id: &str, data: &EntryData) -> Result<String> {
        validate(data, None)?;
        let gid = parse_group_id(group_id)?;
        let mut group = self.db.group_mut(gid).ok_or(Error::GroupNotFound)?;
        let mut entry = group.add_entry();
        apply(&mut entry, data);
        Ok(entry.id().uuid().to_string())
    }

    /// Modifie une entrée. L'ancienne version est conservée dans l'historique
    /// KeePass (utile pour la fusion et pour revenir en arrière).
    pub fn update(&mut self, id: &str, data: &EntryData) -> Result<()> {
        let eid = parse_id(id)?;
        let current = entry_data(&*self.db.entry(eid).ok_or(Error::EntryNotFound)?);
        validate(data, Some(&current))?;
        self.edit_entry(eid, |t| apply(t, data))
    }

    /// Applique `f` à une entrée en archivant sa version actuelle dans
    /// l'historique, puis élague l'historique et les pièces jointes orphelines.
    /// `f` ne doit pas échouer : tout est validé avant.
    fn edit_entry<T>(&mut self, id: EntryId, f: impl FnOnce(&mut EntryTrack<'_>) -> T) -> Result<T> {
        let mut entry = self.db.entry_mut(id).ok_or(Error::EntryNotFound)?;
        let modified = next_modification(entry.times.last_modification);
        let out = {
            let mut t = entry.track_changes();
            let out = f(&mut t);
            t.times.last_modification = Some(modified);
            out
        };
        self.trim_history(id);
        self.db.remove_unused_attachments();
        Ok(out)
    }

    /// Fusionne `other` (autre version du même coffre) dans ce coffre, par
    /// UUID : la modification la plus récente gagne, l'autre va dans
    /// l'historique, les suppressions sont propagées. Renvoie le nombre de
    /// changements appliqués.
    pub fn merge_from(&mut self, other: &Vault) -> Result<usize> {
        // Deux coffres créés séparément n'ont pas le même groupe racine : la
        // bibliothèque KeePass panique dans ce cas au lieu de renvoyer une erreur.
        if self.db.root().id() != other.db.root().id() {
            return Err(Error::DifferentVault);
        }
        // Fusion sur une copie : si la bibliothèque panique malgré tout, le
        // coffre courant reste intact (jamais à moitié fusionné).
        let mut merged = self.db.clone();
        let log = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| merged.merge(&other.db)))
            .map_err(|_| Error::MergeFailed)?
            .map_err(|_| Error::MergeFailed)?;
        groups::settle_recycle_bin(&mut merged, &other.db);
        Self::merge_meta_custom_data(&mut merged, &other.db);
        self.db = merged;
        Ok(log.events.len())
    }

    /// Code TOTP courant d'une entrée, si elle en a un.
    pub fn totp(&self, id: &str) -> Result<Option<crate::otp::Code>> {
        let e = self.db.entry(parse_id(id)?).ok_or(Error::EntryNotFound)?;
        match e.get(fields::OTP) {
            Some(uri) => Ok(Some(crate::otp::Totp::parse(uri)?.code_now())),
            None => Ok(None),
        }
    }

    /// Mot de passe maître (= mot de passe du compte), pour se reconnecter
    /// au serveur sans le redemander tant que le coffre est déverrouillé.
    pub fn password(&self) -> &str {
        self.key.password()
    }

    /// UUID des objets supprimés définitivement (pour les tests de fusion).
    pub fn deleted_ids(&self) -> Vec<String> {
        self.db.deleted_objects.keys().map(|u| u.to_string()).collect()
    }
}

fn apply(e: &mut Entry, data: &EntryData) {
    e.tags = data.tags.clone();
    match data.expires.and_then(|t| chrono::DateTime::from_timestamp(t, 0)) {
        Some(t) => {
            e.times.expires = Some(true);
            e.times.expiry = t.naive_utc();
        }
        None => e.times.expires = Some(false),
    }
    e.set_unprotected(fields::TITLE, data.title.as_str());
    e.set_unprotected(fields::USERNAME, data.username.as_str());
    e.set_protected(fields::PASSWORD, data.password.as_str());
    e.set_unprotected(fields::URL, data.url.as_str());
    e.set_protected(fields::NOTES, data.notes.as_str());
    match &data.otp {
        Some(otp) => e.set_protected(fields::OTP, otp.as_str()),
        None => {
            e.fields.remove(fields::OTP);
        }
    }
    e.fields
        .retain(|k, _| STANDARD_FIELDS.contains(&k.as_str()) || data.custom.iter().any(|c| &c.key == k));
    for c in &data.custom {
        if c.protected {
            e.set_protected(c.key.as_str(), c.value.as_str());
        } else {
            e.set_unprotected(c.key.as_str(), c.value.as_str());
        }
    }
}

/// Limites de taille par champ : évite qu'un client gonfle le coffre jusqu'à
/// dépasser la limite d'ouverture des autres appareils.
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_NOTES_BYTES: usize = 1024 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_CUSTOM_FIELDS: usize = 256;
const MAX_TAGS: usize = 64;
const MAX_TAG_BYTES: usize = 128;

/// Caractère interdit en XML 1.0 (le fichier deviendrait illisible par
/// KeePass) : contrôles hors tab/retours, U+FFFE et U+FFFF.
fn invalid_xml_char(c: char) -> bool {
    (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{FFFE}' | '\u{FFFF}')
}

/// Contrôles de direction et caractères invisibles : dans un nom affiché
/// (groupe, attribut, pièce jointe), ils permettent de déguiser par exemple
/// « facture[U+202E]fdp.exe », qui s'affiche « factureexe.pdf ».
fn spoofing_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Valide un nom affiché (groupe, attribut, pièce jointe).
fn validate_name(name: &str, what: &'static str) -> Result<()> {
    if name.trim().is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(|c| c.is_control() || invalid_xml_char(c) || spoofing_char(c))
    {
        return Err(Error::InvalidArgument(what));
    }
    Ok(())
}

/// Valide une entrée avant écriture. `prev` est la version actuelle lors
/// d'une modification : une valeur reprise telle quelle n'est pas
/// revérifiée, sinon une entrée venue d'un autre logiciel KeePass, aux
/// règles plus souples, ne pourrait plus être modifiée du tout.
fn validate(d: &EntryData, prev: Option<&EntryData>) -> Result<()> {
    let p = prev.cloned().unwrap_or_default();
    let fields = [
        (&d.title, &p.title, MAX_FIELD_BYTES),
        (&d.username, &p.username, MAX_FIELD_BYTES),
        (&d.url, &p.url, MAX_FIELD_BYTES),
        (&*d.password, &*p.password, MAX_FIELD_BYTES),
        (&*d.notes, &*p.notes, MAX_NOTES_BYTES),
    ];
    for (new, old, max) in fields {
        if prev.is_some() && new == old {
            continue;
        }
        if new.len() > max {
            return Err(Error::InvalidArgument("champ trop long"));
        }
        if new.chars().any(invalid_xml_char) {
            return Err(Error::InvalidArgument("caractère de contrôle interdit"));
        }
    }
    if let Some(otp) = &d.otp
        && (prev.is_none() || p.otp.as_ref() != Some(otp))
    {
        crate::otp::Totp::parse(otp)?;
    }
    if d.tags.len() > MAX_TAGS.max(p.tags.len()) {
        return Err(Error::InvalidArgument("trop d'étiquettes"));
    }
    for (i, t) in d.tags.iter().enumerate() {
        if p.tags.contains(t) {
            continue;
        }
        validate_name(t, "étiquette invalide")?;
        // `;` et `,` séparent les étiquettes dans le fichier KeePass ; des
        // espaces autour seraient perdus à la relecture.
        if t.len() > MAX_TAG_BYTES || t.contains([';', ',']) || t.trim() != t {
            return Err(Error::InvalidArgument("étiquette invalide"));
        }
        if d.tags.iter().enumerate().any(|(j, o)| j != i && o.to_lowercase() == t.to_lowercase()) {
            return Err(Error::InvalidArgument("étiquette en double"));
        }
    }
    if let Some(t) = d.expires
        && !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&t)
    {
        return Err(Error::InvalidArgument("date d'expiration hors limites"));
    }
    if d.custom.len() > MAX_CUSTOM_FIELDS.max(p.custom.len()) {
        return Err(Error::InvalidArgument("trop d'attributs"));
    }
    for (i, c) in d.custom.iter().enumerate() {
        // Deux attributs de même nom écraseraient l'un l'autre : toujours
        // refusé, même pour des valeurs reprises.
        if d.custom[..i].iter().any(|o| o.key == c.key) {
            return Err(Error::InvalidArgument("attribut en double"));
        }
        if p.custom.contains(c) {
            continue;
        }
        validate_name(&c.key, "nom d'attribut invalide")?;
        if STANDARD_FIELDS.iter().any(|s| s.eq_ignore_ascii_case(&c.key)) {
            return Err(Error::InvalidArgument("nom d'attribut réservé"));
        }
        if c.value.len() > MAX_NOTES_BYTES {
            return Err(Error::InvalidArgument("attribut trop long"));
        }
        if c.value.chars().any(invalid_xml_char) {
            return Err(Error::InvalidArgument("caractère de contrôle interdit"));
        }
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
