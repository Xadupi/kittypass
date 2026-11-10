//! Opérations sur le coffre déverrouillé, telles que l'interface les voit :
//! groupes, liste filtrée, fiche d'entrée, attributs, pièces jointes,
//! historique, corbeille, générateur.
//!
//! Règle : aucun secret ne part vers l'interface sans demande explicite
//! (`secret`). Les fiches ne contiennent ni mot de passe, ni lien 2FA, ni
//! valeur d'attribut protégé ; à l'enregistrement, l'interface peut
//! demander de garder ces valeurs sans les avoir jamais reçues.

use serde::{Deserialize, Serialize};
use kittypass_core::{
    Error as CoreError, passgen,
    vault::{CustomField, EntryData, EntrySummary, GroupNode, Vault},
};
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult};

/// Nombre maximal de résultats envoyés à la liste (au-delà, l'interface
/// invite à affiner la recherche).
const MAX_LIST: usize = 5000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub icon: Option<usize>,
    pub entry_count: usize,
    pub is_recycle_bin: bool,
    pub children: Vec<GroupView>,
}

impl From<GroupNode> for GroupView {
    fn from(g: GroupNode) -> Self {
        Self {
            id: g.id,
            name: g.name,
            icon: g.icon,
            entry_count: g.entry_count,
            is_recycle_bin: g.is_recycle_bin,
            children: g.children.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EntryListItem {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub expires: Option<i64>,
    pub expired: bool,
    pub modified: Option<i64>,
}

impl From<EntrySummary> for EntryListItem {
    fn from(s: EntrySummary) -> Self {
        Self {
            id: s.id,
            group_id: s.group_id,
            title: s.title,
            username: s.username,
            url: s.url,
            tags: s.tags,
            expires: s.expires,
            expired: s.expired,
            modified: s.modified,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EntryList {
    pub items: Vec<EntryListItem>,
    /// Vrai si la liste a été tronquée à `MAX_LIST` éléments.
    pub truncated: bool,
}

/// Attribut tel qu'affiché : la valeur d'un attribut protégé n'est pas
/// envoyée (`value: None`), elle se demande avec `secret`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CustomView {
    pub key: String,
    pub value: Option<String>,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistoryView {
    pub index: usize,
    pub modified: Option<i64>,
    pub title: String,
    pub username: String,
    pub url: String,
}

/// Fiche d'une entrée pour affichage/édition, sans aucun secret.
#[derive(Debug, Clone, Serialize)]
pub struct EntryView {
    pub id: String,
    pub group_id: String,
    pub in_recycle_bin: bool,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub has_totp: bool,
    pub tags: Vec<String>,
    pub expires: Option<i64>,
    pub custom: Vec<CustomView>,
    pub attachments: Vec<AttachmentView>,
    pub history: Vec<HistoryView>,
}

/// Attribut envoyé par l'interface. `value: None` garde la valeur actuelle
/// de l'attribut `original_key` (ou `key`) : c'est ainsi qu'un attribut
/// protégé, dont l'interface n'a jamais reçu la valeur, est conservé ou
/// renommé.
#[derive(Deserialize)]
pub struct CustomInput {
    pub key: String,
    pub value: Option<Zeroizing<String>>,
    #[serde(default)]
    pub protected: bool,
    #[serde(default)]
    pub original_key: Option<String>,
}

#[derive(Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: Zeroizing<String>,
    pub otp: Option<Zeroizing<String>>,
    /// Modification : garder le lien 2FA existant (jamais renvoyé à l'interface).
    #[serde(default)]
    pub keep_otp: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub expires: Option<i64>,
    /// `None` : garder les attributs actuels tels quels.
    #[serde(default)]
    pub custom: Option<Vec<CustomInput>>,
}

impl EntryInput {
    /// Données à écrire, en reprenant de `current` ce que l'interface a
    /// demandé de garder.
    fn into_data(self, current: Option<&EntryData>) -> AppResult<EntryData> {
        let otp = if self.keep_otp {
            current.and_then(|c| c.otp.clone())
        } else {
            self.otp.filter(|o| !o.trim().is_empty())
        };
        let custom = match self.custom {
            None => current.map(|c| c.custom.clone()).unwrap_or_default(),
            Some(list) => list
                .into_iter()
                .map(|c| {
                    let value = match c.value {
                        Some(v) => v,
                        None => {
                            let from = c.original_key.as_deref().unwrap_or(&c.key);
                            current
                                .and_then(|cur| cur.custom.iter().find(|f| f.key == from))
                                .map(|f| f.value.clone())
                                .ok_or(CoreError::InvalidArgument("valeur d'attribut manquante"))?
                        }
                    };
                    Ok(CustomField { key: c.key, value, protected: c.protected })
                })
                .collect::<AppResult<_>>()?,
        };
        Ok(EntryData {
            title: self.title,
            username: self.username,
            password: self.password,
            url: self.url,
            notes: self.notes,
            otp,
            custom,
            tags: self.tags,
            expires: self.expires,
        })
    }
}

/// Valeur demandée explicitement (affichage ou copie).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretField {
    Password,
    Username,
    Url,
    Totp,
    /// Valeur d'un attribut personnalisé (protégé ou non).
    Custom(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpView {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

/// Options du générateur, telles que l'interface les envoie.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum GeneratorOptions {
    Password {
        length: usize,
        lower: bool,
        upper: bool,
        digits: bool,
        symbols: bool,
        #[serde(default)]
        extended: bool,
        #[serde(default)]
        exclude_ambiguous: bool,
        #[serde(default)]
        include: String,
        #[serde(default)]
        exclude: String,
        #[serde(default = "yes")]
        every_group: bool,
    },
    Passphrase {
        words: usize,
        separator: String,
        #[serde(default)]
        case: WordCaseInput,
    },
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WordCaseInput {
    #[default]
    Lower,
    Upper,
    Title,
}

#[derive(Debug, Clone, Serialize)]
pub struct Generated {
    pub value: Zeroizing<String>,
    /// Entropie estimée en bits.
    pub entropy: f64,
}

fn entry_view(v: &Vault, id: &str) -> AppResult<EntryView> {
    let e = v.get(id)?;
    let summary = v.summary(id)?;
    let in_recycle_bin = v.entry_in_recycle_bin(id)?;
    Ok(EntryView {
        id: id.to_owned(),
        group_id: summary.group_id,
        in_recycle_bin,
        title: e.title,
        username: e.username,
        url: e.url,
        notes: e.notes.to_string(),
        has_totp: e.otp.is_some(),
        tags: e.tags,
        expires: e.expires,
        custom: e
            .custom
            .iter()
            .map(|c| CustomView {
                key: c.key.clone(),
                value: (!c.protected).then(|| c.value.to_string()),
                protected: c.protected,
            })
            .collect(),
        attachments: v
            .attachments(id)?
            .into_iter()
            .map(|a| AttachmentView { name: a.name, size: a.size })
            .collect(),
        history: v
            .history(id)?
            .into_iter()
            .map(|h| HistoryView { index: h.index, modified: h.modified, title: h.title, username: h.username, url: h.url })
            .collect(),
    })
}

fn secret_of(data: &EntryData, field: &SecretField) -> AppResult<Zeroizing<String>> {
    Ok(match field {
        SecretField::Password => data.password.clone(),
        SecretField::Username => Zeroizing::new(data.username.clone()),
        SecretField::Url => Zeroizing::new(data.url.clone()),
        SecretField::Totp => unreachable!("traité à part"),
        SecretField::Custom(key) => data
            .custom
            .iter()
            .find(|c| &c.key == key)
            .map(|c| c.value.clone())
            .ok_or(CoreError::InvalidArgument("attribut inconnu"))?,
    })
}

impl App {
    pub(crate) async fn read<T>(&self, f: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        self.touch();
        let inner = self.inner.lock().await;
        f(inner.vault.as_ref().ok_or(AppError::Locked)?)
    }

    /// Modifie le coffre puis l'enregistre sur le disque.
    pub(crate) async fn write<T>(&self, f: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        self.touch();
        let mut inner = self.inner.lock().await;
        let out = f(inner.vault.as_mut().ok_or(AppError::Locked)?)?;
        self.persist(&inner)?;
        Ok(out)
    }

    // ---------- Groupes ----------

    pub async fn groups(&self) -> AppResult<GroupView> {
        self.read(|v| Ok(v.groups().into())).await
    }

    pub async fn tags(&self) -> AppResult<Vec<(String, usize)>> {
        self.read(|v| Ok(v.tags())).await
    }

    pub async fn add_group(&self, parent: &str, name: &str) -> AppResult<String> {
        self.write(|v| Ok(v.add_group(parent, name)?)).await
    }

    pub async fn rename_group(&self, id: &str, name: &str) -> AppResult<()> {
        self.write(|v| Ok(v.rename_group(id, name)?)).await
    }

    pub async fn move_group(&self, id: &str, parent: &str) -> AppResult<()> {
        self.write(|v| Ok(v.move_group(id, parent)?)).await
    }

    pub async fn delete_group(&self, id: &str) -> AppResult<()> {
        self.write(|v| Ok(v.delete_group(id)?)).await
    }

    pub async fn restore_group(&self, id: &str) -> AppResult<()> {
        self.write(|v| Ok(v.restore_group(id)?)).await
    }

    pub async fn empty_recycle_bin(&self) -> AppResult<usize> {
        self.write(|v| Ok(v.empty_recycle_bin()?)).await
    }

    // ---------- Entrées ----------

    /// Liste : contenu direct d'un groupe si la requête est vide, sinon
    /// recherche (dans `group` et ses sous-groupes, ou dans tout le coffre).
    pub async fn entries(&self, query: &str, group: Option<&str>) -> AppResult<EntryList> {
        self.read(|v| {
            let q = query.trim();
            let list = match (q.is_empty(), group) {
                (true, Some(g)) => v.entries_in(g)?,
                (true, None) => v.list(),
                (false, Some(g)) => v.search_in(g, q)?,
                (false, None) => v.search(q)?,
            };
            let truncated = list.len() > MAX_LIST;
            Ok(EntryList { items: list.into_iter().take(MAX_LIST).map(Into::into).collect(), truncated })
        })
        .await
    }

    pub async fn entry(&self, id: &str) -> AppResult<EntryView> {
        self.read(|v| entry_view(v, id)).await
    }

    /// Version passée d'une entrée (fiche sans secret ni historique).
    pub async fn history_entry(&self, id: &str, index: usize) -> AppResult<EntryView> {
        self.read(|v| {
            let e = v.history_entry(id, index)?;
            let current = entry_view(v, id)?;
            Ok(EntryView {
                title: e.title,
                username: e.username,
                url: e.url,
                notes: e.notes.to_string(),
                has_totp: e.otp.is_some(),
                tags: e.tags,
                expires: e.expires,
                custom: e
                    .custom
                    .iter()
                    .map(|c| CustomView {
                        key: c.key.clone(),
                        value: (!c.protected).then(|| c.value.to_string()),
                        protected: c.protected,
                    })
                    .collect(),
                attachments: Vec::new(),
                history: Vec::new(),
                ..current
            })
        })
        .await
    }

    /// Valeur d'un champ, pour copie ou affichage à la demande. `history`
    /// désigne une version passée.
    pub async fn secret(&self, id: &str, field: SecretField, history: Option<usize>) -> AppResult<Zeroizing<String>> {
        self.read(|v| {
            if field == SecretField::Totp {
                if history.is_some() {
                    return Err(CoreError::InvalidArgument("code 2FA d'une ancienne version").into());
                }
                return Ok(Zeroizing::new(v.totp(id)?.ok_or(AppError::NoTotp)?.code));
            }
            let data = match history {
                Some(i) => v.history_entry(id, i)?,
                None => v.get(id)?,
            };
            secret_of(&data, &field)
        })
        .await
    }

    pub async fn totp(&self, id: &str) -> AppResult<TotpView> {
        let inner = self.inner.lock().await;
        let c = inner.vault.as_ref().ok_or(AppError::Locked)?.totp(id)?.ok_or(AppError::NoTotp)?;
        Ok(TotpView { code: c.code, remaining: c.remaining, period: c.period })
    }

    /// Ajoute une entrée dans `group` (racine si absent).
    pub async fn add(&self, group: Option<&str>, input: EntryInput) -> AppResult<String> {
        self.write(|v| {
            let data = input.into_data(None)?;
            Ok(match group {
                Some(g) => v.add_in(g, &data)?,
                None => v.add(&data)?,
            })
        })
        .await
    }

    pub async fn update(&self, id: &str, input: EntryInput) -> AppResult<()> {
        self.write(|v| {
            let current = v.get(id)?;
            let data = input.into_data(Some(&current))?;
            Ok(v.update(id, &data)?)
        })
        .await
    }

    /// Copie d'une entrée dans le même groupe, titre suivi de « (copie) ».
    /// Les pièces jointes et l'historique ne sont pas repris.
    pub async fn clone_entry(&self, id: &str) -> AppResult<String> {
        self.write(|v| {
            let mut data = v.get(id)?;
            let group = entry_view(v, id)?.group_id;
            data.title = format!("{} (copie)", data.title);
            Ok(v.add_in(&group, &data)?)
        })
        .await
    }

    /// Remplace les étiquettes d'une entrée.
    pub async fn set_entry_tags(&self, id: &str, tags: Vec<String>) -> AppResult<()> {
        self.write(|v| {
            let mut data = v.get(id)?;
            data.tags = tags;
            Ok(v.update(id, &data)?)
        })
        .await
    }

    /// Fait expirer l'entrée maintenant (comme « Faire expirer » de KeePassXC).
    pub async fn expire_entry(&self, id: &str) -> AppResult<()> {
        self.write(|v| {
            let mut data = v.get(id)?;
            data.expires = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64));
            Ok(v.update(id, &data)?)
        })
        .await
    }

    /// Supprime : corbeille d'abord, définitivement depuis la corbeille.
    pub async fn delete(&self, id: &str) -> AppResult<()> {
        self.write(|v| Ok(v.delete(id)?)).await
    }

    pub async fn restore(&self, id: &str) -> AppResult<()> {
        self.write(|v| Ok(v.restore(id)?)).await
    }

    pub async fn move_entry(&self, id: &str, group: &str) -> AppResult<()> {
        self.write(|v| Ok(v.move_entry(id, group)?)).await
    }

    pub async fn restore_history(&self, id: &str, index: usize) -> AppResult<()> {
        self.write(|v| Ok(v.restore_history(id, index)?)).await
    }

    // ---------- Pièces jointes ----------

    pub async fn add_attachment(&self, id: &str, name: &str, data: &[u8]) -> AppResult<()> {
        self.write(|v| Ok(v.add_attachment(id, name, data)?)).await
    }

    pub async fn attachment(&self, id: &str, name: &str) -> AppResult<Zeroizing<Vec<u8>>> {
        self.read(|v| Ok(v.attachment(id, name)?)).await
    }

    pub async fn remove_attachment(&self, id: &str, name: &str) -> AppResult<()> {
        self.write(|v| Ok(v.remove_attachment(id, name)?)).await
    }

    // ---------- Générateur ----------

    pub fn generate(&self, opts: &GeneratorOptions) -> AppResult<Generated> {
        Ok(match opts.clone() {
            GeneratorOptions::Password {
                length,
                lower,
                upper,
                digits,
                symbols,
                extended,
                exclude_ambiguous,
                include,
                exclude,
                every_group,
            } => {
                let o = passgen::Options {
                    length,
                    lower,
                    upper,
                    digits,
                    symbols,
                    extended,
                    exclude_ambiguous,
                    include,
                    exclude,
                    every_group,
                };
                Generated { value: passgen::generate(&o)?, entropy: passgen::entropy_bits(&o) }
            }
            GeneratorOptions::Passphrase { words, separator, case } => {
                let o = passgen::PassphraseOptions {
                    words,
                    separator,
                    case: match case {
                        WordCaseInput::Lower => passgen::WordCase::Lower,
                        WordCaseInput::Upper => passgen::WordCase::Upper,
                        WordCaseInput::Title => passgen::WordCase::Title,
                    },
                };
                Generated { value: passgen::generate_passphrase(&o)?, entropy: passgen::passphrase_entropy_bits(&o) }
            }
        })
    }
}
