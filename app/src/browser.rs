//! Traitement des requêtes de l'extension KeePassXC-Browser.
//!
//! Règles de sécurité :
//! - le canal est chiffré (clé éphémère par connexion) mais n'authentifie
//!   rien à lui seul : toute action sur le coffre exige qu'une association
//!   (clé enregistrée après accord de l'utilisateur) ait été prouvée sur la
//!   connexion (`associate`, `test-associate` ou `keys` de `get-logins`) ;
//! - un identifiant n'est jamais donné à un site sans accord : réglage
//!   « Autoriser » de l'entrée, ou confirmation (avec « Se souvenir ») ;
//! - les codes 2FA et les mises à jour ne portent que sur des entrées déjà
//!   remises sur cette connexion ; toute mise à jour est confirmée ;
//! - une seule demande de confirmation à la fois, abandonnée au bout d'un
//!   délai (refus) ;
//! - les requêtes du navigateur ne repoussent pas le verrouillage
//!   automatique (seules les réponses de l'utilisateur le font).

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    time::Duration,
};

use kittypass_core::{
    browser::{
        crypto::Session,
        matching,
        passkeys::{self, Passkey},
        protocol::{self, Envelope, ErrorCode, encrypted_reply, error_reply, key_exchange_reply, open_request, str_field},
    },
    passgen,
    vault::{Access, EntryData, GroupNode, Vault},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult};

/// Groupe des identifiants enregistrés depuis le navigateur (nom de
/// KeePassXC, pour retrouver le même groupe dans un coffre partagé).
pub const BROWSER_GROUP: &str = "KeePassXC-Browser Passwords";

/// Délai laissé à l'utilisateur pour répondre à une confirmation.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

const MAX_URL_LEN: usize = 2048;
const MAX_MATCHES: usize = 50;
const MAX_RELEASED: usize = 1024;
const MAX_GROUP_PATH_DEPTH: usize = 8;

/// Entrée montrée dans une confirmation (jamais de secret).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PromptEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub group: String,
}

/// Question posée à l'utilisateur par l'interface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Prompt {
    /// Un navigateur demande à être associé : l'utilisateur lui donne un nom.
    Associate,
    /// Un site demande des identifiants qui ne lui sont pas encore permis.
    Access { host: String, submit_host: Option<String>, entries: Vec<PromptEntry> },
    /// Mise à jour d'une entrée depuis le navigateur.
    UpdateLogin { host: String, entry: PromptEntry, username: String },
    /// Création d'une passkey.
    CreatePasskey { rp_id: String, rp_name: String, user_name: String },
    /// Connexion par passkey : choix du compte.
    UsePasskey { rp_id: String, entries: Vec<PromptEntry> },
}

/// Réponse de l'utilisateur.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    Associate { name: String },
    Access { allowed: Vec<String>, remember: bool },
    Confirm { ok: bool },
    Choose { id: String },
}

/// Interface qui pose les questions (fenêtre de l'application de bureau).
pub trait Prompter: Send + Sync {
    /// Pose la question ; `None` = fenêtre fermée ou abandon.
    fn ask(&self, prompt: Prompt) -> impl Future<Output = Option<Answer>> + Send;
    /// L'extension demande d'afficher le déverrouillage (`triggerUnlock`).
    fn unlock_requested(&self) {}
    /// Le coffre vient d'être verrouillé à la demande du navigateur.
    fn locked(&self) {}
}

/// État d'une connexion avec une instance de l'extension.
pub struct BrowserConnection {
    session: Session,
    client_id: Option<String>,
    /// Une association a été prouvée sur cette connexion.
    associated: bool,
    /// Entrées remises au navigateur sur cette connexion (UUID normalisés).
    released: HashSet<String>,
    released_order: VecDeque<String>,
}

impl BrowserConnection {
    pub fn new() -> AppResult<Self> {
        Ok(Self {
            session: Session::new()?,
            client_id: None,
            associated: false,
            released: HashSet::new(),
            released_order: VecDeque::new(),
        })
    }

    fn release(&mut self, id: &str) {
        let id = norm_id(id);
        if self.released.insert(id.clone()) {
            self.released_order.push_back(id);
            if self.released_order.len() > MAX_RELEASED
                && let Some(old) = self.released_order.pop_front()
            {
                self.released.remove(&old);
            }
        }
    }

    fn was_released(&self, id: &str) -> bool {
        self.released.contains(&norm_id(id))
    }
}

/// UUID sans tirets, en minuscules (format de KeePassXC).
fn norm_id(id: &str) -> String {
    id.chars().filter(|c| *c != '-').collect::<String>().to_ascii_lowercase()
}

/// Comparaison en temps constant (pour la longueur donnée).
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Adresse sans requête ni fragment (des jetons s'y trouvent souvent).
fn clean_url(url: &str) -> Option<String> {
    let mut u = matching::parse_page(url)?;
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

fn prompt_entry(id: &str, title: &str, username: &str, group: &str) -> PromptEntry {
    PromptEntry { id: id.to_owned(), title: title.to_owned(), username: username.to_owned(), group: group.to_owned() }
}

fn find_group<'a>(node: &'a GroupNode, name: &str) -> Option<&'a GroupNode> {
    node.children.iter().find(|g| !g.is_recycle_bin && g.name == name)
}

fn group_json(g: &GroupNode, depth: usize) -> Value {
    let children: Vec<Value> = if depth >= kittypass_core::vault::MAX_DEPTH {
        vec![]
    } else {
        g.children.iter().filter(|c| !c.is_recycle_bin).map(|c| group_json(c, depth + 1)).collect()
    };
    json!({ "name": g.name, "uuid": norm_id(&g.id), "children": children })
}

fn contains_group(node: &GroupNode, id: &str) -> bool {
    !node.is_recycle_bin && (norm_id(&node.id) == norm_id(id) || node.children.iter().any(|c| contains_group(c, id)))
}

/// Groupe `path` (« a/b/c ») sous la racine, créé au besoin.
fn ensure_group_path(v: &mut Vault, path: &str) -> AppResult<String> {
    let parts: Vec<&str> = path.split('/').map(str::trim).filter(|p| !p.is_empty()).collect();
    if parts.is_empty() || parts.len() > MAX_GROUP_PATH_DEPTH {
        return Err(kittypass_core::Error::InvalidArgument("nom de groupe invalide").into());
    }
    let mut parent = v.root_id();
    for part in parts {
        let tree = v.groups();
        let node = find_node(&tree, &parent).ok_or(kittypass_core::Error::GroupNotFound)?;
        parent = match find_group(node, part) {
            Some(g) => g.id.clone(),
            None => v.add_group(&parent, part)?,
        };
    }
    Ok(parent)
}

fn find_node<'a>(node: &'a GroupNode, id: &str) -> Option<&'a GroupNode> {
    if node.id == id {
        return Some(node);
    }
    node.children.iter().find_map(|c| find_node(c, id))
}

type Reply = std::result::Result<Map<String, Value>, ErrorCode>;

impl App {
    /// Lecture du coffre sans repousser le verrouillage automatique.
    async fn quiet_read<T>(&self, f: impl FnOnce(&Vault) -> AppResult<T>) -> AppResult<T> {
        let inner = self.inner.lock().await;
        f(inner.vault.as_ref().ok_or(AppError::Locked)?)
    }

    /// Modification du coffre (enregistrée) sans repousser le verrouillage.
    async fn quiet_write<T>(&self, f: impl FnOnce(&mut Vault) -> AppResult<T>) -> AppResult<T> {
        let mut inner = self.inner.lock().await;
        let out = f(inner.vault.as_mut().ok_or(AppError::Locked)?)?;
        self.persist(&inner)?;
        Ok(out)
    }

    /// Pose une question, une seule à la fois, avec délai.
    async fn ask<P: Prompter>(&self, p: &P, prompt: Prompt) -> Option<Answer> {
        let _one = self.browser_prompt.lock().await;
        let answer = tokio::time::timeout(PROMPT_TIMEOUT, p.ask(prompt)).await.ok().flatten();
        if answer.is_some() {
            self.touch();
        }
        answer
    }

    /// Traite une requête brute de l'extension et renvoie la réponse à lui
    /// transmettre.
    pub async fn browser_request<P: Prompter>(&self, conn: &mut BrowserConnection, raw: &[u8], prompter: &P) -> Value {
        let env = match Envelope::parse(raw) {
            Ok(e) => e,
            Err(_) => return error_reply("", ErrorCode::EmptyMessageReceived),
        };
        let action = env.action.clone();
        if action == "change-public-keys" {
            return self.key_exchange(conn, &env);
        }
        if !conn.session.has_peer() {
            return error_reply(&action, ErrorCode::ClientPublicKeyNotReceived);
        }
        if env.client_id.is_some() && env.client_id != conn.client_id {
            return error_reply(&action, ErrorCode::EncryptionKeyUnrecognized);
        }
        let Ok(nonce) = env.nonce() else { return error_reply(&action, ErrorCode::CannotDecryptMessage) };
        let Ok(msg) = open_request(&mut conn.session, &env) else {
            return error_reply(&action, ErrorCode::CannotDecryptMessage);
        };
        let locked = self.inner.lock().await.vault.is_none();
        let needs_vault = action != "generate-password";
        if locked && needs_vault {
            if env.wants_unlock() {
                prompter.unlock_requested();
            }
            return error_reply(&action, ErrorCode::DatabaseNotOpened);
        }
        let result = match action.as_str() {
            "get-databasehash" => self.database_hash().await,
            "associate" => self.associate(conn, &msg, prompter).await,
            "test-associate" => self.test_associate(conn, &msg).await,
            "generate-password" => Self::generate_password(),
            "get-logins" => self.get_logins(conn, &msg, prompter).await,
            _ if !conn.associated => Err(ErrorCode::AssociationFailed),
            "set-login" => self.set_login(conn, &msg, prompter).await,
            "get-totp" => self.get_totp(conn, &msg).await,
            "get-database-groups" => self.database_groups().await,
            "create-new-group" => self.create_group(&msg).await,
            "lock-database" => Ok(Map::new()),
            "passkeys-register" => Ok(self.passkeys_register(&msg, prompter).await),
            "passkeys-get" => Ok(self.passkeys_get(conn, &msg, prompter).await),
            _ => Err(ErrorCode::IncorrectAction),
        };
        let reply = match result {
            Ok(inner) => encrypted_reply(&conn.session, &action, &nonce, env.request_id.as_deref(), inner)
                .unwrap_or_else(|_| error_reply(&action, ErrorCode::Unknown)),
            Err(code) => error_reply(&action, code),
        };
        if action == "lock-database" && conn.associated {
            self.lock().await;
            prompter.locked();
        }
        reply
    }

    fn key_exchange(&self, conn: &mut BrowserConnection, env: &Envelope) -> Value {
        let action = &env.action;
        let (Some(pk), Ok(nonce), Some(client)) = (env.public_key.as_deref(), env.nonce(), env.client_id.as_deref()) else {
            return error_reply(action, ErrorCode::ClientPublicKeyNotReceived);
        };
        if client.is_empty() || client.len() > 128 || conn.session.set_peer(pk).is_err() {
            return error_reply(action, ErrorCode::KeyChangeFailed);
        }
        conn.client_id = Some(client.to_owned());
        // Nouvelle clé : l'association doit être prouvée à nouveau.
        conn.associated = false;
        conn.released.clear();
        conn.released_order.clear();
        key_exchange_reply(&conn.session, &nonce)
    }

    async fn database_hash(&self) -> Reply {
        let hash = self.quiet_read(|v| Ok(v.browser_hash())).await.map_err(|_| ErrorCode::DatabaseNotOpened)?;
        let mut m = Map::new();
        m.insert("hash".into(), hash.into());
        Ok(m)
    }

    async fn associate<P: Prompter>(&self, conn: &mut BrowserConnection, msg: &Map<String, Value>, p: &P) -> Reply {
        let (Some(key), Some(id_key)) = (str_field(msg, "key"), str_field(msg, "idKey")) else {
            return Err(ErrorCode::AssociationFailed);
        };
        // La clé annoncée doit être celle de cette connexion.
        if !ct_eq(key, &conn.session.peer_public_key_b64().unwrap_or_default()) {
            return Err(ErrorCode::AssociationFailed);
        }
        let Some(Answer::Associate { name }) = self.ask(p, Prompt::Associate).await else {
            return Err(ErrorCode::ActionCancelledOrDenied);
        };
        let name = name.trim().to_owned();
        let id_key = id_key.to_owned();
        let saved = name.clone();
        let hash = self
            .quiet_write(move |v| {
                v.browser_associate(&saved, &id_key)?;
                Ok(v.browser_hash())
            })
            .await
            .map_err(|_| ErrorCode::AssociationFailed)?;
        conn.associated = true;
        let mut m = Map::new();
        m.insert("hash".into(), hash.into());
        m.insert("id".into(), name.into());
        Ok(m)
    }

    async fn test_associate(&self, conn: &mut BrowserConnection, msg: &Map<String, Value>) -> Reply {
        let (Some(id), Some(key)) = (str_field(msg, "id"), str_field(msg, "key")) else {
            return Err(ErrorCode::AssociationFailed);
        };
        let (stored, hash) = self
            .quiet_read(|v| Ok((v.browser_association_key(id), v.browser_hash())))
            .await
            .map_err(|_| ErrorCode::DatabaseNotOpened)?;
        if !stored.is_some_and(|s| ct_eq(&s, key)) {
            return Err(ErrorCode::AssociationFailed);
        }
        conn.associated = true;
        let mut m = Map::new();
        m.insert("hash".into(), hash.into());
        m.insert("id".into(), id.into());
        Ok(m)
    }

    fn generate_password() -> Reply {
        let pw = passgen::generate(&passgen::Options::default()).map_err(|_| ErrorCode::Unknown)?;
        let mut m = Map::new();
        m.insert("password".into(), pw.as_str().into());
        Ok(m)
    }

    async fn get_logins<P: Prompter>(&self, conn: &mut BrowserConnection, msg: &Map<String, Value>, p: &P) -> Reply {
        let keys = protocol::keys_field(msg);
        let valid = self
            .quiet_read(|v| Ok(keys.iter().any(|(id, key)| v.browser_association_key(id).is_some_and(|s| ct_eq(&s, key)))))
            .await
            .unwrap_or(false);
        if !valid {
            return Err(ErrorCode::AssociationFailed);
        }
        conn.associated = true;
        let url = str_field(msg, "url").unwrap_or_default();
        if url.is_empty() || url.len() > MAX_URL_LEN {
            return Err(ErrorCode::NoUrlProvided);
        }
        let host = matching::host_of(url).ok_or(ErrorCode::NoUrlProvided)?;
        let submit_host = str_field(msg, "submitUrl").filter(|s| s.len() <= MAX_URL_LEN).and_then(matching::host_of);
        let matches = self
            .quiet_read(|v| Ok(v.browser_matches(url)))
            .await
            .map_err(|_| ErrorCode::DatabaseNotOpened)?;
        let mut allowed = Vec::new();
        let mut ask = Vec::new();
        for (c, _) in matches.into_iter().take(MAX_MATCHES) {
            match c.access.decide(&host, submit_host.as_deref()) {
                Access::Allowed => allowed.push(c),
                Access::Ask => ask.push(c),
                Access::Denied => {}
            }
        }
        if !ask.is_empty() {
            let entries = ask.iter().map(|c| prompt_entry(&c.id, &c.title, &c.username, &c.group)).collect();
            let prompt = Prompt::Access { host: host.clone(), submit_host: submit_host.clone().filter(|s| *s != host), entries };
            let (chosen, remember) = match self.ask(p, prompt).await {
                Some(Answer::Access { allowed, remember }) => (allowed, remember),
                _ => (vec![], false),
            };
            let chosen: HashSet<String> = chosen.iter().map(|s| norm_id(s)).collect();
            let (yes, no): (Vec<_>, Vec<_>) = ask.into_iter().partition(|c| chosen.contains(&norm_id(&c.id)));
            if remember {
                let hosts: Vec<String> = std::iter::once(host.clone()).chain(submit_host.clone()).collect();
                let updates: Vec<(String, kittypass_core::vault::AccessSettings)> = yes
                    .iter()
                    .map(|c| {
                        let mut s = c.access.clone();
                        hosts.iter().for_each(|h| s.allow(h));
                        (c.id.clone(), s)
                    })
                    .chain(no.iter().map(|c| {
                        let mut s = c.access.clone();
                        s.deny(&host);
                        (c.id.clone(), s)
                    }))
                    .collect();
                let _ = self
                    .quiet_write(move |v| {
                        for (id, s) in &updates {
                            v.set_browser_access(id, s)?;
                        }
                        Ok(())
                    })
                    .await;
            }
            allowed.extend(yes);
        }
        if allowed.is_empty() {
            return Err(ErrorCode::NoLoginsFound);
        }
        let ids: Vec<String> = allowed.iter().map(|c| c.id.clone()).collect();
        let details = self
            .quiet_read(move |v| {
                ids.iter()
                    .map(|id| {
                        let d = v.get(id)?;
                        let totp = v.totp(id).ok().flatten().map(|c| c.code);
                        Ok((d, totp))
                    })
                    .collect::<AppResult<Vec<_>>>()
            })
            .await
            .map_err(|_| ErrorCode::DatabaseNotOpened)?;
        let mut entries = Vec::new();
        for (c, (d, totp)) in allowed.iter().zip(details) {
            conn.release(&c.id);
            let mut e = json!({
                "login": d.username,
                "name": d.title,
                "password": d.password.as_str(),
                "uuid": norm_id(&c.id),
                "group": c.group,
                "stringFields": [],
            });
            if let Some(code) = totp {
                e["totp"] = code.into();
            }
            if c.expired {
                e["expired"] = "true".into();
            }
            entries.push(e);
        }
        let hash = self.quiet_read(|v| Ok(v.browser_hash())).await.unwrap_or_default();
        let mut m = Map::new();
        m.insert("count".into(), entries.len().into());
        m.insert("entries".into(), Value::Array(entries));
        m.insert("hash".into(), hash.into());
        if let Some(id) = str_field(msg, "id") {
            m.insert("id".into(), id.into());
        }
        Ok(m)
    }

    async fn set_login<P: Prompter>(&self, conn: &mut BrowserConnection, msg: &Map<String, Value>, p: &P) -> Reply {
        let url = str_field(msg, "url").filter(|u| u.len() <= MAX_URL_LEN).ok_or(ErrorCode::NoUrlProvided)?;
        let clean = clean_url(url).ok_or(ErrorCode::NoUrlProvided)?;
        let host = matching::host_of(url).ok_or(ErrorCode::NoUrlProvided)?;
        let login = str_field(msg, "login").unwrap_or_default().to_owned();
        let password = Zeroizing::new(str_field(msg, "password").unwrap_or_default().to_owned());
        let uuid = str_field(msg, "uuid").filter(|u| !u.is_empty());
        if let Some(uuid) = uuid {
            // Mise à jour : seulement une entrée remise à ce navigateur, et
            // valable pour ce site.
            if !conn.was_released(uuid) {
                return Err(ErrorCode::NoValidUuidProvided);
            }
            let page = matching::parse_page(url).ok_or(ErrorCode::NoUrlProvided)?;
            let current = self.quiet_read(|v| Ok(v.get(uuid)?)).await.map_err(|_| ErrorCode::NoValidUuidProvided)?;
            let mut urls = vec![current.url.clone()];
            urls.extend(current.custom.iter().filter(|c| c.key.starts_with("KP2A_URL")).map(|c| c.value.to_string()));
            if matching::best(&page, urls.iter().map(String::as_str)).is_none() {
                return Err(ErrorCode::NoValidUuidProvided);
            }
            let group = self.quiet_read(|v| Ok(v.summary(uuid)?.group_id)).await.unwrap_or_default();
            let group_name = self
                .quiet_read(|v| Ok(find_node(&v.groups(), &group).map(|g| g.name.clone()).unwrap_or_default()))
                .await
                .unwrap_or_default();
            let prompt = Prompt::UpdateLogin {
                host,
                entry: prompt_entry(uuid, &current.title, &current.username, &group_name),
                username: login.clone(),
            };
            if self.ask(p, prompt).await != Some(Answer::Confirm { ok: true }) {
                return Err(ErrorCode::ActionCancelledOrDenied);
            }
            let id = uuid.to_owned();
            self.quiet_write(move |v| {
                let mut d = v.get(&id)?;
                if !login.is_empty() {
                    d.username = login;
                }
                d.password = password;
                v.update(&id, &d)?;
                Ok(())
            })
            .await
            .map_err(|_| ErrorCode::Unknown)?;
        } else {
            // Nouvel identifiant : l'utilisateur l'a demandé dans le navigateur.
            let group_uuid = str_field(msg, "groupUuid").map(str::to_owned);
            let id = self
                .quiet_write(move |v| {
                    let tree = v.groups();
                    let group = match group_uuid.filter(|g| contains_group(&tree, g)) {
                        Some(g) => find_id(&tree, &g).unwrap_or_else(|| v.root_id()),
                        None => ensure_group_path(v, BROWSER_GROUP)?,
                    };
                    let d = EntryData { title: host, username: login, password, url: clean, ..Default::default() };
                    Ok(v.add_in(&group, &d)?)
                })
                .await
                .map_err(|_| ErrorCode::Unknown)?;
            conn.release(&id);
        }
        let mut m = Map::new();
        m.insert("error".into(), "success".into());
        m.insert("count".into(), Value::Null);
        m.insert("entries".into(), Value::Null);
        Ok(m)
    }

    async fn get_totp(&self, conn: &BrowserConnection, msg: &Map<String, Value>) -> Reply {
        let uuid = str_field(msg, "uuid").ok_or(ErrorCode::NoValidUuidProvided)?;
        if !conn.was_released(uuid) {
            return Err(ErrorCode::NoValidUuidProvided);
        }
        let code = self
            .quiet_read(|v| Ok(v.totp(uuid)?))
            .await
            .map_err(|_| ErrorCode::NoValidUuidProvided)?
            .map(|c| c.code)
            .unwrap_or_default();
        let mut m = Map::new();
        m.insert("totp".into(), code.into());
        Ok(m)
    }

    async fn database_groups(&self) -> Reply {
        let tree = self.quiet_read(|v| Ok(v.groups())).await.map_err(|_| ErrorCode::NoGroupsFound)?;
        let mut m = Map::new();
        m.insert("groups".into(), json!({ "groups": [group_json(&tree, 0)] }));
        Ok(m)
    }

    async fn create_group(&self, msg: &Map<String, Value>) -> Reply {
        let name = str_field(msg, "groupName").ok_or(ErrorCode::CannotCreateNewGroup)?.to_owned();
        let path = name.clone();
        let id = self.quiet_write(move |v| ensure_group_path(v, &path)).await.map_err(|_| ErrorCode::CannotCreateNewGroup)?;
        let mut m = Map::new();
        m.insert("name".into(), name.into());
        m.insert("uuid".into(), norm_id(&id).into());
        Ok(m)
    }

    async fn passkeys_register<P: Prompter>(&self, msg: &Map<String, Value>, p: &P) -> Map<String, Value> {
        passkey_reply(self.try_passkeys_register(msg, p).await)
    }

    async fn try_passkeys_register<P: Prompter>(&self, msg: &Map<String, Value>, p: &P) -> std::result::Result<Value, ErrorCode> {
        let options = msg.get("publicKey").ok_or(ErrorCode::PasskeysEmptyPublicKey)?;
        let origin = str_field(msg, "origin").ok_or(ErrorCode::PasskeysInvalidUrlProvided)?;
        let plan = passkeys::plan_create(options, origin, &related_origins(msg))?;
        let existing = self.quiet_read(|v| Ok(v.passkeys())).await.map_err(|_| ErrorCode::PasskeysUnknownError)?;
        if existing.iter().any(|(_, k)| k.rp_id == plan.rp_id && plan.exclude.contains(&k.credential_id)) {
            return Err(ErrorCode::PasskeysCredentialIsExcluded);
        }
        let prompt =
            Prompt::CreatePasskey { rp_id: plan.rp_id.clone(), rp_name: plan.rp_name.clone(), user_name: plan.user_name.clone() };
        if self.ask(p, prompt).await != Some(Answer::Confirm { ok: true }) {
            return Err(ErrorCode::PasskeysRequestCanceled);
        }
        let (passkey, response) = passkeys::create(&plan)?;
        let group = str_field(msg, "groupName").filter(|g| !g.trim().is_empty()).unwrap_or(BROWSER_GROUP).to_owned();
        let title = plan.rp_name.clone();
        let rp_id = plan.rp_id.clone();
        self.quiet_write(move |v| {
            let gid = ensure_group_path(v, &group).or_else(|_| ensure_group_path(v, BROWSER_GROUP))?;
            // Titre fourni par le site : s'il est refusé (caractères
            // trompeurs), on prend le RP ID vérifié.
            let id = v.add_in(&gid, &passkey.entry_data(&title)).or_else(|_| v.add_in(&gid, &passkey.entry_data(&rp_id)))?;
            Ok(id)
        })
        .await
        .map_err(|_| ErrorCode::PasskeysUnknownError)?;
        Ok(response)
    }

    async fn passkeys_get<P: Prompter>(&self, conn: &mut BrowserConnection, msg: &Map<String, Value>, p: &P) -> Map<String, Value> {
        passkey_reply(self.try_passkeys_get(conn, msg, p).await)
    }

    async fn try_passkeys_get<P: Prompter>(
        &self,
        conn: &mut BrowserConnection,
        msg: &Map<String, Value>,
        p: &P,
    ) -> std::result::Result<Value, ErrorCode> {
        let options = msg.get("publicKey").ok_or(ErrorCode::PasskeysEmptyPublicKey)?;
        let origin = str_field(msg, "origin").ok_or(ErrorCode::PasskeysInvalidUrlProvided)?;
        let plan = passkeys::plan_get(options, origin, &related_origins(msg))?;
        let candidates: Vec<(String, Passkey, EntryData)> = self
            .quiet_read(|v| {
                Ok(v.passkeys()
                    .into_iter()
                    .filter(|(_, k)| plan.accepts(k))
                    .filter_map(|(id, k)| v.get(&id).ok().map(|d| (id, k, d)))
                    .take(MAX_MATCHES)
                    .collect())
            })
            .await
            .map_err(|_| ErrorCode::PasskeysUnknownError)?;
        if candidates.is_empty() {
            return Err(ErrorCode::NoLoginsFound);
        }
        let entries = candidates
            .iter()
            .map(|(id, k, d)| prompt_entry(id, &d.title, if k.username.is_empty() { &d.username } else { &k.username }, ""))
            .collect();
        let Some(Answer::Choose { id }) = self.ask(p, Prompt::UsePasskey { rp_id: plan.rp_id.clone(), entries }).await else {
            return Err(ErrorCode::PasskeysRequestCanceled);
        };
        let (eid, key, _) =
            candidates.iter().find(|(c, _, _)| norm_id(c) == norm_id(&id)).ok_or(ErrorCode::PasskeysRequestCanceled)?;
        conn.release(eid);
        passkeys::assert(&plan, key)
    }
}

fn find_id(tree: &GroupNode, id: &str) -> Option<String> {
    if norm_id(&tree.id) == norm_id(id) {
        return Some(tree.id.clone());
    }
    tree.children.iter().find_map(|c| find_id(c, id))
}

fn related_origins(msg: &Map<String, Value>) -> Vec<String> {
    msg.get("relatedOrigins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(100)
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// Réponse d'une demande de passkey : la credential, ou `{errorCode}` que
/// l'extension transmet au site (et qui permet le repli sur le navigateur).
fn passkey_reply(r: std::result::Result<Value, ErrorCode>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "response".into(),
        match r {
            Ok(v) => v,
            Err(code) => json!({ "errorCode": code as u8 }),
        },
    );
    m
}

/// Réglage de l'appareil : l'intégration navigateur est-elle activée ?
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserSettings {
    pub enabled: bool,
}

/// Navigateur associé, pour l'interface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssociationView {
    pub id: String,
    pub created: Option<i64>,
}

/// Réglages navigateur d'une entrée, pour l'interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryBrowserView {
    /// Jamais proposée au navigateur.
    pub hidden: bool,
    /// Sites autorisés sans confirmation.
    pub allow: Vec<String>,
    /// Sites refusés.
    pub deny: Vec<String>,
}

const SETTINGS_FILE: &str = "browser.json";

impl App {
    pub fn browser_settings(&self) -> BrowserSettings {
        crate::storage::read_json::<BrowserSettings>(&self.dir.join(SETTINGS_FILE)).ok().flatten().unwrap_or_default()
    }

    pub fn save_browser_settings(&self, s: &BrowserSettings) -> AppResult<()> {
        crate::storage::write_atomic(&self.dir.join(SETTINGS_FILE), &serde_json::to_vec_pretty(s)?)
    }

    pub async fn browser_associations(&self) -> AppResult<Vec<AssociationView>> {
        self.read(|v| Ok(v.browser_associations().into_iter().map(|a| AssociationView { id: a.id, created: a.created }).collect()))
            .await
    }

    /// Révoque un navigateur : il devra être associé de nouveau.
    pub async fn browser_revoke(&self, id: &str) -> AppResult<bool> {
        self.write(|v| Ok(v.browser_revoke(id))).await
    }

    pub async fn entry_browser(&self, id: &str) -> AppResult<EntryBrowserView> {
        self.read(|v| {
            let s = v.browser_access(id)?;
            Ok(EntryBrowserView { hidden: v.browser_hidden(id)?, allow: s.allow.into_iter().collect(), deny: s.deny.into_iter().collect() })
        })
        .await
    }

    /// Enregistre les réglages navigateur d'une entrée. Les listes ne
    /// peuvent que perdre des sites (« Oublier ») : en ajouter se fait par
    /// les confirmations, avec l'adresse réelle de la page.
    pub async fn set_entry_browser(&self, id: &str, view: &EntryBrowserView) -> AppResult<()> {
        self.write(|v| {
            let mut s = v.browser_access(id)?;
            s.allow.retain(|h| view.allow.contains(h));
            s.deny.retain(|h| view.deny.contains(h));
            v.set_browser_access(id, &s)?;
            if v.browser_hidden(id)? != view.hidden {
                v.set_browser_hidden(id, view.hidden)?;
            }
            Ok(())
        })
        .await
    }
}
