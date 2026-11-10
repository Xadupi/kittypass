//! Remplissage automatique Android : identifiants proposés pour un site
//! (domaine fourni par le navigateur) ou une appli (`androidapp://paquet`,
//! convention de KeePass2Android et KeePassDX).
//!
//! Ne renvoie que les entrées qui correspondent : l'utilisateur choisit
//! ensuite dans la liste affichée par Android. Les sites refusés dans les
//! réglages d'accès navigateur d'une entrée ne la reçoivent pas non plus ici.

use serde::Serialize;
use zeroize::Zeroizing;

use kittypass_core::browser::matching;

use crate::{App, AppError, AppResult};

/// Au plus, comme dans la liste d'Android.
const MAX_ITEMS: usize = 12;
const MAX_LEN: usize = 253;

#[derive(Serialize)]
pub struct AutofillItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

fn valid_package(p: &str) -> bool {
    !p.is_empty() && p.len() <= MAX_LEN && p.split('.').count() >= 2 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

impl App {
    pub async fn autofill_candidates(&self, web_domain: Option<&str>, package: Option<&str>) -> AppResult<Vec<AutofillItem>> {
        let domain = web_domain.map(str::trim).filter(|d| !d.is_empty() && d.len() <= MAX_LEN);
        let package = package.filter(|p| valid_package(p));
        let inner = self.inner.lock().await;
        let v = inner.vault.as_ref().ok_or(AppError::Locked)?;
        let ids: Vec<String> = if let Some(d) = domain {
            let page = format!("https://{d}/");
            let Some(host) = matching::host_of(&page) else { return Ok(vec![]) };
            v.browser_matches(&page)
                .into_iter()
                .filter(|(c, _)| c.access.decide(&host, None) != kittypass_core::vault::Access::Denied)
                .map(|(c, _)| c.id)
                .collect()
        } else if let Some(p) = package {
            let want = format!("androidapp://{p}");
            v.browser_candidates()
                .into_iter()
                .filter(|c| c.urls.iter().any(|u| u.trim().eq_ignore_ascii_case(&want)))
                .map(|c| c.id)
                .collect()
        } else {
            vec![]
        };
        ids.iter()
            .take(MAX_ITEMS)
            .map(|id| {
                let d = v.get(id)?;
                Ok(AutofillItem { id: id.clone(), title: d.title, username: d.username, password: d.password })
            })
            .collect()
    }
}

/// Résultats au plus pour une recherche manuelle.
const MAX_SEARCH: usize = 30;

impl App {
    /// Recherche manuelle (« Rechercher dans KittyPass… »), quand aucune
    /// entrée ne correspond au site : l'utilisateur choisit lui-même.
    pub async fn autofill_search(&self, query: &str) -> AppResult<Vec<AutofillItem>> {
        let q: String = query.trim().chars().take(MAX_LEN).collect();
        self.read(|v| {
            let list = if q.is_empty() { v.list() } else { v.search(&q)? };
            list.into_iter()
                .take(MAX_SEARCH)
                .map(|e| {
                    let d = v.get(&e.id)?;
                    Ok(AutofillItem { id: e.id, title: d.title, username: d.username, password: d.password })
                })
                .collect()
        })
        .await
    }

    /// Associe le site à l'entrée choisie (URL supplémentaire `KP2A_URL…`,
    /// comme KeePassXC) : la prochaine fois, elle sera proposée directement.
    pub async fn autofill_remember(&self, id: &str, web_domain: &str) -> AppResult<()> {
        let d = web_domain.trim().to_ascii_lowercase();
        let ok = !d.is_empty() && d.len() <= MAX_LEN && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') && d.contains('.');
        if !ok {
            return Ok(()); // domaine fourni par l'appli hôte, illisible : on ignore
        }
        let url = format!("https://{d}");
        self.write(|v| {
            let mut data = v.get(id)?;
            let mut urls = vec![data.url.clone()];
            urls.extend(data.custom.iter().filter(|c| c.key.starts_with(kittypass_core::vault::EXTRA_URL_PREFIX)).map(|c| c.value.to_string()));
            if urls.iter().any(|u| matching::host_of(u).is_some_and(|h| h.eq_ignore_ascii_case(&d))) {
                return Ok(());
            }
            let key = (0..)
                .map(|n| if n == 0 { "KP2A_URL".to_owned() } else { format!("KP2A_URL_{n}") })
                .find(|k| !data.custom.iter().any(|c| &c.key == k))
                .unwrap_or_default();
            data.custom.push(kittypass_core::vault::CustomField { key, value: Zeroizing::new(url), protected: false });
            Ok(v.update(id, &data)?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::valid_package;

    #[test]
    fn packages() {
        assert!(valid_package("com.example.app"));
        assert!(!valid_package("exemple"));
        assert!(!valid_package("com.ex/../x"));
        assert!(!valid_package(""));
    }
}
