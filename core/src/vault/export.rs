//! Exports : copie `.kdbx` chiffrée avec une autre clé, et trois formats
//! **en clair** (CSV au format KeePassXC, XML KeePass 2.x, HTML imprimable).
//! La corbeille n'est jamais exportée en clair. Les octets produits sont
//! effacés de la mémoire à leur libération (`Zeroizing`).

use std::fmt::Write as _;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::{EntryData, GroupNode, MIN_MASTER_PASSWORD_CHARS, MasterKey, Vault, fields};
use crate::{Error, Result};

/// Entrée à exporter, avec son chemin de groupes (racine comprise).
struct Item {
    path: Vec<String>,
    id: String,
    modified: Option<i64>,
    data: EntryData,
}

fn collect(v: &Vault, node: &GroupNode, path: &mut Vec<String>, out: &mut Vec<Item>) -> Result<()> {
    path.push(node.name.clone());
    for s in v.entries_in(&node.id)? {
        out.push(Item { path: path.clone(), id: s.id.clone(), modified: s.modified, data: v.get(&s.id)? });
    }
    for c in node.children.iter().filter(|c| !c.is_recycle_bin) {
        collect(v, c, path, out)?;
    }
    path.pop();
    Ok(())
}

fn iso(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
}

/// Échappement XML/HTML (texte et valeurs d'attributs).
fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

fn uuid_b64(id: &str) -> Result<String> {
    let u = uuid::Uuid::parse_str(id).map_err(|_| Error::InvalidId)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(u.as_bytes()))
}

impl Vault {
    /// Copie chiffrée du coffre complet (historique et corbeille compris)
    /// avec une autre clé maître. Le coffre ouvert n'est pas modifié.
    pub fn export_kdbx(&self, key: &MasterKey) -> Result<Vec<u8>> {
        if key.password().chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(Error::WeakMasterPassword("10 caractères minimum"));
        }
        let mut out = Vec::new();
        self.db.save(&mut out, key.database_key()).map_err(|_| Error::Save)?;
        Ok(out)
    }

    fn export_items(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        collect(self, &self.groups(), &mut Vec::new(), &mut items)?;
        Ok(items)
    }

    /// CSV au format de KeePassXC (« Group », « Title »…) : relu tel quel
    /// par KeePassXC et par l'import de KittyPass. Les attributs et pièces
    /// jointes ne sont pas exportés. Les valeurs ne sont pas modifiées : un
    /// tableur peut interpréter une valeur commençant par `=` comme une
    /// formule (l'interface prévient avant l'export).
    pub fn export_csv(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = ::csv::WriterBuilder::new().quote_style(::csv::QuoteStyle::Always).from_writer(Vec::new());
        let header = ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Tags", "Last Modified"];
        w.write_record(header).map_err(|_| Error::Save)?;
        for it in self.export_items()? {
            let d = &it.data;
            let record = [
                it.path.join("/"),
                d.title.clone(),
                d.username.clone(),
                d.password.to_string(),
                d.url.clone(),
                d.notes.to_string(),
                d.otp.as_deref().map(String::to_owned).unwrap_or_default(),
                d.tags.join(","),
                it.modified.map(iso).unwrap_or_default(),
            ];
            let res = w.write_record(&record);
            drop(Zeroizing::new(record));
            res.map_err(|_| Error::Save)?;
        }
        Ok(Zeroizing::new(w.into_inner().map_err(|_| Error::Save)?))
    }

    /// XML KeePass 2.x non chiffré (importable par KeePass et KeePassXC) :
    /// groupes, champs, attributs, étiquettes, expiration, exclusion des
    /// rapports et pièces jointes. Pas l'historique.
    pub fn export_xml(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut x = Zeroizing::new(String::new());
        let mut binaries: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut body = Zeroizing::new(String::new());
        self.xml_group(&self.groups(), &mut body, &mut binaries)?;
        x.push_str("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>\n<Meta>\n<Generator>KittyPass</Generator>\n<Binaries>\n");
        for (i, b) in binaries.iter().enumerate() {
            let enc = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(b.as_slice()));
            let _ = writeln!(x, "<Binary ID=\"{i}\" Compressed=\"False\">{}</Binary>", enc.as_str());
        }
        x.push_str("</Binaries>\n</Meta>\n<Root>\n");
        x.push_str(&body);
        x.push_str("</Root>\n</KeePassFile>\n");
        Ok(Zeroizing::new(std::mem::take(&mut *x).into_bytes()))
    }

    fn xml_group(&self, node: &GroupNode, x: &mut String, binaries: &mut Vec<Zeroizing<Vec<u8>>>) -> Result<()> {
        let _ = write!(x, "<Group>\n<UUID>{}</UUID>\n<Name>", uuid_b64(&node.id)?);
        escape(&node.name, x);
        x.push_str("</Name>\n");
        if let Some(icon) = node.icon {
            let _ = writeln!(x, "<IconID>{icon}</IconID>");
        }
        for s in self.entries_in(&node.id)? {
            let d = self.get(&s.id)?;
            let _ = write!(x, "<Entry>\n<UUID>{}</UUID>\n", uuid_b64(&s.id)?);
            if self.excluded_from_reports(&s.id)? {
                x.push_str("<QualityCheck>False</QualityCheck>\n");
            }
            if !d.tags.is_empty() {
                x.push_str("<Tags>");
                escape(&d.tags.join(";"), x);
                x.push_str("</Tags>\n");
            }
            x.push_str("<Times>\n");
            if let Some(m) = s.modified {
                let _ = writeln!(x, "<LastModificationTime>{}</LastModificationTime>", iso(m));
            }
            match d.expires {
                Some(t) => {
                    let _ = writeln!(x, "<ExpiryTime>{}</ExpiryTime>\n<Expires>True</Expires>", iso(t));
                }
                None => x.push_str("<Expires>False</Expires>\n"),
            }
            x.push_str("</Times>\n");
            let mut strings: Vec<(&str, &str, bool)> = vec![
                (fields::TITLE, &d.title, false),
                (fields::USERNAME, &d.username, false),
                (fields::PASSWORD, &d.password, true),
                (fields::URL, &d.url, false),
                (fields::NOTES, &d.notes, false),
            ];
            if let Some(otp) = &d.otp {
                strings.push((fields::OTP, otp, true));
            }
            strings.extend(d.custom.iter().map(|c| (c.key.as_str(), c.value.as_str(), c.protected)));
            for (k, v, protected) in strings {
                x.push_str("<String><Key>");
                escape(k, x);
                x.push_str(if protected { "</Key><Value ProtectInMemory=\"True\">" } else { "</Key><Value>" });
                escape(v, x);
                x.push_str("</Value></String>\n");
            }
            for a in self.attachments(&s.id)? {
                x.push_str("<Binary><Key>");
                escape(&a.name, x);
                let _ = writeln!(x, "</Key><Value Ref=\"{}\" /></Binary>", binaries.len());
                binaries.push(self.attachment(&s.id, &a.name)?);
            }
            x.push_str("</Entry>\n");
        }
        for c in node.children.iter().filter(|c| !c.is_recycle_bin) {
            self.xml_group(c, x, binaries)?;
        }
        x.push_str("</Group>\n");
        Ok(())
    }

    /// Page HTML autonome à imprimer (sauvegarde papier). Tout le texte est
    /// échappé, aucun lien n'est cliquable et la page interdit scripts et
    /// ressources externes (CSP).
    pub fn export_html(&self, title: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut h = Zeroizing::new(String::new());
        h.push_str(concat!(
            "<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n",
            "<meta name=\"referrer\" content=\"no-referrer\">\n<title>"
        ));
        escape(title, &mut h);
        h.push_str(concat!(
            "</title>\n<style>\nbody{font:11pt system-ui,sans-serif;margin:1.5em}\n",
            "h2{font-size:13pt;margin:1.5em 0 .3em;border-bottom:1px solid #999}\n",
            "table{border-collapse:collapse;width:100%;margin-bottom:.8em;page-break-inside:avoid}\n",
            "th{text-align:left;width:11em;font-weight:600;vertical-align:top}\n",
            "th,td{border:1px solid #bbb;padding:.2em .4em}\n",
            "td{font-family:ui-monospace,monospace;white-space:pre-wrap;word-break:break-all}\n",
            "caption{text-align:left;font-weight:700;padding:.2em 0}\n</style>\n</head>\n<body>\n<h1>"
        ));
        escape(title, &mut h);
        h.push_str("</h1>\n<p>Document confidentiel : il contient vos mots de passe en clair. Conservez-le en lieu sûr ou détruisez-le.</p>\n");
        let mut current: Option<Vec<String>> = None;
        for it in self.export_items()? {
            if current.as_ref() != Some(&it.path) {
                h.push_str("<h2>");
                escape(&it.path.join(" / "), &mut h);
                h.push_str("</h2>\n");
                current = Some(it.path.clone());
            }
            let d = &it.data;
            h.push_str("<table>\n<caption>");
            escape(&d.title, &mut h);
            h.push_str("</caption>\n");
            let mut rows: Vec<(&str, &str)> = vec![
                ("Identifiant", &d.username),
                ("Mot de passe", &d.password),
                ("URL", &d.url),
                ("2FA (TOTP)", d.otp.as_deref().map_or("", String::as_str)),
                ("Notes", &d.notes),
            ];
            rows.extend(d.custom.iter().map(|c| (c.key.as_str(), c.value.as_str())));
            let tags = d.tags.join(", ");
            rows.push(("Étiquettes", &tags));
            let expires = d.expires.map(iso).unwrap_or_default();
            rows.push(("Expiration", &expires));
            for (k, v) in rows.into_iter().filter(|(_, v)| !v.is_empty()) {
                h.push_str("<tr><th>");
                escape(k, &mut h);
                h.push_str("</th><td>");
                escape(v, &mut h);
                h.push_str("</td></tr>\n");
            }
            let names: Vec<String> = self.attachments(&it.id)?.into_iter().map(|a| a.name).collect();
            if !names.is_empty() {
                h.push_str("<tr><th>Pièces jointes</th><td>");
                escape(&format!("{} (non imprimées)", names.join(", ")), &mut h);
                h.push_str("</td></tr>\n");
            }
            h.push_str("</table>\n");
        }
        h.push_str("</body>\n</html>\n");
        Ok(Zeroizing::new(std::mem::take(&mut *h).into_bytes()))
    }
}
