//! Import et export de fichiers. Les fichiers sont lus et écrits côté Rust :
//! l'interface ne fait que transmettre le chemin choisi dans la boîte de
//! dialogue du système.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use kittypass_core::{
    Error as CoreError,
    vault::{
        MasterKey, Vault,
        import::{self, ImportReport, Imported},
    },
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{App, AppError, AppResult, keyfile::read_key_file};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImportFormat {
    Csv,
    Kdbx,
    Bitwarden,
    #[serde(rename = "1pux")]
    OnePux,
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub format: ImportFormat,
    pub path: PathBuf,
    /// Groupe sous lequel créer le groupe d'import.
    pub parent: String,
    /// Nom du groupe d'import (par défaut : celui du fichier).
    #[serde(default)]
    pub name: Option<String>,
    /// Coffre KeePass : mot de passe et fichier clé éventuel.
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportView {
    pub group_id: String,
    pub imported: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

impl From<ImportReport> for ImportView {
    fn from(r: ImportReport) -> Self {
        Self { group_id: r.group_id, imported: r.imported, skipped: r.skipped, warnings: r.warnings }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Kdbx,
    Csv,
    Xml,
    Html,
}

impl ExportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Kdbx => "kdbx",
            Self::Csv => "csv",
            Self::Xml => "xml",
            Self::Html => "html",
        }
    }

    /// Le fichier produit contient les mots de passe en clair.
    pub fn is_cleartext(self) -> bool {
        self != Self::Kdbx
    }
}

#[derive(Deserialize)]
pub struct ExportRequest {
    pub format: ExportFormat,
    /// Copie `.kdbx` : mot de passe de la copie et fichier clé éventuel.
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

/// Lit un fichier ordinaire d'au plus `max` octets (taille vérifiée avant et
/// pendant la lecture : un fichier qui grossit entre-temps est refusé).
fn read_bounded(path: &Path, max: usize) -> AppResult<Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(AppError::Io("ce n'est pas un fichier".into()));
    }
    if meta.len() > max as u64 {
        return Err(CoreError::TooLarge.into());
    }
    let mut data = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    std::fs::File::open(path)?.take(max as u64 + 1).read_to_end(&mut data)?;
    if data.len() > max {
        return Err(CoreError::TooLarge.into());
    }
    Ok(data)
}

/// Écrit un fichier lisible par son seul propriétaire (Unix), en remplaçant
/// un fichier existant (la boîte de dialogue a déjà demandé confirmation).
fn write_private(path: &Path, data: &[u8]) -> AppResult<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// `path` (existant ou non, lien symbolique compris) désigne un fichier du
/// dossier `dir`.
fn inside(path: &Path, dir: &Path) -> bool {
    let Ok(dir) = dir.canonicalize() else { return false };
    if path.canonicalize().is_ok_and(|p| p.starts_with(&dir)) {
        return true;
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    parent.canonicalize().is_ok_and(|p| p.starts_with(&dir))
}

/// Écrit `data` dans `path`, hors du dossier de KittyPass (jamais par-dessus
/// le coffre lui-même).
pub(crate) fn save_outside(app: &App, path: &Path, data: &[u8]) -> AppResult<()> {
    if inside(path, &app.dir) {
        return Err(AppError::Io("choisissez un emplacement hors du dossier de KittyPass".into()));
    }
    write_private(path, data)
}

impl App {
    /// Importe un fichier dans un nouveau groupe. Tout ou rien.
    pub async fn import_file(&self, req: ImportRequest) -> AppResult<ImportView> {
        self.touch();
        let data = read_bounded(&req.path, import::MAX_IMPORT_BYTES)?;
        let keyfile = req.key_file.as_deref().map(read_key_file).transpose()?;
        let limits = self.limits;
        let format = req.format;
        let password = req.password.clone().unwrap_or_default();
        // Analyse (et dérivation de clé KeePass) hors du fil de l'interface.
        let imported: Imported = tokio::task::spawn_blocking(move || -> AppResult<Imported> {
            Ok(match format {
                ImportFormat::Csv => import::parse_csv(&data)?,
                ImportFormat::Bitwarden => import::parse_bitwarden(&data)?,
                ImportFormat::OnePux => import::parse_1pux(&data)?,
                ImportFormat::Kdbx => {
                    let source = Vault::open_with_key(&data, &MasterKey::new(&password, keyfile), &limits)?;
                    import::parse_kdbx(&source)?
                }
            })
        })
        .await
        .map_err(|_| AppError::Io("import interrompu".into()))??;
        let name = req
            .name
            .filter(|n| !n.trim().is_empty())
            .or_else(|| req.path.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "Import".into());
        let report = self.write(|v| Ok(v.import(&req.parent, &name, imported)?)).await?;
        Ok(report.into())
    }

    /// Contenu du fichier d'export (la copie `.kdbx` est chiffrée avec la clé
    /// demandée, jamais avec celle du coffre sans le dire).
    pub async fn export_bytes(&self, req: &ExportRequest) -> AppResult<Zeroizing<Vec<u8>>> {
        let keyfile = req.key_file.as_deref().map(read_key_file).transpose()?;
        let title = self.status().await.username.map_or_else(|| "KittyPass".to_owned(), |u| format!("KittyPass — {u}"));
        self.read(|v| {
            Ok(match req.format {
                ExportFormat::Kdbx => {
                    let password = req.password.as_deref().ok_or(CoreError::WeakMasterPassword("mot de passe requis"))?;
                    Zeroizing::new(v.export_kdbx(&MasterKey::new(password, keyfile))?)
                }
                ExportFormat::Csv => v.export_csv()?,
                ExportFormat::Xml => v.export_xml()?,
                ExportFormat::Html => v.export_html(&title)?,
            })
        })
        .await
    }

    /// Exporte dans `path`. Refuse d'écraser le fichier du coffre lui-même.
    pub async fn export_to(&self, path: &Path, req: &ExportRequest) -> AppResult<()> {
        if inside(path, &self.dir) {
            return Err(AppError::Io("choisissez un emplacement hors du dossier de KittyPass".into()));
        }
        let data = self.export_bytes(req).await?;
        save_outside(self, path, &data)
    }
}
