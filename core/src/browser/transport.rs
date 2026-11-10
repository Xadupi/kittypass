//! Transport local entre le relais natif (`kittypass-proxy`, lancé par le
//! navigateur) et l'application : socket Unix privé, messages préfixés par
//! leur longueur (u32).
//!
//! Le socket est dans `$XDG_RUNTIME_DIR/kittypass/` (ou
//! `/tmp/kittypass-<uid>/` à défaut), dossier 0700 appartenant à
//! l'utilisateur. Les deux côtés le vérifient : sinon un autre compte
//! pourrait se faire passer pour KittyPass auprès du navigateur (et
//! recevoir les identifiants enregistrés), ou l'inverse.

use std::io::{self, Read, Write};
#[cfg(unix)]
use std::{
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use super::protocol::MAX_MESSAGE_BYTES;

#[cfg(unix)]
pub const SOCKET_NAME: &str = "browser.sock";

/// Windows : pipe nommé propre à l'utilisateur. Le nom seul ne protège de
/// rien (n'importe qui peut le créer) : le serveur le crée avec un accès
/// réservé au propriétaire, et chaque côté vérifie le compte de l'autre.
#[cfg(windows)]
pub fn pipe_name() -> io::Result<String> {
    Ok(format!(r"\\.\pipe\kittypass-browser-{}", crate::winsec::current_user_sid()?))
}

#[cfg(unix)]
/// Identifiant de l'utilisateur courant (sans libc : propriétaire de
/// `/proc/self`).
pub fn current_uid() -> io::Result<u32> {
    Ok(std::fs::metadata("/proc/self")?.uid())
}

#[cfg(unix)]
pub fn socket_dir() -> io::Result<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_absolute()) {
        Some(run) => Ok(run.join("kittypass")),
        None => Ok(std::env::temp_dir().join(format!("kittypass-{}", current_uid()?))),
    }
}

#[cfg(unix)]
pub fn socket_path() -> io::Result<PathBuf> {
    Ok(socket_dir()?.join(SOCKET_NAME))
}

#[cfg(unix)]
fn denied(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_owned())
}

#[cfg(unix)]
/// Le dossier existe, n'est pas un lien, appartient à l'utilisateur et
/// n'est accessible qu'à lui.
pub fn check_private_dir(dir: &Path) -> io::Result<()> {
    let m = std::fs::symlink_metadata(dir)?;
    if !m.is_dir() {
        return Err(denied("le dossier du socket n'est pas un dossier"));
    }
    if m.uid() != current_uid()? {
        return Err(denied("le dossier du socket appartient à un autre utilisateur"));
    }
    if m.permissions().mode() & 0o077 != 0 {
        return Err(denied("le dossier du socket est accessible à d'autres utilisateurs"));
    }
    Ok(())
}

#[cfg(unix)]
/// Crée (au besoin) le dossier du socket, en 0700, et le vérifie.
pub fn prepare_dir(dir: &Path) -> io::Result<()> {
    if std::fs::symlink_metadata(dir).is_err() {
        std::fs::DirBuilder::new().mode(0o700).create(dir).or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        })?;
    }
    check_private_dir(dir)
}

#[cfg(unix)]
/// Le socket appartient à l'utilisateur (vérifié par le relais avant de
/// s'y connecter).
pub fn check_socket(path: &Path) -> io::Result<()> {
    check_private_dir(path.parent().ok_or_else(|| denied("chemin du socket invalide"))?)?;
    let m = std::fs::symlink_metadata(path)?;
    if m.uid() != current_uid()? {
        return Err(denied("le socket appartient à un autre utilisateur"));
    }
    Ok(())
}

/// Lit un message : longueur u32 (ordre natif pour la messagerie native des
/// navigateurs, petit-boutiste sur le socket) puis le JSON. `None` en fin
/// de flux.
pub fn read_frame(r: &mut impl Read, native: bool) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = if native { u32::from_ne_bytes(len) } else { u32::from_le_bytes(len) } as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message trop long"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame(w: &mut impl Write, data: &[u8], native: bool) -> io::Result<()> {
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message trop long"));
    }
    let len = data.len() as u32;
    w.write_all(&if native { len.to_ne_bytes() } else { len.to_le_bytes() })?;
    w.write_all(data)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn frames_round_trip_and_are_bounded() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}", false).unwrap();
        write_frame(&mut buf, b"{}", true).unwrap();
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r, false).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut r, true).unwrap().unwrap(), b"{}");
        assert!(read_frame(&mut r, true).unwrap().is_none());
        // Longueur annoncée énorme : refus sans allouer.
        let mut huge: &[u8] = &[0xff, 0xff, 0xff, 0x7f, 1, 2];
        assert!(read_frame(&mut huge, false).is_err());
        // Message tronqué.
        let mut cut: &[u8] = &[10, 0, 0, 0, b'{'];
        assert!(read_frame(&mut cut, false).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![b' '; MAX_MESSAGE_BYTES + 1], false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_checks() {
        let base = std::env::temp_dir().join(format!("kp-sock-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let d = base.join("ok");
        prepare_dir(&d).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        // Dossier ouvert aux autres : refusé (pas corrigé en silence).
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_dir(&open).is_err());
        // Lien symbolique vers un dossier : refusé.
        let link = base.join("lien");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(check_private_dir(&link).is_err());
        // Fichier à la place du dossier.
        let file = base.join("fichier");
        std::fs::write(&file, b"").unwrap();
        assert!(prepare_dir(&file).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
