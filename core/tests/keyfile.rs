//! Fichier clé : formats, changement de clé, synchronisation entre appareils,
//! interopérabilité KeePassXC dans les deux sens.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use kittypass_core::{
    Error,
    header::OpenLimits,
    keyfile::KeyFile,
    sync::{PushOutcome, Remote, download, sync},
    vault::{EntryData, MasterKey, Vault},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-fichier-cle";

fn e(title: &str) -> EntryData {
    EntryData { title: title.into(), password: Zeroizing::new("secret".into()), ..Default::default() }
}

fn lim() -> OpenLimits {
    OpenLimits::default()
}

fn titles(v: &Vault) -> Vec<String> {
    v.list().into_iter().map(|s| s.title).collect()
}

#[derive(Default)]
struct Mem(Mutex<(i64, Option<Vec<u8>>)>);

impl Remote for Mem {
    async fn fetch(&self) -> kittypass_core::Result<(i64, Option<Vec<u8>>)> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn push(&self, expected: i64, data: Vec<u8>) -> kittypass_core::Result<PushOutcome> {
        let mut s = self.0.lock().unwrap();
        if s.0 != expected {
            return Ok(PushOutcome::Conflict);
        }
        *s = (s.0 + 1, Some(data));
        Ok(PushOutcome::Stored(s.0))
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kp-keyfile-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn has_keepassxc() -> bool {
    Command::new("keepassxc-cli").arg("--version").output().is_ok()
}

fn keepassxc(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

/// Les différents formats de fichier clé acceptés par KeePass.
fn sample_keyfiles() -> Vec<(&'static str, Vec<u8>)> {
    let v1 = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile><Meta><Version>1.00</Version></Meta>\
               <Key><Data>MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=</Data></Key></KeyFile>"
        .to_vec();
    let big: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    vec![
        ("xml2", KeyFile::generate().unwrap().1.to_vec()),
        ("xml1", v1),
        ("raw32", (0..32u8).collect()),
        ("hex64", b"00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF".to_vec()),
        ("photo", b"\x89PNG\r\n\x1a\n une image quelconque".to_vec()),
        ("gros", big),
    ]
}

#[test]
fn both_factors_are_required() {
    let (kf, _) = KeyFile::generate().unwrap();
    let (other, _) = KeyFile::generate().unwrap();
    let mut v = Vault::create_with_key(&MasterKey::new(PW, Some(kf.clone()))).unwrap();
    v.add(&e("Protégée")).unwrap();
    assert!(v.has_key_file());
    let data = v.save().unwrap();

    assert!(matches!(Vault::open(&data, PW, &lim()), Err(Error::InvalidKeyOrCorrupted)), "mot de passe seul");
    assert!(Vault::open_with_key(&data, &MasterKey::new(PW, Some(other)), &lim()).is_err(), "autre fichier");
    assert!(Vault::open_with_key(&data, &MasterKey::new("autre-mot-de-passe", Some(kf.clone())), &lim()).is_err());
    let v = Vault::open_with_key(&data, &MasterKey::new(PW, Some(kf)), &lim()).unwrap();
    assert_eq!(titles(&v), ["Protégée"]);
    assert!(!format!("{:?}", v.master_key()).contains(PW));
}

#[test]
fn every_keyfile_format_round_trips() {
    for (name, bytes) in sample_keyfiles() {
        let kf = KeyFile::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let v = Vault::create_with_key(&MasterKey::new(PW, Some(kf))).unwrap();
        let data = v.save().unwrap();
        let again = KeyFile::from_bytes(&bytes).unwrap();
        assert!(Vault::open_with_key(&data, &MasterKey::new(PW, Some(again)), &lim()).is_ok(), "{name}");
        assert!(Vault::open(&data, PW, &lim()).is_err(), "{name}");
    }
}

#[test]
fn adding_and_removing_keyfile() {
    let mut v = Vault::create(PW).unwrap();
    let (kf, _) = KeyFile::generate().unwrap();
    assert!(matches!(v.set_key_file("mauvais", Some(kf.clone())), Err(Error::InvalidKeyOrCorrupted)));
    assert!(!v.has_key_file());
    v.set_key_file(PW, Some(kf.clone())).unwrap();
    let data = v.save().unwrap();
    assert!(Vault::open(&data, PW, &lim()).is_err());
    let mut v = Vault::open_with_key(&data, &MasterKey::new(PW, Some(kf)), &lim()).unwrap();
    // Changer le mot de passe garde le fichier clé.
    v.change_password(PW, "nouveau-mot-de-passe").unwrap();
    assert!(v.has_key_file());
    assert!(Vault::open(&v.save().unwrap(), "nouveau-mot-de-passe", &lim()).is_err());
    v.set_key_file("nouveau-mot-de-passe", None).unwrap();
    assert!(Vault::open(&v.save().unwrap(), "nouveau-mot-de-passe", &lim()).is_ok());
}

#[tokio::test]
async fn other_device_needs_the_keyfile_and_keeps_its_changes() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("Commune")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let (mut b, seen) = download(&remote, &MasterKey::new(PW, None), &lim()).await.unwrap().unwrap();

    // A ajoute un fichier clé et envoie le coffre re-chiffré.
    let (kf, _) = KeyFile::generate().unwrap();
    a.set_key_file(PW, Some(kf.clone())).unwrap();
    a.add(&e("Après le fichier clé")).unwrap();
    let r = sync(&mut a, seen, &lim(), &remote).await.unwrap();
    assert!(r.pushed);

    // B, sans le fichier : refus, et ses changements locaux restent intacts.
    b.add(&e("Hors ligne sur B")).unwrap();
    assert!(matches!(sync(&mut b, seen, &lim(), &remote).await, Err(Error::InvalidKeyOrCorrupted)));
    assert_eq!(titles(&b), ["Commune", "Hors ligne sur B"]);

    // B reçoit le fichier clé : tout converge, chiffré avec la nouvelle clé.
    b.set_key_file(PW, Some(kf.clone())).unwrap();
    sync(&mut b, seen, &lim(), &remote).await.unwrap();
    assert_eq!(titles(&b), ["Après le fichier clé", "Commune", "Hors ligne sur B"]);
    let stored = remote.0.lock().unwrap().1.clone().unwrap();
    assert!(Vault::open(&stored, PW, &lim()).is_err(), "le serveur ne garde rien d'ouvrable sans le fichier");
    assert!(Vault::open_with_key(&stored, &MasterKey::new(PW, Some(kf)), &lim()).is_ok());

    // Nouvel appareil sans fichier clé : refusé.
    assert!(download(&remote, &MasterKey::new(PW, None), &lim()).await.is_err());
}

#[test]
fn damaged_and_empty_keyfiles_are_refused_early() {
    let (_, xml) = KeyFile::generate().unwrap();
    let text = String::from_utf8(xml.to_vec()).unwrap();
    let i = text.find("</Data>").unwrap() - 10;
    let mut bad = text.into_bytes();
    bad[i] = if bad[i] == b'0' { b'1' } else { b'0' };
    assert!(matches!(KeyFile::from_bytes(&bad), Err(Error::KeyFile(_))));
    assert!(matches!(KeyFile::from_bytes(b""), Err(Error::KeyFile(_))));
}

#[test]
fn keepassxc_opens_our_keyfile_vaults() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = tmp("ours");
    for (name, bytes) in sample_keyfiles() {
        let key_path = dir.join(format!("{name}.key"));
        let db_path = dir.join(format!("{name}.kdbx"));
        std::fs::write(&key_path, &bytes).unwrap();
        let mut v = Vault::create_with_key(&MasterKey::new(PW, Some(KeyFile::from_bytes(&bytes).unwrap()))).unwrap();
        v.add(&e(&format!("Entrée {name}"))).unwrap();
        std::fs::write(&db_path, v.save().unwrap()).unwrap();
        let out = keepassxc(&["ls", "-q", "-k", key_path.to_str().unwrap(), db_path.to_str().unwrap()], &format!("{PW}\n"));
        assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("Entrée {name}")), "{name}");
    }
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn we_open_keepassxc_keyfile_vaults() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = tmp("theirs");
    let key_path = dir.join("cle.keyx");
    let db_path = dir.join("db.kdbx");
    // KeePassXC crée lui-même le fichier clé s'il n'existe pas.
    let out = keepassxc(
        &["db-create", "-q", "-p", "-t", "100", "--set-key-file", key_path.to_str().unwrap(), db_path.to_str().unwrap()],
        &format!("{PW}\n{PW}\n"),
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let key_bytes = std::fs::read(&key_path).unwrap();
    assert!(String::from_utf8_lossy(&key_bytes).contains("<Version>2.0</Version>"));
    let kf = KeyFile::from_bytes(&key_bytes).unwrap();
    let data = std::fs::read(&db_path).unwrap();
    let mut v = Vault::open_with_key(&data, &MasterKey::new(PW, Some(kf)), &lim()).unwrap();
    assert!(Vault::open(&data, PW, &lim()).is_err());
    // Et le fichier modifié par nous reste lisible par KeePassXC.
    v.add(&e("Ajoutée par KittyPass")).unwrap();
    std::fs::write(&db_path, v.save().unwrap()).unwrap();
    let out = keepassxc(&["ls", "-q", "-k", key_path.to_str().unwrap(), db_path.to_str().unwrap()], &format!("{PW}\n"));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Ajoutée par KittyPass"));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn key_change_alone_is_pushed_and_reencrypts_remote() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let (kf, _) = KeyFile::generate().unwrap();
    a.set_key_file(PW, Some(kf.clone())).unwrap();
    assert!(a.previous_master_key().is_some());
    let r = sync(&mut a, 1, &lim(), &remote).await.unwrap();
    assert!(r.pushed, "aucune entrée modifiée, mais le distant doit être re-chiffré");
    assert!(a.previous_master_key().is_none(), "ancienne clé oubliée après envoi");
    let stored = remote.0.lock().unwrap().1.clone().unwrap();
    assert!(Vault::open(&stored, PW, &lim()).is_err());
    // Synchronisation suivante : rien à envoyer.
    assert!(!sync(&mut a, r.version, &lim(), &remote).await.unwrap().pushed);
}

#[tokio::test]
async fn password_change_propagates_the_same_way() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("Une")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let (mut b, seen) = download(&remote, &MasterKey::new(PW, None), &lim()).await.unwrap().unwrap();
    a.change_password(PW, "nouveau-mot-de-passe").unwrap();
    // Deux changements de suite : l'ancienne clé gardée est la plus ancienne.
    let (kf, _) = KeyFile::generate().unwrap();
    a.set_key_file("nouveau-mot-de-passe", Some(kf.clone())).unwrap();
    sync(&mut a, seen, &lim(), &remote).await.unwrap();
    assert!(sync(&mut b, seen, &lim(), &remote).await.is_err());
    b.change_password(PW, "nouveau-mot-de-passe").unwrap();
    b.set_key_file("nouveau-mot-de-passe", Some(kf)).unwrap();
    sync(&mut b, seen, &lim(), &remote).await.unwrap();
    assert_eq!(titles(&b), ["Une"]);
}

#[test]
fn reverting_a_key_change() {
    let mut v = Vault::create(PW).unwrap();
    let (kf, _) = KeyFile::generate().unwrap();
    v.set_key_file(PW, Some(kf)).unwrap();
    v.revert_key_change();
    assert!(!v.has_key_file() && v.previous_master_key().is_none());
    assert!(Vault::open(&v.save().unwrap(), PW, &lim()).is_ok());
    // Sans changement en attente : sans effet.
    v.revert_key_change();
    assert!(!v.has_key_file());
}
