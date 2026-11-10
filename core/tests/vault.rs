//! Tests du coffre : fonctionnement, attaques sur le fichier, interopérabilité.

use std::io::Write;
use std::process::{Command, Stdio};

use kittypass_core::{
    Error,
    header::{self, Kdf, OpenLimits},
    vault::{CustomField, EntryData, Vault},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-maître-de-test";

fn entry(title: &str) -> EntryData {
    EntryData {
        title: title.into(),
        username: "alice@example.org".into(),
        password: Zeroizing::new("S3cr3t-P@ss!".into()),
        url: "https://example.org/login".into(),
        notes: Zeroizing::new("note confidentielle".into()),
        otp: Some(Zeroizing::new("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP".into())),
        custom: vec![
            CustomField { key: "Code PIN".into(), value: Zeroizing::new("1234".into()), protected: true },
            CustomField { key: "Question".into(), value: Zeroizing::new("chat".into()), protected: false },
        ],
        tags: vec!["banque".into(), "perso".into()],
        expires: Some(4_102_444_800), // 2100-01-01
    }
}

fn saved_vault() -> (Vec<u8>, String) {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&entry("Banque")).unwrap();
    (v.save().unwrap(), id)
}

#[test]
fn roundtrip_keeps_every_field() {
    let (bytes, id) = saved_vault();
    let v = Vault::open(&bytes, PW, &OpenLimits::default()).unwrap();
    assert_eq!(v.get(&id).unwrap(), entry("Banque"));
}

#[test]
fn new_vault_uses_argon2id_64mib() {
    let (bytes, _) = saved_vault();
    let info = header::inspect(&bytes).unwrap();
    assert_eq!(info.major, 4);
    assert!(matches!(info.kdf, Kdf::Argon2id { memory_bytes, .. } if memory_bytes == 64 << 20));
}

#[test]
fn wrong_password_is_rejected() {
    let (bytes, _) = saved_vault();
    for pw in ["", "mot-de-passe-maître-de-tesT", "mot-de-passe-maître-de-test ", "x"] {
        assert!(matches!(
            Vault::open(&bytes, pw, &OpenLimits::default()),
            Err(Error::InvalidKeyOrCorrupted)
        ));
    }
}

#[test]
fn no_plaintext_in_saved_file() {
    let (bytes, _) = saved_vault();
    for needle in ["S3cr3t-P@ss!", "Banque", "alice@example.org", "example.org", "confidentielle", "JBSWY3DP"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "« {needle} » trouvé en clair dans le fichier"
        );
    }
}

#[test]
fn each_save_uses_fresh_randomness() {
    let v = Vault::create(PW).unwrap();
    let a = v.save().unwrap();
    let b = v.save().unwrap();
    assert_ne!(a, b, "deux sauvegardes identiques : sel/IV réutilisés");
}

/// Altère un octet à différents endroits (en-tête, HMAC, blocs chiffrés) :
/// l'ouverture doit toujours échouer proprement, jamais accepter le fichier.
#[test]
fn any_tampering_is_detected() {
    let (bytes, _) = saved_vault();
    let len = bytes.len();
    let mut positions: Vec<usize> = (0..12).collect(); // signature + version
    positions.extend((12..len).step_by(len / 40)); // échantillon sur tout le fichier
    positions.push(len - 1);
    for pos in positions {
        let mut t = bytes.clone();
        t[pos] ^= 0x01;
        assert!(
            Vault::open(&t, PW, &OpenLimits::default()).is_err(),
            "altération à l'octet {pos}/{len} non détectée"
        );
    }
}

#[test]
fn truncation_and_extension_are_detected() {
    let (bytes, _) = saved_vault();
    for cut in [0, 1, 11, 12, 100, bytes.len() / 2, bytes.len() - 1] {
        assert!(Vault::open(&bytes[..cut], PW, &OpenLimits::default()).is_err(), "coupé à {cut}");
    }
    let mut ext = bytes.clone();
    ext.extend_from_slice(&[0u8; 64]);
    // KeePass ignore les octets après le bloc final : on vérifie seulement que
    // le contenu n'est pas altéré.
    if let Ok(v) = Vault::open(&ext, PW, &OpenLimits::default()) {
        assert_eq!(v.len(), 1);
    }
}

/// Un serveur compromis remplace la mémoire Argon2 par 4 Go dans un vrai
/// fichier : le refus doit être immédiat, avant toute dérivation de clé.
#[test]
fn kdf_bomb_in_real_file_is_refused_fast() {
    let (mut bytes, _) = saved_vault();
    let needle = (64u64 << 20).to_le_bytes();
    let pos = bytes.windows(8).position(|w| w == needle).expect("champ M introuvable");
    bytes[pos..pos + 8].copy_from_slice(&(4u64 << 30).to_le_bytes());
    let start = std::time::Instant::now();
    let r = Vault::open(&bytes, PW, &OpenLimits::default());
    assert!(matches!(r, Err(Error::KdfOutOfBounds(_))));
    assert!(start.elapsed().as_millis() < 100);
}

#[test]
fn crud_and_search() {
    let mut v = Vault::create(PW).unwrap();
    let a = v.add(&entry("Banque")).unwrap();
    let b = v.add(&entry("Mail perso")).unwrap();
    assert_eq!(v.len(), 2);

    let mut changed = entry("Banque");
    changed.password = Zeroizing::new("nouveau".into());
    changed.otp = None;
    v.update(&a, &changed).unwrap();
    assert_eq!(v.get(&a).unwrap(), changed);
    assert_eq!(v.history_len(&a).unwrap(), 1, "l'ancienne version doit être gardée");

    assert_eq!(v.search("MAIL").unwrap().len(), 1);
    assert_eq!(v.search("example.org").unwrap().len(), 2);
    // La recherche ne doit jamais révéler le contenu des mots de passe.
    assert!(v.search("nouveau").unwrap().is_empty());
    assert!(v.search("S3cr3t").unwrap().is_empty());

    // Première suppression : corbeille (hors liste et recherche).
    v.delete(&b).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v.list().len(), 1);
    assert!(v.search("Mail").unwrap().is_empty());
    assert!(v.deleted_ids().is_empty());
    // Seconde suppression, depuis la corbeille : définitive.
    v.delete(&b).unwrap();
    assert_eq!(v.len(), 1);
    assert!(v.deleted_ids().contains(&b), "suppression non inscrite pour la synchro");
    assert!(matches!(v.get(&b), Err(Error::EntryNotFound)));

    // Tout survit à un aller-retour disque.
    let v2 = Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap();
    assert_eq!(v2.get(&a).unwrap(), changed);
    assert!(v2.deleted_ids().contains(&b));
}

#[test]
fn invalid_ids_are_rejected() {
    let mut v = Vault::create(PW).unwrap();
    for id in ["", "abc", "../../etc/passwd", "00000000-0000-0000-0000-00000000000g"] {
        assert!(matches!(v.get(id), Err(Error::InvalidId)));
        assert!(matches!(v.delete(id), Err(Error::InvalidId)));
    }
    let unknown = "6f1c5b0e-0000-4000-8000-000000000000";
    assert!(matches!(v.get(unknown), Err(Error::EntryNotFound)));
    assert!(matches!(v.update(unknown, &entry("x")), Err(Error::EntryNotFound)));
}

#[test]
fn weak_master_password_refused_on_create_only() {
    assert!(matches!(Vault::create(""), Err(Error::WeakMasterPassword(_))));
    assert!(matches!(Vault::create("123456789"), Err(Error::WeakMasterPassword(_))));
    let mut v = Vault::create(PW).unwrap();
    assert!(v.change_password(PW, "court").is_err());
    assert!(v.change_password("mauvais-actuel", "nouveau-mot-de-passe-long").is_err());
}

#[test]
fn change_password_reencrypts() {
    let mut v = Vault::create(PW).unwrap();
    v.add(&entry("x")).unwrap();
    v.change_password(PW, "nouveau-mot-de-passe-long").unwrap();
    let bytes = v.save().unwrap();
    assert!(Vault::open(&bytes, PW, &OpenLimits::default()).is_err());
    assert_eq!(Vault::open(&bytes, "nouveau-mot-de-passe-long", &OpenLimits::default()).unwrap().len(), 1);
}

#[test]
fn input_validation() {
    let mut v = Vault::create(PW).unwrap();
    let mut e = entry("x");
    e.title = "a\u{0}b".into();
    assert!(v.add(&e).is_err(), "octet nul accepté : fichier illisible par KeePass");
    let mut e = entry("x");
    e.username = "\u{1b}[31m".into();
    assert!(v.add(&e).is_err(), "séquence d'échappement terminal acceptée");
    let mut e = entry("x");
    e.title = "a".repeat(70_000);
    assert!(v.add(&e).is_err());
    let mut e = entry("x");
    e.otp = Some(Zeroizing::new("javascript:alert(1)".into()));
    assert!(v.add(&e).is_err());
    // Unicode, XML spécial et multi-lignes doivent passer et survivre.
    let mut e = entry("<x>&amp;\"'</x> 🔐 été");
    e.notes = Zeroizing::new("ligne 1\nligne 2\t]]>".into());
    let id = v.add(&e).unwrap();
    let v2 = Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap();
    assert_eq!(v2.get(&id).unwrap(), e);
}

#[test]
fn debug_output_never_leaks_secrets() {
    let e = entry("Banque");
    let s = format!("{e:?}");
    assert!(!s.contains("S3cr3t") && !s.contains("confidentielle") && !s.contains("JBSWY3DP"), "{s}");
    let v = Vault::create(PW).unwrap();
    assert!(!format!("{v:?}").contains(PW));
}

// ---------- Interopérabilité avec KeePassXC (si installé) ----------

fn keepassxc() -> Option<&'static str> {
    Command::new("keepassxc-cli").arg("--version").output().ok().map(|_| "keepassxc-cli")
}

fn run_cli(args: &[&str], stdin: &str) -> std::process::Output {
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

#[test]
fn keepassxc_reads_our_vault() {
    let Some(_) = keepassxc() else { return eprintln!("keepassxc-cli absent, test ignoré") };
    let dir = std::env::temp_dir().join(format!("kp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ours.kdbx");
    let (bytes, _) = saved_vault();
    std::fs::write(&path, bytes).unwrap();

    let out = run_cli(&["show", "-s", "-q", path.to_str().unwrap(), "Banque"], &format!("{PW}\n"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("S3cr3t-P@ss!") && stdout.contains("alice@example.org"), "{stdout}");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn we_read_keepassxc_vault() {
    let Some(_) = keepassxc() else { return eprintln!("keepassxc-cli absent, test ignoré") };
    let dir = std::env::temp_dir().join(format!("kp-test2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("theirs.kdbx");
    let p = path.to_str().unwrap();

    let out = run_cli(&["db-create", "-q", "-p", p], &format!("{PW}\n{PW}\n"));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = run_cli(&["add", "-q", "-u", "bob", "--url", "https://kpxc.test", "-p", p, "Depuis KeePassXC"], &format!("{PW}\nmdp-kpxc-123\n"));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let v = Vault::open(&std::fs::read(&path).unwrap(), PW, &OpenLimits::default()).unwrap();
    let s = v.search("KeePassXC").unwrap();
    assert_eq!(s.len(), 1);
    let mut e = v.get(&s[0].id).unwrap();
    assert_eq!(e.username, "bob");
    assert_eq!(e.password.as_str(), "mdp-kpxc-123");
    // KeePassXC crée du KDBX 3.1 : il doit être converti pour pouvoir être
    // enregistré, et KeePassXC doit relire le résultat.
    assert!(v.format_version().starts_with("KDBX4"), "{}", v.format_version());
    let mut v = v;
    e.password = Zeroizing::new("modifié-par-kittypass".into());
    v.update(&s[0].id, &e).unwrap();
    std::fs::write(&path, v.save().unwrap()).unwrap();
    let out = run_cli(&["show", "-s", "-q", p, "Depuis KeePassXC"], &format!("{PW}\n"));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("modifié-par-kittypass"));
    let reopened = Vault::open(&std::fs::read(&path).unwrap(), PW, &OpenLimits::default()).unwrap();
    assert!(matches!(header::inspect(&std::fs::read(&path).unwrap()).unwrap().kdf, Kdf::Argon2id { .. }));
    assert_eq!(reopened.history_len(&s[0].id).unwrap(), 1);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn rapid_edits_keep_every_version() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&entry("x")).unwrap();
    for i in 0..5 {
        let mut e = entry("x");
        e.password = Zeroizing::new(format!("v{i}"));
        v.update(&id, &e).unwrap();
    }
    assert_eq!(v.history_len(&id).unwrap(), 5, "versions perdues lors d'éditions rapides");
    // Et le fichier reste fusionnable avec lui-même.
    let copy = Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap();
    v.merge_from(&copy).unwrap();
}

/// Champs numériques d'en-tête trop courts : la bibliothèque KDBX paniquait
/// (trouvé par cargo fuzz). Appel direct, sans le `catch_unwind` du coffre.
#[test]
fn short_numeric_header_fields_are_errors_not_panics() {
    fn file(major: u16, header: &[u8]) -> Vec<u8> {
        let mut d = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&major.to_le_bytes());
        d.extend_from_slice(header);
        d.extend_from_slice(&[0; 64]);
        d
    }
    let key = keepass::DatabaseKey::new().with_password("x");
    // KDBX 3 : compression (3), tours (6), flux interne (10) sur 1 octet.
    for t in [3u8, 6, 10] {
        let data = file(3, &[t, 1, 0, 7]);
        assert!(keepass::Database::parse(&data, key.clone()).is_err(), "kdbx3 type {t}");
    }
    // KDBX 4 : compression (3) sur 1 octet.
    assert!(keepass::Database::parse(&file(4, &[3, 1, 0, 0, 0, 7]), key.clone()).is_err());
    // KDBX 4 : paramètres de dérivation (11) avec un u32 et un u64 sur 1 octet.
    for ty in [0x04u8, 0x05, 0x0c, 0x0d] {
        let mut dict = vec![0x00, 0x01, ty, 1, 0, 0, 0, b'R', 1, 0, 0, 0, 7, 0];
        let mut h = vec![11];
        h.extend_from_slice(&(dict.len() as u32).to_le_bytes());
        h.append(&mut dict);
        assert!(keepass::Database::parse(&file(4, &h), key.clone()).is_err(), "variant {ty:#x}");
    }
}
