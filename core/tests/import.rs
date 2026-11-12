//! Imports CSV, KeePass, Bitwarden et 1Password : correspondance des champs,
//! groupes, fichiers hostiles (caractères interdits, tailles, bombes zip,
//! chemins de pièces jointes) et interopérabilité avec KeePassXC.

use std::io::{Cursor, Write};
use std::process::{Command, Stdio};

use kittypass_core::{
    Error,
    header::OpenLimits,
    vault::{
        EntryData, GroupNode, Vault,
        import::{Imported, parse_1pux, parse_bitwarden, parse_csv, parse_kdbx},
    },
};
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;

const PW: &str = "mot-de-passe-import";
const SECRET_B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

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
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    out
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kp-import-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Importe dans un coffre neuf, le rouvre et rend (coffre, groupe d'import).
fn import(imported: Imported) -> (Vault, GroupNode, kittypass_core::vault::import::ImportReport) {
    let mut v = Vault::create(PW).unwrap();
    let report = v.import(&v.root_id(), "Import", imported).unwrap();
    let v = Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap();
    let group = find_group(&v.groups(), &report.group_id).unwrap();
    (v, group, report)
}

fn find_group(node: &GroupNode, id: &str) -> Option<GroupNode> {
    if node.id == id {
        return Some(node.clone());
    }
    node.children.iter().find_map(|c| find_group(c, id))
}

fn child<'a>(node: &'a GroupNode, name: &str) -> &'a GroupNode {
    node.children.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("groupe « {name} » absent"))
}

fn entries(v: &Vault, node: &GroupNode) -> Vec<(String, EntryData)> {
    v.entries_in(&node.id).unwrap().into_iter().map(|s| (s.id.clone(), v.get(&s.id).unwrap())).collect()
}

fn entry(v: &Vault, node: &GroupNode, title: &str) -> (String, EntryData) {
    entries(v, node).into_iter().find(|(_, d)| d.title == title).unwrap_or_else(|| panic!("entrée « {title} » absente"))
}

fn custom<'a>(d: &'a EntryData, key: &str) -> Option<&'a kittypass_core::vault::CustomField> {
    d.custom.iter().find(|c| c.key == key)
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        w.start_file(*name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------- CSV

#[test]
fn csv_keepassxc_format() {
    let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
        \"Root\",\"Banque\",\"alice\",\"p@ss,\"\"word\"\"\",\"https://banque.example\",\"ligne 1\nligne 2\",\"\",\"0\",\"\",\"\"\n\
        \"Root/Travail/Serveurs\",\"SSH\",\"root\",\"=cmd|'/C calc'!A0\",\"\",\"\",\"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\",\"0\",\"\",\"\"\n";
    let parsed = parse_csv(csv.as_bytes()).unwrap();
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    let (v, g, report) = import(parsed);
    assert_eq!((report.imported, report.skipped), (2, 0));
    // « Root » commun retiré, chemins recréés.
    let (_, banque) = entry(&v, &g, "Banque");
    assert_eq!(banque.username, "alice");
    assert_eq!(banque.password.as_str(), "p@ss,\"word\"");
    assert_eq!(banque.notes.as_str(), "ligne 1\nligne 2");
    let serveurs = child(child(&g, "Travail"), "Serveurs");
    let (_, ssh) = entry(&v, serveurs, "SSH");
    // Les secrets ne sont jamais modifiés (même une « formule »).
    assert_eq!(ssh.password.as_str(), "=cmd|'/C calc'!A0");
    assert!(ssh.otp.as_deref().unwrap().starts_with("otpauth://"));
}

#[test]
fn csv_browser_exports_semicolon_and_cp1252() {
    // Chrome : name,url,username,password,note
    let chrome = "name,url,username,password,note\nexample.com,https://example.com/login,bob,secret,\n";
    let (v, g, _) = import(parse_csv(chrome.as_bytes()).unwrap());
    let (_, d) = entry(&v, &g, "example.com");
    assert_eq!((d.username.as_str(), d.password.as_str(), d.url.as_str()), ("bob", "secret", "https://example.com/login"));

    // Excel français : « ; » et Windows-1252.
    let mut excel = b"Titre;Identifiant;Mot de passe;Site web\n".to_vec();
    excel.extend_from_slice(b"Caf\xe9;jos\xe9;\x80uro;https://caf.example\n");
    let parsed = parse_csv(&excel).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    let (v, g, _) = import(parsed);
    let (_, d) = entry(&v, &g, "Café");
    assert_eq!((d.username.as_str(), d.password.as_str()), ("josé", "€uro"));

    // Titre absent : déduit de l'URL.
    let no_title = "url,username,password\nhttps://user:pw@login.example.org:8443/x,u,p\n";
    let (v, g, _) = import(parse_csv(no_title.as_bytes()).unwrap());
    assert_eq!(entries(&v, &g)[0].1.title, "login.example.org:8443");
}

#[test]
fn csv_hostile_input() {
    assert!(matches!(parse_csv(b"foo,bar\n1,2\n"), Err(Error::InvalidArgument(_))));
    assert!(matches!(parse_csv(b"\xFF\xFEt\0i\0"), Err(Error::InvalidArgument(_))));
    assert!(matches!(parse_csv(b""), Err(Error::InvalidArgument(_))));
    let big = vec![b'a'; kittypass_core::vault::import::MAX_IMPORT_BYTES + 1];
    assert!(matches!(parse_csv(&big), Err(Error::TooLarge)));

    // Caractère interdit en XML dans le mot de passe : entrée ignorée, le
    // secret n'est jamais « nettoyé » silencieusement ni recopié dans
    // l'avertissement.
    let csv = "title,username,password,url,group\n\
        Bonne,u,ok,,\n\
        Mauvaise,u,se\u{1}cret-unique-42,,\n\
        \u{202E}Usurp\u{200B}ation,u\u{0}x,p,https://a\u{7}.example,../../etc\n\
        Profonde,u,p,,a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t\n";
    let parsed = parse_csv(csv.as_bytes()).unwrap();
    let (v, g, report) = import(parsed);
    assert_eq!((report.imported, report.skipped), (3, 1));
    assert!(report.warnings.iter().all(|w| !w.contains("cret-unique-42")));
    assert!(report.warnings.iter().any(|w| w.contains("Mauvaise")));
    // Les caractères trompeurs disparaissent des noms de groupes ; les
    // caractères de contrôle des champs visibles.
    let all = entries_rec(&v, &g);
    let usurp = all.iter().find(|d| d.title.contains("Usurp")).unwrap();
    assert_eq!(usurp.username, "ux");
    assert_eq!(usurp.url, "https://a.example");
    assert!(g.children.iter().any(|c| c.name == ".."));
    // Profondeur bornée à 16 niveaux sous le groupe d'import.
    assert!(depth(&g) <= 16, "profondeur {}", depth(&g));
}

fn depth(n: &GroupNode) -> usize {
    n.children.iter().map(|c| 1 + depth(c)).max().unwrap_or(0)
}

fn entries_rec(v: &Vault, n: &GroupNode) -> Vec<EntryData> {
    let mut out: Vec<EntryData> = entries(v, n).into_iter().map(|(_, d)| d).collect();
    for c in &n.children {
        out.extend(entries_rec(v, c));
    }
    out
}

#[test]
fn csv_too_many_entries() {
    let mut csv = String::from("title,password\n");
    for i in 0..=kittypass_core::vault::import::MAX_IMPORT_ENTRIES {
        csv.push_str(&format!("t{i},p\n"));
    }
    assert!(matches!(parse_csv(csv.as_bytes()), Err(Error::InvalidArgument(_))));
}

#[test]
fn import_is_atomic_and_keeps_vault_intact_on_error() {
    let mut v = Vault::create(PW).unwrap();
    v.add(&EntryData { title: "Existante".into(), ..Default::default() }).unwrap();
    let before = v.groups();
    let parsed = parse_csv(b"title,password\na,b\n").unwrap();
    assert!(v.import("groupe-inexistant", "Import", parsed).is_err());
    assert_eq!(format!("{:?}", v.groups()), format!("{before:?}"));
}

// ---------------------------------------------------------- Bitwarden

const BITWARDEN: &str = r#"{
  "encrypted": false,
  "folders": [{"id": "f1", "name": "Perso/Banques"}],
  "items": [
    {"type": 1, "name": "Banque", "folderId": "f1", "favorite": true, "notes": "note",
     "login": {"username": "alice", "password": "pw1", "totp": "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
               "uris": [{"uri": "https://a.example"}, {"uri": "https://b.example"}, {"uri": "https://c.example"}]},
     "fields": [{"name": "PIN", "value": "1234", "type": 1}, {"name": "Lien", "value": null, "type": 3},
                {"name": "Title", "value": "piège", "type": 0}]},
    {"type": 2, "name": "Note sécurisée", "notes": "texte", "secureNote": {"type": 0}},
    {"type": 3, "name": "Carte", "card": {"cardholderName": "A", "number": "4111111111111111", "code": "123", "expMonth": "4"}},
    {"type": 4, "name": "Moi", "identity": {"firstName": "Alice", "passportNumber": "X123"}},
    {"type": 5, "name": "Clé", "sshKey": {"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA"}},
    {"type": 9, "name": "Inconnu"}
  ]
}"#;

#[test]
fn bitwarden_mapping() {
    let parsed = parse_bitwarden(BITWARDEN.as_bytes()).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    let (v, g, report) = import(parsed);
    assert_eq!(report.imported, 5);
    let banques = child(child(&g, "Perso"), "Banques");
    let (id, d) = entry(&v, banques, "Banque");
    assert_eq!((d.username.as_str(), d.password.as_str(), d.url.as_str()), ("alice", "pw1", "https://a.example"));
    assert_eq!(d.otp.as_deref().unwrap(), &format!("otpauth://totp/KittyPass?secret={SECRET_B32}"));
    assert_eq!(custom(&d, "KP2A_URL").unwrap().value.as_str(), "https://b.example");
    assert_eq!(custom(&d, "KP2A_URL_1").unwrap().value.as_str(), "https://c.example");
    assert!(custom(&d, "PIN").unwrap().protected);
    assert!(custom(&d, "Lien").is_none());
    // Un attribut nommé comme un champ standard ne l'écrase pas.
    assert_eq!(custom(&d, "Title (importé)").unwrap().value.as_str(), "piège");
    assert!(d.tags.contains(&"Favori".to_owned()));
    assert!(!v.excluded_from_reports(&id).unwrap());

    let (_, card) = entry(&v, &g, "Carte");
    assert!(custom(&card, "Numéro de carte").unwrap().protected);
    assert!(custom(&card, "Code de sécurité").unwrap().protected);
    assert!(!custom(&card, "Titulaire").unwrap().protected);
    let (_, me) = entry(&v, &g, "Moi");
    assert!(custom(&me, "Numéro de passeport").unwrap().protected);
    let (_, key) = entry(&v, &g, "Clé");
    assert!(custom(&key, "Clé privée SSH").unwrap().protected);
}

#[test]
fn bitwarden_rejects_encrypted_and_garbage() {
    let enc = r#"{"encrypted": true, "passwordProtected": true, "data": "2.abc"}"#;
    assert!(matches!(parse_bitwarden(enc.as_bytes()), Err(Error::InvalidArgument(m)) if m.contains("chiffré")));
    assert!(parse_bitwarden(b"{\"items\": 3}").is_err());
    assert!(parse_bitwarden(b"[").is_err());
    // Profondeur JSON extrême : serde_json la refuse sans débordement de pile.
    let deep = "[".repeat(100_000);
    assert!(parse_bitwarden(deep.as_bytes()).is_err());
    // BOM accepté.
    let bom = [b"\xEF\xBB\xBF".as_slice(), br#"{"items":[{"type":2,"name":"n"}]}"#].concat();
    assert_eq!(parse_bitwarden(&bom).unwrap().entries.len(), 1);
}

// ---------------------------------------------------------- 1Password

fn onepux_export(items: &str) -> String {
    format!(
        r#"{{"accounts":[{{"attrs":{{"accountName":"Moi"}},"vaults":[{{"attrs":{{"name":"Privé"}},"items":[{items}]}}]}}]}}"#
    )
}

const ONEPUX_ITEMS: &str = r#"
{"state":"active","favIndex":1,"overview":{"title":"Banque","url":"https://a.example","urls":[{"url":"https://a.example"},{"url":"https://b.example"}],"tags":["finance"]},
 "details":{"notesPlain":"note","loginFields":[
   {"designation":"username","value":"alice","name":"user"},
   {"designation":"password","value":"pw1","name":"pass","fieldType":"P"},
   {"value":"extra","name":"remember","fieldType":"T"}],
  "sections":[{"title":"Sécurité","fields":[
    {"title":"2FA","id":"otp","value":{"totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
    {"title":"PIN","id":"pin","value":{"concealed":"9876"}},
    {"title":"Mail","value":{"email":{"email_address":"a@b.example"}}},
    {"title":"Expire","value":{"monthYear":202711}},
    {"title":"Scan","value":{"file":{"documentId":"doc1","fileName":"scan.pdf"}}},
    {"title":"Absent","value":{"file":{"documentId":"nope","fileName":"x.txt"}}}]}]}},
{"state":"archived","overview":{"title":"Ancien"},"details":{"password":"old"}},
{"state":"trashed","overview":{"title":"Supprimé"},"details":{"password":"x"}},
{"state":"active","overview":{"title":"Document"},"details":{"documentAttributes":{"documentId":"doc2","fileName":"../../.bashrc"}}}
"#;

#[test]
fn onepux_mapping() {
    let export = onepux_export(ONEPUX_ITEMS);
    let data = zip(&[
        ("export.attributes", b"{}"),
        ("export.data", export.as_bytes()),
        ("files/doc1__scan.pdf", b"%PDF-1.7"),
        ("files/doc2__.bashrc", b"echo hi"),
    ]);
    let parsed = parse_1pux(&data).unwrap();
    assert_eq!(parsed.warnings.len(), 1, "{:?}", parsed.warnings);
    let (v, g, report) = import(parsed);
    assert_eq!(report.imported, 3);
    let prive = child(&g, "Privé");
    let (id, d) = entry(&v, prive, "Banque");
    assert_eq!((d.username.as_str(), d.password.as_str(), d.url.as_str()), ("alice", "pw1", "https://a.example"));
    assert_eq!(custom(&d, "KP2A_URL").unwrap().value.as_str(), "https://b.example");
    assert!(d.otp.as_deref().unwrap().contains("JBSWY3DPEHPK3PXP"));
    assert!(custom(&d, "Sécurité : PIN").unwrap().protected);
    assert_eq!(custom(&d, "Sécurité : Mail").unwrap().value.as_str(), "a@b.example");
    assert_eq!(custom(&d, "Sécurité : Expire").unwrap().value.as_str(), "11/2027");
    assert!(!custom(&d, "remember").unwrap().protected);
    assert!(d.tags.contains(&"finance".to_owned()) && d.tags.contains(&"Favori".to_owned()));
    assert_eq!(v.attachment(&id, "scan.pdf").unwrap().as_slice(), b"%PDF-1.7");
    let (_, old) = entry(&v, prive, "Ancien");
    assert!(old.tags.contains(&"Archivé".to_owned()));
    assert!(entries(&v, prive).iter().all(|(_, d)| d.title != "Supprimé"));
    // Nom de fichier avec « ../ » : séparateurs neutralisés.
    let (doc, _) = entry(&v, prive, "Document");
    let names: Vec<String> = v.attachments(&doc).unwrap().into_iter().map(|a| a.name).collect();
    assert_eq!(names, [".._.._.bashrc"]);
}

#[test]
fn onepux_hostile_archives() {
    assert!(matches!(parse_1pux(b"pas un zip"), Err(Error::InvalidArgument(_))));
    assert!(matches!(parse_1pux(&zip(&[("autre", b"x")])), Err(Error::InvalidArgument(_))));
    assert!(matches!(parse_1pux(&zip(&[("export.data", b"{")])), Err(Error::InvalidArgument(_))));
    // Bombe zip : export.data de 64 Mio + 1 de zéros (≈ 64 Kio compressés).
    let bomb = vec![b' '; kittypass_core::vault::import::MAX_IMPORT_BYTES + 1];
    let data = zip(&[("export.data", &bomb)]);
    assert!(data.len() < 1024 * 1024);
    assert!(matches!(parse_1pux(&data), Err(Error::TooLarge)));
    // Pièce jointe de plus de 16 Mio une fois décompressée : ignorée, le
    // reste est importé.
    let export = onepux_export(
        r#"{"overview":{"title":"Gros"},"details":{"documentAttributes":{"documentId":"big","fileName":"big.bin"}}}"#,
    );
    let big = vec![0u8; 16 * 1024 * 1024 + 1];
    let parsed = parse_1pux(&zip(&[("export.data", export.as_bytes()), ("files/big__big.bin", &big)])).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    assert!(parsed.entries[0].attachments.is_empty());
    assert!(parsed.warnings[0].contains("trop volumineuse"));
    // Structure inattendue : aucun plantage.
    for weird in [r#"{"accounts":3}"#, r#"{"accounts":[{"vaults":[{"items":[1,null,"x",{"overview":[]}]}]}]}"#] {
        let _ = parse_1pux(&zip(&[("export.data", weird.as_bytes())])).unwrap();
    }
}

// ------------------------------------------------------------- KeePass

#[test]
fn kdbx_copy_keeps_structure_and_skips_recycle_bin() {
    let mut src = Vault::create("autre-coffre-source").unwrap();
    let g = src.add_group(&src.root_id(), "Travail").unwrap();
    let mut data = EntryData {
        title: "Serveur".into(),
        username: "root".into(),
        password: Zeroizing::new("pw".into()),
        tags: vec!["prod".into()],
        expires: Some(1_900_000_000),
        ..Default::default()
    };
    data.custom.push(kittypass_core::vault::CustomField { key: "Clé".into(), value: Zeroizing::new("v".into()), protected: true });
    let id = src.add_in(&g, &data).unwrap();
    src.add_attachment(&id, "id_ed25519", b"KEY").unwrap();
    src.set_excluded_from_reports(&id, true).unwrap();
    let vide = src.add_group(&src.root_id(), "Vide").unwrap();
    src.add_group(&vide, "Sous-vide").unwrap();
    src.add_group(&g, "Archives").unwrap();
    let gone = src.add(&EntryData { title: "À la corbeille".into(), ..Default::default() }).unwrap();
    src.delete(&gone).unwrap();

    let (v, g, report) = import(parse_kdbx(&src).unwrap());
    assert_eq!(report.imported, 1);
    let (new_id, d) = entry(&v, child(&g, "Travail"), "Serveur");
    assert_ne!(new_id, id);
    assert_eq!(d.expires, Some(1_900_000_000));
    assert_eq!(d.tags, ["prod"]);
    assert!(custom(&d, "Clé").unwrap().protected);
    assert_eq!(v.attachment(&new_id, "id_ed25519").unwrap().as_slice(), b"KEY");
    assert!(v.excluded_from_reports(&new_id).unwrap());
    // Les groupes vides sont recréés.
    assert!(child(child(&g, "Vide"), "Sous-vide").children.is_empty());
    child(child(&g, "Travail"), "Archives");
}

#[test]
fn keepassxc_interop_kdbx_and_csv() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = tmp("kx");
    let db = dir.join("kx.kdbx");
    let db_s = db.to_str().unwrap();
    keepassxc(&["db-create", "-q", "-p", db_s], &format!("{PW}\n{PW}\n"));
    keepassxc(&["mkdir", "-q", db_s, "Équipe"], &format!("{PW}\n"));
    keepassxc(
        &["add", "-q", "-u", "bob", "--url", "https://x.example", "-p", db_s, "Équipe/Compte"],
        &format!("{PW}\nsecr\"et;,\n"),
    );

    // KDBX créé par KeePassXC.
    let src = Vault::open(&std::fs::read(&db).unwrap(), PW, &OpenLimits::default()).unwrap();
    let (v, g, _) = import(parse_kdbx(&src).unwrap());
    let (_, d) = entry(&v, child(&g, "Équipe"), "Compte");
    assert_eq!((d.username.as_str(), d.password.as_str()), ("bob", "secr\"et;,"));

    // CSV exporté par KeePassXC.
    let out = keepassxc(&["export", "-q", "-f", "csv", db_s], &format!("{PW}\n"));
    let (v, g, _) = import(parse_csv(&out.stdout).unwrap());
    let (_, d) = entry(&v, child(&g, "Équipe"), "Compte");
    assert_eq!((d.username.as_str(), d.password.as_str(), d.url.as_str()), ("bob", "secr\"et;,", "https://x.example"));
    let _ = std::fs::remove_dir_all(dir);
}
