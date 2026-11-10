//! Exports : copie chiffrée, CSV, XML KeePass et HTML. Aller-retour par
//! l'import de KittyPass et par KeePassXC, échappement des valeurs hostiles,
//! corbeille jamais exportée en clair.

use std::io::Write;
use std::process::{Command, Stdio};

use kittypass_core::{
    Error,
    header::OpenLimits,
    keyfile::KeyFile,
    vault::{CustomField, EntryData, MasterKey, Vault, import::parse_csv},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-export";
const OTP: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
const HOSTILE: &str = "<script>alert('x')</script>\"&;,\n=1+1";

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

/// Coffre d'exemple : un groupe, une entrée complète et hostile, une entrée
/// à la corbeille. Rend (coffre, id de l'entrée complète).
fn sample() -> (Vault, String) {
    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Travail & <Co>").unwrap();
    let mut d = EntryData {
        title: format!("Serveur {HOSTILE}"),
        username: "root".into(),
        password: Zeroizing::new(HOSTILE.into()),
        url: "javascript:alert(1)".into(),
        notes: Zeroizing::new("ligne 1\nligne 2 ]]> <!--".into()),
        otp: Some(Zeroizing::new(OTP.into())),
        tags: vec!["prod".into(), "ssh".into()],
        expires: Some(1_900_000_000),
        ..Default::default()
    };
    d.custom.push(CustomField { key: "PIN".into(), value: Zeroizing::new("1234".into()), protected: true });
    d.custom.push(CustomField { key: "Note <b>".into(), value: Zeroizing::new("visible".into()), protected: false });
    let id = v.add_in(&g, &d).unwrap();
    v.add_attachment(&id, "id_ed25519", &[0, 1, 2, 255]).unwrap();
    v.set_excluded_from_reports(&id, true).unwrap();
    let gone = v.add(&EntryData { title: "Corbeille-secrète".into(), password: Zeroizing::new("supprimé-42".into()), ..Default::default() }).unwrap();
    v.delete(&gone).unwrap();
    (v, id)
}

#[test]
fn kdbx_copy_uses_new_key_only() {
    let (v, _) = sample();
    assert!(matches!(v.export_kdbx(&MasterKey::new("court", None)), Err(Error::WeakMasterPassword(_))));
    let (kf, _) = KeyFile::generate().unwrap();
    let key = MasterKey::new("autre-mot-de-passe", Some(kf));
    let copy = v.export_kdbx(&key).unwrap();
    assert!(Vault::open(&copy, PW, &OpenLimits::default()).is_err());
    assert!(Vault::open(&copy, "autre-mot-de-passe", &OpenLimits::default()).is_err());
    let c = Vault::open_with_key(&copy, &key, &OpenLimits::default()).unwrap();
    // Copie complète : corbeille comprise.
    assert_eq!(c.entries_in(&c.recycle_bin().unwrap()).unwrap().len(), 1);
    // Le coffre d'origine garde sa clé.
    assert!(Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).is_ok());
}

#[test]
fn csv_round_trip_and_no_recycle_bin() {
    let (v, _) = sample();
    let csv = v.export_csv().unwrap();
    let text = String::from_utf8(csv.to_vec()).unwrap();
    assert!(text.starts_with("\"Group\",\"Title\",\"Username\",\"Password\""));
    assert!(!text.contains("supprimé-42") && !text.contains("Corbeille"));
    let parsed = parse_csv(&csv).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    let e = &parsed.entries[0];
    assert_eq!(e.path, ["Travail & <Co>"]);
    assert_eq!(e.data.password.as_str(), HOSTILE);
    assert_eq!(e.data.notes.as_str(), "ligne 1\nligne 2 ]]> <!--");
    assert_eq!(e.data.otp.as_deref().unwrap(), OTP);
    assert_eq!(e.data.tags, ["prod", "ssh"]);
}

#[test]
fn xml_is_well_formed_and_escaped() {
    let (v, _) = sample();
    let xml = String::from_utf8(v.export_xml().unwrap().to_vec()).unwrap();
    assert!(!xml.contains("<script>") && !xml.contains("<b>") && !xml.contains("<Co>"));
    assert!(xml.contains("&lt;script&gt;"));
    assert!(xml.contains("<QualityCheck>False</QualityCheck>"));
    assert!(xml.contains("<Binary ID=\"0\" Compressed=\"False\">AAEC/w==</Binary>"));
    assert!(!xml.contains("supprimé-42"));
}

#[test]
fn xml_and_kdbx_copy_read_by_keepassxc() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (v, id) = sample();

    // XML → keepassxc-cli import → relu par KittyPass.
    let xml_path = dir.join("export.xml");
    let db_path = dir.join("depuis-xml.kdbx");
    std::fs::write(&xml_path, v.export_xml().unwrap().as_slice()).unwrap();
    keepassxc(&["import", "-q", "-p", xml_path.to_str().unwrap(), db_path.to_str().unwrap()], &format!("{PW}\n{PW}\n"));
    let back = Vault::open(&std::fs::read(&db_path).unwrap(), PW, &OpenLimits::default()).unwrap();
    let orig = v.get(&id).unwrap();
    let got = back.get(&id).unwrap();
    assert_eq!(got, orig);
    assert_eq!(back.attachment(&id, "id_ed25519").unwrap().as_slice(), &[0, 1, 2, 255]);
    assert!(back.excluded_from_reports(&id).unwrap());
    assert!(back.recycle_bin().is_none_or(|b| back.entries_in(&b).unwrap().is_empty()));

    // Copie .kdbx avec fichier clé : ouverte par KeePassXC.
    let kf_path = dir.join("cle.keyx");
    let (kf, kf_bytes) = KeyFile::generate().unwrap();
    std::fs::write(&kf_path, kf_bytes.as_slice()).unwrap();
    let copy_path = dir.join("copie.kdbx");
    std::fs::write(&copy_path, v.export_kdbx(&MasterKey::new("autre-mot-de-passe", Some(kf))).unwrap()).unwrap();
    let out = keepassxc(
        &["show", "-q", "-s", "-a", "PIN", "-k", kf_path.to_str().unwrap(), copy_path.to_str().unwrap(), &format!("Travail & <Co>/{}", orig.title)],
        "autre-mot-de-passe\n",
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1234");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn html_is_escaped_and_inert() {
    let (v, _) = sample();
    let html = String::from_utf8(v.export_html("Coffre <img src=x onerror=alert(1)>").unwrap().to_vec()).unwrap();
    assert!(html.contains("Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\""));
    for bad in ["<script", "<img", "<b>", "<a ", "href", "<!--"] {
        assert!(!html.contains(bad), "{bad} présent");
    }
    assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&quot;&amp;"));
    assert!(html.contains("javascript:alert(1)")); // en texte, jamais en lien
    assert!(html.contains("<th>PIN</th><td>1234</td>"));
    assert!(html.contains("id_ed25519 (non imprimées)"));
    assert!(!html.contains("supprimé-42"));
}
