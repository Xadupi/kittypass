//! Agent SSH : réglages et clé lus par KeePassXC, et relus après une
//! réécriture du fichier par KeePassXC.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use kittypass_core::{
    header::OpenLimits,
    ssh::{AgentSettings, SETTINGS_ATTACHMENT},
    vault::{EntryData, KeySource, Vault},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-ssh";

fn keepassxc(args: &[&str]) -> Option<std::process::Output> {
    let mut child = Command::new("keepassxc-cli").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
    child.stdin.take().unwrap().write_all(PW.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    Some(out)
}

#[test]
fn keepassxc_reads_and_keeps_ssh_settings() {
    if Command::new("keepassxc-cli").arg("--version").output().is_err() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-ssh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("coffre.kdbx");

    let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfausse\n-----END OPENSSH PRIVATE KEY-----\n";
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&EntryData { title: "Serveur".into(), password: Zeroizing::new("phrase".into()), ..Default::default() }).unwrap();
    v.add_attachment(&id, "id_ed25519", key).unwrap();
    let settings = AgentSettings {
        allow: true,
        add_at_open: true,
        remove_at_close: true,
        use_lifetime: true,
        lifetime_secs: 3600,
        use_attachment: true,
        attachment_name: "id_ed25519".into(),
        ..Default::default()
    };
    v.set_entry_ssh(&id, &settings).unwrap();
    std::fs::write(&file, v.save().unwrap()).unwrap();
    let path = file.to_str().unwrap();

    // KeePassXC voit les deux pièces jointes, au même contenu.
    let xml = keepassxc(&["attachment-export", "-q", "--stdout", path, "Serveur", SETTINGS_ATTACHMENT]).unwrap();
    assert_eq!(xml.stdout, settings.to_xml().as_bytes());
    let k = keepassxc(&["attachment-export", "-q", "--stdout", path, "Serveur", "id_ed25519"]).unwrap();
    assert_eq!(k.stdout, key);

    // KeePassXC réécrit le fichier (modification d'un autre champ) : les
    // réglages SSH restent lisibles par KittyPass.
    keepassxc(&["edit", "-q", "-u", "alice", path, "Serveur"]).unwrap();
    let v = Vault::open(&std::fs::read(&file).unwrap(), PW, &OpenLimits::default()).unwrap();
    assert_eq!(v.entry_ssh(&id).unwrap(), settings);
    assert_eq!(v.ssh_entries().len(), 1);
    let k = v.ssh_key(&id).unwrap();
    assert!(matches!(&k.source, KeySource::Attachment(d) if &d[..] == key));
    let _ = std::fs::remove_dir_all(&dir);
}
