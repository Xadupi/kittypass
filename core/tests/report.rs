//! Bilan de santé des mots de passe et préparation HIBP : estimation de
//! robustesse, réutilisation, expiration, exclusion compatible KeePassXC,
//! entrées hostiles.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kittypass_core::{
    header::OpenLimits,
    hibp,
    vault::{EntryData, Quality, Vault, strength},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-rapport";
const STRONG: &str = "q7#Vt9!mZ2@wL4$kR8%xN";

fn e(title: &str, pw: &str) -> EntryData {
    EntryData { title: title.into(), password: Zeroizing::new(pw.into()), ..Default::default() }
}

fn reopen(v: &Vault) -> Vault {
    Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap()
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
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    out
}

// ---------------------------------------------------------------- robustesse

#[test]
fn strength_matches_keepassxc_thresholds() {
    assert_eq!(Quality::from_bits(0.0), Quality::Bad);
    assert_eq!(Quality::from_bits(f64::NAN), Quality::Bad);
    assert_eq!(Quality::from_bits(39.9), Quality::Poor);
    assert_eq!(Quality::from_bits(40.0), Quality::Weak);
    assert_eq!(Quality::from_bits(75.0), Quality::Good);
    assert_eq!(Quality::from_bits(100.0), Quality::Excellent);

    assert_eq!(strength("", &[]).quality, Quality::Bad);
    assert_eq!(strength("", &[]).bits, 0.0);
    for weak in ["password", "123456", "azerty", "Password1", "qwertyuiop", "aaaaaaaaaaaaaaaa", "abcdefgh"] {
        assert!(strength(weak, &[]).quality <= Quality::Poor, "{weak} jugé {:?}", strength(weak, &[]));
    }
    assert!(strength(STRONG, &[]).quality >= Quality::Good);
    assert_eq!(strength("correct horse battery staple jumping quietly", &[]).quality, Quality::Excellent);
}

#[test]
fn reusing_title_or_username_is_penalised() {
    let alone = strength("Zorglub-Marseille", &[]).bits;
    let with_inputs = strength("Zorglub-Marseille", &["zorglub", "marseille"]).bits;
    assert!(with_inputs < alone, "{with_inputs} >= {alone}");
    // Des entrées vides ou énormes ne posent pas problème.
    let huge = "x".repeat(1_000_000);
    let t = Instant::now();
    strength(STRONG, &["", &huge, &huge]);
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[test]
fn hostile_passwords_are_evaluated_quickly() {
    for pw in [
        "a".repeat(1_000_000),
        "ab".repeat(500_000),
        "0123456789".repeat(100_000),
        "é🔑\u{202e}\0".repeat(100_000),
        "password".repeat(100_000),
    ] {
        let t = Instant::now();
        let s = strength(&pw, &[]);
        assert!(t.elapsed() < Duration::from_secs(2), "trop lent : {:?}", t.elapsed());
        assert!(s.bits.is_finite() && s.bits >= 0.0);
    }
}

// ---------------------------------------------------------------- rapport

#[test]
fn report_finds_weak_reused_and_expired() {
    let mut v = Vault::create(PW).unwrap();
    let weak = v.add(&e("Faible", "password")).unwrap();
    let r1 = v.add(&e("Réutilisé 1", "Partage-Commun-2024!xyz")).unwrap();
    let r2 = v.add(&e("Réutilisé 2", "Partage-Commun-2024!xyz")).unwrap();
    let r3 = v.add(&e("Réutilisé 3", "Partage-Commun-2024!xyz")).unwrap();
    let expired = v.add(&EntryData { expires: Some(1_000_000_000), ..e("Expirée", STRONG) }).unwrap();
    let _fine = v.add(&e("Saine", "unique-Tr3s-L0ng-et-Sur!42")).unwrap();
    let _empty = v.add(&e("Sans mot de passe", "")).unwrap();
    let binned = v.add(&e("Jetée", "123456")).unwrap();
    v.delete(&binned).unwrap();

    let r = v.health_report();
    assert_eq!(r.checked, 6, "corbeille et mots de passe vides ignorés");
    assert_eq!(r.excluded, 0);
    let ids: Vec<&str> = r.items.iter().map(|i| i.entry.id.as_str()).collect();
    assert_eq!(ids.len(), 5, "{:?}", r.items.iter().map(|i| &i.entry.title).collect::<Vec<_>>());
    assert_eq!(ids[0], weak, "le pire en premier");
    for id in [&r1, &r2, &r3] {
        let item = r.items.iter().find(|i| &i.entry.id == id).unwrap();
        assert_eq!(item.reused, 2, "deux autres entrées partagent ce mot de passe");
    }
    let ex = r.items.iter().find(|i| i.entry.id == expired).unwrap();
    assert!(ex.expired && ex.quality >= Quality::Good && ex.reused == 0);
    assert!(!ids.contains(&binned.as_str()));
}

#[test]
fn reuse_with_binned_entry_does_not_count() {
    let mut v = Vault::create(PW).unwrap();
    v.add(&e("Active", STRONG)).unwrap();
    let old = v.add(&e("Ancienne", STRONG)).unwrap();
    assert_eq!(v.health_report().items.len(), 2);
    v.delete(&old).unwrap();
    assert!(v.health_report().items.is_empty());
}

#[test]
fn report_never_contains_passwords() {
    let mut v = Vault::create(PW).unwrap();
    v.add(&e("Faible", "secret-faible-1")).unwrap();
    v.add(&e("A", "secret-reutilise-xyz")).unwrap();
    v.add(&e("B", "secret-reutilise-xyz")).unwrap();
    let dump = format!("{:?}", v.health_report());
    assert!(!dump.contains("secret-"), "{dump}");
}

#[test]
fn exclusion_persists_and_is_versioned() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("Connu", "password")).unwrap();
    assert!(!v.excluded_from_reports(&id).unwrap());
    v.set_excluded_from_reports(&id, true).unwrap();
    assert_eq!(v.history(&id).unwrap().len(), 1, "nouvelle version, comme KeePassXC");
    // Sans changement : aucune version de plus.
    v.set_excluded_from_reports(&id, true).unwrap();
    assert_eq!(v.history(&id).unwrap().len(), 1);

    let mut v = reopen(&v);
    assert!(v.excluded_from_reports(&id).unwrap());
    let r = v.health_report();
    assert_eq!(r.excluded, 1);
    assert!(r.items[0].excluded, "toujours listée, marquée exclue");
    let h = v.password_hashes();
    assert!(h[0].excluded);

    v.set_excluded_from_reports(&id, false).unwrap();
    assert!(!reopen(&v).excluded_from_reports(&id).unwrap());
    // Modifier l'entrée ne perd pas l'exclusion.
    v.set_excluded_from_reports(&id, true).unwrap();
    let mut d = v.get(&id).unwrap();
    d.title = "Renommée".into();
    v.update(&id, &d).unwrap();
    assert!(reopen(&v).excluded_from_reports(&id).unwrap());
    assert!(v.set_excluded_from_reports("pas-un-uuid", true).is_err());
}

#[test]
fn exclusion_survives_merge() {
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("Partagée", "password")).unwrap();
    let mut b = reopen(&a);
    a.set_excluded_from_reports(&id, true).unwrap();
    b.merge_from(&reopen(&a)).unwrap();
    assert!(b.excluded_from_reports(&id).unwrap());
}

#[test]
fn password_hashes_skip_bin_and_empty() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("Une", "password")).unwrap();
    v.add(&e("Vide", "")).unwrap();
    let gone = v.add(&e("Jetée", "autre")).unwrap();
    v.delete(&gone).unwrap();
    let h = v.password_hashes();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].id, id);
    assert_eq!(h[0].sha1.as_str(), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    assert_eq!(hibp::prefix(&h[0].sha1).unwrap(), "5BAA6");
}

#[test]
fn large_vault_report_is_fast_enough() {
    let mut v = Vault::create(PW).unwrap();
    for i in 0..1000 {
        let pw = format!("{}-{i}-{}", "Zq9!".repeat(20), "x".repeat(i % 50));
        v.add(&e(&format!("Entrée {i}"), &pw)).unwrap();
    }
    let t = Instant::now();
    let r = v.health_report();
    let elapsed = t.elapsed();
    assert_eq!(r.checked, 1000);
    assert!(elapsed < Duration::from_secs(10), "rapport trop lent : {elapsed:?}");
    eprintln!("rapport de 1000 entrées : {elapsed:?}");
}

// ---------------------------------------------------------------- KeePassXC

#[test]
fn keepassxc_sees_our_exclusion() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-report-out-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ours.kdbx");
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("Connue", "password")).unwrap();
    v.set_excluded_from_reports(&id, true).unwrap();
    std::fs::write(&path, v.save().unwrap()).unwrap();
    let out = keepassxc(&["export", "-q", "-f", "xml", path.to_str().unwrap()], &format!("{PW}\n"));
    let xml = String::from_utf8_lossy(&out.stdout);
    let entry = &xml[xml.find("<Entry>").unwrap()..];
    let entry = &entry[..entry.find("<History>").unwrap_or(entry.len())];
    // KeePassXC 2.7+ convertit l'ancienne clé KnownBad en champ standard.
    assert!(entry.contains("<QualityCheck>False</QualityCheck>"), "exclusion absente de l'export KeePassXC : {entry}");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn we_see_keepassxc_exclusion() {
    if !has_keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-report-in-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Generator>KeePassXC</Generator></Meta><Root><Group>
<UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Racine</Name>
<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>
<String><Key>Title</Key><Value>Exclue dans KeePassXC</Value></String>
<String><Key>Password</Key><Value>123456</Value></String>
<CustomData><Item><Key>KnownBad</Key><Value>true</Value></Item></CustomData>
</Entry>
<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID>
<String><Key>Title</Key><Value>Normale</Value></String>
<String><Key>Password</Key><Value>123456</Value></String>
</Entry></Group></Root></KeePassFile>"#;
    let xml_path = dir.join("in.xml");
    let db_path = dir.join("db.kdbx");
    std::fs::write(&xml_path, xml).unwrap();
    keepassxc(&["import", "-q", "-p", xml_path.to_str().unwrap(), db_path.to_str().unwrap()], &format!("{PW}\n{PW}\n"));
    let v = Vault::open(&std::fs::read(&db_path).unwrap(), PW, &OpenLimits::default()).unwrap();
    let r = v.health_report();
    assert_eq!(r.excluded, 1);
    let ex = r.items.iter().find(|i| i.entry.title == "Exclue dans KeePassXC").unwrap();
    let normal = r.items.iter().find(|i| i.entry.title == "Normale").unwrap();
    assert!(ex.excluded && !normal.excluded);
    assert_eq!(ex.reused, 1);
    std::fs::remove_dir_all(dir).ok();
}
