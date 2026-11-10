//! Étiquettes, expiration et recherche avancée (syntaxe KeePassXC).

use std::io::Write;
use std::process::{Command, Stdio};

use kittypass_core::{
    Error,
    header::OpenLimits,
    vault::{CustomField, EntryData, Vault},
};
use proptest::prelude::*;
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-recherche";
const YEAR_2100: i64 = 4_102_444_800;

fn reopen(v: &Vault) -> Vault {
    Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn entry(title: &str) -> EntryData {
    EntryData { title: title.into(), password: Zeroizing::new("x".into()), ..Default::default() }
}

// ---------------------------------------------------------------- étiquettes

#[test]
fn tags_roundtrip_and_counts() {
    let mut v = Vault::create(PW).unwrap();
    let a = v.add(&EntryData { tags: vec!["travail".into(), "vpn".into()], ..entry("A") }).unwrap();
    v.add(&EntryData { tags: vec!["travail".into()], ..entry("B") }).unwrap();
    let c = v.add(&EntryData { tags: vec!["poubelle".into()], ..entry("C") }).unwrap();
    v.delete(&c).unwrap();
    let v = reopen(&v);
    assert_eq!(v.get(&a).unwrap().tags, ["travail", "vpn"]);
    assert_eq!(v.tags(), [("travail".to_string(), 2), ("vpn".to_string(), 1)], "corbeille exclue");
    assert_eq!(v.list().iter().find(|s| s.id == a).unwrap().tags, ["travail", "vpn"]);
}

#[test]
fn hostile_tags_are_refused() {
    let mut v = Vault::create(PW).unwrap();
    let long = "x".repeat(129);
    let too_many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
    let cases: Vec<Vec<String>> = vec![
        vec!["a;b".into()],
        vec!["a,b".into()],
        vec!["a\tb".into()],
        vec![" espace".into()],
        vec!["espace ".into()],
        vec!["".into()],
        vec!["Perso".into(), "perso".into()],
        vec!["\u{202E}gat".into()],
        vec![long],
        too_many,
    ];
    for tags in cases {
        let d = EntryData { tags: tags.clone(), ..entry("x") };
        assert!(matches!(v.add(&d), Err(Error::InvalidArgument(_))), "{tags:?}");
    }
    assert!(v.is_empty());
    v.add(&EntryData { tags: vec!["avec espace".into(), "émoji 🔑".into()], ..entry("ok") }).unwrap();
}

// ---------------------------------------------------------------- expiration

#[test]
fn expiry_roundtrip_flags_and_clearing() {
    let mut v = Vault::create(PW).unwrap();
    let past = v.add(&EntryData { expires: Some(now() - 3600), ..entry("Périmée") }).unwrap();
    let soon = v.add(&EntryData { expires: Some(now() + 3 * 86_400), ..entry("Bientôt") }).unwrap();
    let later = v.add(&EntryData { expires: Some(YEAR_2100), ..entry("Lointaine") }).unwrap();
    v.add(&entry("Jamais")).unwrap();

    let mut v = reopen(&v);
    assert_eq!(v.get(&later).unwrap().expires, Some(YEAR_2100));
    let list = v.list();
    let get = |id: &str| list.iter().find(|s| s.id == id).unwrap().clone();
    assert!(get(&past).expired);
    assert!(!get(&soon).expired);
    let ids: Vec<_> = v.expiring(7 * 86_400).into_iter().map(|s| s.id).collect();
    assert_eq!(ids, [past.clone(), soon.clone()], "triées de la plus proche à la plus lointaine");

    v.update(&past, &entry("Périmée")).unwrap();
    assert_eq!(v.get(&past).unwrap().expires, None);
    assert!(!reopen(&v).list().iter().any(|s| s.expired));
    // L'historique garde l'ancienne date et sa restauration la ramène.
    v.restore_history(&past, 0).unwrap();
    assert!(v.get(&past).unwrap().expires.is_some());
}

#[test]
fn out_of_range_expiry_is_refused() {
    let mut v = Vault::create(PW).unwrap();
    for t in [i64::MIN, i64::MAX, 253_402_300_800, -62_135_596_801] {
        assert!(matches!(v.add(&EntryData { expires: Some(t), ..entry("x") }), Err(Error::InvalidArgument(_))));
    }
    // Bornes incluses.
    for t in [253_402_300_799, -62_135_596_800, 0] {
        let id = v.add(&EntryData { expires: Some(t), ..entry("x") }).unwrap();
        assert_eq!(reopen(&v).get(&id).unwrap().expires, Some(t));
    }
}

// ---------------------------------------------------------------- recherche

fn sample() -> (Vault, Vec<String>) {
    let mut v = Vault::create(PW).unwrap();
    let travail = v.add_group(&v.root_id(), "Travail").unwrap();
    let serveurs = v.add_group(&travail, "Serveurs").unwrap();
    let ids = vec![
        v.add(&EntryData {
            title: "Banque Populaire".into(),
            username: "alice".into(),
            password: Zeroizing::new("motdepasse-secret".into()),
            url: "https://banque.example.org".into(),
            notes: Zeroizing::new("Été 2024, conseiller Martin".into()),
            tags: vec!["finance".into()],
            ..Default::default()
        })
        .unwrap(),
        v.add_in(
            &serveurs,
            &EntryData {
                title: "SSH prod".into(),
                username: "root".into(),
                url: "ssh://prod.example.com".into(),
                tags: vec!["serveur".into(), "critique".into()],
                custom: vec![
                    CustomField { key: "Port".into(), value: Zeroizing::new("2222".into()), protected: false },
                    CustomField { key: "Passphrase".into(), value: Zeroizing::new("caché".into()), protected: true },
                ],
                expires: Some(now() - 60),
                ..Default::default()
            },
        )
        .unwrap(),
        v.add_in(
            &travail,
            &EntryData { title: "Mail pro".into(), username: "alice@corp".into(), ..Default::default() },
        )
        .unwrap(),
    ];
    v.add_attachment(&ids[1], "id_ed25519.pub", b"ssh-ed25519 AAAA").unwrap();
    let gone = v.add(&EntryData { title: "Banque fermée".into(), ..Default::default() }).unwrap();
    v.delete(&gone).unwrap();
    (v, ids)
}

fn titles(v: &Vault, q: &str) -> Vec<String> {
    v.search(q).unwrap().into_iter().map(|s| s.title).collect()
}

#[test]
fn default_fields_never_include_password() {
    let (v, _) = sample();
    assert_eq!(titles(&v, "banque"), ["Banque Populaire"], "corbeille exclue");
    assert_eq!(titles(&v, "MARTIN"), ["Banque Populaire"], "notes");
    assert_eq!(titles(&v, "critique"), ["SSH prod"], "étiquettes");
    assert_eq!(titles(&v, "example"), ["Banque Populaire", "SSH prod"]);
    assert!(titles(&v, "motdepasse").is_empty());
    assert_eq!(titles(&v, "p:motdepasse"), ["Banque Populaire"]);
    assert_eq!(titles(&v, "été"), titles(&v, "ÉTÉ"), "casse Unicode");
    assert_eq!(titles(&v, "").len(), 3);
}

#[test]
fn field_prefixes() {
    let (v, ids) = sample();
    assert_eq!(titles(&v, "u:alice"), ["Banque Populaire", "Mail pro"]);
    assert_eq!(titles(&v, "username:root"), ["SSH prod"]);
    assert_eq!(titles(&v, "url:ssh://"), ["SSH prod"]);
    assert_eq!(titles(&v, "t:mail"), ["Mail pro"]);
    assert_eq!(titles(&v, "tag:fin"), ["Banque Populaire"]);
    assert_eq!(titles(&v, "g:serveurs"), ["SSH prod"]);
    assert_eq!(titles(&v, "group:travail"), ["Mail pro", "SSH prod"], "chemin complet");
    assert_eq!(titles(&v, "attr:port"), ["SSH prod"]);
    assert_eq!(titles(&v, "attr:2222"), ["SSH prod"]);
    assert!(titles(&v, "attr:caché").is_empty(), "valeur protégée jamais cherchée");
    assert_eq!(titles(&v, "attach:ed25519"), ["SSH prod"]);
    assert_eq!(titles(&v, &format!("uuid:{}", ids[2])), ["Mail pro"]);
    assert_eq!(titles(&v, &format!("uuid:{}", ids[2].replace('-', ""))), ["Mail pro"]);
    assert_eq!(titles(&v, "is:expired"), ["SSH prod"]);
    assert_eq!(titles(&v, "-is:expired"), ["Banque Populaire", "Mail pro"]);
    assert!(titles(&v, "is:inconnu").is_empty());
    // Champ inconnu : texte ordinaire.
    assert!(titles(&v, "foo:bar").is_empty());
}

#[test]
fn modifiers_wildcards_and_phrases() {
    let (v, _) = sample();
    assert_eq!(titles(&v, "-banque"), ["Mail pro", "SSH prod"]);
    assert_eq!(titles(&v, "!banque"), ["Mail pro", "SSH prod"]);
    assert_eq!(titles(&v, "alice -t:mail"), ["Banque Populaire"], "ET entre termes");
    assert!(titles(&v, "+t:ssh").is_empty(), "exact : champ entier");
    assert_eq!(titles(&v, "+t:\"ssh prod\""), ["SSH prod"]);
    assert_eq!(titles(&v, "+t:ssh*"), ["SSH prod"]);
    assert_eq!(titles(&v, "t:b*e p*"), ["Banque Populaire"]);
    assert_eq!(titles(&v, "u:al?ce"), ["Banque Populaire", "Mail pro"]);
    assert_eq!(titles(&v, "\"banque populaire\""), ["Banque Populaire"]);
    assert!(titles(&v, "\"populaire banque\"").is_empty());
    // « url: » vide : champ renseigné ; « -url: » : champ vide.
    assert_eq!(titles(&v, "-url:"), ["Mail pro"]);
    assert_eq!(titles(&v, "tag:").len(), 2);
}

#[test]
fn scoped_search() {
    let (v, _) = sample();
    let travail = v.groups().children.iter().find(|g| g.name == "Travail").unwrap().id.clone();
    let names: Vec<_> = v.search_in(&travail, "").unwrap().into_iter().map(|s| s.title).collect();
    assert_eq!(names, ["Mail pro", "SSH prod"], "sous-groupes inclus");
    assert!(v.search_in(&travail, "banque").unwrap().is_empty());
    assert!(matches!(v.search_in("6f1c5b0e-0000-4000-8000-000000000000", ""), Err(Error::GroupNotFound)));
    assert!(matches!(v.search_in("x", ""), Err(Error::InvalidId)));
    // Chercher dans la corbeille elle-même ne la rend pas cherchable.
    assert!(v.search_in(&v.recycle_bin().unwrap(), "").unwrap().is_empty());
}

#[test]
fn oversized_query_is_an_error() {
    let (v, _) = sample();
    assert!(matches!(v.search(&"a".repeat(1025)), Err(Error::InvalidArgument(_))));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]
    /// N'importe quelle requête : jamais de panique, et l'exclusion d'un
    /// terme donne exactement le complément.
    #[test]
    fn any_query_is_safe(q in "[a-z:*?+!\"\\- é]{0,40}") {
        let (v, _) = sample();
        let all = v.search("").unwrap().len();
        if let Ok(hits) = v.search(&q) {
            prop_assert!(hits.len() <= all);
        }
    }

    #[test]
    fn exclusion_is_complement(word in "[a-z]{1,6}") {
        let (v, _) = sample();
        let all = v.search("").unwrap().len();
        let yes = v.search(&word).unwrap().len();
        let no = v.search(&format!("-{word}")).unwrap().len();
        prop_assert_eq!(yes + no, all);
    }
}

// ---------------------------------------------------------------- KeePassXC

#[test]
fn keepassxc_sees_tags_and_expiry() {
    if Command::new("keepassxc-cli").arg("--version").output().is_err() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-search-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ours.kdbx");
    let mut v = Vault::create(PW).unwrap();
    v.add(&EntryData { tags: vec!["un".into(), "deux".into()], expires: Some(YEAR_2100), ..entry("Tagguée") })
        .unwrap();
    std::fs::write(&path, v.save().unwrap()).unwrap();

    let mut child = Command::new("keepassxc-cli")
        .args(["export", "-q", "-f", "xml", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("{PW}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let xml = String::from_utf8_lossy(&out.stdout);
    // KeePassXC trie les étiquettes et les sépare par des virgules.
    assert!(xml.contains("<Tags>deux,un</Tags>"), "étiquettes absentes de l'export KeePassXC");
    // Dates KDBX 4 : secondes depuis 0001-01-01, i64 little-endian en base64.
    // 2100-01-01 = 4102444800 + 62135596800 = 66238041600.
    let entry = &xml[xml.find("<Entry>").unwrap()..];
    let times = &entry[..entry.find("</Times>").unwrap()];
    assert!(times.contains("<ExpiryTime>AE4YbA8AAAA=</ExpiryTime>"), "date d'expiration altérée : {times}");
    assert!(times.contains("<Expires>True</Expires>"));
    std::fs::remove_dir_all(dir).ok();
}

/// Une entrée venue d'un autre logiciel KeePass, aux règles plus souples
/// (étiquette très longue, attribut « password » en minuscules, valeur
/// énorme), doit rester modifiable ; seules les valeurs nouvelles sont
/// vérifiées.
#[test]
fn foreign_entries_stay_editable() {
    if Command::new("keepassxc-cli").arg("--version").output().is_err() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-foreign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let long_tag = "t".repeat(200);
    let big = "x".repeat(70_000);
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Generator>test</Generator></Meta><Root><Group>
<UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Racine</Name>
<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><Tags>{long_tag}</Tags>
<String><Key>Title</Key><Value>Étrangère</Value></String>
<String><Key>UserName</Key><Value>{big}</Value></String>
<String><Key>password</Key><Value>attribut minuscule</Value></String>
</Entry></Group></Root></KeePassFile>"#
    );
    let xml_path = dir.join("in.xml");
    let db_path = dir.join("db.kdbx");
    std::fs::write(&xml_path, xml).unwrap();
    let mut child = Command::new("keepassxc-cli")
        .args(["import", "-q", "-p", xml_path.to_str().unwrap(), db_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("{PW}\n{PW}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut v = Vault::open(&std::fs::read(&db_path).unwrap(), PW, &OpenLimits::default()).unwrap();
    let id = v.search("Étrangère").unwrap()[0].id.clone();
    let mut d = v.get(&id).unwrap();
    assert_eq!(d.tags, std::slice::from_ref(&long_tag));
    assert_eq!(d.custom[0].key, "password");
    d.password = Zeroizing::new("nouveau".into());
    v.update(&id, &d).expect("entrée étrangère non modifiable");
    let d = reopen(&v).get(&id).unwrap();
    assert_eq!(d.password.as_str(), "nouveau");
    assert_eq!(d.username.len(), 70_000);
    assert_eq!(d.tags, [long_tag]);

    // Mais une nouvelle valeur hors règles reste refusée.
    let mut bad = d.clone();
    bad.tags.push("a;b".into());
    assert!(v.update(&id, &bad).is_err());
    let mut bad = d.clone();
    bad.username.push('y');
    assert!(v.update(&id, &bad).is_err(), "valeur modifiée : limites appliquées");
    let mut bad = d;
    bad.custom.push(CustomField { key: "Title".into(), ..Default::default() });
    assert!(v.update(&id, &bad).is_err());
    std::fs::remove_dir_all(dir).ok();
}
