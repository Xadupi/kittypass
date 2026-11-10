//! Groupes, corbeille, historique, attributs personnalisés, pièces jointes :
//! fonctionnement, entrées hostiles, fusion entre appareils, interopérabilité.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use kittypass_core::{
    Error,
    header::OpenLimits,
    vault::{CustomField, EntryData, GroupNode, MAX_ATTACHMENT_BYTES, MAX_DEPTH, RECYCLE_BIN_NAME, Vault},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-structure";

fn e(title: &str, pw: &str) -> EntryData {
    EntryData { title: title.into(), password: Zeroizing::new(pw.into()), ..Default::default() }
}

fn reopen(v: &Vault) -> Vault {
    Vault::open(&v.save().unwrap(), PW, &OpenLimits::default()).unwrap()
}

fn find<'a>(n: &'a GroupNode, name: &str) -> Option<&'a GroupNode> {
    if n.name == name {
        return Some(n);
    }
    n.children.iter().find_map(|c| find(c, name))
}

fn bin(v: &Vault) -> String {
    v.recycle_bin().expect("corbeille")
}

fn titles(v: &Vault) -> Vec<String> {
    v.list().into_iter().map(|s| s.title).collect()
}

// ---------------------------------------------------------------- groupes

#[test]
fn new_vault_has_recycle_bin_listed_last() {
    let mut v = Vault::create(PW).unwrap();
    v.add_group(&v.root_id(), "Zèbre").unwrap();
    v.add_group(&v.root_id(), "abeille").unwrap();
    let tree = v.groups();
    let names: Vec<_> = tree.children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["abeille", "Zèbre", RECYCLE_BIN_NAME]);
    assert!(tree.children[2].is_recycle_bin);
    assert_eq!(tree.children[2].icon, Some(43));
    assert_eq!(reopen(&v).recycle_bin(), v.recycle_bin(), "corbeille perdue à l'enregistrement");
}

#[test]
fn nested_groups_and_entries_survive_roundtrip() {
    let mut v = Vault::create(PW).unwrap();
    let perso = v.add_group(&v.root_id(), "Perso").unwrap();
    let banque = v.add_group(&perso, "Banque").unwrap();
    let id = v.add_in(&banque, &e("Compte courant", "x")).unwrap();
    v.add(&e("À la racine", "y")).unwrap();

    let v = reopen(&v);
    let tree = v.groups();
    let b = find(&tree, "Banque").unwrap();
    assert_eq!(b.entry_count, 1);
    assert_eq!(find(&tree, "Perso").unwrap().children.len(), 1);
    let inside = v.entries_in(&banque).unwrap();
    assert_eq!(inside.len(), 1);
    assert_eq!(inside[0].id, id);
    assert_eq!(inside[0].group_id, banque);
    assert_eq!(v.list().len(), 2);
}

#[test]
fn move_and_rename() {
    let mut v = Vault::create(PW).unwrap();
    let a = v.add_group(&v.root_id(), "A").unwrap();
    let b = v.add_group(&v.root_id(), "B").unwrap();
    let id = v.add_in(&a, &e("x", "x")).unwrap();
    v.move_entry(&id, &b).unwrap();
    assert!(v.entries_in(&a).unwrap().is_empty());
    assert_eq!(v.entries_in(&b).unwrap().len(), 1);
    assert_eq!(v.history_len(&id).unwrap(), 0, "un déplacement ne crée pas de version");

    v.move_group(&b, &a).unwrap();
    v.rename_group(&a, "A renommé").unwrap();
    let v = reopen(&v);
    let tree = v.groups();
    assert_eq!(find(&tree, "A renommé").unwrap().children[0].name, "B");
}

#[test]
fn impossible_group_moves_are_refused() {
    let mut v = Vault::create(PW).unwrap();
    let a = v.add_group(&v.root_id(), "A").unwrap();
    let child = v.add_group(&a, "Enfant").unwrap();
    // Cycle : un groupe dans son propre descendant, ou dans lui-même.
    assert!(matches!(v.move_group(&a, &child), Err(Error::InvalidArgument(_))));
    assert!(matches!(v.move_group(&a, &a), Err(Error::InvalidArgument(_))));
    // La racine ne bouge pas et ne se supprime pas.
    assert!(v.move_group(&v.root_id(), &a).is_err());
    assert!(matches!(v.delete_group(&v.root_id()), Err(Error::InvalidArgument(_))));

    let unknown = "6f1c5b0e-0000-4000-8000-000000000000";
    assert!(matches!(v.move_group(&a, unknown), Err(Error::GroupNotFound)));
    assert!(matches!(v.add_group(unknown, "x"), Err(Error::GroupNotFound)));
    assert!(matches!(v.add_in(unknown, &e("x", "x")), Err(Error::GroupNotFound)));
    assert!(matches!(v.entries_in(unknown), Err(Error::GroupNotFound)));
    for bad in ["", "../..", "zzz"] {
        assert!(matches!(v.add_group(bad, "x"), Err(Error::InvalidId)));
        assert!(matches!(v.delete_group(bad), Err(Error::InvalidId)));
    }
    // Rien n'a bougé.
    assert_eq!(find(&v.groups(), "A").unwrap().children[0].name, "Enfant");
}

#[test]
fn hostile_names_are_refused() {
    let mut v = Vault::create(PW).unwrap();
    let root = v.root_id();
    let long = "x".repeat(257);
    for bad in ["", "   ", "a\u{0}b", "a\u{1b}[31m", "facture\u{202E}fdp.exe", "zéro\u{200B}largeur", "\u{FFFE}", &long] {
        assert!(matches!(v.add_group(&root, bad), Err(Error::InvalidArgument(_))), "{bad:?}");
    }
    let g = v.add_group(&root, "ok").unwrap();
    assert!(v.rename_group(&g, "a\u{2066}b").is_err());
    assert!(v.add_group(&root, "Émoji 🐱 et accents").is_ok());
}

/// La bibliothèque KeePass ne relit plus un fichier imbriqué sur ~100
/// niveaux : la profondeur est bornée à la création et au déplacement.
#[test]
fn nesting_is_bounded_so_the_vault_stays_readable() {
    let mut v = Vault::create(PW).unwrap();
    let mut chain = vec![v.root_id()];
    for i in 0..MAX_DEPTH {
        let g = v.add_group(chain.last().unwrap(), &format!("niveau {i}")).unwrap();
        chain.push(g);
    }
    assert!(matches!(v.add_group(chain.last().unwrap(), "de trop"), Err(Error::InvalidArgument(_))));
    // Déplacer un sous-arbre de 2 niveaux sous le niveau 63 dépasserait aussi.
    let a = v.add_group(&v.root_id(), "A").unwrap();
    v.add_group(&a, "B").unwrap();
    assert!(matches!(v.move_group(&a, &chain[MAX_DEPTH - 1]), Err(Error::InvalidArgument(_))));
    v.move_group(&a, &chain[MAX_DEPTH - 2]).unwrap();
    let v = reopen(&v);
    let mut depth = 0;
    let mut n = &v.groups();
    while let Some(c) = n.children.iter().find(|c| c.name.starts_with("niveau")) {
        n = c;
        depth += 1;
    }
    assert_eq!(depth, MAX_DEPTH);
}

// ---------------------------------------------------------------- corbeille

#[test]
fn deleted_entry_goes_to_bin_and_comes_back_to_its_group() {
    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Travail").unwrap();
    let id = v.add_in(&g, &e("VPN", "x")).unwrap();
    v.delete(&id).unwrap();
    assert!(titles(&v).is_empty());
    assert_eq!(v.entries_in(&bin(&v)).unwrap().len(), 1);

    let mut v = reopen(&v);
    v.restore(&id).unwrap();
    assert_eq!(v.entries_in(&g).unwrap()[0].id, id);
    assert!(matches!(v.restore(&id), Err(Error::InvalidArgument(_))), "restauration hors corbeille");
}

#[test]
fn restore_falls_back_to_root_when_origin_is_gone() {
    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Éphémère").unwrap();
    let id = v.add_in(&g, &e("x", "x")).unwrap();
    v.move_entry(&id, &bin(&v)).unwrap();
    v.delete_group(&g).unwrap(); // → corbeille
    v.delete_group(&g).unwrap(); // → définitif
    v.restore(&id).unwrap();
    assert_eq!(v.entries_in(&v.root_id()).unwrap()[0].id, id);
}

#[test]
fn group_deletion_is_two_step() {
    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Projet").unwrap();
    let sub = v.add_group(&g, "Sous-projet").unwrap();
    let id = v.add_in(&sub, &e("Serveur", "x")).unwrap();

    v.delete_group(&g).unwrap();
    assert!(titles(&v).is_empty(), "le contenu d'un groupe supprimé doit sortir de la liste");
    assert!(v.deleted_ids().is_empty());
    v.restore_group(&g).unwrap();
    assert_eq!(titles(&v), ["Serveur"]);

    v.delete_group(&g).unwrap();
    v.delete_group(&g).unwrap();
    assert!(matches!(v.get(&id), Err(Error::EntryNotFound)));
    let gone = v.deleted_ids();
    for x in [&g, &sub, &id] {
        assert!(gone.contains(x), "{x} non inscrit dans DeletedObjects");
    }
}

#[test]
fn bin_cannot_be_hidden_inside_a_deleted_group() {
    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Conteneur").unwrap();
    v.move_group(&bin(&v), &g).unwrap();
    assert!(matches!(v.delete_group(&g), Err(Error::InvalidArgument(_))));
    assert!(matches!(v.restore_group(&bin(&v)), Err(Error::InvalidArgument(_))));
}

#[test]
fn deleting_the_bin_itself_then_recreating_it() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    v.delete(&id).unwrap();
    let old_bin = bin(&v);
    v.delete_group(&old_bin).unwrap();
    assert!(v.recycle_bin().is_none());
    assert!(matches!(v.get(&id), Err(Error::EntryNotFound)));
    let v2 = reopen(&v);
    assert!(v2.recycle_bin().is_none(), "référence pendante vers l'ancienne corbeille");

    let mut v = v2;
    let id2 = v.add(&e("y", "y")).unwrap();
    v.delete(&id2).unwrap();
    assert_ne!(bin(&v), old_bin);
    assert_eq!(v.entries_in(&bin(&v)).unwrap().len(), 1);
}

#[test]
fn empty_recycle_bin_deletes_for_good() {
    let mut v = Vault::create(PW).unwrap();
    let ids: Vec<_> = (0..3).map(|i| v.add(&e(&format!("e{i}"), "x")).unwrap()).collect();
    let g = v.add_group(&v.root_id(), "G").unwrap();
    v.add_in(&g, &e("dans G", "x")).unwrap();
    v.add(&e("garder", "x")).unwrap();
    for id in &ids {
        v.delete(id).unwrap();
    }
    v.delete_group(&g).unwrap();
    assert_eq!(v.empty_recycle_bin().unwrap(), 4);
    assert_eq!(v.len(), 1);
    assert_eq!(v.groups().children.len(), 1, "seule la corbeille vide doit rester");
    assert_eq!(v.empty_recycle_bin().unwrap(), 0);
}

// ---------------------------------------------------------------- historique

#[test]
fn history_can_be_browsed_and_restored() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("Banque", "v0")).unwrap();
    v.update(&id, &e("Banque", "v1")).unwrap();
    v.update(&id, &e("Banque (nouveau)", "v2")).unwrap();

    let h = v.history(&id).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].title, "Banque", "index 0 = version la plus récente");
    assert!(h[0].modified >= h[1].modified);
    assert_eq!(v.history_entry(&id, 1).unwrap().password.as_str(), "v0");
    assert!(v.history_entry(&id, 2).is_err());
    assert!(v.restore_history(&id, 99).is_err());

    v.restore_history(&id, 1).unwrap();
    let v = reopen(&v);
    assert_eq!(v.get(&id).unwrap().password.as_str(), "v0");
    assert_eq!(v.get(&id).unwrap().title, "Banque");
    // La version remplacée (v2) n'est pas perdue.
    assert_eq!(v.history_entry(&id, 0).unwrap().password.as_str(), "v2");
}

#[test]
fn history_is_capped_to_ten_versions_newest_kept() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "v0")).unwrap();
    for i in 1..=15 {
        v.update(&id, &e("x", &format!("v{i}"))).unwrap();
    }
    assert_eq!(v.history_len(&id).unwrap(), 10);
    assert_eq!(v.history_entry(&id, 0).unwrap().password.as_str(), "v14");
    assert_eq!(v.history_entry(&id, 9).unwrap().password.as_str(), "v5");
}

#[test]
fn history_is_capped_by_size() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "v0")).unwrap();
    v.add_attachment(&id, "gros.bin", &vec![7u8; 3 * 1024 * 1024]).unwrap();
    for i in 1..=4 {
        v.update(&id, &e("x", &format!("v{i}"))).unwrap();
    }
    // Chaque version porte 3 MiB : 6 MiB au plus par défaut.
    assert!(v.history_len(&id).unwrap() <= 2, "{}", v.history_len(&id).unwrap());
}

// ---------------------------------------------------------------- attributs

fn field(key: &str, value: &str, protected: bool) -> CustomField {
    CustomField { key: key.into(), value: Zeroizing::new(value.into()), protected }
}

#[test]
fn custom_fields_roundtrip_and_removal() {
    let mut v = Vault::create(PW).unwrap();
    let mut d = e("x", "x");
    d.custom = vec![field("PIN", "0000", true), field("Compte", "42", false)];
    let id = v.add(&d).unwrap();
    let got = reopen(&v).get(&id).unwrap().custom;
    assert_eq!(got, vec![field("Compte", "42", false), field("PIN", "0000", true)]);

    d.custom = vec![field("Compte", "43", false)];
    v.update(&id, &d).unwrap();
    assert_eq!(reopen(&v).get(&id).unwrap().custom, vec![field("Compte", "43", false)]);
    // L'ancienne valeur protégée reste dans l'historique.
    assert_eq!(v.history_entry(&id, 0).unwrap().custom.len(), 2);
    // Debug ne fuit jamais une valeur protégée.
    let dbg = format!("{:?}", field("PIN", "0000", true));
    assert!(!dbg.contains("0000"), "{dbg}");
}

#[test]
fn hostile_custom_fields_are_refused() {
    let mut v = Vault::create(PW).unwrap();
    let cases: Vec<Vec<CustomField>> = vec![
        vec![field("Password", "x", false)],
        vec![field("password", "x", false)],
        vec![field("OTP", "x", false)],
        vec![field("Title", "x", false)],
        vec![field("", "x", false)],
        vec![field("a\nb", "x", false)],
        vec![field("ok", "a\u{7}b", false)],
        vec![field("ok", "\u{FFFF}", false)],
        vec![field("dup", "1", false), field("dup", "2", true)],
        vec![field("gros", &"x".repeat(1024 * 1024 + 1), false)],
        (0..257).map(|i| field(&format!("k{i}"), "v", false)).collect(),
    ];
    for custom in cases {
        let d = EntryData { custom, ..e("x", "x") };
        assert!(matches!(v.add(&d), Err(Error::InvalidArgument(_))));
    }
    assert!(v.is_empty());
    // Les retours à la ligne sont permis dans une valeur.
    let d = EntryData { custom: vec![field("Adresse", "1 rue\n75000\tParis", false)], ..e("x", "x") };
    v.add(&d).unwrap();
}

// ---------------------------------------------------------------- pièces jointes

#[test]
fn attachments_roundtrip() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    let data: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    v.add_attachment(&id, "clé.pem", &data).unwrap();
    v.add_attachment(&id, "vide.txt", b"").unwrap();
    let v = reopen(&v);
    let list = v.attachments(&id).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!((list[0].name.as_str(), list[0].size), ("clé.pem", 100_000));
    assert_eq!(&*v.attachment(&id, "clé.pem").unwrap(), &data);
    assert!(v.attachment(&id, "vide.txt").unwrap().is_empty());
    assert!(matches!(v.attachment(&id, "absent"), Err(Error::AttachmentNotFound)));
}

/// Régression du correctif de keepass-rs : retirer ou remplacer une pièce
/// jointe effaçait aussi les données encore utilisées par l'historique.
#[test]
fn removed_and_replaced_attachments_stay_in_history() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    v.add_attachment(&id, "doc", b"version 1").unwrap();
    v.add_attachment(&id, "doc", b"version 2").unwrap();
    v.remove_attachment(&id, "doc").unwrap();
    assert!(v.attachments(&id).unwrap().is_empty());
    assert!(matches!(v.remove_attachment(&id, "doc"), Err(Error::AttachmentNotFound)));

    let mut v = reopen(&v);
    // Historique : [0] = avec « version 2 », [1] = avec « version 1 », [2] = sans.
    v.restore_history(&id, 1).unwrap();
    assert_eq!(&*v.attachment(&id, "doc").unwrap(), b"version 1");
    let v = reopen(&v);
    assert_eq!(&*v.attachment(&id, "doc").unwrap(), b"version 1");
    let mut v = v;
    let idx = v
        .history(&id)
        .unwrap()
        .iter()
        .position(|_| true)
        .unwrap();
    v.restore_history(&id, idx).unwrap(); // version sans pièce jointe
    v.restore_history(&id, 0).unwrap(); // retour à « version 1 »
    assert_eq!(&*reopen(&v).attachment(&id, "doc").unwrap(), b"version 1");
}

#[test]
fn hostile_attachment_names_are_refused() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    for bad in ["", " ", ".", "..", "../../.bashrc", "a/b", "C:\\Windows\\x", "a\u{0}b", "image\u{202E}gnp.exe"] {
        assert!(matches!(v.add_attachment(&id, bad, b"x"), Err(Error::InvalidArgument(_))), "{bad:?}");
    }
    assert!(v.attachments(&id).unwrap().is_empty());
    assert_eq!(v.history_len(&id).unwrap(), 0, "un refus ne doit pas créer de version");
}

#[test]
fn attachment_size_limits() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    assert!(matches!(v.add_attachment(&id, "trop", &vec![0; MAX_ATTACHMENT_BYTES + 1]), Err(Error::TooLarge)));
    let big = vec![1u8; 15 * 1024 * 1024];
    v.add_attachment(&id, "a", &big).unwrap();
    v.add_attachment(&id, "b", &big).unwrap();
    // 45 MiB au total : refusé, le coffre doit rester ouvrable partout.
    assert!(matches!(v.add_attachment(&id, "c", &big), Err(Error::TooLarge)));
    assert!(reopen(&v).attachments(&id).unwrap().len() == 2);
}

#[test]
fn permanent_deletion_frees_attachment_data() {
    let mut v = Vault::create(PW).unwrap();
    let id = v.add(&e("x", "x")).unwrap();
    // Données aléatoires : incompressibles, la taille du fichier les reflète.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let noise: Vec<u8> = (0..2_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    v.add_attachment(&id, "bruit", &noise).unwrap();
    v.add_attachment(&id, "bruit", b"petit").unwrap();
    let with = v.save().unwrap().len();
    v.delete_permanently(&id).unwrap();
    let without = v.save().unwrap().len();
    assert!(without + 1_000_000 < with, "données orphelines conservées ({with} → {without})");
}

#[test]
fn unknown_or_invalid_entry_ids() {
    let mut v = Vault::create(PW).unwrap();
    let unknown = "6f1c5b0e-0000-4000-8000-000000000000";
    assert!(matches!(v.add_attachment(unknown, "a", b"x"), Err(Error::EntryNotFound)));
    assert!(matches!(v.history(unknown), Err(Error::EntryNotFound)));
    assert!(matches!(v.restore(unknown), Err(Error::EntryNotFound)));
    assert!(matches!(v.move_entry("pas-un-uuid", &v.root_id()), Err(Error::InvalidId)));
    assert!(matches!(v.attachments("x"), Err(Error::InvalidId)));
}

// ---------------------------------------------------------------- fusion

/// Correctif de keepass-rs : la fusion recopiait les références de pièces
/// jointes d'un coffre à l'autre sans les données. Chaque appareil numérote
/// ses pièces jointes à partir de 0 : sans correctif, l'entrée de B pointe
/// vers le fichier de A.
#[test]
fn merge_carries_attachments_across_devices() {
    let mut a = Vault::create(PW).unwrap();
    let shared = a.add(&e("Partagée", "x")).unwrap();
    let mut b = reopen(&a);

    let ea = a.add(&e("Chez A", "x")).unwrap();
    a.add_attachment(&ea, "a.txt", b"contenu de A").unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let eb = b.add(&e("Chez B", "x")).unwrap();
    b.add_attachment(&eb, "b.txt", b"contenu de B").unwrap();
    b.add_attachment(&shared, "s.txt", b"ajout de B sur la partagee").unwrap();

    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    for v in [reopen(&a), reopen(&b)] {
        assert_eq!(&*v.attachment(&ea, "a.txt").unwrap(), b"contenu de A");
        assert_eq!(&*v.attachment(&eb, "b.txt").unwrap(), b"contenu de B");
        assert_eq!(&*v.attachment(&shared, "s.txt").unwrap(), b"ajout de B sur la partagee");
    }
}

#[test]
fn merge_keeps_attachment_history_and_dedupes() {
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("x", "x")).unwrap();
    a.add_attachment(&id, "f", b"v1").unwrap();
    let mut b = reopen(&a);
    std::thread::sleep(Duration::from_millis(1100));
    b.add_attachment(&id, "f", b"v2").unwrap();

    a.merge_from(&b).unwrap();
    a.merge_from(&b).unwrap(); // idempotente
    assert_eq!(&*a.attachment(&id, "f").unwrap(), b"v2");
    let a = reopen(&a);
    let old = a.history(&id).unwrap().len();
    assert!(old >= 1);
    let mut a = a;
    a.restore_history(&id, 0).unwrap();
    assert_eq!(&*a.attachment(&id, "f").unwrap(), b"v1");
}

#[test]
fn moves_and_bin_propagate_through_merge() {
    let mut a = Vault::create(PW).unwrap();
    let g = a.add_group(&a.root_id(), "Dossier").unwrap();
    let id = a.add(&e("x", "x")).unwrap();
    let mut b = reopen(&a);
    std::thread::sleep(Duration::from_millis(1100));
    b.move_entry(&id, &g).unwrap();
    b.delete_group(&g).unwrap();
    a.merge_from(&b).unwrap();
    assert!(titles(&a).is_empty(), "le groupe mis à la corbeille sur B doit l'être sur A");
    assert_eq!(a.recycle_bin(), b.recycle_bin());
}

#[test]
fn independent_recycle_bins_converge() {
    let mut base = Vault::create(PW).unwrap();
    let x = base.add(&e("x", "x")).unwrap();
    let y = base.add(&e("y", "y")).unwrap();
    // Coffre sans corbeille (cas d'un fichier venu d'ailleurs).
    let old = bin(&base);
    base.delete_group(&old).unwrap();
    let mut a = reopen(&base);
    let mut b = reopen(&base);
    std::thread::sleep(Duration::from_millis(1100));
    a.delete(&x).unwrap();
    b.delete(&y).unwrap();
    assert_ne!(a.recycle_bin(), b.recycle_bin());

    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert_eq!(a.recycle_bin(), b.recycle_bin(), "les appareils doivent s'accorder sur la corbeille");
}

// ---------------------------------------------------------------- KeePassXC

fn keepassxc() -> bool {
    Command::new("keepassxc-cli").arg("--version").output().is_ok()
}

fn cli(args: &[&str]) -> std::process::Output {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("{PW}\n").as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn keepassxc_reads_groups_attributes_and_attachments() {
    if !keepassxc() {
        return eprintln!("keepassxc-cli absent, test ignoré");
    }
    let dir = std::env::temp_dir().join(format!("kp-structure-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ours.kdbx");
    let p = path.to_str().unwrap();

    let mut v = Vault::create(PW).unwrap();
    let g = v.add_group(&v.root_id(), "Perso").unwrap();
    let mut d = e("Banque", "mdp");
    d.custom = vec![field("PIN", "2468", true)];
    let id = v.add_in(&g, &d).unwrap();
    v.add_attachment(&id, "rib.txt", b"FR76 test").unwrap();
    v.add_attachment(&id, "rib.txt", b"FR76 final").unwrap();
    std::fs::write(&path, v.save().unwrap()).unwrap();

    let out = cli(&["show", "-q", "-s", "-a", "PIN", p, "Perso/Banque"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2468");

    let exported = dir.join("rib.txt");
    let out = cli(&["attachment-export", "-q", p, "Perso/Banque", "rib.txt", exported.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(&exported).unwrap(), b"FR76 final");

    // Et dans l'autre sens : pièce jointe ajoutée par KeePassXC.
    let src = dir.join("src.bin");
    std::fs::write(&src, b"depuis keepassxc").unwrap();
    let out = cli(&["attachment-import", "-q", p, "Perso/Banque", "kpxc.bin", src.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v = Vault::open(&std::fs::read(&path).unwrap(), PW, &OpenLimits::default()).unwrap();
    assert_eq!(&*v.attachment(&id, "kpxc.bin").unwrap(), b"depuis keepassxc");
    assert_eq!(&*v.attachment(&id, "rib.txt").unwrap(), b"FR76 final");
    std::fs::remove_dir_all(dir).ok();
}
