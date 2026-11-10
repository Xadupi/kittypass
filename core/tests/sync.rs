//! Scénarios de synchronisation entre appareils, et serveur malveillant.

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use kittypass_core::{
    Error,
    header::OpenLimits,
    sync::{PushOutcome, Remote, sync},
    vault::{EntryData, MasterKey, Vault},
};
use zeroize::Zeroizing;

const PW: &str = "mot-de-passe-maître-sync";

/// Serveur en mémoire, mêmes règles que le vrai (If-Match).
#[derive(Default)]
struct Mem {
    state: Mutex<(i64, Option<Vec<u8>>)>,
    /// Nombre de conflits à simuler (un autre appareil écrit juste avant nous).
    forced_conflicts: AtomicUsize,
}

impl Remote for Mem {
    async fn fetch(&self) -> kittypass_core::Result<(i64, Option<Vec<u8>>)> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn push(&self, expected: i64, data: Vec<u8>) -> kittypass_core::Result<PushOutcome> {
        let mut s = self.state.lock().unwrap();
        if self.forced_conflicts.load(Ordering::SeqCst) > 0 {
            self.forced_conflicts.fetch_sub(1, Ordering::SeqCst);
            s.0 += 1;
            return Ok(PushOutcome::Conflict);
        }
        if s.0 != expected {
            return Ok(PushOutcome::Conflict);
        }
        *s = (s.0 + 1, Some(data));
        Ok(PushOutcome::Stored(s.0))
    }
}

fn e(title: &str, pw: &str) -> EntryData {
    EntryData { title: title.into(), username: "u".into(), password: Zeroizing::new(pw.into()), ..Default::default() }
}

fn lim() -> OpenLimits {
    OpenLimits::default()
}

/// Un deuxième appareil qui récupère le coffre depuis le serveur.
fn clone_from(remote: &Mem) -> Vault {
    let data = remote.state.lock().unwrap().1.clone().unwrap();
    Vault::open(&data, PW, &lim()).unwrap()
}

fn titles(v: &Vault) -> Vec<String> {
    v.list().into_iter().map(|s| s.title).collect()
}

#[tokio::test]
async fn first_sync_uploads_then_nothing_to_do() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("Banque", "1")).unwrap();
    let r = sync(&mut a, 0, &lim(), &remote).await.unwrap();
    assert_eq!((r.version, r.pushed), (1, true));
    // Sans changement : pas de nouvel envoi (sinon chaque synchro créerait
    // une version et effacerait l'historique utile côté serveur).
    let r = sync(&mut a, 1, &lim(), &remote).await.unwrap();
    assert_eq!((r.version, r.pushed, r.pulled), (1, false, 0));
}

#[tokio::test]
async fn two_devices_converge() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id1 = a.add(&e("Banque", "1")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();

    let mut b = clone_from(&remote);
    b.add(&e("Mail", "2")).unwrap();
    a.update(&id1, &e("Banque", "1-modifié")).unwrap();

    let ra = sync(&mut a, 1, &lim(), &remote).await.unwrap();
    let rb = sync(&mut b, 1, &lim(), &remote).await.unwrap();
    assert!(ra.pushed && rb.pushed);
    let ra2 = sync(&mut a, ra.version, &lim(), &remote).await.unwrap();

    for v in [&a, &b] {
        assert_eq!(titles(v), ["Banque", "Mail"]);
        assert_eq!(v.get(&id1).unwrap().password.as_str(), "1-modifié");
    }
    // Tout est aligné : plus rien à envoyer de part et d'autre.
    assert!(!ra2.pushed);
    assert!(!sync(&mut b, rb.version, &lim(), &remote).await.unwrap().pushed);
}

#[tokio::test]
async fn same_entry_edited_on_both_newest_wins_old_kept_in_history() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("Banque", "v0")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let mut b = clone_from(&remote);

    a.update(&id, &e("Banque", "depuis-A")).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    b.update(&id, &e("Banque", "depuis-B")).unwrap(); // plus récent

    let v = sync(&mut a, 1, &lim(), &remote).await.unwrap().version;
    sync(&mut b, 1, &lim(), &remote).await.unwrap();
    sync(&mut a, v, &lim(), &remote).await.unwrap();

    for v in [&a, &b] {
        assert_eq!(v.get(&id).unwrap().password.as_str(), "depuis-B");
        assert!(v.history_len(&id).unwrap() >= 2, "la version perdante doit rester dans l'historique");
    }
}

#[tokio::test]
async fn deletion_propagates_and_does_not_come_back() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("À supprimer", "x")).unwrap();
    a.add(&e("Garder", "y")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let mut b = clone_from(&remote);

    std::thread::sleep(Duration::from_millis(1100));
    a.delete(&id).unwrap();
    let v = sync(&mut a, 1, &lim(), &remote).await.unwrap().version;
    // B n'a pas touché l'entrée : elle doit disparaître chez lui aussi, et ne
    // pas être ressuscitée par son envoi.
    let vb = sync(&mut b, 1, &lim(), &remote).await.unwrap().version;
    sync(&mut a, v, &lim(), &remote).await.unwrap();
    assert_eq!(titles(&a), ["Garder"]);
    assert_eq!(titles(&b), ["Garder"]);
    assert!(!sync(&mut b, vb, &lim(), &remote).await.unwrap().pushed);
}

#[tokio::test]
async fn permanent_deletion_propagates() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("À supprimer", "x")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let mut b = clone_from(&remote);

    std::thread::sleep(Duration::from_millis(1100));
    a.delete_permanently(&id).unwrap();
    let v = sync(&mut a, 1, &lim(), &remote).await.unwrap().version;
    sync(&mut b, v, &lim(), &remote).await.unwrap();
    assert!(matches!(b.get(&id), Err(Error::EntryNotFound)));
    assert!(b.deleted_ids().contains(&id));
}

#[tokio::test]
async fn edit_after_deletion_is_not_lost() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("Banque", "v0")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let mut b = clone_from(&remote);

    std::thread::sleep(Duration::from_millis(1100));
    a.delete(&id).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    b.update(&id, &e("Banque", "modifié-après")).unwrap();

    let v = sync(&mut a, 1, &lim(), &remote).await.unwrap().version;
    sync(&mut b, 1, &lim(), &remote).await.unwrap();
    sync(&mut a, v, &lim(), &remote).await.unwrap();
    // Choix de sécurité des données : une modification postérieure à la
    // suppression l'emporte, rien n'est perdu silencieusement.
    for v in [&a, &b] {
        assert_eq!(v.get(&id).unwrap().password.as_str(), "modifié-après");
    }
}

#[tokio::test]
async fn rapid_edits_in_same_second_do_not_break_merge() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    let id = a.add(&e("Banque", "0")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let mut b = clone_from(&remote);
    for i in 1..=5 {
        a.update(&id, &e("Banque", &i.to_string())).unwrap();
    }
    let v = sync(&mut a, 1, &lim(), &remote).await.unwrap().version;
    sync(&mut b, 1, &lim(), &remote).await.expect("fusion cassée par des dates d'historique en double");
    sync(&mut a, v, &lim(), &remote).await.unwrap();
    assert_eq!(b.get(&id).unwrap().password.as_str(), "5");
}

#[tokio::test]
async fn conflicts_are_retried_then_give_up() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("x", "1")).unwrap();
    remote.forced_conflicts.store(2, Ordering::SeqCst);
    assert!(sync(&mut a, 0, &lim(), &remote).await.unwrap().pushed);

    a.add(&e("y", "2")).unwrap();
    remote.forced_conflicts.store(100, Ordering::SeqCst);
    assert!(matches!(sync(&mut a, 0, &lim(), &remote).await, Err(Error::SyncContention)));
}

// ---------- Serveur malveillant ou compromis ----------

#[tokio::test]
async fn rollback_is_detected() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("x", "1")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    // L'appareil a déjà vu la version 5 ; le serveur prétend être en version 1
    // (il rejoue un vieux fichier, par exemple pour ressusciter un ancien mot de passe).
    assert!(matches!(sync(&mut a, 5, &lim(), &remote).await, Err(Error::RollbackDetected)));
}

#[tokio::test]
async fn tampered_remote_file_is_rejected_and_local_untouched() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("x", "1")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    {
        let mut s = remote.state.lock().unwrap();
        let data = s.1.as_mut().unwrap();
        let n = data.len();
        data[n / 2] ^= 0x40;
    }
    a.add(&e("local seulement", "2")).unwrap();
    assert!(matches!(sync(&mut a, 1, &lim(), &remote).await, Err(Error::InvalidKeyOrCorrupted)));
    assert_eq!(titles(&a), ["local seulement", "x"]);
}

#[tokio::test]
async fn kdf_bomb_from_server_is_refused() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    {
        let mut s = remote.state.lock().unwrap();
        let data = s.1.as_mut().unwrap();
        let pos = data.windows(8).position(|w| w == (64u64 << 20).to_le_bytes()).unwrap();
        data[pos..pos + 8].copy_from_slice(&(64u64 << 30).to_le_bytes());
    }
    let start = std::time::Instant::now();
    assert!(matches!(sync(&mut a, 1, &lim(), &remote).await, Err(Error::KdfOutOfBounds(_))));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn foreign_vault_with_other_password_is_rejected() {
    let remote = Mem::default();
    let mut other = Vault::create("un-tout-autre-mot-de-passe").unwrap();
    other.add(&e("piège", "x")).unwrap();
    *remote.state.lock().unwrap() = (3, Some(other.save().unwrap()));
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("à moi", "1")).unwrap();
    assert!(matches!(sync(&mut a, 0, &lim(), &remote).await, Err(Error::InvalidKeyOrCorrupted)));
    assert_eq!(titles(&a), ["à moi"]);
    // Et le coffre distant n'a pas été écrasé.
    assert_eq!(remote.state.lock().unwrap().0, 3);
}

#[tokio::test]
async fn independently_created_vaults_are_refused_not_crashed() {
    let remote = Mem::default();
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("A", "1")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    // Même mot de passe, mais coffre créé séparément sur un autre appareil.
    let mut b = Vault::create(PW).unwrap();
    b.add(&e("B", "2")).unwrap();
    assert!(matches!(sync(&mut b, 0, &lim(), &remote).await, Err(Error::DifferentVault)));
    assert_eq!(titles(&b), ["B"]);
    assert_eq!(remote.state.lock().unwrap().0, 1, "coffre distant écrasé");
}

#[tokio::test]
async fn new_device_downloads_existing_vault() {
    let remote = Mem::default();
    assert!(kittypass_core::sync::download(&remote, &MasterKey::new(PW, None), &lim()).await.unwrap().is_none());
    let mut a = Vault::create(PW).unwrap();
    a.add(&e("A", "1")).unwrap();
    sync(&mut a, 0, &lim(), &remote).await.unwrap();
    let (mut b, v) = kittypass_core::sync::download(&remote, &MasterKey::new(PW, None), &lim()).await.unwrap().unwrap();
    assert_eq!((titles(&b), v), (vec!["A".to_owned()], 1));
    assert!(!sync(&mut b, v, &lim(), &remote).await.unwrap().pushed);
    assert!(matches!(
        kittypass_core::sync::download(&remote, &MasterKey::new("mauvais-mot-de-passe", None), &lim()).await,
        Err(Error::InvalidKeyOrCorrupted)
    ));
}
