# KittyPass — Ce qu'il reste à faire

État au 10 novembre 2026. Les cases cochées sont faites ; les autres restent à faire,
dans l'ordre conseillé à l'intérieur de chaque partie.

## 0. Urgent

- [ ] **Premier commit.** Le dépôt n'a encore aucun commit : tout le travail n'existe que sur ce disque.
- [ ] **Copie hors de ce PC**, par exemple un dépôt Git privé sur le serveur Proxmox.
- [ ] **CI à brancher.** `.github/workflows/ci.yml` existe, mais la branche locale s'appelle `master` alors que
      la CI surveille `main`, et le dépôt n'a pas de dépôt distant. Elle n'a donc jamais tourné.

## 1. Agent SSH

- [x] Fait le 10 novembre 2026, comme dans KeePassXC :
  - réglages `KeeAgent.settings` (relus par KeePassXC) ;
  - clés OpenSSH chiffrées ou non, en pièce jointe ou dans un fichier ;
  - ajout au déverrouillage, retrait au verrouillage, à la fermeture et à l'arrêt par signal ;
  - vérification que l'agent appartient au même utilisateur ;
  - onglet « SSH » de l'éditeur et section « Agent SSH » des Paramètres ;
  - tests, essai réel dans l'appli, documentation dans `ARCHITECTURE.md`.
- [ ] Windows : canal nommé d'OpenSSH pour Windows (et Pageant).
- Limite choisie : l'ancien format PEM n'est pas lu. Il faut le convertir une fois avec
  `ssh-keygen -p -f fichier`.

## 2. Fonctions du serveur dans l'appli

- [x] Fait le 10 novembre 2026, onglet « Compte » des Paramètres :
  - délai de verrouillage automatique réglable (30 s à 24 h, ou jamais), dans `lock.json` ;
  - changement du mot de passe maître (clé du compte sur le serveur, puis coffre re-chiffré) ; les autres
    appareils sont déconnectés et demandent le nouveau mot de passe à leur synchronisation suivante ;
  - activation de la 2FA (QR code, clé, codes de secours affichés une fois) et désactivation (mot de passe et code) ;
  - appareils connectés : liste, déconnexion d'un appareil ou de tous les autres ;
  - versions du coffre : « Récupérer » copie une version dans un nouveau groupe sans rien écraser (l'ancien mot de passe
    est demandé si besoin) ; « Enregistrer » sauve le fichier chiffré.
  - Nouvelle route serveur `GET /api/v1/account` (nom, 2FA active, 2FA imposée).
- [x] Essai réel (serveur et deux profils jetables) : 2FA, récupération d'une version, délai, changement de mot de passe adopté par le 2e appareil, désactivation de la 2FA.
- Limite : si l'envoi du coffre re-chiffré échoue juste après le changement de mot de passe, il faut synchroniser avant
  de quitter l'appli (l'ancienne clé n'est gardée qu'en mémoire).

## 3. Navigateur (KeePassXC-Browser)

- [x] Linux : association, remplissage, 2FA, enregistrement, générateur, passkeys.
- [ ] Windows : canal nommé et manifestes dans le registre.
- [x] `kittypass-proxy` dans le .deb et l'AppImage (`cargo tauri build --config tauri.linux.json`). Les manifestes
      sont posés par l'appli (Paramètres › Navigateur) ; dans une AppImage, le relais est recopié dans
      `~/.local/share/kittypass/bin/` pour garder un chemin stable.
- [ ] Tester pour de vrai l'enregistrement depuis la bannière de l'extension (seulement couvert par les tests
      d'intégration pour l'instant).

## 4. Saisie automatique

- [x] Portail KDE et X11 testés pour de vrai (AZERTY, accents, €).
- [ ] Tester pour de vrai le raccourci global (KDE demande de confirmer).
- [ ] Tester pour de vrai Ctrl+Maj+V de bout en bout vers une autre application.
- [ ] Windows (SendInput).

## 5. Windows

- [ ] Déverrouillage par Windows Hello (`KeyCredentialManager` + DPAPI), comme prévu dans `ARCHITECTURE.md`.
- [ ] Navigateur (partie 3), saisie automatique (partie 4), agent SSH via le canal d'OpenSSH pour Windows
      (`\\.\pipe\openssh-ssh-agent`).
- [ ] Construire et essayer les installeurs NSIS et MSI sur une vraie machine Windows.

## 6. Android (gros chantier)

- [ ] Projet Kotlin et cœur Rust exposé par UniFFI.
- [ ] Interface Material You (couleurs dynamiques), avec le vert KittyPass quand elles ne sont pas disponibles.
- [ ] Service de remplissage automatique (Autofill).
- [ ] Déverrouillage biométrique (Keystore, StrongBox si disponible, clé invalidée si une nouvelle empreinte
      est ajoutée).
- [ ] `FLAG_SECURE`, presse-papiers marqué sensible, verrouillage automatique.
- [ ] Synchronisation et mode hors ligne, comme sur le bureau.

## 7. Sécurité et qualité (promis dans `ARCHITECTURE.md`, pas encore faits)

- [x] Fuzzing (`cargo-fuzz`, 13 cibles dans `core/fuzz`) : KDBX, fichier clé, imports, protocole
      navigateur, passkeys, URL, KeeAgent, clés SSH, OTP, saisie automatique. Un plantage trouvé et corrigé
      (en-têtes KDBX malformés, dans `vendor/keepass`). Lancé aussi dans la CI (30 s par cible).
- [x] `cargo deny` (`deny.toml`) dans la CI. p256 0.14 et ed25519-dalek 3 pour corriger
      RUSTSEC-2026-0387 ; 4 crates non maintenues tolérées (Tauri/gtk, keyring/zbus), à revoir.
- [ ] Épinglage optionnel du certificat du serveur.
- [ ] Linux : déverrouillage rapide optionnel par le trousseau du système, avec expiration (prévu, pas fait).
- [x] Tests d'intrusion (54 attaques en boîte noire sur un serveur jetable, en plus des 46 tests d'API) et relecture
      du serveur et de l'appli. Corrigé : limitation par /64 en IPv6, quota de 2 Gio par compte, 8 transferts de
      coffre simultanés au plus, en-têtes limités à 64 Kio et 10 s, 512 connexions au plus.
- [ ] Refaire une relecture de sécurité après chaque grosse fonction (et avant la mise en service).

## 8. Mise en service

- [ ] Déployer le serveur sur Proxmox (suivre `DEPLOIEMENT.md`) : domaine, HTTPS par Caddy, première invitation
      admin, 2FA, sauvegardes (`kittypass.db` d'un côté, `secret.key` à part).
- [ ] Construire le .deb de version finale et l'installer.
- [ ] Migrer le vrai coffre KeePassXC (import KDBX) et vérifier.
- [ ] Supprimer le dossier `essai/` une fois les tests finis (il contient une invitation et des données de
      test).

## 9. Plus tard (KeePassXC en a, KittyPass non)

- [ ] Clés matérielles (YubiKey en défi-réponse) pour le coffre.
- [ ] Partage de groupes entre utilisateurs du serveur (KeeShare ou équivalent).
- [ ] Icônes d'entrées (favicons).
- [ ] Icône dans la zone de notification, et démarrage réduit.
- [ ] Interface en ligne de commande (`kittypass-cli`, comme `keepassxc-cli`).
