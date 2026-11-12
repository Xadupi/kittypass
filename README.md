# KittyPass

Gestionnaire de mots de passe compatible KeePass (KDBX 4), synchronisé par un
serveur auto-hébergé. Le serveur ne voit jamais le mot de passe maître ni le
contenu des coffres (zero-knowledge).

## Plateformes

| Plateforme | Fichier |
|---|---|
| Windows 10/11 | `KittyPass_<version>_x64-setup.exe` (WebView2 inclus) |
| Debian / Ubuntu | `KittyPass_<version>_amd64.deb` |
| Autres Linux | `KittyPass_<version>_amd64.AppImage` |
| Android 8+ | `KittyPass-<version>.apk` |
| Serveur (Proxmox VE) | `kittypass-proxmox.sh` |

Les fichiers sont dans les [Releases](../../releases).

## Fonctions

- Coffres KDBX 4 lisibles par KeePass/KeePassXC, fichiers clés, groupes, corbeille
- Synchronisation chiffrée avec fusion des modifications
- 2FA (TOTP), demandée seulement à la première connexion d'un appareil
- Intégration navigateur via l'extension KeePassXC-Browser
- Saisie automatique (raccourci global), agent SSH
- Android : remplissage automatique, déverrouillage biométrique
- Import KeePassXC (CSV), Bitwarden, 1Password ; export CSV/HTML/XML
- Dossier de démarrage au choix

## Installer le serveur

Sur l'hôte Proxmox, en root :

```bash
bash kittypass-proxmox.sh
```

Le script crée un conteneur LXC Debian 13 et installe le serveur (avec Caddy
pour le HTTPS, ou derrière un reverse proxy existant). Détails :
[docs/DEPLOIEMENT.md](docs/DEPLOIEMENT.md).

## Structure

```
core/     KDBX, dérivation des clés, fusion, client de synchronisation
server/   serveur (axum + SQLite) : comptes, 2FA, stockage versionné
app/      logique commune de l'application
desktop/  application Tauri 2 (Linux, Windows, Android)
proxy/    relais entre l'extension navigateur et KittyPass
deploy/   Docker, Caddy, script Proxmox
docs/     architecture, déploiement, reste à faire
```

## Compiler

```bash
cargo test --workspace
cd desktop && cargo tauri build --bundles deb,appimage --config tauri.linux.json
```

Serveur seul : `cargo build --release -p kittypass-server`.
Script Proxmox : `deploy/proxmox/make-installer.sh`.

## Documentation

- [Architecture et modèle de menace](docs/ARCHITECTURE.md)
- [Déploiement](docs/DEPLOIEMENT.md)
- [Reste à faire](docs/RESTE-A-FAIRE.md)

## Licence

GPL-3.0-or-later
