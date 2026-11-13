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
| macOS 11+ (Apple Silicon) | `KittyPass_<version>_aarch64.dmg` (non signé) |
| Android 8+ | `KittyPass-<version>.apk` |
| iOS (expérimental) | `KittyPass-unsigned.ipa` (à signer soi-même, ex. AltStore/Sideloadly) |
| Serveur Proxmox VE | `kittypass-proxmox.sh` |
| Serveur Linux (systemd) | `kittypass-linux.sh` |
| Serveur Windows | `kittypass-server-windows.zip` |
| Serveur Docker | `ghcr.io/xadupi/kittypass-server` |

Les fichiers sont dans les [Releases](../../releases), avec `SHA256SUMS.txt`.

macOS : l'application n'a pas de signature Apple. Si macOS dit qu'elle est
« endommagée », après l'avoir copiée dans Applications :
`xattr -cr /Applications/KittyPass.app`

## Fonctions

- Coffres KDBX 4 lisibles par KeePass/KeePassXC, fichiers clés, groupes, corbeille
- Synchronisation chiffrée avec fusion des modifications
- 2FA (TOTP), demandée seulement à la première connexion d'un appareil
- Intégration navigateur via l'extension KeePassXC-Browser
- Saisie automatique (raccourci global), agent SSH
- Fenêtre d'accès rapide toujours au premier plan pour les demandes de
  l'extension et la saisie automatique, sans afficher le reste de l'application
- Icônes des sites (favicons), téléchargeables toutes d'un coup ; recherche
  dans la page d'accueil et le domaine parent
- Android : remplissage automatique, déverrouillage biométrique
- Import KDBX (groupes vides compris), KeePassXC (CSV), Bitwarden,
  1Password ; export CSV/HTML/XML
- Thèmes clair, pastel, sombre ; style « Liquid Glass » sur macOS et iOS
- Dossier de démarrage au choix

## Installer le serveur

Sur l'hôte Proxmox, en root :

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Xadupi/kittypass/master/deploy/proxmox/kittypass.sh)"
```

Le script télécharge `kittypass-proxmox.sh` de la dernière Release, vérifie
son empreinte (`SHA256SUMS.txt`), puis le lance. On peut aussi télécharger
`kittypass-proxmox.sh` à la main et lancer `bash kittypass-proxmox.sh`.

Le script crée un conteneur LXC Debian 13 et installe le serveur (avec Caddy
pour le HTTPS, ou derrière un reverse proxy existant). Détails :
[docs/DEPLOIEMENT.md](docs/DEPLOIEMENT.md).

### Linux (sans conteneur)

Sur une machine x86_64 avec systemd (Debian, Ubuntu, Fedora…), en root :

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Xadupi/kittypass/master/deploy/linux/kittypass.sh)"
```

Ou avec le fichier de la Release :

```bash
bash kittypass-linux.sh                          # questions interactives
PROXY_IP=192.168.1.10 bash kittypass-linux.sh    # derrière un reverse proxy
DOMAIN=coffre.exemple.fr bash kittypass-linux.sh # HTTPS avec Caddy
bash kittypass-linux.sh --uninstall              # retrait (données gardées)
```

Service systemd durci, utilisateur `kittypass`, données dans
`/var/lib/kittypass`, réglages dans `/etc/kittypass.env`.

### Windows

Décompresser `kittypass-server-windows.zip` et lancer `Installer.cmd`
(droits administrateur). Ou dans PowerShell administrateur :

```powershell
.\install.ps1 -Port 8080 [-ProxyIp 192.168.1.10] [-Require2fa]
.\install.ps1 -Update      # mise à jour
.\install.ps1 -Uninstall   # retrait (données gardées)
```

Le serveur tourne en tâche planifiée au démarrage (compte LocalService),
données dans `C:\ProgramData\KittyPass Server`. Le pare-feu n'est ouvert que
sur les réseaux privés.

### Avec Docker

```bash
docker run -d --name kittypass -p 8080:8080 -v kittypass-data:/data \
  ghcr.io/xadupi/kittypass-server:latest
docker exec kittypass kittypass-server invite --admin   # première invitation
```

Le serveur parle HTTP : placez-le derrière un reverse proxy HTTPS.
Fichiers prêts dans `deploy/` : `docker-compose.yml` (avec Caddy et HTTPS
automatique) et `docker-compose.simple.yml` (derrière un proxy existant).

## Mises à jour

- **Application** (Windows, macOS, AppImage) : Paramètres → Mises à jour,
  recherche au démarrage, installation en un clic. Les mises à jour sont
  signées ; une version modifiée est refusée.
- **Paquet .deb, Android, iOS** : l'appli signale la nouvelle version et
  ouvre la page de téléchargement.
- **Serveur Linux et Proxmox** : `kittypass-update` (dans le conteneur :
  `pct exec <CTID> -- /usr/local/sbin/kittypass-update`). Chaque semaine automatiquement :
  `kittypass-update --auto on`, ou `AUTO_UPDATE=oui` à l'installation.
- **Serveur Windows** :
  `powershell -ExecutionPolicy Bypass -File "C:\Program Files\KittyPass Server\install.ps1" -Update -Online`
- **Docker** : `docker compose pull && docker compose up -d`.

## Structure

```
core/     KDBX, dérivation des clés, fusion, client de synchronisation
server/   serveur (axum + SQLite) : comptes, 2FA, stockage versionné
app/      logique commune de l'application
desktop/  application Tauri 2 (Linux, Windows, macOS, Android, iOS)
proxy/    relais entre l'extension navigateur et KittyPass
deploy/   Docker, Caddy, installateurs Proxmox, Linux et Windows
docs/     architecture, déploiement, reste à faire
```

## Compiler

```bash
cargo test --workspace
cd desktop && cargo tauri build --bundles deb,appimage --config tauri.linux.json
```

Serveur seul : `cargo build --release -p kittypass-server`.
Installateurs serveur : `deploy/proxmox/make-installer.sh`,
`deploy/linux/make-installer.sh` (cible musl, paquet `musl-tools`),
`deploy/windows/make-package.sh` (cargo-xwin).
Image Docker : `docker build -t kittypass-server .`

macOS et iOS se compilent sur la CI GitHub (machines macOS), qui teste aussi
les installateurs serveur Linux, Windows et Docker.

## Documentation

- [Architecture et modèle de menace](docs/ARCHITECTURE.md)
- [Déploiement](docs/DEPLOIEMENT.md)
- [Reste à faire](docs/RESTE-A-FAIRE.md)

## Licence

GPL-3.0-or-later, voir [LICENSE](LICENSE)
