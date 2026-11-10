# Déployer le serveur sur Proxmox

## Recommandation

Une **VM Debian** ou un **conteneur LXC non privilégié** dédié, avec Docker. Le serveur
n'écoute que sur le réseau interne ; seul Caddy est exposé sur les ports 80 et 443.

```
Internet ──443──► routeur (redirection 80/443) ──► VM/LXC : Caddy ──► kittypass (8080, interne)
```

## Étapes

1. Un nom de domaine (ou un sous-domaine DynDNS) qui pointe vers ton IP publique.
2. Sur le routeur, rediriger les ports 80 et 443 vers la VM.
3. Dans la VM :
   ```bash
   git clone <dépôt> kittypass && cd kittypass/deploy
   sed -i 's/coffre.example.org/ton.domaine/' Caddyfile
   docker compose up -d --build
   ```
4. Créer ta première invitation **admin**, puis t'inscrire depuis une application :
   ```bash
   docker compose exec kittypass kittypass-server invite --admin
   ```
5. Activer immédiatement la 2FA sur le compte admin.

## Créer les comptes

Depuis l'appli, avec un compte admin : **Paramètres › Compte › Administration du serveur**.
« Créer une invitation » donne un code (valable 1 à 30 jours, une seule fois) à transmettre avec
l'adresse du serveur. La personne choisit « Créer un compte » dans KittyPass, colle le code et
choisit son identifiant et son mot de passe, que l'admin ne connaît jamais (c'est aussi la clé de
son coffre). La même section liste les comptes et permet d'en désactiver ou réactiver un.
Inviter un autre admin demande d'avoir activé la 2FA.

## Administration (ligne de commande)

```bash
docker compose exec kittypass kittypass-server invite        # invitation simple, 72 h
docker compose exec kittypass kittypass-server invite 24     # valable 24 h
docker compose exec kittypass kittypass-server users
docker compose exec kittypass kittypass-server disable bob   # coupe aussi ses sessions
```

## Sauvegardes

Le volume `kittypass-data` contient deux fichiers indispensables :

- `kittypass.db` : comptes et coffres chiffrés ;
- `secret.key` : clé maître du serveur. **Sans elle, plus personne ne peut se
  connecter et les 2FA sont perdues.** Sauvegarde-la à part (hors ligne), pas avec la
  base : séparées, une fuite de l'une sans l'autre ne sert à rien.

Pour une sauvegarde à chaud cohérente de la base :

```bash
docker compose exec kittypass sh -c 'sqlite3 /data/kittypass.db ".backup /data/backup.db"'
```

Les fichiers `.kdbx` restent chiffrés par le mot de passe maître de chaque utilisateur.

## Durcissement conseillé

- Pare-feu Proxmox : n'autoriser que 80 et 443 vers la VM.
- Mises à jour automatiques (`unattended-upgrades`) dans la VM.
- `KITTYPASS_REQUIRE_2FA=true` dès que tous les comptes ont configuré leur 2FA.
- fail2ban sur les journaux : chaque échec est tracé (`login_bad_password`,
  `refresh_token_reuse`…) dans la table `audit` et sur la sortie standard.

## Proxmox (conteneur LXC, script tout-en-un)

Sur le PC de développement : `bash deploy/proxmox/make-installer.sh` produit
`deploy/proxmox/kittypass-proxmox.sh` (script + serveur embarqué, empreinte SHA-256 vérifiée).
Puis :

```bash
scp deploy/proxmox/kittypass-proxmox.sh root@192.168.1.5:/root/
ssh root@192.168.1.5 bash /root/kittypass-proxmox.sh
```

Le script crée un conteneur Debian 13 non privilégié (1 cœur, 512 Mo, 4 Go, démarrage auto),
installe le service systemd durci (`/var/lib/kittypass`), Caddy + HTTPS si `DOMAIN=` est donné,
et affiche une invitation administrateur valable 72 h. Variables : `CTID`, `CT_NAME`, `STORAGE`,
`BRIDGE`, `CT_IP`, `CT_GW`, `DOMAIN`, `REQUIRE_2FA`.
