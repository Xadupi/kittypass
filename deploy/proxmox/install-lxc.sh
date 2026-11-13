#!/usr/bin/env bash
# KittyPass : installe le serveur dans un conteneur LXC Debian 13 sur Proxmox VE.
# Dans l'esprit des « community-scripts » : à lancer en root dans le shell de
# l'hôte Proxmox. Le binaire du serveur est embarqué à la fin de ce fichier
# (voir make-installer.sh) ; rien n'est téléchargé hors des dépôts Debian et
# du modèle de conteneur Proxmox.
#
# Utilisation :
#   bash kittypass-proxmox.sh                     # questions interactives
#   DOMAIN=coffre.exemple.fr bash kittypass-proxmox.sh
# Variables (toutes facultatives) :
#   CTID      numéro du conteneur (défaut : prochain libre)
#   CT_NAME   nom d'hôte (défaut : kittypass)
#   STORAGE   stockage du disque (défaut : local-lvm, sinon local)
#   BRIDGE    pont réseau (défaut : vmbr0)
#   CT_IP     « dhcp » (défaut) ou adresse fixe, ex. 192.168.1.50/24
#   CT_GW     passerelle si adresse fixe, ex. 192.168.1.1
#   PROXY_IP  IP d'un reverse proxy HTTPS existant (NPM, Traefik…) : pas de Caddy,
#             le serveur écoute sur :8080 et ne fait confiance qu'à cette IP
#   DOMAIN    sans PROXY_IP : nom de domaine public, installe Caddy et le HTTPS
#   REQUIRE_2FA  « true » pour imposer la 2FA à tous les comptes
#   AUTO_UPDATE  « oui » : mise à jour chaque semaine depuis GitHub (kittypass-update)
set -Eeuo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=

C_OK=$'\e[32m'; C_ERR=$'\e[31m'; C_INFO=$'\e[36m'; C_RST=$'\e[0m'
msg()  { printf '%s➜%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s✔%s %s\n' "$C_OK" "$C_RST" "$*"; }
die()  { printf '%s✘ %s%s\n' "$C_ERR" "$*" "$C_RST" >&2; exit 1; }
trap 'die "échec ligne $LINENO : $BASH_COMMAND"' ERR

[[ $EUID -eq 0 ]] || die "à lancer en root sur l'hôte Proxmox"
command -v pct >/dev/null && command -v pveam >/dev/null || die "pct/pveam introuvables : ce n'est pas un hôte Proxmox VE"

# --- Binaire embarqué
PAYLOAD_LINE=$(awk '/^__KITTYPASS_PAYLOAD__$/ {print NR + 1; exit 0}' "$0")
[[ -n "${PAYLOAD_LINE:-}" ]] || die "binaire embarqué absent : utilise le fichier produit par make-installer.sh"
WORK=$(mktemp -d)
cleanup() { rm -rf -- "${WORK:?}"; }
trap cleanup EXIT
tail -n +"$PAYLOAD_LINE" "$0" | base64 -d | tar -xz -C "$WORK"
[[ -x "$WORK/kittypass-server" ]] || die "binaire embarqué illisible"
( cd "$WORK" && sha256sum -c --quiet kittypass-server.sha256 ) || die "binaire embarqué corrompu (empreinte)"
ok "binaire du serveur vérifié ($(cat "$WORK/VERSION" 2>/dev/null || echo version inconnue))"

# --- Paramètres
ask() { # ask VAR "question" défaut
  local var=$1 q=$2 def=$3 val
  if [[ -n "${!var:-}" ]]; then return; fi
  if [[ -t 0 ]]; then read -rp "$q [$def] : " val || true; fi
  printf -v "$var" '%s' "${val:-$def}"
}
CTID=${CTID:-$(pvesh get /cluster/nextid)}
ask CT_NAME "Nom du conteneur" "kittypass"
if [[ -z "${STORAGE:-}" ]]; then
  if pvesm status -content rootdir 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx local-lvm; then def_st=local-lvm; else def_st=local; fi
  ask STORAGE "Stockage du disque" "$def_st"
fi
ask BRIDGE "Pont réseau" "vmbr0"
ask CT_IP "Adresse IP (dhcp ou x.x.x.x/24)" "dhcp"
if [[ "$CT_IP" != dhcp ]]; then ask CT_GW "Passerelle" "$(ip route | awk '/^default/ {print $3; exit}')"; fi
ask PROXY_IP "IP de ton reverse proxy HTTPS existant (vide : aucun)" ""
if [[ -n "$PROXY_IP" ]]; then DOMAIN=; else ask DOMAIN "Nom de domaine public, Caddy sera installé (vide : aucun)" ""; fi
REQUIRE_2FA=${REQUIRE_2FA:-false}
ask AUTO_UPDATE "Mise à jour automatique chaque semaine depuis GitHub (oui/non)" "non"

[[ "$CTID" =~ ^[0-9]+$ ]] || die "CTID invalide"
pct status "$CTID" >/dev/null 2>&1 && die "le conteneur $CTID existe déjà"
[[ "$CT_NAME" =~ ^[a-z0-9-]{1,63}$ ]] || die "nom de conteneur invalide"
[[ -z "$DOMAIN" || "$DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || die "domaine invalide"
[[ -z "$PROXY_IP" || "$PROXY_IP" =~ ^[0-9a-fA-F.:/]+$ ]] || die "PROXY_IP invalide"
[[ "$REQUIRE_2FA" =~ ^(true|false)$ ]] || die "REQUIRE_2FA : true ou false"

# --- Modèle Debian 13
msg "recherche du modèle Debian 13…"
pveam update >/dev/null
TEMPLATE=$(pveam available --section system | awk '{print $2}' | grep -E '^debian-13-standard_.*_amd64\.tar\.(zst|gz|xz)$' | sort -V | tail -1)
[[ -n "$TEMPLATE" ]] || die "modèle Debian 13 introuvable (pveam available)"
TSTORE=local
if ! pveam list "$TSTORE" | grep -q "$TEMPLATE"; then
  msg "téléchargement de $TEMPLATE…"
  pveam download "$TSTORE" "$TEMPLATE" >/dev/null
fi
ok "modèle $TEMPLATE"

# --- Conteneur (non privilégié, petit, démarrage automatique)
if [[ "$CT_IP" == dhcp ]]; then NET="name=eth0,bridge=$BRIDGE,ip=dhcp,ip6=auto"
else NET="name=eth0,bridge=$BRIDGE,ip=$CT_IP,gw=$CT_GW"; fi
trap 'die "échec ligne $LINENO : $BASH_COMMAND — pour recommencer : pct stop $CTID; pct destroy $CTID"' ERR
msg "création du conteneur $CTID ($CT_NAME)…"
pct create "$CTID" "$TSTORE:vztmpl/$TEMPLATE" \
  --hostname "$CT_NAME" --cores 1 --memory 512 --swap 256 \
  --rootfs "$STORAGE:4" --net0 "$NET" --unprivileged 1 --features nesting=1 \
  --onboot 1 --tags kittypass --description "Serveur KittyPass (gestionnaire de mots de passe)" >/dev/null
pct start "$CTID"
for _ in $(seq 1 30); do
  pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null' 2>/dev/null && break
  sleep 2
done
pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null' || die "le conteneur n'a pas d'accès réseau/DNS"
ok "conteneur démarré"

# --- Système
msg "mise à jour de Debian et sécurité automatique…"
pct exec "$CTID" -- bash -c 'export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 LANG=C.UTF-8
  apt-get update -qq && apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade >/dev/null 2>&1
  apt-get -y -qq install unattended-upgrades sqlite3 ca-certificates curl >/dev/null
  echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null'
ok "Debian à jour"

# --- KittyPass
if [[ -n "$PROXY_IP" ]]; then BIND=0.0.0.0:8080; PROXIES=$PROXY_IP
elif [[ -n "$DOMAIN" ]]; then BIND=127.0.0.1:8080; PROXIES=127.0.0.1; else BIND=0.0.0.0:8080; PROXIES=; fi
pct push "$CTID" "$WORK/kittypass-server" /usr/local/bin/kittypass-server --perms 755
pct push "$CTID" "$WORK/kittypass-update" /usr/local/sbin/kittypass-update --perms 755
pct exec "$CTID" -- bash -c "set -e
  id kittypass >/dev/null 2>&1 || useradd --system --home-dir /var/lib/kittypass --shell /usr/sbin/nologin kittypass
  install -d -m 700 -o kittypass -g kittypass /var/lib/kittypass
  cat > /etc/kittypass.env <<EOF
KITTYPASS_DATA=/var/lib/kittypass
KITTYPASS_BIND=$BIND
KITTYPASS_TRUSTED_PROXIES=$PROXIES
KITTYPASS_REQUIRE_2FA=$REQUIRE_2FA
EOF
  chmod 644 /etc/kittypass.env
  cat > /etc/systemd/system/kittypass.service <<'EOF'
[Unit]
Description=Serveur KittyPass
After=network-online.target
Wants=network-online.target

[Service]
User=kittypass
Group=kittypass
EnvironmentFile=/etc/kittypass.env
ExecStart=/usr/local/bin/kittypass-server serve
Restart=on-failure
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/kittypass
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now kittypass >/dev/null 2>&1
  for i in \$(seq 1 20); do
    curl -fsS -o /dev/null http://127.0.0.1:8080/health 2>/dev/null && exit 0
    sleep 1
  done
  journalctl -u kittypass -n 20 --no-pager; exit 1"
ok "service kittypass actif"
if [[ "$AUTO_UPDATE" =~ ^(o|oui|y|yes|true)$ ]]; then pct exec "$CTID" -- /usr/local/sbin/kittypass-update --auto on; fi

# --- HTTPS (Caddy) si un domaine est donné
if [[ -n "$DOMAIN" ]]; then
  msg "installation de Caddy pour https://$DOMAIN …"
  pct exec "$CTID" -- bash -c "set -e; export DEBIAN_FRONTEND=noninteractive
    apt-get -y -qq install caddy >/dev/null
    cat > /etc/caddy/Caddyfile <<'EOF'
$DOMAIN {
	@api path /api/v1/* /health
	handle @api {
		reverse_proxy 127.0.0.1:8080 {
			header_up X-Forwarded-For {remote_host}
		}
	}
	handle {
		respond 404
	}
	request_body {
		max_size 64MB
	}
	header -Server
}
EOF
    systemctl reload-or-restart caddy"
  ok "Caddy configuré (certificat Let's Encrypt obtenu au premier accès)"
fi

# --- Première invitation administrateur
INVITE=$(pct exec "$CTID" -- runuser -u kittypass -- env KITTYPASS_DATA=/var/lib/kittypass /usr/local/bin/kittypass-server invite --admin 72 2>/dev/null)
CT_ADDR=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')

echo
ok "KittyPass est installé dans le conteneur $CTID ($CT_NAME, $CT_ADDR)."
if [[ -n "$PROXY_IP" ]]; then
  echo "  Dans ton reverse proxy ($PROXY_IP) : hôte HTTPS → http://$CT_ADDR:8080"
  echo "  (transmettre X-Forwarded-For ; limite de corps ≥ 64 Mo ; WebSocket inutile)."
  echo "  Adresse à donner à l'appli : l'URL https de ton reverse proxy."
elif [[ -n "$DOMAIN" ]]; then
  echo "  Adresse à donner à l'appli : https://$DOMAIN"
  echo "  Redirige les ports 80 et 443 de ta box vers $CT_ADDR, et fais pointer $DOMAIN vers ton IP publique."
else
  echo "  Serveur en HTTP sur http://$CT_ADDR:8080 (réseau local seulement)."
  echo "  ⚠ L'appli exige le HTTPS hors de localhost : relance avec DOMAIN=… ou place un"
  echo "    reverse proxy HTTPS (Caddy, Nginx Proxy Manager…) devant ce conteneur."
fi
echo "  Invitation ADMIN (72 h, une seule fois) : $INVITE"
echo "  → Dans KittyPass : « Créer un compte », colle ce code, puis active la 2FA."
echo "  Sauvegarde : /var/lib/kittypass (kittypass.db, et secret.key À GARDER À PART)."
echo "  Mise à jour : pct exec $CTID -- /usr/local/sbin/kittypass-update   (automatique : … kittypass-update --auto on)"
exit 0
__KITTYPASS_PAYLOAD__
