#!/usr/bin/env bash
# KittyPass : installe le serveur directement sur une machine Linux avec
# systemd (Debian, Ubuntu, Fedora, Arch…), sans Docker ni conteneur.
# Le binaire (statique, musl) est embarqué à la fin de ce fichier : voir
# make-installer.sh.
#
# Utilisation, en root :
#   bash kittypass-linux.sh                    # questions interactives
#   DOMAIN=coffre.exemple.fr bash kittypass-linux.sh
#   bash kittypass-linux.sh --update           # remplace seulement le binaire
#   bash kittypass-linux.sh --uninstall        # retire le service (garde les données)
# Variables (facultatives) :
#   PROXY_IP     IP d'un reverse proxy HTTPS existant : écoute sur :8080
#   DOMAIN       sans PROXY_IP : domaine public, installe Caddy (apt ou dnf)
#   PORT         port d'écoute (défaut 8080)
#   REQUIRE_2FA  « true » pour imposer la 2FA à tous les comptes
set -Eeuo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=

C_OK=$'\e[32m'; C_ERR=$'\e[31m'; C_INFO=$'\e[36m'; C_RST=$'\e[0m'
msg()  { printf '%s➜%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s✔%s %s\n' "$C_OK" "$C_RST" "$*"; }
die()  { printf '%s✘ %s%s\n' "$C_ERR" "$*" "$C_RST" >&2; exit 1; }
trap 'die "échec ligne $LINENO : $BASH_COMMAND"' ERR

[[ $EUID -eq 0 ]] || die "à lancer en root (sudo bash $0)"
command -v systemctl >/dev/null || die "systemd est nécessaire"
[[ "$(uname -m)" == x86_64 ]] || die "seul x86_64 est pris en charge"

BIN=/usr/local/bin/kittypass-server
DATA=/var/lib/kittypass
UNIT=/etc/systemd/system/kittypass.service

if [[ "${1:-}" == --uninstall ]]; then
  systemctl disable --now kittypass 2>/dev/null || true
  rm -f -- "$UNIT" "$BIN" /etc/kittypass.env
  systemctl daemon-reload
  ok "service retiré. Données gardées dans $DATA (à supprimer à la main si voulu)."
  exit 0
fi

# --- Binaire embarqué
PAYLOAD_LINE=$(awk '/^__KITTYPASS_PAYLOAD__$/ {print NR + 1; exit 0}' "$0")
[[ -n "${PAYLOAD_LINE:-}" ]] || die "binaire embarqué absent : utilise le fichier produit par make-installer.sh"
WORK=$(mktemp -d)
cleanup() { rm -rf -- "${WORK:?}"; }
trap cleanup EXIT
tail -n +"$PAYLOAD_LINE" "$0" | base64 -d | tar -xz -C "$WORK"
( cd "$WORK" && sha256sum -c --quiet kittypass-server.sha256 ) || die "binaire embarqué corrompu (empreinte)"
ok "binaire du serveur vérifié ($(cat "$WORK/VERSION" 2>/dev/null || echo version inconnue))"

if [[ "${1:-}" == --update ]]; then
  [[ -f "$UNIT" ]] || die "KittyPass n'est pas installé ici"
  install -m 755 "$WORK/kittypass-server" "$BIN"
  systemctl restart kittypass
  ok "serveur mis à jour et redémarré"
  exit 0
fi
[[ -f "$UNIT" ]] && die "déjà installé : utilise --update pour mettre à jour"

# --- Paramètres
ask() { # ask VAR "question" défaut
  local var=$1 q=$2 def=$3 val
  if [[ -n "${!var:-}" ]]; then return; fi
  if [[ -t 0 ]]; then read -rp "$q [$def] : " val || true; fi
  printf -v "$var" '%s' "${val:-$def}"
}
ask PROXY_IP "IP de ton reverse proxy HTTPS existant (vide : aucun)" ""
if [[ -n "$PROXY_IP" ]]; then DOMAIN=; else ask DOMAIN "Nom de domaine public, Caddy sera installé (vide : aucun)" ""; fi
PORT=${PORT:-8080}
REQUIRE_2FA=${REQUIRE_2FA:-false}
[[ -z "$DOMAIN" || "$DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || die "domaine invalide"
[[ -z "$PROXY_IP" || "$PROXY_IP" =~ ^[0-9a-fA-F.:/]+$ ]] || die "PROXY_IP invalide"
[[ "$PORT" =~ ^[0-9]{2,5}$ ]] || die "PORT invalide"
[[ "$REQUIRE_2FA" =~ ^(true|false)$ ]] || die "REQUIRE_2FA : true ou false"

# --- Serveur
if [[ -n "$PROXY_IP" ]]; then BIND=0.0.0.0:$PORT; PROXIES=$PROXY_IP
elif [[ -n "$DOMAIN" ]]; then BIND=127.0.0.1:$PORT; PROXIES=127.0.0.1; else BIND=0.0.0.0:$PORT; PROXIES=; fi
install -m 755 "$WORK/kittypass-server" "$BIN"
id kittypass >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin kittypass 2>/dev/null \
  || useradd --system --home-dir "$DATA" --shell /sbin/nologin kittypass
install -d -m 700 -o kittypass -g kittypass "$DATA"
cat > /etc/kittypass.env <<EOF
KITTYPASS_DATA=$DATA
KITTYPASS_BIND=$BIND
KITTYPASS_TRUSTED_PROXIES=$PROXIES
KITTYPASS_REQUIRE_2FA=$REQUIRE_2FA
EOF
chmod 644 /etc/kittypass.env
cat > "$UNIT" <<EOF
[Unit]
Description=Serveur KittyPass
After=network-online.target
Wants=network-online.target

[Service]
User=kittypass
Group=kittypass
EnvironmentFile=/etc/kittypass.env
ExecStart=$BIN serve
Restart=on-failure
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$DATA
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
up=
for _ in $(seq 1 20); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then up=1; break; fi
  sleep 1
done
[[ -n "$up" ]] || { journalctl -u kittypass -n 20 --no-pager; die "le service ne répond pas"; }
ok "service kittypass actif (port $PORT)"

# --- HTTPS (Caddy) si un domaine est donné
if [[ -n "$DOMAIN" ]]; then
  msg "installation de Caddy pour https://$DOMAIN …"
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get -y -qq install caddy >/dev/null
  elif command -v dnf >/dev/null; then dnf -y -q install caddy
  else die "installe Caddy à la main, puis relance"; fi
  cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	@api path /api/v1/* /health
	handle @api {
		reverse_proxy 127.0.0.1:$PORT {
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
  systemctl enable --now caddy >/dev/null 2>&1
  systemctl reload-or-restart caddy
  ok "Caddy configuré (certificat Let's Encrypt obtenu au premier accès)"
fi

# --- Première invitation administrateur
INVITE=$(runuser -u kittypass -- env KITTYPASS_DATA="$DATA" "$BIN" invite --admin 72 2>/dev/null)
ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
ok "KittyPass est installé."
if [[ -n "$PROXY_IP" ]]; then
  echo "  Dans ton reverse proxy ($PROXY_IP) : hôte HTTPS → http://$ADDR:$PORT"
elif [[ -n "$DOMAIN" ]]; then
  echo "  Adresse à donner à l'appli : https://$DOMAIN (ports 80 et 443 ouverts vers cette machine)"
else
  echo "  Serveur en HTTP sur http://$ADDR:$PORT : place un reverse proxy HTTPS devant."
fi
echo "  Invitation ADMIN (72 h, une seule fois) : $INVITE"
echo "  Sauvegarde : $DATA (kittypass.db, et secret.key À GARDER À PART)."
echo "  Mise à jour : sudo bash <nouveau kittypass-linux.sh> --update"
exit 0
__KITTYPASS_PAYLOAD__
