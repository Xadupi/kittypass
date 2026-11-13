#!/usr/bin/env bash
# KittyPass : installation en une ligne sur une machine Linux avec systemd, en root :
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Xadupi/kittypass/master/deploy/linux/kittypass.sh)"
#
# Télécharge kittypass-linux.sh de la dernière Release, vérifie son
# empreinte avec SHA256SUMS.txt, puis le lance (mêmes variables :
# DOMAIN, PROXY_IP, AUTO_UPDATE…). KITTYPASS_VERSION=v1.2.3 fixe une version.
set -Eeuo pipefail
REPO=${KITTYPASS_REPO:-Xadupi/kittypass}
ASSET=kittypass-linux.sh
die() { printf '\e[31m✘ %s\e[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "à lancer en root"
command -v curl >/dev/null || die "curl est nécessaire"

if [[ -n "${KITTYPASS_VERSION:-}" ]]; then base="https://github.com/$REPO/releases/download/$KITTYPASS_VERSION"
else base="https://github.com/$REPO/releases/latest/download"; fi
WORK=$(mktemp -d)
trap 'rm -rf -- "${WORK:?}"' EXIT
printf '➜ téléchargement de %s…\n' "$ASSET"
curl -fsSL -o "$WORK/$ASSET" "$base/$ASSET" || die "téléchargement impossible ($base/$ASSET)"
curl -fsSL -o "$WORK/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || die "SHA256SUMS.txt introuvable"
( cd "$WORK" && grep -E "^[0-9a-f]{64}  $ASSET\$" SHA256SUMS.txt | sha256sum -c --quiet ) || die "empreinte incorrecte : fichier refusé"
printf '\e[32m✔\e[0m empreinte vérifiée\n'
bash "$WORK/$ASSET" "$@"
