#!/usr/bin/env bash
# Produit deploy/proxmox/kittypass-proxmox.sh : install-lxc.sh + binaire
# statique du serveur (musl) et kittypass-update embarqués. Demande musl-tools.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/deploy/proxmox/kittypass-proxmox.sh"
T=x86_64-unknown-linux-musl
rustup target add "$T" >/dev/null 2>&1 || true
CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-musl-gcc}" cargo build --release -p kittypass-server --target "$T" --manifest-path "$ROOT/Cargo.toml"
TMP=$(mktemp -d); trap 'rm -rf -- "${TMP:?}"' EXIT
cp "$ROOT/target/$T/release/kittypass-server" "$ROOT/deploy/linux/kittypass-update" "$TMP/"
( cd "$TMP" && sha256sum kittypass-server kittypass-update > kittypass-server.sha256 )
echo "kittypass-server $(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/server/Cargo.toml" | head -n1)" > "$TMP/VERSION"
{ cat "$ROOT/deploy/proxmox/install-lxc.sh"; tar -czf - -C "$TMP" kittypass-server kittypass-update kittypass-server.sha256 VERSION | base64 -w 76; } > "$OUT"
chmod 755 "$OUT"
echo "créé : $OUT ($(du -h "$OUT" | cut -f1))"
