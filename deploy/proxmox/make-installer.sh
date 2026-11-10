#!/usr/bin/env bash
# Produit deploy/proxmox/kittypass-proxmox.sh : install-lxc.sh + binaire du serveur embarqué.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/deploy/proxmox/kittypass-proxmox.sh"
cargo build --release -p kittypass-server --manifest-path "$ROOT/Cargo.toml"
TMP=$(mktemp -d); trap 'rm -rf -- "${TMP:?}"' EXIT
cp "$ROOT/target/release/kittypass-server" "$TMP/"
strip "$TMP/kittypass-server" 2>/dev/null || true
( cd "$TMP" && sha256sum kittypass-server > kittypass-server.sha256 )
"$TMP/kittypass-server" --version > "$TMP/VERSION" 2>/dev/null || echo "kittypass-server" > "$TMP/VERSION"
{ cat "$ROOT/deploy/proxmox/install-lxc.sh"; tar -czf - -C "$TMP" kittypass-server kittypass-server.sha256 VERSION | base64 -w 76; } > "$OUT"
chmod 755 "$OUT"
echo "créé : $OUT ($(du -h "$OUT" | cut -f1))"
