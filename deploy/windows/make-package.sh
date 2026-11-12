#!/usr/bin/env bash
# Produit deploy/windows/kittypass-server-windows.zip (compilation croisée
# depuis Linux avec cargo-xwin).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
T=x86_64-pc-windows-msvc
cargo xwin build --release -p kittypass-server --target "$T" --manifest-path "$ROOT/Cargo.toml"
TMP=$(mktemp -d); trap 'rm -rf -- "${TMP:?}"' EXIT
D="$TMP/KittyPass-Server"; mkdir -p "$D"
cp "$ROOT/target/$T/release/kittypass-server.exe" "$D/"
( cd "$D" && sha256sum kittypass-server.exe > kittypass-server.exe.sha256 )
cp "$ROOT/deploy/windows/install.ps1" "$ROOT/deploy/windows/Installer.cmd" "$D/"
OUT="$ROOT/deploy/windows/kittypass-server-windows.zip"
rm -f -- "$OUT"; ( cd "$TMP" && zip -qr "$OUT" KittyPass-Server )
echo "créé : $OUT ($(du -h "$OUT" | cut -f1))"
