#!/bin/sh
# Construit le relais navigateur kittypass-proxy et le place là où Tauri
# l'attend (externalBin : nom suffixé par la cible Rust). Lancé par
# `cargo tauri build --config tauri.linux.json` (paquets .deb et AppImage),
# ou avec KP_TARGET=x86_64-pc-windows-msvc pour Windows depuis Linux (cargo-xwin).
set -eu
cd "$(dirname "$0")/.."
mkdir -p binaries
if [ -n "${KP_TARGET:-}" ]; then
  cargo xwin build --release -p kittypass-proxy --target "$KP_TARGET"
  ext=""; case "$KP_TARGET" in *windows*) ext=".exe";; esac
  cp "../target/$KP_TARGET/release/kittypass-proxy$ext" "binaries/kittypass-proxy-$KP_TARGET$ext"
else
  cargo build --release -p kittypass-proxy
  triple=$(rustc -vV | sed -n 's/^host: //p')
  cp ../target/release/kittypass-proxy "binaries/kittypass-proxy-$triple"
fi
