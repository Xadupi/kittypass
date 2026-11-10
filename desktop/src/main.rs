// Pas de console supplémentaire sous Windows en version finale.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    kittypass_desktop_lib::run();
}
