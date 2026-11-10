//! Options WebAuthn hostiles venant de la page web (via l'extension).
#![no_main]
use kittypass_core::browser::passkeys;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    let related = ["https://login.example.com".to_owned()];
    if let Ok(plan) = passkeys::plan_create(&v, "https://example.com", &related) {
        let _ = passkeys::create(&plan);
    }
    let _ = passkeys::plan_get(&v, "https://example.com", &related);
});
