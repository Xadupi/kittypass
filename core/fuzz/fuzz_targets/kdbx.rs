//! Ouverture d'un coffre KDBX hostile (en-tête, KDF, blocs). Limites de KDF
//! très basses : seul le code d'analyse est exercé, pas Argon2.
#![no_main]
use kittypass_core::{header::OpenLimits, vault::Vault};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = OpenLimits {
        max_file_bytes: 1 << 20,
        max_argon2_memory_bytes: 64 * 1024,
        max_argon2_iterations: 2,
        max_argon2_parallelism: 2,
        max_argon2_cost: 128 * 1024,
        max_aes_rounds: 100,
    };
    let _ = kittypass_core::header::inspect(data);
    let _ = Vault::open(data, "fuzz", &limits);
});
