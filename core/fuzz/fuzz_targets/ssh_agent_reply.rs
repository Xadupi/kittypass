//! Réponses d'un agent SSH hostile.
#![no_main]
use kittypass_core::ssh::agent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 4 {
        let _ = agent::reply_len([data[0], data[1], data[2], data[3]]);
    }
    let _ = agent::parse_status(data);
    let _ = agent::parse_identities(data);
});
