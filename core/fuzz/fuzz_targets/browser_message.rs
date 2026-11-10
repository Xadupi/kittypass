//! Messages de l'extension (avant tout déchiffrement) : enveloppe, nonce,
//! clés publiques et messages chiffrés hostiles.
#![no_main]
use kittypass_core::browser::{crypto, protocol::Envelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = Envelope::parse(data) {
        let _ = env.nonce();
        let _ = env.wants_unlock();
        if let Some(k) = &env.public_key {
            let _ = crypto::decode_key(k);
            if let Ok(mut s) = crypto::Session::new() {
                if s.set_peer(k).is_ok() {
                    if let (Some(m), Ok(n)) = (&env.message, env.nonce()) {
                        let _ = s.decrypt(m, &n);
                    }
                }
            }
        }
    }
});
