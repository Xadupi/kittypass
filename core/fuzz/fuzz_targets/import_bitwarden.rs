#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = kittypass_core::vault::import::parse_bitwarden(data);
});
