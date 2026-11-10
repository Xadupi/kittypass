#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = kittypass_core::keyfile::KeyFile::from_bytes(data);
});
