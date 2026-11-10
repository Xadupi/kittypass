#![no_main]
use kittypass_core::ssh;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ssh::key_info(data);
    let _ = ssh::public_blob(data);
    let _ = ssh::load_key(data, "", "fuzz");
});
