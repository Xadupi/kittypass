#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &str| {
    if let Ok(t) = kittypass_core::otp::Totp::parse(data) {
        let _ = t.code_at(1_800_000_000);
        let _ = t.code_at(u64::MAX);
    }
});
