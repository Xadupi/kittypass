#![no_main]
use kittypass_core::browser::matching;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let (a, b) = data.split_once('\n').unwrap_or((data, "https://example.com/"));
    let _ = matching::host_of(a);
    if let (Some(p), Some(e)) = (matching::parse_page(a), matching::parse_entry(b)) {
        let _ = matching::compare(&p, &e);
    }
});
