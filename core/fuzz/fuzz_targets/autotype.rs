#![no_main]
use kittypass_core::autotype;
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;
fuzz_target!(|data: &str| {
    let _ = autotype::validate(data);
    let _ = autotype::fields(data);
    let _ = autotype::compile(data, |_| Some(Zeroizing::new("valeur {TAB} +^%~".to_owned())));
});
