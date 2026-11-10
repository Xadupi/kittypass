//! Réglages KeeAgent (XML, UTF-8 ou UTF-16) : relus puis réécrits, la
//! réécriture doit se relire à l'identique.
#![no_main]
use kittypass_core::ssh::AgentSettings;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = AgentSettings::parse(data) {
        if s.check().is_ok() {
            let again = AgentSettings::parse(s.to_xml().as_bytes()).expect("réécriture illisible");
            assert_eq!(again, s);
        }
        let _ = s.lifetime();
    }
});
