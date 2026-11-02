#![no_main]

use boringtun_amnezia::SignatureTemplate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(spec) = std::str::from_utf8(input) {
        let _ = SignatureTemplate::parse(spec);
    }
});
