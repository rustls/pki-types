#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rustls_pki_types::PrivateKeyDer::try_from(data);
});
