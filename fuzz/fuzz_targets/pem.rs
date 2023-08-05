#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

fuzz_target!(|data: &[u8]| {
    // cover the code paths that use std::io
    for x in CertificateDer::pem_reader_iter(&mut Cursor::new(data)) {
        match x {
            Ok(_item) => (),
            Err(_err) => break,
        }
    }

    // cover the code paths that use slices
    for x in PrivateKeyDer::pem_slice_iter(data) {
        match x {
            Ok(_item) => (),
            Err(_err) => break,
        }
    }
});
