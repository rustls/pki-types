use rustls_pki_types::PrivateKeyDer;

#[test]
fn test_private_key_from_der() {
    fn is_pkcs8(key: &PrivateKeyDer<'_>) -> bool {
        matches!(key, PrivateKeyDer::Pkcs8(_))
    }
    fn is_pkcs1(key: &PrivateKeyDer<'_>) -> bool {
        matches!(key, PrivateKeyDer::Pkcs1(_))
    }
    fn is_sec1(key: &PrivateKeyDer<'_>) -> bool {
        matches!(key, PrivateKeyDer::Sec1(_))
    }

    let test_cases: &[(&[u8], fn(&PrivateKeyDer<'_>) -> bool); 11] = &[
        (&include_bytes!("../tests/keys/eddsakey.der")[..], is_pkcs8),
        (
            &include_bytes!("../tests/keys/nistp256key.der")[..],
            is_sec1,
        ),
        (
            &include_bytes!("../tests/keys/nistp256key.pkcs8.der")[..],
            is_pkcs8,
        ),
        (
            &include_bytes!("../tests/keys/nistp384key.der")[..],
            is_sec1,
        ),
        (
            &include_bytes!("../tests/keys/nistp384key.pkcs8.der")[..],
            is_pkcs8,
        ),
        (
            &include_bytes!("../tests/keys/nistp521key.der")[..],
            is_sec1,
        ),
        (
            &include_bytes!("../tests/keys/nistp521key.pkcs8.der")[..],
            is_pkcs8,
        ),
        (
            &include_bytes!("../tests/keys/rsa2048key.pkcs1.der")[..],
            is_pkcs1,
        ),
        (
            &include_bytes!("../tests/keys/rsa2048key.pkcs8.der")[..],
            is_pkcs8,
        ),
        (
            &include_bytes!("../tests/keys/rsa4096key.pkcs8.der")[..],
            is_pkcs8,
        ),
        (
            &include_bytes!("../tests/keys/edd25519_v2.der")[..],
            is_pkcs8,
        ),
    ];

    for (key_bytes, expected_check_fn) in test_cases.iter() {
        assert!(expected_check_fn(
            &PrivateKeyDer::try_from(*key_bytes).unwrap()
        ));
    }
}
