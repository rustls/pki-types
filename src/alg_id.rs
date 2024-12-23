//! Common values of the PKIX [`AlgorithmIdentifier`] type.
//!
//! If you need to use an [`AlgorithmIdentifier`] not defined here,
//! you can define it locally.

use super::AlgorithmIdentifier;

// See src/data/README.md.

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp256r1`.
pub const ECDSA_P256: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-p256.der"));

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp384r1`.
pub const ECDSA_P384: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-p384.der"));

/// AlgorithmIdentifier for `id-ecPublicKey` with named curve `secp521r1`.
pub const ECDSA_P521: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-p521.der"));

/// AlgorithmIdentifier for `ecdsa-with-SHA256`.
pub const ECDSA_SHA256: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-sha256.der"));

/// AlgorithmIdentifier for `ecdsa-with-SHA384`.
pub const ECDSA_SHA384: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-sha384.der"));

/// AlgorithmIdentifier for `ecdsa-with-SHA512`.
pub const ECDSA_SHA512: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ecdsa-sha512.der"));

/// AlgorithmIdentifier for `rsaEncryption`.
pub const RSA_ENCRYPTION: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-encryption.der"));

/// AlgorithmIdentifier for `sha256WithRSAEncryption`.
pub const RSA_PKCS1_SHA256: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pkcs1-sha256.der"));

/// AlgorithmIdentifier for `sha384WithRSAEncryption`.
pub const RSA_PKCS1_SHA384: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pkcs1-sha384.der"));

/// AlgorithmIdentifier for `sha512WithRSAEncryption`.
pub const RSA_PKCS1_SHA512: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pkcs1-sha512.der"));

/// AlgorithmIdentifier for `rsassaPss` with:
///
/// - hashAlgorithm: sha256
/// - maskGenAlgorithm: mgf1 with sha256
/// - saltLength: 32
pub const RSA_PSS_SHA256: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pss-sha256.der"));

/// AlgorithmIdentifier for `rsassaPss` with:
///
/// - hashAlgorithm: sha384
/// - maskGenAlgorithm: mgf1 with sha384
/// - saltLength: 48
pub const RSA_PSS_SHA384: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pss-sha384.der"));

/// AlgorithmIdentifier for `rsassaPss` with:
///
/// - hashAlgorithm: sha512
/// - maskGenAlgorithm: mgf1 with sha512
/// - saltLength: 64
pub const RSA_PSS_SHA512: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-rsa-pss-sha512.der"));

/// AlgorithmIdentifier for `ED25519`.
pub const ED25519: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(include_bytes!("data/alg-ed25519.der"));
