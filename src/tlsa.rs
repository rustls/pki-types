//! This types in this module relate to the TLSA and DANE
//! as described by [RFC6698](https://datatracker.ietf.org/doc/html/rfc6698)
use crate::Der;

/// Corresponds to the TLSA DNS RR Type as defined by
/// [RFC6698](https://datatracker.ietf.org/doc/html/rfc6698)
#[derive(Clone, Debug, PartialEq)]
pub struct TlsaRecord<'a> {
    /// Specifies the provided association that will be used to match
    /// the certificate presented in the TLS handshake.
    pub certificate_usage: CertificateUsage,

    /// specifies which part of the TLS certificate presented by the
    /// server will be matched against the association data
    pub selector: Selector,

    /// Specifies how the certificate association is presented.
    pub matching: MatchingType,

    /// This field specifies the "certificate association data" to be
    /// matched.  These bytes are either raw data (that is, the full
    /// certificate or its SubjectPublicKeyInfo, depending on the selector)
    /// for matching type 0, or the hash of the raw data for matching types 1
    /// and 2.  The data refers to the certificate in the association, not to
    /// the TLS ASN.1 Certificate object.
    pub association_data: Der<'a>,
}

/// A TLSA Certificate Usage as described in [RFC6698 section
/// 7.2](https://datatracker.ietf.org/doc/html/rfc6698#section-7.2).
/// This may be extended by future RFCs and is thus marked as
/// non-exhaustive.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateUsage {
    /// Certificate usage 0 is used to specify a CA certificate, or
    /// the public key of such a certificate, that MUST be found in any of
    /// the PKIX certification paths for the end entity certificate given
    /// by the server in TLS.  This certificate usage is sometimes
    /// referred to as "CA constraint" because it limits which CA can be
    /// used to issue certificates for a given service on a host.  The
    /// presented certificate MUST pass PKIX certification path
    /// validation, and a CA certificate that matches the TLSA record MUST
    /// be included as part of a valid certification path.  Because this
    /// certificate usage allows both trust anchors and CA certificates,
    /// the certificate might or might not have the basicConstraints
    /// extension present
    CAConstraint = 0,
    /// Certificate usage 1 is used to specify an end entity
    /// certificate, or the public key of such a certificate, that MUST be
    /// matched with the end entity certificate given by the server in
    /// TLS.  This certificate usage is sometimes referred to as "service
    /// certificate constraint" because it limits which end entity
    /// certificate can be used by a given service on a host.  The target
    /// certificate MUST pass PKIX certification path validation and MUST
    /// match the TLSA record.
    ServiceCertificateConstraint = 1,
    /// Certificate usage 2 is used to specify a certificate, or the
    /// public key of such a certificate, that MUST be used as the trust
    /// anchor when validating the end entity certificate given by the
    /// server in TLS.  This certificate usage is sometimes referred to as
    /// "trust anchor assertion" and allows a domain name administrator to
    /// specify a new trust anchor -- for example, if the domain issues
    /// its own certificates under its own CA that is not expected to be
    /// in the end users' collection of trust anchors.  The target
    /// certificate MUST pass PKIX certification path validation, with any
    /// certificate matching the TLSA record considered to be a trust
    /// anchor for this certification path validation.
    TrustAnchorAssertion = 2,
    /// Certificate usage 3 is used to specify a certificate, or the
    /// public key of such a certificate, that MUST match the end entity
    /// certificate given by the server in TLS.  This certificate usage is
    /// sometimes referred to as "domain-issued certificate" because it
    /// allows for a domain name administrator to issue certificates for a
    /// domain without involving a third-party CA.  The target certificate
    /// MUST match the TLSA record.  The difference between certificate
    /// usage 1 and certificate usage 3 is that certificate usage 1
    /// requires that the certificate pass PKIX validation, but PKIX
    /// validation is not tested for certificate usage 3.
    DomainIssuedCertificate = 3,
    /// Usage that is not presently defined by the registry of certificate
    /// usage types
    Unassigned(u8),
    /// Private use, with no specified behavior
    PrivateUse = 255,
}

/// specifies which part of the TLS certificate presented by the server will
/// be matched against the association data.  This value is defined in an
/// IANA registry and is described in [RFC5598 Section
/// 7.3](https://datatracker.ietf.org/doc/html/rfc6698#section-7.3)
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector {
    /// the Certificate binary structure as defined in
    /// [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)
    FullCertificate = 0,
    /// DER-encoded binary structure as defined in
    /// [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)
    SubjectPublicKeyInfo = 1,
}

/// Specifies how the certificate association is presented.
/// The value is defined in an IANA registry is and described in [RFC6698 Section
/// 7.4](https://datatracker.ietf.org/doc/html/rfc6698#section-7.4)
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchingType {
    /// Exact match on selected content
    ExactMatch = 0,
    /// SHA-256 hash of selected content
    /// [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)
    Sha256 = 1,
    /// SHA-512 hash of selected content
    /// [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)
    Sha512 = 2,
}
