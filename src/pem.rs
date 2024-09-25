use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use core::iter;
use core::ops::ControlFlow;
#[cfg(feature = "std")]
use std::io::{self, ErrorKind};

use crate::base64;
use crate::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer, SubjectPublicKeyInfoDer,
};

/// The contents of a single recognised block in a PEM file.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum Item {
    /// A DER-encoded x509 certificate.
    ///
    /// Appears as "CERTIFICATE" in PEM files.
    X509Certificate(CertificateDer<'static>),

    /// A DER-encoded Subject Public Key Info; as specified in RFC 7468.
    ///
    /// Appears as "PUBLIC KEY" in PEM files.
    SubjectPublicKeyInfo(SubjectPublicKeyInfoDer<'static>),

    /// A DER-encoded plaintext RSA private key; as specified in PKCS #1/RFC 3447
    ///
    /// Appears as "RSA PRIVATE KEY" in PEM files.
    Pkcs1Key(PrivatePkcs1KeyDer<'static>),

    /// A DER-encoded plaintext private key; as specified in PKCS #8/RFC 5958
    ///
    /// Appears as "PRIVATE KEY" in PEM files.
    Pkcs8Key(PrivatePkcs8KeyDer<'static>),

    /// A Sec1-encoded plaintext private key; as specified in RFC 5915
    ///
    /// Appears as "EC PRIVATE KEY" in PEM files.
    Sec1Key(PrivateSec1KeyDer<'static>),

    /// A Certificate Revocation List; as specified in RFC 5280
    ///
    /// Appears as "X509 CRL" in PEM files.
    Crl(CertificateRevocationListDer<'static>),

    /// A Certificate Signing Request; as specified in RFC 2986
    ///
    /// Appears as "CERTIFICATE REQUEST" in PEM files.
    Csr(CertificateSigningRequestDer<'static>),
}

/// Extract and decode the next PEM section from `input`
///
/// - `Ok(None)` is returned if there is no PEM section to read from `input`
/// - Syntax errors and decoding errors produce a `Err(...)`
/// - Otherwise each decoded section is returned with a `Ok(Some((Item::..., remainder)))` where
///   `remainder` is the part of the `input` that follows the returned section
pub fn read_one_from_slice(mut input: &[u8]) -> Result<Option<(Item, &[u8])>, Error> {
    let mut b64buf = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;

    loop {
        let next_line = if let Some(index) = input
            .iter()
            .position(|byte| *byte == b'\n' || *byte == b'\r')
        {
            let (line, newline_plus_remainder) = input.split_at(index);
            input = &newline_plus_remainder[1..];
            Some(line)
        } else {
            None
        };

        match read_one_impl(next_line, &mut section, &mut b64buf)? {
            ControlFlow::Continue(()) => continue,
            ControlFlow::Break(item) => return Ok(item.map(|item| (item, input))),
        }
    }
}

/// Extract and decode the next PEM section from `rd`.
///
/// - Ok(None) is returned if there is no PEM section read from `rd`.
/// - Underlying IO errors produce a `Err(...)`
/// - Otherwise each decoded section is returned with a `Ok(Some(Item::...))`
///
/// You can use this function to build an iterator, for example:
/// `for item in iter::from_fn(|| read_one(rd).transpose()) { ... }`
#[cfg(feature = "std")]
pub fn read_one(rd: &mut dyn io::BufRead) -> Result<Option<Item>, Error> {
    let mut b64buf = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;
    let mut line = Vec::with_capacity(80);

    loop {
        line.clear();
        let len = read_until_newline(rd, &mut line).map_err(Error::Io)?;

        let next_line = if len == 0 {
            None
        } else {
            Some(line.as_slice())
        };

        match read_one_impl(next_line, &mut section, &mut b64buf) {
            Ok(ControlFlow::Break(opt)) => return Ok(opt),
            Ok(ControlFlow::Continue(())) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn read_one_impl(
    next_line: Option<&[u8]>,
    section: &mut Option<(Vec<u8>, Vec<u8>)>,
    b64buf: &mut Vec<u8>,
) -> Result<ControlFlow<Option<Item>, ()>, Error> {
    let line = if let Some(line) = next_line {
        line
    } else {
        // EOF
        return match section.take() {
            Some((_, end_marker)) => Err(Error::MissingSectionEnd { end_marker }),
            None => Ok(ControlFlow::Break(None)),
        };
    };

    if line.starts_with(b"-----BEGIN ") {
        let (mut trailer, mut pos) = (0, line.len());
        for (i, &b) in line.iter().enumerate().rev() {
            match b {
                b'-' => {
                    trailer += 1;
                    pos = i;
                }
                b'\n' | b'\r' | b' ' => continue,
                _ => break,
            }
        }

        if trailer != 5 {
            return Err(Error::IllegalSectionStart {
                line: line.to_vec(),
            });
        }

        let ty = &line[11..pos];
        let mut end = Vec::with_capacity(10 + 4 + ty.len());
        end.extend_from_slice(b"-----END ");
        end.extend_from_slice(ty);
        end.extend_from_slice(b"-----");
        *section = Some((ty.to_owned(), end));
        return Ok(ControlFlow::Continue(()));
    }

    if let Some((section_label, end_marker)) = section.as_ref() {
        if line.starts_with(end_marker) {
            let kind = match SectionKind::try_from(&section_label[..]) {
                Ok(kind) => kind,
                // unhandled section: have caller try again
                Err(()) => {
                    *section = None;
                    b64buf.clear();
                    return Ok(ControlFlow::Continue(()));
                }
            };

            let mut der = vec![0u8; base64::decoded_length(b64buf.len())];
            let der_len = match kind.secret() {
                true => base64::decode_secret(b64buf, &mut der),
                false => base64::decode_public(b64buf, &mut der),
            }
            .map_err(|err| Error::Base64Decode(format!("{err:?}")))?
            .len();

            der.truncate(der_len);

            return Ok(ControlFlow::Break(Some(kind.item(der))));
        }
    }

    if section.is_some() {
        b64buf.extend(line);
    }

    Ok(ControlFlow::Continue(()))
}

/// A single recognised section in a PEM file.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SectionKind {
    /// A DER-encoded x509 certificate.
    ///
    /// Appears as "CERTIFICATE" in PEM files.
    Certificate,

    /// A DER-encoded Subject Public Key Info; as specified in RFC 7468.
    ///
    /// Appears as "PUBLIC KEY" in PEM files.
    PublicKey,

    /// A DER-encoded plaintext RSA private key; as specified in PKCS #1/RFC 3447
    ///
    /// Appears as "RSA PRIVATE KEY" in PEM files.
    RsaPrivateKey,

    /// A DER-encoded plaintext private key; as specified in PKCS #8/RFC 5958
    ///
    /// Appears as "PRIVATE KEY" in PEM files.
    PrivateKey,

    /// A Sec1-encoded plaintext private key; as specified in RFC 5915
    ///
    /// Appears as "EC PRIVATE KEY" in PEM files.
    EcPrivateKey,

    /// A Certificate Revocation List; as specified in RFC 5280
    ///
    /// Appears as "X509 CRL" in PEM files.
    Crl,

    /// A Certificate Signing Request; as specified in RFC 2986
    ///
    /// Appears as "CERTIFICATE REQUEST" in PEM files.
    Csr,
}

impl SectionKind {
    fn secret(&self) -> bool {
        match self {
            Self::RsaPrivateKey | Self::PrivateKey | Self::EcPrivateKey => true,
            Self::Certificate | Self::PublicKey | Self::Crl | Self::Csr => false,
        }
    }

    fn item(&self, der: Vec<u8>) -> Item {
        match self {
            Self::Certificate => Item::X509Certificate(der.into()),
            Self::PublicKey => Item::SubjectPublicKeyInfo(der.into()),
            Self::RsaPrivateKey => Item::Pkcs1Key(der.into()),
            Self::PrivateKey => Item::Pkcs8Key(der.into()),
            Self::EcPrivateKey => Item::Sec1Key(der.into()),
            Self::Crl => Item::Crl(der.into()),
            Self::Csr => Item::Csr(der.into()),
        }
    }
}

impl TryFrom<&[u8]> for SectionKind {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(match value {
            b"CERTIFICATE" => Self::Certificate,
            b"PUBLIC KEY" => Self::PublicKey,
            b"RSA PRIVATE KEY" => Self::RsaPrivateKey,
            b"PRIVATE KEY" => Self::PrivateKey,
            b"EC PRIVATE KEY" => Self::EcPrivateKey,
            b"X509 CRL" => Self::Crl,
            b"CERTIFICATE REQUEST" => Self::Csr,
            _ => return Err(()),
        })
    }
}

/// Errors that may arise when parsing the contents of a PEM file
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// a section is missing its "END marker" line
    MissingSectionEnd {
        /// the expected "END marker" line that was not found
        end_marker: Vec<u8>,
    },

    /// syntax error found in the line that starts a new section
    IllegalSectionStart {
        /// line that contains the syntax error
        line: Vec<u8>,
    },

    /// base64 decode error
    Base64Decode(String),

    /// I/O errors, from APIs that accept `std::io` types.
    #[cfg(feature = "std")]
    Io(io::Error),
}

// Ported from https://github.com/rust-lang/rust/blob/91cfcb021935853caa06698b759c293c09d1e96a/library/std/src/io/mod.rs#L1990 and
// modified to look for our accepted newlines.
#[cfg(feature = "std")]
fn read_until_newline<R: io::BufRead + ?Sized>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut read = 0;
    loop {
        let (done, used) = {
            let available = match r.fill_buf() {
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            match available
                .iter()
                .copied()
                .position(|b| b == b'\n' || b == b'\r')
            {
                Some(i) => {
                    buf.extend_from_slice(&available[..=i]);
                    (true, i + 1)
                }
                None => {
                    buf.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        r.consume(used);
        read += used;
        if done || used == 0 {
            return Ok(read);
        }
    }
}

/// Extract and return all PEM sections by reading `rd`.
#[cfg(feature = "std")]
pub fn read_all(rd: &mut dyn io::BufRead) -> impl Iterator<Item = Result<Item, Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose())
}
