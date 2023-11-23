//! DNS name validation according to RFC1035, but with underscores allowed.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::hash::{Hash, Hasher};
use core::{fmt, str};
#[cfg(feature = "std")]
use std::error::Error as StdError;
#[cfg(feature = "std")]
use std::net::IpAddr;

/// Encodes ways a client can know the expected name of the server.
///
/// This currently covers knowing the DNS name of the server, but
/// will be extended in the future to supporting privacy-preserving names
/// for the server ("ECH").  For this reason this enum is `non_exhaustive`.
///
/// # Making one
///
/// If you have a DNS name as a `&str`, this type implements `TryFrom<&str>`,
/// so you can do:
///
/// ```
/// # use rustls_pki_types::ServerName;
/// ServerName::try_from("example.com").expect("invalid DNS name");
///
/// // or, alternatively...
///
/// let x = "example.com".try_into().expect("invalid DNS name");
/// # let _: ServerName = x;
/// ```
#[non_exhaustive]
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum ServerName<'a> {
    /// The server is identified by a DNS name.  The name
    /// is sent in the TLS Server Name Indication (SNI)
    /// extension.
    DnsName(DnsName<'a>),

    /// The server is identified by an IP address. SNI is not
    /// done.
    #[cfg(feature = "std")]
    IpAddress(IpAddr),
}

impl<'a> ServerName<'a> {
    /// Produce an owned `ServerName` from this (potentially borrowed) `ServerName`.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> ServerName<'static> {
        match self {
            Self::DnsName(d) => ServerName::DnsName(d.to_owned()),
            Self::IpAddress(i) => ServerName::IpAddress(*i),
        }
    }
}

impl<'a> fmt::Debug for ServerName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DnsName(d) => f.debug_tuple("DnsName").field(&d.as_ref()).finish(),
            #[cfg(feature = "std")]
            Self::IpAddress(i) => f.debug_tuple("IpAddress").field(i).finish(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ServerName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match str::from_utf8(value) {
            Ok(s) => Self::try_from(s),
            Err(_) => Err(InvalidDnsNameError),
        }
    }
}

/// Attempt to make a ServerName from a string by parsing as a DNS name or IP address.
impl<'a> TryFrom<&'a str> for ServerName<'a> {
    type Error = InvalidDnsNameError;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        match DnsName::try_from(s) {
            Ok(dns) => Ok(Self::DnsName(dns)),
            #[cfg(feature = "std")]
            Err(InvalidDnsNameError) => match s.parse() {
                Ok(ip) => Ok(Self::IpAddress(ip)),
                Err(_) => Err(InvalidDnsNameError),
            },
            #[cfg(not(feature = "std"))]
            Err(InvalidDnsNameError) => Err(InvalidDnsNameError),
        }
    }
}

/// A type which encapsulates a string (borrowed or owned) that is a syntactically valid DNS name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsName<'a>(DnsNameInner<'a>);

impl<'a> DnsName<'a> {
    /// Produce a borrowed `DnsName` from this owned `DnsName`.
    pub fn borrow(&'a self) -> DnsName<'_> {
        Self(match self {
            Self(DnsNameInner::Borrowed(s)) => DnsNameInner::Borrowed(s),
            #[cfg(feature = "alloc")]
            Self(DnsNameInner::Owned(s)) => DnsNameInner::Borrowed(s.as_str()),
        })
    }

    /// Copy this object to produce an owned `DnsName`, smashing the case to lowercase
    /// in one operation.
    #[cfg(feature = "alloc")]
    pub fn to_lowercase_owned(&self) -> DnsName<'static> {
        DnsName(DnsNameInner::Owned(self.as_ref().to_ascii_lowercase()))
    }

    /// Produce an owned `DnsName` from this (potentially borrowed) `DnsName`.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> DnsName<'static> {
        DnsName(DnsNameInner::Owned(match self {
            Self(DnsNameInner::Borrowed(s)) => s.to_string(),
            #[cfg(feature = "alloc")]
            Self(DnsNameInner::Owned(s)) => s.clone(),
        }))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<String> for DnsName<'static> {
    type Error = InvalidDnsNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate(value.as_bytes())?;
        Ok(Self(DnsNameInner::Owned(value)))
    }
}

impl<'a> TryFrom<&'a str> for DnsName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(value: &'a str) -> Result<DnsName<'a>, Self::Error> {
        validate(value.as_bytes())?;
        Ok(Self(DnsNameInner::Borrowed(value)))
    }
}

impl<'a> TryFrom<&'a [u8]> for DnsName<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(value: &'a [u8]) -> Result<DnsName<'a>, Self::Error> {
        validate(value)?;
        Ok(Self(DnsNameInner::Borrowed(str::from_utf8(value).unwrap())))
    }
}

impl<'a> AsRef<str> for DnsName<'a> {
    fn as_ref(&self) -> &str {
        match self {
            Self(DnsNameInner::Borrowed(s)) => s,
            #[cfg(feature = "alloc")]
            Self(DnsNameInner::Owned(s)) => s.as_str(),
        }
    }
}

#[derive(Clone, Eq)]
enum DnsNameInner<'a> {
    Borrowed(&'a str),
    #[cfg(feature = "alloc")]
    Owned(String),
}

impl<'a> PartialEq<DnsNameInner<'a>> for DnsNameInner<'a> {
    fn eq(&self, other: &DnsNameInner<'a>) -> bool {
        match (self, other) {
            (Self::Borrowed(s), Self::Borrowed(o)) => s.eq_ignore_ascii_case(o),
            #[cfg(feature = "alloc")]
            (Self::Borrowed(s), Self::Owned(o)) => s.eq_ignore_ascii_case(o.as_str()),
            #[cfg(feature = "alloc")]
            (Self::Owned(s), Self::Borrowed(o)) => s.eq_ignore_ascii_case(o),
            #[cfg(feature = "alloc")]
            (Self::Owned(s), Self::Owned(o)) => s.eq_ignore_ascii_case(o.as_str()),
        }
    }
}

impl<'a> Hash for DnsNameInner<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let s = match self {
            Self::Borrowed(s) => s,
            #[cfg(feature = "alloc")]
            Self::Owned(s) => s.as_str(),
        };

        s.chars().for_each(|c| c.to_ascii_lowercase().hash(state));
    }
}

impl<'a> fmt::Debug for DnsNameInner<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Borrowed(s) => f.write_fmt(format_args!("{:?}", s)),
            #[cfg(feature = "alloc")]
            Self::Owned(s) => f.write_fmt(format_args!("{:?}", s)),
        }
    }
}

/// The provided input could not be parsed because
/// it is not a syntactically-valid DNS Name.
#[derive(Debug)]
pub struct InvalidDnsNameError;

impl fmt::Display for InvalidDnsNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid dns name")
    }
}

#[cfg(feature = "std")]
impl StdError for InvalidDnsNameError {}

fn validate(input: &[u8]) -> Result<(), InvalidDnsNameError> {
    use State::*;
    let mut state = Start;

    /// "Labels must be 63 characters or less."
    const MAX_LABEL_LENGTH: usize = 63;

    /// https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
    const MAX_NAME_LENGTH: usize = 253;

    if input.len() > MAX_NAME_LENGTH {
        return Err(InvalidDnsNameError);
    }

    for ch in input {
        state = match (state, ch) {
            (Start | Next | NextAfterNumericOnly | Hyphen { .. }, b'.') => {
                return Err(InvalidDnsNameError)
            }
            (Subsequent { .. }, b'.') => Next,
            (NumericOnly { .. }, b'.') => NextAfterNumericOnly,
            (Subsequent { len } | NumericOnly { len } | Hyphen { len }, _)
                if len >= MAX_LABEL_LENGTH =>
            {
                return Err(InvalidDnsNameError)
            }
            (Start | Next | NextAfterNumericOnly, b'0'..=b'9') => NumericOnly { len: 1 },
            (NumericOnly { len }, b'0'..=b'9') => NumericOnly { len: len + 1 },
            (Start | Next | NextAfterNumericOnly, b'a'..=b'z' | b'A'..=b'Z' | b'_') => {
                Subsequent { len: 1 }
            }
            (Subsequent { len } | NumericOnly { len } | Hyphen { len }, b'-') => {
                Hyphen { len: len + 1 }
            }
            (
                Subsequent { len } | NumericOnly { len } | Hyphen { len },
                b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9',
            ) => Subsequent { len: len + 1 },
            _ => return Err(InvalidDnsNameError),
        };
    }

    if matches!(
        state,
        Start | Hyphen { .. } | NumericOnly { .. } | NextAfterNumericOnly
    ) {
        return Err(InvalidDnsNameError);
    }

    Ok(())
}

enum State {
    Start,
    Next,
    NumericOnly { len: usize },
    NextAfterNumericOnly,
    Subsequent { len: usize },
    Hyphen { len: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::format;

    #[cfg(feature = "alloc")]
    static TESTS: &[(&str, bool)] = &[
        ("", false),
        ("localhost", true),
        ("LOCALHOST", true),
        (".localhost", false),
        ("..localhost", false),
        ("1.2.3.4", false),
        ("127.0.0.1", false),
        ("absolute.", true),
        ("absolute..", false),
        ("multiple.labels.absolute.", true),
        ("foo.bar.com", true),
        ("infix-hyphen-allowed.com", true),
        ("-prefixhypheninvalid.com", false),
        ("suffixhypheninvalid--", false),
        ("suffixhypheninvalid-.com", false),
        ("foo.lastlabelendswithhyphen-", false),
        ("infix_underscore_allowed.com", true),
        ("_prefixunderscorevalid.com", true),
        ("labelendswithnumber1.bar.com", true),
        ("xn--bcher-kva.example", true),
        (
            "sixtythreesixtythreesixtythreesixtythreesixtythreesixtythreesix.com",
            true,
        ),
        (
            "sixtyfoursixtyfoursixtyfoursixtyfoursixtyfoursixtyfoursixtyfours.com",
            false,
        ),
        (
            "012345678901234567890123456789012345678901234567890123456789012.com",
            true,
        ),
        (
            "0123456789012345678901234567890123456789012345678901234567890123.com",
            false,
        ),
        (
            "01234567890123456789012345678901234567890123456789012345678901-.com",
            false,
        ),
        (
            "012345678901234567890123456789012345678901234567890123456789012-.com",
            false,
        ),
        ("numeric-only-final-label.1", false),
        ("numeric-only-final-label.absolute.1.", false),
        ("1starts-with-number.com", true),
        ("1Starts-with-number.com", true),
        ("1.2.3.4.com", true),
        ("123.numeric-only-first-label", true),
        ("a123b.com", true),
        ("numeric-only-middle-label.4.com", true),
        ("1000-sans.badssl.com", true),
        ("twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfi", true),
        ("twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourc", false),
    ];

    #[cfg(feature = "alloc")]
    #[test]
    fn test_validation() {
        for (input, expected) in TESTS {
            #[cfg(feature = "std")]
            println!("test: {:?} expected valid? {:?}", input, expected);
            let name_ref = DnsName::try_from(*input);
            assert_eq!(*expected, name_ref.is_ok());
            let name = DnsName::try_from(input.to_string());
            assert_eq!(*expected, name.is_ok());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn error_is_debug() {
        assert_eq!(format!("{:?}", InvalidDnsNameError), "InvalidDnsNameError");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn error_is_display() {
        assert_eq!(format!("{}", InvalidDnsNameError), "invalid dns name");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dns_name_is_debug() {
        let example = DnsName::try_from("example.com".to_string()).unwrap();
        assert_eq!(format!("{:?}", example), "DnsName(\"example.com\")");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dns_name_traits() {
        let example = DnsName::try_from("example.com".to_string()).unwrap();
        assert_eq!(example, example); // PartialEq

        #[cfg(feature = "std")]
        {
            use std::collections::HashSet;
            let mut h = HashSet::<DnsName>::new();
            h.insert(example);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn try_from_ascii_rejects_bad_utf8() {
        assert_eq!(
            format!("{:?}", DnsName::try_from(&b"\x80"[..])),
            "Err(InvalidDnsNameError)"
        );
    }
}
