//! DNS name validation according to RFC1035, but with underscores allowed.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::hash::{Hash, Hasher};
use core::{fmt, str};
#[cfg(feature = "std")]
use std::error::Error as StdError;

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
            Err(InvalidDnsNameError) => match IpAddr::try_from(s) {
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
    enum State {
        Start,
        Next,
        NumericOnly { len: usize },
        NextAfterNumericOnly,
        Subsequent { len: usize },
        Hyphen { len: usize },
    }

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

/// `no_std` implementation of `std::net::IpAddr`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpAddr {
    /// An Ipv4 address.
    V4(Ipv4Addr),
    /// An Ipv6 address.
    V6(Ipv6Addr),
}

impl TryFrom<&str> for IpAddr {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match Ipv4Addr::try_from(value) {
            Ok(v4) => Ok(Self::V4(v4)),
            Err(_) => match Ipv6Addr::try_from(value) {
                Ok(v6) => Ok(Self::V6(v6)),
                Err(e) => Err(e),
            },
        }
    }
}

#[cfg(feature = "std")]
impl From<std::net::IpAddr> for IpAddr {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => Self::V4(v4.into()),
            std::net::IpAddr::V6(v6) => Self::V6(v6.into()),
        }
    }
}

/// `no_std` implementation of `std::net::Ipv4Addr`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Addr([u8; 4]);

impl TryFrom<&str> for Ipv4Addr {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut is_first_byte = true;
        let mut current_octet: [u8; 3] = [0, 0, 0];
        let mut current_size = 0;
        let mut dot_count = 0;

        let mut octet = 0;
        let mut octets: [u8; 4] = [0, 0, 0, 0];

        // Returns a u32 so it's possible to identify (and error) when
        // provided textual octets > 255, not representable by u8.
        fn radix10_to_octet(textual_octets: &[u8]) -> u32 {
            let mut result: u32 = 0;
            for digit in textual_octets.iter() {
                result *= 10;
                result += u32::from(*digit);
            }
            result
        }

        for (i, &b) in value.as_bytes().iter().enumerate() {
            match b {
                b'.' => {
                    if is_first_byte {
                        // IPv4 address cannot start with a dot.
                        return Err(AddrParseError);
                    }
                    if i == value.len() - 1 {
                        // IPv4 address cannot end with a dot.
                        return Err(AddrParseError);
                    }
                    if dot_count == 3 {
                        // IPv4 address cannot have more than three dots.
                        return Err(AddrParseError);
                    }
                    dot_count += 1;
                    if current_size == 0 {
                        // IPv4 address cannot contain two dots in a row.
                        return Err(AddrParseError);
                    }
                    let current_raw_octet = radix10_to_octet(&current_octet[..current_size]);
                    if current_raw_octet > 255 {
                        // No octet can be greater than 255.
                        return Err(AddrParseError);
                    }
                    octets[octet] =
                        TryInto::<u8>::try_into(current_raw_octet).expect("invalid character");
                    octet += 1;
                    // We move on to the next textual octet.
                    current_octet = [0, 0, 0];
                    current_size = 0;
                }
                number @ b'0'..=b'9' => {
                    if number == b'0'
                        && current_size == 0
                        && value.as_bytes().get(i + 1) != Some(&b'.')
                        && i != value.len() - 1
                    {
                        // No octet can start with 0 if a dot does not follow and if we are not at the end.
                        return Err(AddrParseError);
                    }
                    if current_size >= current_octet.len() {
                        // More than 3 octets in a triple
                        return Err(AddrParseError);
                    }
                    current_octet[current_size] = number - b'0';
                    current_size += 1;
                }
                _ => {
                    return Err(AddrParseError);
                }
            }

            is_first_byte = false;
        }

        let last_octet = radix10_to_octet(&current_octet[..current_size]);
        if current_size > 0 && last_octet > 255 {
            // No octet can be greater than 255.
            return Err(AddrParseError);
        }
        octets[octet] = TryInto::<u8>::try_into(last_octet).expect("invalid character");

        if dot_count != 3 {
            return Err(AddrParseError);
        }

        Ok(Ipv4Addr(octets))
    }
}

#[cfg(feature = "std")]
impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self(addr.octets())
    }
}

impl AsRef<[u8; 4]> for Ipv4Addr {
    fn as_ref(&self) -> &[u8; 4] {
        &self.0
    }
}

/// `no_std` implementation of `std::net::Ipv6Addr`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv6Addr([u8; 16]);

impl TryFrom<&str> for Ipv6Addr {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Compressed addresses are not supported. Also, IPv4-mapped IPv6
        // addresses are not supported. This makes 8 groups of 4
        // hexadecimal characters + 7 colons.
        if value.len() != 39 {
            return Err(AddrParseError);
        }

        let mut is_first_byte = true;
        let mut current_textual_block_size = 0;
        let mut colon_count = 0;

        let mut octet = 0;
        let mut previous_character = None;
        let mut octets: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        for (i, &b) in value.as_bytes().iter().enumerate() {
            match b {
                b':' => {
                    if is_first_byte {
                        // Uncompressed IPv6 address cannot start with a colon.
                        return Err(AddrParseError);
                    }
                    if i == value.len() - 1 {
                        // Uncompressed IPv6 address cannot end with a colon.
                        return Err(AddrParseError);
                    }
                    if colon_count == 7 {
                        // IPv6 address cannot have more than seven colons.
                        return Err(AddrParseError);
                    }
                    colon_count += 1;
                    if current_textual_block_size == 0 {
                        // Uncompressed IPv6 address cannot contain two colons in a row.
                        return Err(AddrParseError);
                    }
                    if current_textual_block_size != 4 {
                        // Compressed IPv6 addresses are not supported.
                        return Err(AddrParseError);
                    }
                    // We move on to the next textual block.
                    current_textual_block_size = 0;
                    previous_character = None;
                }
                character @ b'0'..=b'9' | character @ b'a'..=b'f' | character @ b'A'..=b'F' => {
                    if current_textual_block_size == 4 {
                        // Blocks cannot contain more than 4 hexadecimal characters.
                        return Err(AddrParseError);
                    }
                    if let Some(previous_character_) = previous_character {
                        octets[octet] = (TryInto::<u8>::try_into(
                            TryInto::<u8>::try_into(
                                (TryInto::<char>::try_into(previous_character_)
                                    .expect("invalid character"))
                                .to_digit(16)
                                // Safe to unwrap because we know character is within hexadecimal bounds ([0-9a-f])
                                .unwrap(),
                            )
                            .expect("invalid character"),
                        )
                        .expect("invalid character")
                            << 4)
                            | (TryInto::<u8>::try_into(
                                TryInto::<char>::try_into(character)
                                    .expect("invalid character")
                                    .to_digit(16)
                                    // Safe to unwrap because we know character is within hexadecimal bounds ([0-9a-f])
                                    .unwrap(),
                            )
                            .expect("invalid character"));
                        previous_character = None;
                        octet += 1;
                    } else {
                        previous_character = Some(character);
                    }
                    current_textual_block_size += 1;
                }
                _ => {
                    return Err(AddrParseError);
                }
            }

            is_first_byte = false;
        }

        if colon_count != 7 {
            return Err(AddrParseError);
        }

        Ok(Ipv6Addr(octets))
    }
}

#[cfg(feature = "std")]
impl From<std::net::Ipv6Addr> for Ipv6Addr {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self(addr.octets())
    }
}

impl AsRef<[u8; 16]> for Ipv6Addr {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

/// An error indicating that an `IpAddrRef` could not built because
/// the input could not be parsed as an IP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddrParseError;

impl core::fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for AddrParseError {}

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

    const fn ipv4_address(
        ip_address: &str,
        octets: [u8; 4],
    ) -> (&str, Result<Ipv4Addr, AddrParseError>) {
        (ip_address, Ok(Ipv4Addr(octets)))
    }

    const IPV4_ADDRESSES: &[(&str, Result<Ipv4Addr, AddrParseError>)] = &[
        // Valid IPv4 addresses
        ipv4_address("0.0.0.0", [0, 0, 0, 0]),
        ipv4_address("1.1.1.1", [1, 1, 1, 1]),
        ipv4_address("205.0.0.0", [205, 0, 0, 0]),
        ipv4_address("0.205.0.0", [0, 205, 0, 0]),
        ipv4_address("0.0.205.0", [0, 0, 205, 0]),
        ipv4_address("0.0.0.205", [0, 0, 0, 205]),
        ipv4_address("0.0.0.20", [0, 0, 0, 20]),
        // Invalid IPv4 addresses
        ("", Err(AddrParseError)),
        ("...", Err(AddrParseError)),
        (".0.0.0.0", Err(AddrParseError)),
        ("0.0.0.0.", Err(AddrParseError)),
        ("0.0.0", Err(AddrParseError)),
        ("0.0.0.", Err(AddrParseError)),
        ("256.0.0.0", Err(AddrParseError)),
        ("0.256.0.0", Err(AddrParseError)),
        ("0.0.256.0", Err(AddrParseError)),
        ("0.0.0.256", Err(AddrParseError)),
        ("1..1.1.1", Err(AddrParseError)),
        ("1.1..1.1", Err(AddrParseError)),
        ("1.1.1..1", Err(AddrParseError)),
        ("025.0.0.0", Err(AddrParseError)),
        ("0.025.0.0", Err(AddrParseError)),
        ("0.0.025.0", Err(AddrParseError)),
        ("0.0.0.025", Err(AddrParseError)),
        ("1234.0.0.0", Err(AddrParseError)),
        ("0.1234.0.0", Err(AddrParseError)),
        ("0.0.1234.0", Err(AddrParseError)),
        ("0.0.0.1234", Err(AddrParseError)),
    ];

    #[test]
    fn parse_ipv4_address_test() {
        for &(ip_address, expected_result) in IPV4_ADDRESSES {
            assert_eq!(Ipv4Addr::try_from(ip_address), expected_result);
        }
    }

    const fn ipv6_address(
        ip_address: &str,
        octets: [u8; 16],
    ) -> (&str, Result<Ipv6Addr, AddrParseError>) {
        (ip_address, Ok(Ipv6Addr(octets)))
    }

    const IPV6_ADDRESSES: &[(&str, Result<Ipv6Addr, AddrParseError>)] = &[
        // Valid IPv6 addresses
        ipv6_address(
            "2a05:d018:076c:b685:e8ab:afd3:af51:3aed",
            [
                0x2a, 0x05, 0xd0, 0x18, 0x07, 0x6c, 0xb6, 0x85, 0xe8, 0xab, 0xaf, 0xd3, 0xaf, 0x51,
                0x3a, 0xed,
            ],
        ),
        ipv6_address(
            "2A05:D018:076C:B685:E8AB:AFD3:AF51:3AED",
            [
                0x2a, 0x05, 0xd0, 0x18, 0x07, 0x6c, 0xb6, 0x85, 0xe8, 0xab, 0xaf, 0xd3, 0xaf, 0x51,
                0x3a, 0xed,
            ],
        ),
        ipv6_address(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ],
        ),
        ipv6_address(
            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ],
        ),
        ipv6_address(
            "FFFF:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ],
        ),
        // Invalid IPv6 addresses
        // Missing octets on uncompressed addresses. The unmatching letter has the violation
        (
            "aaa:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:aaa:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:aaa:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:aaa:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:aaa:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:aaa:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:aaa:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:aaa",
            Err(AddrParseError),
        ),
        // Wrong hexadecimal characters on different positions
        (
            "ffgf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:gfff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:fffg:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffgf:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:gfff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:fgff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffgf:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffgf:fffg",
            Err(AddrParseError),
        ),
        // Wrong colons on uncompressed addresses
        (
            ":ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff::ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff::ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff::ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff::ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff::ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff::ffff:ffff",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff::ffff",
            Err(AddrParseError),
        ),
        // More colons than allowed
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:",
            Err(AddrParseError),
        ),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Err(AddrParseError),
        ),
        // v Invalid hexadecimal
        (
            "ga05:d018:076c:b685:e8ab:afd3:af51:3aed",
            Err(AddrParseError),
        ),
        // Cannot start with colon
        (
            ":a05:d018:076c:b685:e8ab:afd3:af51:3aed",
            Err(AddrParseError),
        ),
        // Cannot end with colon
        (
            "2a05:d018:076c:b685:e8ab:afd3:af51:3ae:",
            Err(AddrParseError),
        ),
        // Cannot have more than seven colons
        (
            "2a05:d018:076c:b685:e8ab:afd3:af51:3a::",
            Err(AddrParseError),
        ),
        // Cannot contain two colons in a row
        (
            "2a05::018:076c:b685:e8ab:afd3:af51:3aed",
            Err(AddrParseError),
        ),
        // v Textual block size is longer
        (
            "2a056:d018:076c:b685:e8ab:afd3:af51:3ae",
            Err(AddrParseError),
        ),
        // v Textual block size is shorter
        (
            "2a0:d018:076c:b685:e8ab:afd3:af51:3aed ",
            Err(AddrParseError),
        ),
        // Shorter IPv6 address
        ("d018:076c:b685:e8ab:afd3:af51:3aed", Err(AddrParseError)),
        // Longer IPv6 address
        (
            "2a05:d018:076c:b685:e8ab:afd3:af51:3aed3aed",
            Err(AddrParseError),
        ),
        // These are valid IPv6 addresses, but we don't support compressed addresses
        ("0:0:0:0:0:0:0:1", Err(AddrParseError)),
        (
            "2a05:d018:76c:b685:e8ab:afd3:af51:3aed",
            Err(AddrParseError),
        ),
    ];

    #[test]
    fn parse_ipv6_address_test() {
        for &(ip_address, expected_result) in IPV6_ADDRESSES {
            assert_eq!(Ipv6Addr::try_from(ip_address), expected_result);
        }
    }

    #[test]
    fn try_from_ascii_ip_address_test() {
        const IP_ADDRESSES: &[(&str, Result<IpAddr, AddrParseError>)] = &[
            // Valid IPv4 addresses
            ("127.0.0.1", Ok(IpAddr::V4(Ipv4Addr([127, 0, 0, 1])))),
            // Invalid IPv4 addresses
            (
                // Ends with a dot; misses one octet
                "127.0.0.",
                Err(AddrParseError),
            ),
            // Valid IPv6 addresses
            (
                "0000:0000:0000:0000:0000:0000:0000:0001",
                Ok(IpAddr::V6(Ipv6Addr([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]))),
            ),
            // Invalid IPv6 addresses
            (
                // IPv6 addresses in compressed form are not supported
                "0:0:0:0:0:0:0:1",
                Err(AddrParseError),
            ),
            // Something else
            (
                // A hostname
                "example.com",
                Err(AddrParseError),
            ),
        ];
        for &(ip_address, expected_result) in IP_ADDRESSES {
            assert_eq!(IpAddr::try_from(ip_address), expected_result)
        }
    }

    #[test]
    fn try_from_ascii_str_ip_address_test() {
        const IP_ADDRESSES: &[(&str, Result<IpAddr, AddrParseError>)] = &[
            // Valid IPv4 addresses
            ("127.0.0.1", Ok(IpAddr::V4(Ipv4Addr([127, 0, 0, 1])))),
            // Invalid IPv4 addresses
            (
                // Ends with a dot; misses one octet
                "127.0.0.",
                Err(AddrParseError),
            ),
            // Valid IPv6 addresses
            (
                "0000:0000:0000:0000:0000:0000:0000:0001",
                Ok(IpAddr::V6(Ipv6Addr([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]))),
            ),
            // Invalid IPv6 addresses
            (
                // IPv6 addresses in compressed form are not supported
                "0:0:0:0:0:0:0:1",
                Err(AddrParseError),
            ),
            // Something else
            (
                // A hostname
                "example.com",
                Err(AddrParseError),
            ),
        ];
        for &(ip_address, expected_result) in IP_ADDRESSES {
            assert_eq!(IpAddr::try_from(ip_address), expected_result)
        }
    }
}
