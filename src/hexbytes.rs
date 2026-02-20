//! Utility for handling bytes that can be represented as hex strings.

use std::{fmt, str::FromStr};

use hex::{decode, encode_upper};

use crate::error;

/// The values of this type can be treated as bytes or as hex encoded strings
///
/// Mostly used for crate's internal purposes,
/// but can also be used as a hex encode/decode utility.
///
/// # Examples
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #
/// use ripple_keypairs::HexBytes;
///
/// let hexbytes = HexBytes::from_hex_unchecked("00");
///
/// assert_eq!(hexbytes.as_bytes(), &[0]);
/// assert_eq!(hexbytes.as_hex(), "00");
/// assert_eq!(hexbytes, HexBytes::from_bytes(&[0]));
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexBytes {
    bytes: Vec<u8>,
    hex_string: String,
}

impl HexBytes {
    /// Construct from raw bytes
    pub fn from_bytes(bytes: &impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        Self {
            bytes: bytes.to_owned(),
            hex_string: encode_upper(bytes),
        }
    }

    /// Construct from hex string
    ///
    /// # Panics
    ///
    /// Need a hex encoded string, panic otherwise.
    pub fn from_hex_unchecked(hex_string: &str) -> Self {
        Self::from_hex(hex_string).expect("need a hex encoded string")
    }

    /// Construct from hex string
    ///
    /// # Errors
    ///
    /// [`error::Error::DecodeError`] if a string is not hex encoded.
    pub fn from_hex(hex_string: &str) -> error::Result<Self> {
        let bytes = decode(hex_string).map_err(|_| error::Error::DecodeError)?;

        Ok(Self {
            bytes,
            // We normalize to uppercase to ensure equality checks match
            // regardless of input casing.
            hex_string: hex_string.to_uppercase(),
        })
    }

    /// Treat as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Treat as a hex encoded string
    pub fn as_hex(&self) -> &str {
        &self.hex_string
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl From<&[u8]> for HexBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(&bytes)
    }
}

impl FromStr for HexBytes {
    type Err = error::Error;

    fn from_str(s: &str) -> error::Result<Self> {
        Self::from_hex(s)
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for HexBytes {
    fn as_ref(&self) -> &str {
        self.as_hex()
    }
}

impl From<HexBytes> for Vec<u8> {
    fn from(hex_bytes: HexBytes) -> Self {
        hex_bytes.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes() {
        assert_eq!(HexBytes::from_hex("000000").unwrap().as_bytes(), &[0, 0, 0]);
    }

    #[test]
    fn bytes_to_hex() {
        assert_eq!(
            HexBytes::from_bytes(&[222, 173, 190, 239]).to_string(),
            "DEADBEEF"
        );
    }

    #[test]
    fn bytes_into_hex_bytes() {
        let hex: HexBytes = [222, 173, 190, 239].as_ref().into();

        assert_eq!(hex.as_bytes(), &[222, 173, 190, 239]);
        assert_eq!(hex.as_hex(), "DEADBEEF");
    }

    #[test]
    fn parse() {
        let hex = "00".parse::<HexBytes>().unwrap();

        assert_eq!(hex.as_hex(), "00");
        assert_eq!(hex.as_bytes(), &[0]);
    }

    #[test]
    fn empty_bytes() {
        let hex = HexBytes::from_bytes(&[]);

        assert_eq!(hex.as_bytes(), &[]);
        assert_eq!(hex.as_hex(), "");
    }

    #[test]
    fn empty_hex_string() {
        let hex = HexBytes::from_hex_unchecked("");

        assert_eq!(hex.as_bytes(), &[]);
        assert_eq!(hex.as_hex(), "");
    }
}
