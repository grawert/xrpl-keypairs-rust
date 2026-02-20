//! Cryptographic key pairs for the XRP Ledger
//!
//! This crate is a fork of [`ripple-keypairs`](https://crates.io/crates/ripple-keypairs)
//! by [Stanislav Otovchits](https://github.com/otov4its), originally licensed under ISC.
//!
//! Original work Copyright (c) Stanislav Otovchits
//! Modified work Copyright (c) Uwe Grawert
//!
//! An implementation of XRP Ledger keypairs & wallet generation
//! which supports rfc6979 and eddsa deterministic signatures.
//!
//! # Examples
//!
//! ## Generate a random XRP Ledger address
//!
//! ```
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! #
//! use ripple_keypairs::Seed;
//!
//! let seed = Seed::random();
//! let (_, public_key) = seed.derive_keypair()?;
//! let address = public_key.derive_address();
//!
//! assert!(address.starts_with("r"));
//! #
//! # Ok(())
//! # }
//! ```
//!
//! ## Encode a seed in Base58 XRP Ledger format
//!
//! ```
//! use ripple_keypairs::{Seed, Entropy, Algorithm};
//!
//! let entropy = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
//! let seed = Seed::new(Entropy::Array(entropy), Algorithm::Secp256k1);
//!
//! assert_eq!(seed.to_string(), "sp5fghtJtpUorTwvof1NpDXAzNwf5");
//! ```
//!
//! ## Parse a string into a seed
//!
//! ```
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! #
//! use std::str::FromStr;
//! use ripple_keypairs::{Seed, error};
//!
//! let seed = Seed::from_str("sp5fghtJtpUorTwvof1NpDXAzNwf5")?;
//!
//! assert_eq!(seed, "sp5fghtJtpUorTwvof1NpDXAzNwf5".parse()?);
//! assert_eq!(Err(error::Error::DecodeError), "bad seed".parse::<Seed>());
//! #
//! # Ok(())
//! # }
//! ```

#![deny(
    warnings,
    clippy::all,
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs,
    non_ascii_idents,
    unreachable_pub
)]
#![doc(test(attr(deny(warnings))))]
#![doc(html_root_url = "https://docs.rs/xrpl-keypairs/0.2.0")]

use std::{
    convert::{TryFrom, TryInto},
    fmt,
    str::FromStr,
};

use getrandom::getrandom;

mod utils;

mod hexbytes;
pub use hexbytes::HexBytes;

mod algorithm;
use algorithm as alg;

pub mod error;
/// Result with error type
pub type KeyPairResult = error::Result<(PrivateKey, PublicKey)>;

pub use codec::{Algorithm, Entropy as EntropyArray};
use ripple_address_codec as codec;

use Algorithm::*;
use Entropy::*;

/// Entropy which is used to generate seed
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Entropy {
    /// Random entropy
    Random,
    /// An array of bytes
    Array(EntropyArray),
}

/// A seed that can be used to generate keypairs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed {
    entropy: EntropyArray,
    kind: Algorithm,
}

impl Seed {
    /// Generate a new seed
    pub fn new(entropy: Entropy, kind: Algorithm) -> Self {
        let entropy = match entropy {
            Array(entropy) => entropy,

            Random => {
                let mut entropy: EntropyArray = [0; 16];
                getrandom(&mut entropy).expect("unspecified random generator error");
                entropy
            }
        };

        Self { entropy, kind }
    }

    /// Generate a random seed (Defaults to Secp256k1)
    pub fn random() -> Self {
        Self::new(Random, Secp256k1)
    }

    /// Derive a public and private key from a seed
    pub fn derive_keypair(&self) -> KeyPairResult {
        let keypair = self.method().derive_keypair(self.as_entropy())?;

        /* additional safety check */
        {
            let test_message =
                utils::sha512_digest_32("This test message should verify".as_bytes());

            let (private_key, public_key) = &keypair;

            public_key
                .verify(&test_message, &private_key.sign(&test_message))
                .map_err(|_| error::Error::DeriveKeyPairError)?;
        }

        Ok(keypair)
    }

    /// Seed as [`EntropyArray`]
    pub fn as_entropy(&self) -> &EntropyArray {
        &self.entropy
    }

    /// Seed as [`Algorithm`]
    pub fn as_kind(&self) -> &Algorithm {
        &self.kind
    }

    fn method(&self) -> &'static dyn alg::Seed {
        match self.kind {
            Secp256k1 => &alg::secp256k1::SeedEcDsaSecP256K1,
            Ed25519 => &alg::ed25519::SeedEd25519,
        }
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.method().encode(&self.entropy))
    }
}

impl FromStr for Seed {
    type Err = error::Error;

    fn from_str(s: &str) -> error::Result<Self> {
        let (entropy, kind) = codec::decode_seed(s).map_err(|_| error::Error::DecodeError)?;
        Ok(Self::new(Array(entropy), *kind))
    }
}

impl AsRef<EntropyArray> for Seed {
    fn as_ref(&self) -> &EntropyArray {
        self.as_entropy()
    }
}

impl AsRef<Algorithm> for Seed {
    fn as_ref(&self) -> &Algorithm {
        self.as_kind()
    }
}

/// Signatures can be treated as bytes or as hex encoded strings.
pub trait Signature: AsRef<[u8]> + AsRef<str> + ToString + Into<Vec<u8>> {}

impl Signature for HexBytes {}

/// A private key that can be used to sign messages
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    bytes: Vec<u8>,
    kind: Algorithm,
}

impl PrivateKey {
    /// Sign message
    pub fn sign(&self, message: &impl AsRef<[u8]>) -> impl Signature {
        self.method()
            .sign(message.as_ref(), &self.method().as_bytes(&self.bytes))
    }

    /// Returns the algorithm type of this private key.
    pub fn kind(&self) -> Algorithm {
        self.kind
    }

    fn method(&self) -> &'static dyn alg::Sign {
        match self.kind {
            Secp256k1 => &alg::secp256k1::PrivateKeyEcDsaSecP256K1,
            Ed25519 => &alg::ed25519::PrivateKeyEd25519,
        }
    }

    /// Create a private key from raw bytes of the specified algorithm
    pub fn from_slice<S: AsRef<[u8]>>(bytes: S, kind: Algorithm) -> error::Result<Self> {
        let bytes = bytes.as_ref();

        if bytes.len() != 32 {
            return Err(error::Error::InvalidKeyLength);
        }

        Ok(PrivateKey {
            bytes: bytes.to_vec(),
            kind,
        })
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("hex", &self.to_string())
            .field("algorithm", &self.kind)
            .finish()
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.method()
                .encode_to_hex(&self.method().as_bytes(&self.bytes))
        )
    }
}

/// A public key that can be used to derive an address and verify signatures
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    bytes: Vec<u8>,
    kind: Algorithm,
}

impl PublicKey {
    /// Returns the algorithm type of this public key.
    pub fn kind(&self) -> Algorithm {
        self.kind
    }

    /// Verify a signature
    pub fn verify(
        &self,
        message: &impl AsRef<[u8]>,
        signature: &impl AsRef<[u8]>,
    ) -> error::Result<()> {
        self.method().verify(
            message.as_ref(),
            signature.as_ref(),
            &self.method().as_bytes(&self.bytes),
        )
    }

    /// Derive an XRP Ledger classic address
    pub fn derive_address(&self) -> String {
        let hex_str = self.to_string();
        let hex = HexBytes::from_hex_unchecked(&hex_str);
        let hash: [u8; 20] = utils::hash160(hex.as_bytes())[..20].try_into().unwrap();

        codec::encode_account_id(&hash)
    }

    fn method(&self) -> &'static dyn alg::Verify {
        match self.kind {
            Secp256k1 => &alg::secp256k1::PublicKeyEcDsaSecP256K1,
            Ed25519 => &alg::ed25519::PublicKeyEd25519,
        }
    }

    /// Create a public key from encoded bytes or raw Ed25519 bytes.
    ///
    /// This method supports two formats:
    /// 1. **XRPL Encoded (33 bytes):**
    ///    - Ed25519: Prefixed with `0xED`.
    ///    - Secp256k1: Prefixed with `0x02` or `0x03`.
    /// 2. **Raw Ed25519 (32 bytes):**
    ///    - Commonly returned by BIP-39/SLIP-10 derivation tools.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// #
    /// use ripple_keypairs::{PublicKey, Algorithm};
    ///
    /// // Standard XRPL hex (33 bytes)
    /// let key: PublicKey = "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435".parse()?;
    /// assert_eq!(key.kind(), Algorithm::Secp256k1);
    ///
    /// // Raw Ed25519 (32 bytes)
    /// let raw_bytes = [0u8; 32];
    /// let key = PublicKey::from_encoded_slice(&raw_bytes)?;
    /// assert_eq!(key.kind(), Algorithm::Ed25519);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::InvalidKeyLength`] if length is not 32 or 33.
    /// Returns [`error::Error::DecodeError`] if 33-byte prefix is unrecognized.
    pub fn from_encoded_slice<S: AsRef<[u8]>>(bytes: S) -> error::Result<Self> {
        let bytes = bytes.as_ref();

        match bytes.len() {
            33 => {
                let (algorithm, raw_bytes) = match bytes[0] {
                    0xED => (Ed25519, bytes[1..].to_vec()),
                    0x02 | 0x03 => (Secp256k1, bytes.to_vec()),
                    _ => return Err(error::Error::DecodeError),
                };

                Ok(PublicKey {
                    bytes: raw_bytes,
                    kind: algorithm,
                })
            }
            32 => {
                // If 32 bytes, treat as raw Ed25519 public key.
                Ok(PublicKey {
                    bytes: bytes.to_vec(),
                    kind: Ed25519,
                })
            }
            _ => Err(error::Error::InvalidKeyLength),
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("hex", &self.to_string())
            .field("algorithm", &self.kind)
            .finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.method()
                .encode_to_hex(&self.method().as_bytes(&self.bytes))
        )
    }
}

impl TryFrom<[u8; 33]> for PublicKey {
    type Error = error::Error;
    fn try_from(bytes: [u8; 33]) -> error::Result<Self> {
        Self::from_encoded_slice(&bytes)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = error::Error;
    fn try_from(bytes: &[u8]) -> error::Result<Self> {
        Self::from_encoded_slice(bytes)
    }
}

impl FromStr for PublicKey {
    type Err = error::Error;

    fn from_str(s: &str) -> error::Result<Self> {
        let bytes = hex::decode(s).map_err(|_| error::Error::DecodeError)?;
        Self::from_encoded_slice(&bytes)
    }
}
