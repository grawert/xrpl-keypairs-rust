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
//! assert_eq!(Err(error::DecodeError), "bad seed".parse::<Seed>());
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
    rustdoc::missing_doc_code_examples,
    non_ascii_idents,
    unreachable_pub
)]
#![doc(test(attr(deny(warnings))))]
#![doc(html_root_url = "https://docs.rs/ripple-keypairs/0.2.0")]

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
type KeyPairResult = error::Result<(PrivateKey, PublicKey)>;

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
///
/// # Examples
///
/// ## Generate a new seed
///
/// ```
/// use ripple_keypairs::{Seed, Entropy, Algorithm};
///
/// let seed = Seed::new(Entropy::Random, Algorithm::Secp256k1);
///
/// assert!(seed.to_string().starts_with("s"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed {
    entropy: EntropyArray,
    kind: Algorithm,
}

impl Seed {
    /// Generate a new seed
    ///
    /// # Examples
    ///
    /// ```
    /// use ripple_keypairs::{Seed, Entropy, Algorithm};
    ///
    /// let seed_secp256k1 = Seed::new(Entropy::Random, Algorithm::Secp256k1);
    ///
    /// assert!(seed_secp256k1.to_string().starts_with("s"));
    /// assert_eq!(seed_secp256k1.as_kind(), &Algorithm::Secp256k1);
    ///
    /// let seed_ed25519 = Seed::new(Entropy::Random, Algorithm::Ed25519);
    ///
    /// assert!(seed_ed25519.to_string().starts_with("s"));
    /// assert_eq!(seed_ed25519.as_kind(), &Algorithm::Ed25519);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics only if something goes wrong with the random generator
    /// when using the [`Entropy::Random`] parameter.
    pub fn new(entropy: Entropy, kind: Algorithm) -> Self {
        let entropy = match entropy {
            Array(entropy) => entropy,

            Random => {
                let mut entropy: EntropyArray = [0; 16];

                getrandom(&mut entropy)
    .expect("unspecified random generator error");

                entropy
            }
        };

        Self { entropy, kind }
    }

    /// Generate a random seed
    ///
    /// The algorithm defaults to Secp256k1.
    ///
    /// # Examples
    ///
    /// ```
    /// use ripple_keypairs::{Seed, Algorithm};
    ///
    /// let seed = Seed::random();
    ///
    /// assert_eq!(seed.as_kind(), &Algorithm::Secp256k1);
    /// assert_ne!(Seed::random(), Seed::random());
    /// ```
    pub fn random() -> Self {
        Self::new(Random, Secp256k1)
    }

    /// Derive a public and private key from a seed
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// #
    /// use ripple_keypairs::Seed;
    ///
    /// let seed = Seed::random();
    /// let (private_key, public_key) = seed.derive_keypair()?;
    /// let msg = "Test message";
    ///
    /// assert_eq!(public_key.verify(&msg, &private_key.sign(&msg)), Ok(()));
    /// #
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// May return [`error::DeriveKeyPairError`] if the derived keypair
    /// did not generate a verifiable signature
    pub fn derive_keypair(&self) -> KeyPairResult {
        let keypair = self.method().derive_keypair(self.as_entropy())?;

        /* additional safety check */
        {
            let test_message =
                utils::sha512_digest_32("This test message should verify".as_bytes());

            let (private_key, public_key) = &keypair;

            public_key
                .verify(&test_message, &private_key.sign(&test_message))
                .map_err(|_| error::DeriveKeyPairError)?;
        }

        Ok(keypair)
    }

    /// Seed as [`EntropyArray`]
    ///
    /// # Examples
    /// ```
    /// use ripple_keypairs::{Seed, Entropy, Algorithm, EntropyArray};
    ///
    /// let seed = Seed::new(Entropy::Array([0; 16]), Algorithm::Secp256k1);
    ///
    /// assert_eq!(seed.as_entropy(), &[0; 16]);
    /// assert_eq!(seed.as_entropy(), <Seed as AsRef<EntropyArray>>::as_ref(&seed));
    /// ```
    ///
    /// # Traits
    ///
    /// This method is used in [`AsRef`] trait.
    pub fn as_entropy(&self) -> &EntropyArray {
        &self.entropy
    }

    /// Seed as [`Algorithm`]
    ///
    /// # Examples
    /// ```
    /// use ripple_keypairs::{Seed, Entropy, Algorithm};
    ///
    /// let seed = Seed::new(Entropy::Random, Algorithm::Ed25519);
    ///
    /// assert_eq!(seed.as_kind(), &Algorithm::Ed25519);
    /// assert_eq!(seed.as_kind(), <Seed as AsRef<Algorithm>>::as_ref(&seed));
    /// ```
    ///
    /// # Traits
    ///
    /// This method is used in [`AsRef`] trait.
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
        let (entropy, kind) = codec::decode_seed(s).map_err(|_| error::DecodeError)?;

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
///
/// # Examples
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #
/// use ripple_keypairs::Seed;
///
/// let seed = "sp5fghtJtpUorTwvof1NpDXAzNwf5".parse::<Seed>()?;
///
/// let (private_key, _) = seed.derive_keypair()?;
///
/// let signature = private_key.sign(&"test message");
///
/// assert_eq!(signature.to_string(), "30440220583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE02207D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D");
/// assert_eq!(signature.into(), vec![48, 68, 2, 32, 88, 58, 145, 201, 94, 84, 230, 166, 81, 196, 123, 236, 34, 116, 78, 11, 16, 30, 44, 64, 96, 231, 176, 143, 99, 65, 101, 125, 173, 155, 195, 238, 2, 32, 125, 20, 137, 199, 57, 93, 176, 24, 141, 58, 86, 169, 119, 236, 186, 84, 179, 111, 169, 55, 27, 64, 49, 150, 85, 177, 180, 66, 158, 51, 239, 45]);
///
/// assert_eq!(private_key.to_string(), "00D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23");
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PrivateKey {
    bytes: Vec<u8>,
    kind: Algorithm,
}

impl PrivateKey {
    /// Sign message
    ///
    /// Returns the [`Signature`] which that can be treated
    /// as bytes or as a hex encoded string.
    pub fn sign(&self, message: &impl AsRef<[u8]>) -> impl Signature {
        self.method()
            .sign(message.as_ref(), &self.method().as_bytes(&self.bytes))
    }

    fn method(&self) -> &'static dyn alg::Sign {
        match self.kind {
            Secp256k1 => &alg::secp256k1::PrivateKeyEcDsaSecP256K1,
            Ed25519 => &alg::ed25519::PrivateKeyEd25519,
        }
    }

    /// Create a private key from raw bytes of the specified algorithm
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// #
    /// use ripple_keypairs::{Algorithm, PrivateKey};
    ///
    /// let bytes = hex::decode("D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23")?;
    /// let key = PrivateKey::from_slice(bytes, Algorithm::Secp256k1)?;
    ///
    /// assert_eq!(key.to_string(), "00D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23");
    /// #
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`error::InvalidKeyLength`] if bytes length is not 32.
    pub fn from_slice<S: AsRef<[u8]>>(bytes: S, kind: Algorithm) -> error::Result<Self> {
        let bytes = bytes.as_ref();

        if bytes.len() != 32 {
            return Err(error::InvalidKeyLength);
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
    /// Display as a hex encoded string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.method()
                .encode_to_hex(&self.method().as_bytes(&self.bytes))
        )
    }
}

/// A public key that can be used to derive an XRP Ledger classic address and verify signatures
///
/// # Examples
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #
/// use ripple_keypairs::{Seed, error};
///
/// let seed = "sp5fghtJtpUorTwvof1NpDXAzNwf5".parse::<Seed>()?;
///
/// let (private_key, public_key) = seed.derive_keypair()?;
///
/// assert_eq!(public_key.derive_address(), "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1");
///
/// assert_eq!(public_key.to_string(), "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435");
///
/// let msg = "Test message";
///
/// assert_eq!(public_key.verify(&msg, &private_key.sign(&msg)), Ok(()));
/// assert_eq!(public_key.verify(&msg, &"bad signature"), Err(error::InvalidSignature));
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    bytes: Vec<u8>,
    kind: Algorithm,
}

impl PublicKey {
    /// Verify a signature
    ///
    /// # Errors
    ///
    /// Returns [`error::InvalidSignature`] if the signature is invalid.
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
        let hex = HexBytes::from_hex_unchecked(&self.to_string());
        let hash: [u8; 20] = utils::hash160(hex.as_bytes())[..20].try_into().unwrap();

        codec::encode_account_id(&hash)
    }

    fn method(&self) -> &'static dyn alg::Verify {
        match self.kind {
            Secp256k1 => &alg::secp256k1::PublicKeyEcDsaSecP256K1,
            Ed25519 => &alg::ed25519::PublicKeyEd25519,
        }
    }

    /// Create a public key from encoded bytes with algorithm prefix
    ///
    /// Ed25519 keys are prefixed with `0xED`.
    /// Secp256k1 keys are prefixed with `0x02` or `0x03` (compressed point).
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// #
    /// use ripple_keypairs::PublicKey;
    ///
    /// let key: PublicKey = "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435".parse()?;
    ///
    /// assert_eq!(key.to_string(), "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435");
    /// #
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`error::InvalidKeyLength`] if bytes length is not 33.
    /// Returns [`error::DecodeError`] if the prefix byte is unrecognised.
    pub fn from_encoded_slice<S: AsRef<[u8]>>(bytes: S) -> error::Result<Self> {
        let bytes = bytes.as_ref();

        if bytes.len() != 33 {
            return Err(error::InvalidKeyLength);
        }

        let (algorithm, raw_bytes) = match bytes[0] {
            0xED => (Ed25519, bytes[1..].to_vec()),
            0x02 | 0x03 => (Secp256k1, bytes.to_vec()),
            _ => return Err(error::DecodeError),
        };

        Ok(PublicKey {
            bytes: raw_bytes,
            kind: algorithm,
        })
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
    /// Display as a hex encoded string
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
        let bytes = hex::decode(s).map_err(|_| error::DecodeError)?;
        Self::from_encoded_slice(&bytes)
    }
}
