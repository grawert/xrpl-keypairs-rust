//! Internal traits for cryptographic operations.

use std::fmt;
use crate::{error::Result, EntropyArray, HexBytes, KeyPairResult};

pub(super) mod ed25519;
pub(super) mod secp256k1;

/// Common functionality for keys, including length and prefixing.
pub(super) trait Key {
    /// The length of the raw key bytes.
    fn key_length(&self) -> usize;

    /// The prefix used when encoding the key to hex.
    fn prefix(&self) -> &[u8];

    /// Returns a slice of the key bytes up to the defined length.
    fn as_bytes<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[..self.key_length()]
    }

    /// Encodes the key bytes into a hex string with the appropriate prefix.
    fn encode_to_hex(&self, bytes: &[u8]) -> String {
        HexBytes::from_bytes(&[self.prefix(), bytes].concat()).to_string()
    }
}

/// Trait for signing messages.
pub(super) trait Sign: Key + fmt::Debug {
    /// Signs a message using the provided private key bytes.
    fn sign(&self, message: &[u8], private_key: &[u8]) -> HexBytes;
}

/// Trait for verifying signatures.
pub(super) trait Verify: Key + fmt::Debug {
    /// Verifies a signature against a message and public key.
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()>;
}

/// Trait for deriving keypairs from seed entropy.
pub(super) trait Seed: fmt::Debug {
    /// Derives a private and public key from entropy.
    fn derive_keypair(&self, entropy: &EntropyArray) -> KeyPairResult;

    /// Encodes entropy into a base58 seed string.
    fn encode(&self, entropy: &EntropyArray) -> String;
}
