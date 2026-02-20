use std::fmt;

use crate::{error::Result, EntropyArray, HexBytes, KeyPairResult};

pub(super) mod ed25519;
pub(super) mod secp256k1;

pub(super) trait Key {
    fn key_length(&self) -> usize;

    fn prefix(&self) -> &[u8];

    fn as_bytes<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[..self.key_length()]
    }

    fn encode_to_hex(&self, bytes: &[u8]) -> String {
        HexBytes::from_bytes(&[self.prefix(), bytes].concat()).to_string()
    }
}

pub(super) trait Sign: Key + fmt::Debug {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> HexBytes;
}

pub(super) trait Verify: Key + fmt::Debug {
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()>;
}

pub(super) trait Seed: fmt::Debug {
    fn derive_keypair(&self, entropy: &EntropyArray) -> KeyPairResult;

    fn encode(&self, entropy: &EntropyArray) -> String;
}
