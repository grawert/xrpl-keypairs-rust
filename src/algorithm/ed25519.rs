//! Ed25519 implementation for the XRP Ledger.

use std::convert::TryFrom;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ripple_address_codec as codec;

use crate::{
    error::{Error, Result},
    utils, Algorithm::Ed25519, EntropyArray, HexBytes, KeyPairResult, PrivateKey, PublicKey,
};
use super::{Key, Seed, Sign, Verify};

#[derive(Debug)]
pub(crate) struct PrivateKeyEd25519;

impl Sign for PrivateKeyEd25519 {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> HexBytes {
        let signing_key = SigningKey::try_from(private_key)
            .expect("private key bytes must be valid at this point");
        HexBytes::from_bytes(&signing_key.sign(message).to_vec())
    }
}

impl Key for PrivateKeyEd25519 {
    fn key_length(&self) -> usize { 32 }
    fn prefix(&self) -> &[u8] { &[0xED] }
}

#[derive(Debug)]
pub(crate) struct PublicKeyEd25519;

impl Verify for PublicKeyEd25519 {
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        let signature = Signature::try_from(signature).map_err(|_| Error::InvalidSignature)?;
        let verifying_key = VerifyingKey::try_from(public_key).map_err(|_| Error::InvalidSignature)?;
        verifying_key.verify(message, &signature).map_err(|_| Error::InvalidSignature)
    }
}

impl Key for PublicKeyEd25519 {
    fn key_length(&self) -> usize { 32 }
    fn prefix(&self) -> &[u8] { &[0xED] }
}

#[derive(Debug)]
pub(crate) struct SeedEd25519;

impl Seed for SeedEd25519 {
    fn derive_keypair(&self, entropy: &EntropyArray) -> KeyPairResult {
        let raw_priv = utils::sha512_digest_32(entropy);
        let signing_key = SigningKey::try_from(raw_priv.as_slice())
            .map_err(|_| Error::DeriveKeyPairError)?;
        let raw_pub = signing_key.verifying_key().as_bytes().to_vec();

        Ok((
            PrivateKey { bytes: raw_priv, kind: Ed25519 },
            PublicKey { bytes: raw_pub, kind: Ed25519 },
        ))
    }

    fn encode(&self, entropy: &EntropyArray) -> String {
        codec::encode_seed(entropy, &Ed25519)
    }
}
