use ring::signature::{self, KeyPair};

use ripple_address_codec as codec;

use crate::{
    error::{DeriveKeyPairError, InvalidSignature, Result},
    utils, Ed25519, EntropyArray, HexBytes, KeyPairResult, PrivateKey, PublicKey,
};

use super::{Key, Seed, Sign, Verify};

#[derive(Debug)]
pub(crate) struct PrivateKeyEd25519;

impl Sign for PrivateKeyEd25519 {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> HexBytes {
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(private_key).unwrap();

        HexBytes::from_bytes(&key_pair.sign(message))
    }
}

impl Key for PrivateKeyEd25519 {
    fn key_lenght(&self) -> usize {
        Self::LENGHT
    }

    fn prefix(&self) -> &[u8] {
        Self::PREFIX
    }
}

impl PrivateKeyEd25519 {
    const LENGHT: usize = 32;
    const PREFIX: &'static [u8] = &[0xED];
}

#[derive(Debug)]
pub(crate) struct PublicKeyEd25519;

impl Verify for PublicKeyEd25519 {
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);

        public_key
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }
}

impl Key for PublicKeyEd25519 {
    fn key_lenght(&self) -> usize {
        Self::LENGHT
    }

    fn prefix(&self) -> &[u8] {
        Self::PREFIX
    }
}

impl PublicKeyEd25519 {
    const LENGHT: usize = 32;
    const PREFIX: &'static [u8] = &[0xED];
}

#[derive(Debug)]
pub(crate) struct SeedEd25519;

impl Seed for SeedEd25519 {
    fn derive_keypair(&self, entropy: &EntropyArray) -> KeyPairResult {
        let raw_priv = utils::sha512_digest_32(entropy);

        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&raw_priv)
            .map_err(|_| DeriveKeyPairError)?;

        let raw_pub = key_pair.public_key().as_ref().to_vec();

        let kind = Ed25519;

        Ok((
            PrivateKey {
                bytes: raw_priv,
                kind,
            },
            PublicKey {
                bytes: raw_pub,
                kind,
            },
        ))
    }

    fn encode(&self, entropy: &EntropyArray) -> String {
        codec::encode_seed(entropy, &Ed25519)
    }
}
