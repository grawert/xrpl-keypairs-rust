use std::convert::TryInto;

use ring::digest;

use num_bigint::{BigInt, Sign as BigIntSign};

use libsecp256k1::{
    sign, verify, Message, PublicKey as SecPublicKey, SecretKey as SecPrivateKey,
    Signature as SecSignature,
};

use ripple_address_codec::encode_seed;

use crate::{
    error::{DeriveKeyPairError, InvalidSignature, Result},
    utils,
    Algorithm::Secp256k1,
    EntropyArray, HexBytes, KeyPairResult, PrivateKey, PublicKey,
};

use super::{Key, Seed, Sign, Verify};

#[derive(Debug)]
pub(crate) struct PrivateKeyEcDsaSecP256K1;

impl Sign for PrivateKeyEcDsaSecP256K1 {
    fn sign(&self, message: &[u8], private_key: &[u8]) -> HexBytes {
        let (signature, _) = sign(
            &prepare_message(message),
            &SecPrivateKey::parse_slice(private_key).unwrap(),
        );

        HexBytes::from_bytes(&signature.serialize_der())
    }
}

impl Key for PrivateKeyEcDsaSecP256K1 {
    fn key_lenght(&self) -> usize {
        Self::LENGHT
    }

    fn prefix(&self) -> &[u8] {
        Self::PREFIX
    }
}

impl PrivateKeyEcDsaSecP256K1 {
    const LENGHT: usize = 32;
    const PREFIX: &'static [u8] = &[0x00];
}

#[derive(Debug)]
pub(crate) struct PublicKeyEcDsaSecP256K1;

impl Verify for PublicKeyEcDsaSecP256K1 {
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        let message = &prepare_message(message);
        let signature = &SecSignature::parse_der(signature)?;
        let mut compressed = [0; Self::LENGHT];
        compressed.copy_from_slice(public_key);
        let pubkey = &SecPublicKey::parse_compressed(&compressed).unwrap();

        match verify(message, signature, pubkey) {
            true => Ok(()),
            false => Err(InvalidSignature),
        }
    }
}

impl Key for PublicKeyEcDsaSecP256K1 {
    fn key_lenght(&self) -> usize {
        Self::LENGHT
    }

    fn prefix(&self) -> &[u8] {
        Self::PREFIX
    }
}

impl PublicKeyEcDsaSecP256K1 {
    const LENGHT: usize = 33;
    const PREFIX: &'static [u8] = &[];
}

#[derive(Debug)]
pub(crate) struct SeedEcDsaSecP256K1;

impl Seed for SeedEcDsaSecP256K1 {
    fn derive_keypair(&self, entropy: &EntropyArray) -> KeyPairResult {
        let private_key_bytes = Self::derive_private_key(entropy).ok_or(DeriveKeyPairError)?;

        let private_key =
            SecPrivateKey::parse(&private_key_bytes).map_err(|_| DeriveKeyPairError)?;
        let public_key = SecPublicKey::from_secret_key(&private_key);
        let public_key_bytes = public_key.serialize_compressed();

        let kind = Secp256k1;

        Ok((
            PrivateKey {
                bytes: private_key_bytes.into(),
                kind,
            },
            PublicKey {
                bytes: public_key_bytes.into(),
                kind,
            },
        ))
    }

    fn encode(&self, entropy: &EntropyArray) -> String {
        encode_seed(entropy, &Secp256k1)
    }
}

type PrivateKeyBytes = [u8; PrivateKeyEcDsaSecP256K1::LENGHT];

impl SeedEcDsaSecP256K1 {
    // There is no pub const for order `n` in dependency `libsecp256k1`,
    // so define it here
    fn order_n() -> BigInt {
        let n = b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

        BigInt::parse_bytes(n, 16).unwrap()
    }

    fn derive_scalar(bytes: &[u8], discrim: Option<u32>) -> BigInt {
        let order = Self::order_n();

        for i in 0..=0xffffffff as u32 {
            let mut hasher = digest::Context::new(&digest::SHA512);

            hasher.update(bytes);

            if let Some(d) = discrim {
                hasher.update(&d.to_be_bytes());
            }

            hasher.update(&i.to_be_bytes());

            let key = BigInt::from_bytes_be(
                BigIntSign::Plus,
                &hasher.finish().as_ref()[..PrivateKeyEcDsaSecP256K1::LENGHT],
            );

            if key > 0.into() && key < order {
                return key;
            }
        }

        // This line is practically impossible to reach
        unreachable!();
    }

    fn derive_private_key(bytes: &EntropyArray) -> Option<PrivateKeyBytes> {
        let order = Self::order_n();

        let private_gen = Self::derive_scalar(bytes, None);

        let private_bytes = Self::big_int_to_private_key_bytes(&private_gen);

        let private_key = SecPrivateKey::parse(&private_bytes).ok()?;
        let public_key = SecPublicKey::from_secret_key(&private_key);

        let public = Self::derive_scalar(&public_key.serialize_compressed(), Some(0));

        let result = (public + private_gen) % order;

        Some(Self::big_int_to_private_key_bytes(&result))
    }

    fn big_int_to_private_key_bytes(big_int: &BigInt) -> PrivateKeyBytes {
        HexBytes::from_hex_unchecked(&format!("{:064X}", big_int))
            .as_bytes()
            .try_into()
            .unwrap()
    }
}

fn prepare_message(message: &[u8]) -> Message {
    let message_hash = utils::sha512_digest_32(message);

    Message::parse_slice(&message_hash).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_big_int_to_32_bytes() {
        let big_int: BigInt = 1.into();

        assert_eq!(
            SeedEcDsaSecP256K1::big_int_to_private_key_bytes(&big_int),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
        );
    }
}
