use std::str::FromStr;
use ripple_keypairs::{
    error::Error,
    Algorithm::{self, Ed25519, Secp256k1},
    Entropy::{Array, Random},
    EntropyArray, HexBytes, PrivateKey, PublicKey, Seed,
};

use fixtures::*;

mod fixtures {
    use super::*;

    pub const ENTROPY: EntropyArray = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    pub struct TestData {
        pub algorithm: Algorithm,
        pub entropy: EntropyArray,
        pub seed: &'static str,
        pub private_key: &'static str,
        pub public_key: &'static str,
        pub address: &'static str,
        pub message: &'static str,
        pub signature: &'static str,
    }

    pub static TEST_SECP256K1: TestData = TestData {
        algorithm: Secp256k1,
        entropy: ENTROPY,
        seed: "sp5fghtJtpUorTwvof1NpDXAzNwf5",
        private_key: "00D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23",
        public_key: "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435",
        address: "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1",
        message: "test message",
        signature: "30440220583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE02207D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D"
    };

    pub static TEST_ED25519: TestData = TestData {
        algorithm: Ed25519,
        entropy: ENTROPY,
        seed: "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r",
        private_key: "EDB4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3",
        public_key: "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63",
        address: "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD",
        message: "test message",
        signature: "CB199E1BFD4E3DAA105E4832EEDFA36413E1F44205E4EFB9E27E826044C21E3E2E848BBC8195E8959BADF887599B7310AD1B7047EF11B682E0D068F73749750E"
    };
}

/// Validates full generation, signing, and addressing flow for an algorithm.
fn run_full_api_flow(data: &TestData) {
    // Seed and Keypair derivation
    let seed = Seed::new(Array(data.entropy), data.algorithm);
    let (private, public) = seed.derive_keypair().expect("Derivation failed");

    assert_eq!(seed.to_string(), data.seed);
    assert_eq!(private.to_string(), data.private_key);
    assert_eq!(public.to_string(), data.public_key);

    // Cryptographic operations
    let sig = private.sign(&data.message);
    assert_eq!(sig.to_string(), data.signature);
    assert_eq!(public.verify(&data.message, &sig), Ok(()));

    // Address encoding
    assert_eq!(public.derive_address(), data.address);
}

#[test]
fn test_secp256k1_implementation() {
    run_full_api_flow(&TEST_SECP256K1);
}

#[test]
fn test_ed25519_implementation() {
    run_full_api_flow(&TEST_ED25519);
}

#[test]
fn test_ed25519_raw_32byte_import() {
    // Import raw 32-byte key (no ED prefix)
    let raw_hex = &TEST_ED25519.public_key[2..];
    let raw_bytes = hex::decode(raw_hex).unwrap();
    let public = PublicKey::from_encoded_slice(&raw_bytes).expect("Should accept raw 32-bytes");

    assert_eq!(public.to_string(), TEST_ED25519.public_key);
}

#[test]
fn test_ed25519_prefixed_33byte_import() {
    // Import standard 33-byte key (with ED prefix)
    let prefixed_bytes = hex::decode(TEST_ED25519.public_key).unwrap();
    let public = PublicKey::from_encoded_slice(&prefixed_bytes).expect("Should accept prefixed 33-bytes");

    assert_eq!(public.to_string(), TEST_ED25519.public_key);
}

#[test]
fn test_seed_parsing_and_randomness() {
    for alg in [Secp256k1, Ed25519] {
        let s1 = Seed::new(Random, alg);
        let s2 = Seed::new(Random, alg);

        assert_ne!(s1.to_string(), s2.to_string(), "Seeds must be unique");

        let parsed: Seed = s1.to_string().parse().expect("Failed to parse encoded seed");
        assert_eq!(parsed.as_kind(), &alg);
    }
}

#[test]
fn test_error_cases() {
    // Test InvalidKeyLength
    let short_bytes = vec![0u8; 31];
    assert!(PrivateKey::from_slice(&short_bytes, Ed25519).is_err());
    assert!(PublicKey::from_encoded_slice(&short_bytes).is_err());

    // Test DecodeError (Invalid prefix for 33 bytes)
    let mut bad_prefix = vec![0xFF; 33];
    assert_eq!(PublicKey::from_encoded_slice(&bad_prefix).unwrap_err(), Error::DecodeError);
}
