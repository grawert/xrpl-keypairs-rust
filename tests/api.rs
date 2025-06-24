use std::str::FromStr;

use ripple_keypairs::{
    error::{DecodeError, InvalidKeyLength, InvalidSignature},
    Algorithm::{Ed25519, Secp256k1},
    Entropy::{Array, Random},
    EntropyArray, HexBytes, PrivateKey, PublicKey, Seed,
};

use fixtures::*;

mod fixtures {
    use super::*;

    pub const ENTROPY: EntropyArray = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    pub struct TestData {
        pub entropy: EntropyArray,
        pub seed: &'static str,
        pub private_key: &'static str,
        pub public_key: &'static str,
        pub address: &'static str,
        pub message: &'static str,
        pub signature: &'static str,
    }

    pub static TEST_SECP256K1: TestData = TestData {
        entropy: ENTROPY,
        seed: "sp5fghtJtpUorTwvof1NpDXAzNwf5",
        private_key: "00D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23",
        public_key: "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435",
        address: "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1",
        message: "test message",
        signature: "30440220583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE02207D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D"
    };

    pub static TEST_ED25519: TestData = TestData {
        entropy: ENTROPY,
        seed: "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r",
        private_key: "EDB4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3",
        public_key: "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63",
        address: "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD",
        message: "test message",
        signature: "CB199E1BFD4E3DAA105E4832EEDFA36413E1F44205E4EFB9E27E826044C21E3E2E848BBC8195E8959BADF887599B7310AD1B7047EF11B682E0D068F73749750E"
    };

    pub fn secp256k1_test_seed() -> Seed {
        Seed::from_str(TEST_SECP256K1.seed).unwrap()
    }

    pub fn ed25519_test_seed() -> Seed {
        Seed::from_str(TEST_ED25519.seed).unwrap()
    }
}

mod secp256k1 {
    use super::*;

    #[test]
    fn new_seed() {
        let seed = Seed::new(Array(TEST_SECP256K1.entropy), Secp256k1);

        assert_eq!(TEST_SECP256K1.seed, seed.to_string());
    }

    #[test]
    fn random_seed_starts_with_s() {
        let seed = Seed::random();

        assert!(seed.to_string().starts_with("s") && !seed.to_string().starts_with("sEd"));
    }

    #[test]
    fn random_seed() {
        assert_ne!(Seed::random().to_string(), Seed::random().to_string());
    }

    #[test]
    fn parse_random_seed() {
        let random_seed = Seed::random();
        let parsed_seed: Seed = random_seed.to_string().parse().unwrap();

        assert_eq!(parsed_seed, random_seed);
    }

    #[test]
    fn parse_seed() {
        let seed: Seed = TEST_SECP256K1.seed.parse().unwrap();

        assert_eq!(seed.as_kind(), &Secp256k1);
        assert_eq!(seed.as_entropy(), &TEST_SECP256K1.entropy);
    }

    #[test]
    fn bad_seed() {
        assert_eq!(
            "sXXXghtJtpUorTwvof1NpDXAzNwf5".parse::<Seed>().unwrap_err(),
            DecodeError
        );
    }

    #[test]
    fn key_imports() {
        let private_bytes = hex::decode(&TEST_SECP256K1.private_key[2..]).unwrap();
        let private = PrivateKey::from_slice(private_bytes, Secp256k1).unwrap();
        let public: PublicKey = TEST_SECP256K1.public_key.parse().unwrap();

        assert!(public.to_string() == TEST_SECP256K1.public_key);
        assert!(private.to_string() == TEST_SECP256K1.private_key);
    }

    #[test]
    fn key_imports_wrong_keylength() {
        let private_bytes = hex::decode(&TEST_SECP256K1.private_key[0..]).unwrap();

        assert!(private_bytes.len() != 32);
        assert_eq!(
            PrivateKey::from_slice(private_bytes, Secp256k1).unwrap_err(),
            InvalidKeyLength
        );
        assert_eq!(
            PublicKey::from_str(&TEST_SECP256K1.public_key[2..]).unwrap_err(),
            InvalidKeyLength
        );
    }

    #[test]
    fn derive_keypair() {
        let seed = secp256k1_test_seed();
        let (private, public) = seed.derive_keypair().unwrap();

        assert_eq!(
            (private.to_string().as_str(), public.to_string().as_str()),
            (TEST_SECP256K1.private_key, TEST_SECP256K1.public_key)
        );
    }

    #[test]
    fn sign() {
        let seed = secp256k1_test_seed();
        let (private, _) = seed.derive_keypair().unwrap();

        assert_eq!(
            private.sign(&TEST_SECP256K1.message).to_string(),
            TEST_SECP256K1.signature
        )
    }

    #[test]
    fn verify() {
        let seed = secp256k1_test_seed();
        let (_, public) = seed.derive_keypair().unwrap();

        let sig = HexBytes::from_hex_unchecked(TEST_SECP256K1.signature);

        assert_eq!(public.verify(&TEST_SECP256K1.message, &sig), Ok(()));
    }

    #[test]
    fn verify_bad_signature() {
        let seed = secp256k1_test_seed();
        let (_, public) = seed.derive_keypair().unwrap();

        assert_eq!(
            public.verify(&TEST_SECP256K1.message, &"bad signature"),
            Err(InvalidSignature)
        );
    }

    #[test]
    fn derive_address() {
        let (_, public) = secp256k1_test_seed().derive_keypair().unwrap();

        assert_eq!(public.derive_address(), TEST_SECP256K1.address);
    }

    #[test]
    fn random_address() {
        let random_seed = Seed::new(Random, Secp256k1);
        let (_, public) = random_seed.derive_keypair().unwrap();
        let address = public.derive_address();

        assert_eq!("r", &address[..1]);
    }
}

mod ed25519 {
    use super::*;

    #[test]
    fn new_seed() {
        let seed = Seed::new(Array(TEST_ED25519.entropy), Ed25519);

        assert_eq!(TEST_ED25519.seed, seed.to_string());
    }

    #[test]
    fn random_seed_starts_with_sed() {
        let seed = Seed::new(Random, Ed25519);

        assert!(seed.to_string().starts_with("sEd"));
    }

    #[test]
    fn random_seed() {
        assert_ne!(
            Seed::new(Random, Ed25519).to_string(),
            Seed::new(Random, Ed25519).to_string()
        );
    }

    #[test]
    fn parse_random_seed() {
        let random_seed = Seed::new(Random, Ed25519);
        let parsed_seed: Seed = random_seed.to_string().parse().unwrap();

        assert_eq!(parsed_seed.as_kind(), random_seed.as_kind());
        assert_eq!(parsed_seed.as_entropy(), random_seed.as_entropy());
    }

    #[test]
    fn parse_seed() {
        let seed: Seed = TEST_ED25519.seed.parse().unwrap();

        assert_eq!(seed.as_kind(), &Ed25519);
        assert_eq!(seed.as_entropy(), &TEST_ED25519.entropy);
    }

    #[test]
    fn bad_seed() {
        assert_eq!(
            "sEdXXXCy2JT7JaM7v95H9SxkhP9wS2r"
                .parse::<Seed>()
                .unwrap_err(),
            DecodeError
        );
    }

    #[test]
    fn key_imports() {
        let private_bytes = hex::decode(&TEST_ED25519.private_key[2..]).unwrap();
        let private = PrivateKey::from_slice(private_bytes, Ed25519).unwrap();
        let public: PublicKey = TEST_ED25519.public_key.parse().unwrap();

        assert!(public.to_string() == TEST_ED25519.public_key);
        assert!(private.to_string() == TEST_ED25519.private_key);
    }

    #[test]
    fn key_imports_wrong_keylength() {
        let private_bytes = hex::decode(&TEST_ED25519.private_key[0..]).unwrap();

        assert!(private_bytes.len() != 32);
        assert_eq!(
            PrivateKey::from_slice(private_bytes, Ed25519).unwrap_err(),
            InvalidKeyLength
        );
        assert_eq!(
            PublicKey::from_str(&TEST_ED25519.public_key[2..]).unwrap_err(),
            InvalidKeyLength
        );
    }

    #[test]
    fn derive_keypair() {
        let seed = ed25519_test_seed();
        let (private, public) = seed.derive_keypair().unwrap();

        assert_eq!(
            (private.to_string().as_str(), public.to_string().as_str()),
            (TEST_ED25519.private_key, TEST_ED25519.public_key)
        );
    }

    #[test]
    fn sign() {
        let seed = ed25519_test_seed();
        let (private, _) = seed.derive_keypair().unwrap();

        assert_eq!(
            private.sign(&TEST_ED25519.message).to_string(),
            TEST_ED25519.signature
        )
    }

    #[test]
    fn verify() {
        let seed = ed25519_test_seed();
        let (_, public) = seed.derive_keypair().unwrap();

        let sig = HexBytes::from_hex_unchecked(TEST_ED25519.signature);

        assert_eq!(public.verify(&TEST_ED25519.message, &sig), Ok(()));
    }

    #[test]
    fn verify_bad_signature() {
        let seed = ed25519_test_seed();
        let (_, public) = seed.derive_keypair().unwrap();

        assert_eq!(
            public.verify(&TEST_ED25519.message, &"bad signature"),
            Err(InvalidSignature)
        );
    }

    #[test]
    fn derive_address() {
        let (_, public) = ed25519_test_seed().derive_keypair().unwrap();

        assert_eq!(public.derive_address(), TEST_ED25519.address);
    }

    #[test]
    fn random_address() {
        let random_seed = Seed::new(Random, Ed25519);
        let (_, public) = random_seed.derive_keypair().unwrap();
        let address = public.derive_address();

        assert_eq!("r", &address[..1]);
    }
}
