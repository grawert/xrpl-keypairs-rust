# xrpl-keypairs

Cryptographic key pairs for the XRP Ledger. Supports secp256k1 (ECDSA/RFC6979) and Ed25519 deterministic signatures.

> Fork of [ripple-keypairs](https://crates.io/crates/ripple-keypairs) by Stanislav Otovchits (ISC).
> Improvements: owned `Algorithm` type, raw key imports, structured `Debug`, fixed prefix disambiguation.

## Installation

```toml
[dependencies]
xrpl-keypairs = "0.2"
```

Imports as `ripple_keypairs`:

```rust
use ripple_keypairs::{Seed, Algorithm, Entropy, PrivateKey, PublicKey};
```

## Usage

### Generate a random address

```rust
let seed = Seed::random(); // defaults to Secp256k1
let (_, public_key) = seed.derive_keypair()?;
let address = public_key.derive_address();

assert!(address.starts_with("r"));
```

### Generate an Ed25519 address

```rust
let seed = Seed::new(Entropy::Random, Algorithm::Ed25519);
let (_, public_key) = seed.derive_keypair()?;
let address = public_key.derive_address();
```

### Parse a seed from string

```rust
let seed: Seed = "sp5fghtJtpUorTwvof1NpDXAzNwf5".parse()?;
let (private_key, public_key) = seed.derive_keypair()?;
```

### Sign and verify

```rust
let (private_key, public_key) = seed.derive_keypair()?;

let signature = private_key.sign(&"my message");
public_key.verify(&"my message", &signature)?;
```

### Import raw keys

```rust
// Private key from raw 32 bytes
let bytes = hex::decode("D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23")?;
let private_key = PrivateKey::from_slice(bytes, Algorithm::Secp256k1)?;

// Public key from hex string (prefix byte included)
let public_key: PublicKey = "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435".parse()?;
```
