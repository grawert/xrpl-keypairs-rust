//! Internal cryptographic utility functions for the XRP Ledger.

use ripemd::Ripemd160;
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

/// Compute the SHA-256 digest of the input data.
pub(super) fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute the RIPEMD-160 digest of the input data.
fn ripemd160_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute a RIPEMD-160 hash of a SHA-256 hash (Hash160).
pub(super) fn hash160(data: &[u8]) -> Vec<u8> {
    ripemd160_digest(&sha256_digest(data))
}

/// Compute the first 32 bytes of a SHA-512 digest.
pub(super) fn sha512_digest_32(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    // Grab only the first 32 bytes of the 64-byte SHA-512 output
    hasher.finalize()[..32].to_vec()
}
