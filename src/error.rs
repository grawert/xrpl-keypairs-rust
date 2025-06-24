//! Errors

use std::{error, fmt, result};

use base_x;

pub use Error::*;

/// Result with error type
pub type Result<T> = result::Result<T, Error>;

/// Error enum type
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Error {
    ExpectedMinEntorpyLenght(usize),
    DecodeError,
    InvalidSignature,
    InvalidKeyLength,
    DeriveKeyPairError,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpectedMinEntorpyLenght(n) => write!(f, "{} {}", "entropy lenght must be >=", n),
            DecodeError => f.write_str("decode error"),
            InvalidSignature => f.write_str("invalid signature"),
            InvalidKeyLength => f.write_str("invalid key length"),
            DeriveKeyPairError => f.write_str("derive keypair error"),
        }
    }
}

macro_rules! impl_from_error {
    ($t:ty => $m:ident) => {
        #[doc(hidden)]
        impl From<$t> for Error {
            fn from(_: $t) -> Self {
                $m
            }
        }
    };
}

impl_from_error!(base_x::DecodeError => DecodeError);
impl_from_error!(libsecp256k1::Error => InvalidSignature);
