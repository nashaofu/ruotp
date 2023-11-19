use thiserror::Error;

use crate::algorithm::Algorithm;

#[derive(Debug, Error)]
pub enum OTPError {
    #[error("Base32DecodeError")]
    Base32DecodeError,
    #[error("HmacError: `{0}` key length error")]
    HmacKeyLengthError(Algorithm),
    #[error("ToKeyUriError: `{0}`")]
    ToKeyUriError(String),
    #[error("Error: `{0}`")]
    Error(String),
}

impl OTPError {
    pub fn new<S: ToString>(err: S) -> Self {
        OTPError::Error(err.to_string())
    }
}
