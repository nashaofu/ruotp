use hmac::{
    digest::{
        block_buffer::Eager,
        core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        crypto_common::BlockSizeUser,
        typenum::{IsLess, Le, NonZero, U256},
        HashMarker,
    },
    Hmac, Mac,
};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fmt;

use crate::error::OTPError;

#[derive(Debug, Clone)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Algorithm {
    fn hash<D>(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OTPError>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        let mut hmac = Hmac::<D>::new_from_slice(&key)
            .map_err(|_| OTPError::HmacKeyLengthError(self.clone()))?;

        hmac.update(data);

        let hash = hmac.finalize().into_bytes().to_vec();

        Ok(hash)
    }

    pub fn digest(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OTPError> {
        match self {
            Algorithm::Sha1 => self.hash::<Sha1>(key, data),
            Algorithm::Sha256 => self.hash::<Sha256>(key, data),
            Algorithm::Sha512 => self.hash::<Sha512>(key, data),
        }
    }
}
