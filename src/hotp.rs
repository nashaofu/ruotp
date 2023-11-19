use base32::{decode, encode, Alphabet};

use crate::algorithm::Algorithm;
use crate::error::OTPError;
use crate::utils::{generate_hotp_token, to_key_uri, KeyUriOptions, KeyUriType};

#[derive(Debug, Clone)]
pub struct HOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    /// The number of digits a token will have. Usually 6 or 8.
    digits: u32,
}

impl HOTP {
    pub fn new(algorithm: Algorithm, secret: Vec<u8>, digits: u32) -> Self {
        HOTP {
            algorithm,
            secret,
            digits,
        }
    }

    pub fn from_base32(secret: &str) -> Result<Self, OTPError> {
        let secret = decode(Alphabet::RFC4648 { padding: false }, secret)
            .ok_or(OTPError::Base32DecodeError)?;

        Ok(HOTP::new(Algorithm::Sha1, secret, 6))
    }
}

impl HOTP {
    pub fn generate_token(&self, counter: u64) -> Result<String, OTPError> {
        generate_hotp_token(&self.algorithm, &self.secret, counter, self.digits)
    }

    pub fn to_key_uri<T: ToString>(
        &self,
        account_name: T,
        issuer: Option<T>,
        counter: u64,
    ) -> Result<String, OTPError> {
        let secret = encode(Alphabet::RFC4648 { padding: false }, &self.secret);
        to_key_uri(KeyUriOptions {
            r#type: KeyUriType::HOTP,
            secret,
            counter: Some(counter),
            period: None,
            algorithm: Some(self.algorithm.clone()),
            digits: Some(self.digits),
            account_name: account_name.to_string(),
            issuer: issuer.and_then(|issuer| Some(issuer.to_string())),
        })
    }
}
