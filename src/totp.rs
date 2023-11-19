use base32::{decode, encode, Alphabet};

use crate::algorithm::Algorithm;
use crate::error::OTPError;
use crate::utils::{generate_hotp_token, to_key_uri, KeyUriOptions, KeyUriType};

#[derive(Debug, Clone)]
pub struct TOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    digits: u32,
    period: u64,
}

impl TOTP {
    pub fn new(algorithm: Algorithm, secret: Vec<u8>, digits: u32, period: u64) -> Self {
        TOTP {
            algorithm,
            secret,
            digits,
            period,
        }
    }

    pub fn from_base32(secret: &str) -> Result<Self, OTPError> {
        let secret = decode(Alphabet::RFC4648 { padding: false }, secret)
            .ok_or(OTPError::Base32DecodeError)?;

        Ok(TOTP::new(Algorithm::Sha1, secret, 6, 30))
    }
}

impl TOTP {
    pub fn generate_token(&self, epoch: u64) -> Result<String, OTPError> {
        let counter = epoch / self.period;
        generate_hotp_token(&self.algorithm, &self.secret, counter, self.digits)
    }

    pub fn to_key_uri<T: ToString>(
        &self,
        account_name: T,
        issuer: Option<T>,
    ) -> Result<String, OTPError> {
        let secret = encode(Alphabet::RFC4648 { padding: false }, &self.secret);
        to_key_uri(KeyUriOptions {
            r#type: KeyUriType::TOTP,
            secret,
            counter: None,
            period: Some(self.period),
            algorithm: Some(self.algorithm.clone()),
            digits: Some(self.digits),
            account_name: account_name.to_string(),
            issuer: issuer.and_then(|issuer| Some(issuer.to_string())),
        })
    }
}
