use std::collections::HashMap;
use urlencoding::encode;

use crate::{Algorithm, OTPError};

pub fn generate_hotp_token(
    algorithm: &Algorithm,
    secret: &[u8],
    counter: u64,
    digits: u32,
) -> Result<String, OTPError> {
    let hash = algorithm.digest(&secret, &counter.to_be_bytes())?;
    let offset: usize = (hash[hash.len() - 1] & 0xf) as usize;

    let binary = ((hash[offset] as u64) & 0x7f) << 24
        | ((hash[offset + 1] as u64) & 0xff) << 16
        | ((hash[offset + 2] as u64) & 0xff) << 8
        | ((hash[offset + 3] as u64) & 0xff);

    let mut token = (binary % 10_u64.pow(digits)).to_string();

    while token.len() < (digits as usize) {
        token = format!("0{}", token);
    }

    Ok(token)
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyUriType {
    HOTP,
    TOTP,
}

#[derive(Debug)]
pub struct KeyUriOptions {
    pub r#type: KeyUriType,
    pub secret: String,
    pub counter: Option<u64>,
    pub period: Option<u64>,
    pub algorithm: Option<Algorithm>,
    pub digits: Option<u32>,
    pub account_name: String,
    pub issuer: Option<String>,
}

pub fn to_key_uri(options: KeyUriOptions) -> Result<String, OTPError> {
    let mut params: HashMap<&str, String> = HashMap::new();
    params.insert("secret", options.secret);

    let key_uri_type = match options.r#type {
        KeyUriType::HOTP => {
            let counter = options.counter.ok_or(OTPError::ToKeyUriError(
                "counter to be a number when options.type is 'hotp'.".to_string(),
            ))?;
            params.insert("counter", counter.to_string());

            "hotp"
        }
        KeyUriType::TOTP => {
            if let Some(period) = options.period {
                params.insert("period", period.to_string());
            }

            "totp"
        }
    };

    if let Some(algorithm) = options.algorithm {
        params.insert("algorithm", algorithm.to_string().to_uppercase());
    }

    if let Some(digits) = options.digits {
        params.insert("digits", digits.to_string());
    }

    let mut label = encode(&options.account_name).to_string();
    if let Some(issuer) = options.issuer {
        let issuer_encoded = encode(&issuer).to_string();
        params.insert("issuer", issuer_encoded.clone());
        label = format!("{}:{}", issuer_encoded, label);
    }

    let query: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    let query = query.join("&");

    Ok(format!("otpauth://{}/{}?{}", key_uri_type, label, query))
}
