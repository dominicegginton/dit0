use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngExt;
use reqwest::Client;
use sha1::Sha1;
use std::collections::BTreeMap;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

const DEFAULT_YUBICO_API_URL: &str = "https://api.yubico.com/wsapi/2.0/verify";

pub const MODHEX_CHARS: &str = "cbdefghijklnrtuv";

/// Check if a string has the valid length (44 chars) and uses the modhex alphabet.
pub fn is_valid_otp(otp: &str) -> bool {
    otp.len() == 44 && otp.chars().all(|c| MODHEX_CHARS.contains(c))
}

/// Extract the 12-character public ID from a YubiKey OTP.
pub fn extract_public_id(otp: &str) -> Option<&str> {
    if is_valid_otp(otp) {
        Some(&otp[..12])
    } else {
        None
    }
}

#[derive(Error, Debug)]
pub enum YubikeyError {
    #[error("Invalid OTP format: must be 44 modhex characters")]
    InvalidFormat,
    #[error("Network error validating OTP: {0}")]
    Network(#[from] reqwest::Error),
    #[error("YubiKey validation failed with status: {0}")]
    ValidationFailed(String),
    #[error("OTP replayed: {0}")]
    ReplayedOtp(String),
    #[error("Signature mismatch in validation response")]
    InvalidSignature,
    #[error("OTP mismatch in validation response")]
    OtpMismatch,
    #[error("Nonce mismatch in validation response")]
    NonceMismatch,
}

#[derive(Clone, Debug)]
pub struct YubikeyValidator {
    client_id: Option<String>,
    secret_key: Option<Vec<u8>>,
    api_url: String,
    http_client: Client,
}

impl YubikeyValidator {
    pub fn new(
        client_id: Option<String>,
        secret_key_b64: Option<String>,
        api_url: Option<String>,
    ) -> Self {
        let secret_key = secret_key_b64.and_then(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
        });

        Self {
            client_id,
            secret_key,
            api_url: api_url.unwrap_or_else(|| DEFAULT_YUBICO_API_URL.to_string()),
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Verify a Yubico OTP against the YubiCloud / Validation Server.
    pub async fn verify_otp(&self, otp: &str) -> Result<(), YubikeyError> {
        let otp = otp.trim();
        if !is_valid_otp(otp) {
            return Err(YubikeyError::InvalidFormat);
        }

        let id = match &self.client_id {
            Some(val) if !val.is_empty() => val.as_str(),
            _ => {
                return Err(YubikeyError::ValidationFailed(
                    "Yubico Client ID is not configured. Please set 'yubico_client_id' in your config.json (Get a free API key at https://upgrade.yubico.com/get_api_key/)".to_string()
                ));
            }
        };

        let nonce: String = {
            let mut rng = rand::rng();
            (&mut rng)
                .sample_iter(rand::distr::Alphanumeric)
                .take(20)
                .map(char::from)
                .collect()
        };

        let mut params = BTreeMap::new();
        params.insert("id", id);
        params.insert("otp", otp);
        params.insert("nonce", nonce.as_str());

        // Compute HMAC-SHA1 signature if secret_key is provided
        let signature = if let Some(key) = &self.secret_key {
            let query_str = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");

            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 init");
            mac.update(query_str.as_bytes());
            let sig_bytes = mac.finalize().into_bytes();
            Some(base64::engine::general_purpose::STANDARD.encode(sig_bytes))
        } else {
            None
        };

        let mut req = self.http_client.get(&self.api_url);
        for (k, v) in &params {
            req = req.query(&[(*k, *v)]);
        }
        if let Some(sig) = &signature {
            req = req.query(&[("h", sig.as_str())]);
        }

        let resp = req.send().await?.text().await?;

        // Parse key=value response lines
        let mut resp_map = BTreeMap::new();
        for line in resp.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                resp_map.insert(k.to_string(), v.to_string());
            }
        }

        let status = resp_map
            .get("status")
            .map(|s| s.as_str())
            .unwrap_or("NO_STATUS");

        if status != "OK" {
            if status == "REPLAYED_OTP" {
                return Err(YubikeyError::ReplayedOtp(status.to_string()));
            }
            return Err(YubikeyError::ValidationFailed(status.to_string()));
        }

        // Verify nonce and OTP in response
        if let Some(resp_nonce) = resp_map.get("nonce") {
            if resp_nonce != &nonce {
                return Err(YubikeyError::NonceMismatch);
            }
        }

        if let Some(resp_otp) = resp_map.get("otp") {
            if resp_otp != otp {
                return Err(YubikeyError::OtpMismatch);
            }
        }

        // Verify response signature if we have a secret key
        if let (Some(key), Some(resp_sig)) = (&self.secret_key, resp_map.get("h")) {
            let resp_query = resp_map
                .iter()
                .filter(|(k, _)| k.as_str() != "h")
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");

            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 init");
            mac.update(resp_query.as_bytes());
            let computed_sig =
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

            if computed_sig != *resp_sig {
                return Err(YubikeyError::InvalidSignature);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_otp_format() {
        let valid_otp = "ccccccdefghijklnrtuvcbdefghijklnrtuvcbdefghi";
        assert_eq!(valid_otp.len(), 44);
        assert!(is_valid_otp(valid_otp));
        assert_eq!(extract_public_id(valid_otp), Some("ccccccdefghi"));

        let invalid_len = "ccccccdefghijklnrtuv";
        assert!(!is_valid_otp(invalid_len));
        assert_eq!(extract_public_id(invalid_len), None);

        let invalid_chars = "ccccccdefghijklnrtuvcbdefghijklnrtuvcbdefghZ";
        assert!(!is_valid_otp(invalid_chars));
        assert_eq!(extract_public_id(invalid_chars), None);
    }
}
