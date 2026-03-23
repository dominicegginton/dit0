use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ldap_port: u16,
    pub web_port: u16,
    pub ts_api_base_url: String,
    pub ts_api_key: String,
    pub ts_api_domain: String,
    pub base_dn: String,
    pub ts_hostname: String,
    pub ts_auth_key: Option<String>,
    pub otp_hmac_key: Option<String>,
    pub data_dir: String,
}

impl Config {
    pub fn new() -> Self {
        Config {
            ldap_port: env::var("LDAP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(389),
            web_port: env::var("WEB_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(443),
            ts_api_base_url: env::var("TS_API_BASE_URL")
                .unwrap_or("https://api.tailscale.com/api/v2".to_string()),
            ts_api_key: env::var("TS_API_KEY")
                .ok()
                .expect("TS_API_KEY environment variable is required"),
            ts_api_domain: env::var("TS_API_DOMAIN")
                .ok()
                .expect("TS_API_DOMAIN environment variable is required"),
            base_dn: env::var("BASE_DN")
                .ok()
                .expect("BASE_DN environment variable is required"),
            ts_hostname: env::var("TS_HOSTNAME").unwrap_or("dit0".to_string()),
            ts_auth_key: env::var("TS_AUTH_KEY").ok(),
            otp_hmac_key: env::var("OTP_HMAC_KEY").ok(),
            data_dir: env::var("DATA_DIR").unwrap_or("/var/lib/dit0".to_string()),
        }
    }
}
