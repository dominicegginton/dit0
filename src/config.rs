use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ldap_port: u16,
    pub web_port: u16,
    pub ts_api_base_url: String,
    pub ts_api_key_file: String,
    pub ts_id: String,
    pub base_dn: String,
    pub ts_hostname: String,
    pub ts_auth_key_file: Option<String>,
    pub otp_hmac_key_file: String,
    pub data_dir: String,
}

impl Config {
    pub fn from_file() -> Self {
        let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.json".to_string());

        if !Path::new(&config_path).exists() {
            panic!("Config file not found: {}", config_path);
        }

        let content = fs::read_to_string(&config_path).expect("failed to read config file");
        let config = serde_json::from_str::<Config>(&content).expect("failed to parse config file");

        config
    }

    pub fn ts_api_key(&self) -> Option<String> {
        fs::read_to_string(&self.ts_api_key_file)
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn ts_auth_key(&self) -> Option<String> {
        self.ts_auth_key_file
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok().map(|s| s.trim().to_string()))
    }

    pub fn otp_hmac_key(&self) -> Option<String> {
        fs::read_to_string(&self.otp_hmac_key_file)
            .ok()
            .map(|s| s.trim().to_string())
    }
}
