// #![deny(warnings)]
#![allow(clippy::result_large_err)]

mod config;
mod http;
mod ldap;
mod objects;
mod state;
mod tailscale;

use crate::config::Config;
use crate::http::server::HttpsServer;
use crate::http::server::Server;
use crate::ldap::LdapServer;

use lmdb::{Database, Environment};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::path::Path;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .try_init()
        .expect("failed to initialize tracing");

    let config = config::Config::new();

    let mut ts_api = tailscale::Tailscale::from_config(config.clone());
    let mut ts_net = libtailscale::Tailscale::new();

    let ts_net_config_dir = std::path::PathBuf::from(&config.data_dir).join("tsnet");
    ts_net
        .set_dir(&ts_net_config_dir.to_string_lossy())
        .expect("Failed to set Tailscale directory");

    ts_net
        .set_hostname(&config.ts_hostname)
        .expect("Failed to set hostname");

    ts_net.start().expect("Failed to start Tailscale");
    ts_net.up().expect("Failed to bring up Tailscale");

    let loopback_info = ts_net.loopback().expect("Failed to get loopback info");
    ts_api.set_local_api(loopback_info.address, loopback_info.credential);

    let mut preferred_cert_domain = config.ts_hostname.clone();
    match ts_api.status().await {
        Ok(s) => {
            if let Some(arr) = s.get("CertDomains").and_then(|v| v.as_array()) {
                if let Some(first) = arr.get(0).and_then(|v| v.as_str()) {
                    preferred_cert_domain = first.to_string();
                }
            } else if let Some(dnsname) = s
                .get("Self")
                .and_then(|v| v.get("DNSName"))
                .and_then(|v| v.as_str())
            {
                preferred_cert_domain = dnsname.trim_end_matches('.').to_string();
            }
        }
        Err(e) => tracing::warn!("Failed to get LocalAPI status: {}", e),
    }

    let lmdb_dir: std::path::PathBuf = std::path::Path::new(&config.data_dir).join("lmdb");
    std::fs::create_dir_all(&lmdb_dir).expect("Failed to create lmdb directory");

    let env = Environment::new()
        .set_max_dbs(3)
        .set_map_size(10 * 1024 * 1024)
        .open(&lmdb_dir)
        .expect("Failed to open LMDB environment");

    let flags = lmdb::DatabaseFlags::empty();

    let otp_db = env
        .create_db(Some("otp"), flags)
        .expect("Failed to create OTP database");

    let lockout_db = env
        .create_db(Some("lockouts"), flags)
        .expect("Failed to create lockouts database");

    let owned_certs = ts_api
        .certificate_pair(&preferred_cert_domain)
        .await
        .expect("Failed to fetch certificate pair");

    let state = crate::state::State {
        config: config.clone(),
        tailscale: ts_api.clone(),
        otp_db: otp_db.clone(),
        env: Arc::new(env),
        lockout_db: lockout_db.clone(),
        ts_net: Arc::new(ts_net),
        certs: std::sync::Arc::new((owned_certs.0.clone(), owned_certs.1.clone_key())),
    };

    let http_state = state.clone();
    let ldap_state = state.clone();

    let http_handle = tokio::spawn(async move {
        let server =
            HttpsServer::from_state(http_state.clone()).expect("Failed to create HTTPS server");
        server
            .spawn(tokio::runtime::Handle::current())
            .expect("Failed to spawn HTTPS server");
    });

    let ldap_handle = tokio::spawn(async move {
        let server = LdapServer::from_state(ldap_state.clone());
        server
            .spawn(tokio::runtime::Handle::current())
            .expect("Failed to spawn LDAP server");
    });

    let _ = tokio::join!(http_handle, ldap_handle);

    // wait for servers to finish (they won't, but this keeps the main function alive)
    futures::future::pending::<()>().await;

    Ok(())
}
