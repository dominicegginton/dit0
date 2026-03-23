// #![deny(warnings)]
#![allow(clippy::result_large_err)]

mod certs;
mod config;
mod http;
mod ldap;
mod lmdb;
mod logger;
mod objects;
mod state;
mod tailscale;
use crate::certs::CertLoader;
use crate::http::server::Server;
use crate::http::server::{HttpServer, HttpsServer};
use crate::ldap::LdapServer;

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = logger::init();
    let config = config::Config::new();
    let mut tailscale_api = tailscale::Tailscale::new(config.clone());
    let mut ts_server = libtailscale::Tailscale::new();

    let ts_net_config_dir = std::path::PathBuf::from(&config.data_dir).join("tsnet");

    ts_server
        .set_dir(&ts_net_config_dir.to_string_lossy())
        .expect("Failed to set Tailscale directory");
    ts_server
        .set_hostname(&config.ts_hostname)
        .expect("Failed to set hostname");
    ts_server.start().expect("Failed to start Tailscale");
    ts_server.up().expect("Failed to bring up Tailscale");
    let loopback_info = ts_server.loopback().expect("Failed to get loopback info");
    tailscale_api.set_local_api(loopback_info.address, loopback_info.credential);

    let (env, otp_db, lockout_db) = lmdb::init(&config).unwrap();

    let cert_dir = ts_net_config_dir.join("certs");
    let certs_loader = certs::Certificates::new(cert_dir);
    let owned_certs = match certs_loader.load_certs() {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(
                "Certificates not found or failed to load: {}. Starting HTTP-only.",
                e
            );
            None
        }
    };

    let state = crate::state::State {
        config: config.clone(),
        tailscale: tailscale_api.clone(),
        otp_db: otp_db.clone(),
        env: env.clone(),
        lockout_db: lockout_db.clone(),
        ts_net: Arc::new(ts_server),
        certs: std::sync::Arc::new(None),
    };

    let http_state = state.clone();
    let ldap_state = state.clone();

    // if the certs are not present - start only the http server
    // else start both https and ldap servers
    if owned_certs.as_ref().map(|c| c.0.is_empty()).unwrap_or(true) {
        let http_handle = tokio::spawn(async move {
            let server = HttpServer::new(http_state.ts_net.clone());
            server
                .spawn(tokio::runtime::Handle::current())
                .expect("Failed to spawn HTTP server");
        });

        let _ = http_handle.await;
    } else {
        let owned = owned_certs.expect("owned_certs should exist in this branch");
        let http_handle = tokio::spawn(async move {
            let server =
                HttpsServer::new(http_state.clone(), owned).expect("Failed to create HTTPS server");
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
    }

    // wait for servers to finish (they won't, but this keeps the main function alive)
    futures::future::pending::<()>().await;

    Ok(())
}
