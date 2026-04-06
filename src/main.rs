// #![deny(warnings)]
// #![allow(clippy::result_large_err)]

mod config;
mod http;
mod ldap;
mod objects;
mod state;
mod tailscale;

use crate::http::server::HttpsServer;
use crate::http::server::Server;
use crate::ldap::LdapServer;

use lmdb::Environment;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .try_init()
        .expect("failed to initialize tracing");

    let config = config::Config::from_file();

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
        .set_max_dbs(2)
        .set_map_size(10 * 1024 * 1024)
        .open(&lmdb_dir)
        .expect("Failed to open LMDB environment");

    let flags = lmdb::DatabaseFlags::empty();

    let otp_db = env
        .create_db(Some("otp"), flags)
        .expect("Failed to create OTP database");

    let owned_certs = ts_api
        .certificate_pair(&preferred_cert_domain)
        .await
        .expect("Failed to fetch certificate pair");

    let certs_store = std::sync::Arc::new(tokio::sync::RwLock::new((
        owned_certs.0.clone(),
        owned_certs.1.clone_key(),
    )));

    let state = crate::state::State {
        config: config.clone(),
        tailscale: ts_api.clone(),
        otp_db: otp_db.clone(),
        env: Arc::new(env),
        ts_net: Arc::new(ts_net),
        certs: certs_store.clone(),
    };

    let http_state = state.clone();
    let ldap_state = state.clone();

    // ── Certificate renewal background task ─────────────────────────────────
    // Tailscale certs typically expire after 90 days. Refresh every 24 hours
    // so the running server never serves an expired certificate.
    let cert_renewal_ts = ts_api.clone();
    let cert_renewal_domain = preferred_cert_domain.clone();
    let cert_renewal_store = certs_store.clone();
    let cert_renewal_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
        // Skip the first immediate tick — certs were just fetched above.
        interval.tick().await;
        loop {
            interval.tick().await;
            tracing::info!("Renewing TLS certificate for {}", cert_renewal_domain);
            match cert_renewal_ts.certificate_pair(&cert_renewal_domain).await {
                Ok(new_certs) => {
                    let mut store = cert_renewal_store.write().await;
                    *store = (new_certs.0, new_certs.1.clone_key());
                    tracing::info!("TLS certificate renewed successfully");
                }
                Err(e) => {
                    tracing::error!("TLS certificate renewal failed: {} — will retry in 24h", e);
                }
            }
        }
    });

    let http_handle = tokio::spawn(async move {
        let certs = {
            let guard = http_state.certs.read().await;
            (guard.0.clone(), guard.1.clone_key())
        };
        let server = HttpsServer::from_state(http_state.clone());
        server
            .spawn(tokio::runtime::Handle::current(), certs)
            .expect("Failed to spawn HTTPS server");
    });

    let ldap_handle = tokio::spawn(async move {
        let certs = {
            let guard = ldap_state.certs.read().await;
            (guard.0.clone(), guard.1.clone_key())
        };
        let server = LdapServer::from_state(ldap_state.clone());
        server
            .spawn(tokio::runtime::Handle::current(), certs)
            .expect("Failed to spawn LDAP server");
    });

    let _ = tokio::join!(http_handle, ldap_handle, cert_renewal_handle);

    // wait for servers to finish (they won't, but this keeps the main function alive)
    futures::future::pending::<()>().await;

    Ok(())
}
