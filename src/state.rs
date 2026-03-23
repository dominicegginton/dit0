use crate::config::Config;
use crate::tailscale::Tailscale;
use libtailscale::Tailscale as TsNet;
use lmdb::{Database, Environment};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use std::sync::Arc;

#[derive(Clone)]
pub struct State {
    pub config: Config,
    pub tailscale: Tailscale,
    pub otp_db: Database,
    pub env: Arc<Environment>,
    pub lockout_db: Database,
    pub ts_net: Arc<TsNet>,
    pub certs: std::sync::Arc<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>,
}
