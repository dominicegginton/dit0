use crate::audit::AuditLog;
use crate::config::Config;
use crate::tailscale::Tailscale;
use crate::yubikey::YubikeyValidator;
use libtailscale::Tailscale as TsNet;
use lmdb::{Database, Environment};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct State {
    pub config: Config,
    pub tailscale: Tailscale,
    pub yubikey_db: Database,
    pub yubikey_validator: Arc<YubikeyValidator>,
    pub env: Arc<Environment>,
    pub ts_net: Arc<TsNet>,
    pub certs: Arc<RwLock<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>,
    pub audit_log: AuditLog,
}
