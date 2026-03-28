use futures::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use lmdb::{Database, Environment};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use tracing::error;

use super::handlers::handle_request;
use crate::config::Config;
use crate::tailscale::Tailscale;

pub async fn handle_client(
    socket: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    addr: std::net::SocketAddr,
    env: Arc<Environment>,
    otp_db: Database,
    lockout_db: Database,
    tailscale: Tailscale,
    base_dn: String,
) {
    let mut stream = socket;
    let mut framed = Framed::new(&mut stream, LdapCodec::default());
    const MAX_REQUESTS: usize = 1000;
    let mut request_count = 0usize;
    loop {
        let msg: Option<Result<ldap3_proto::proto::LdapMsg, _>> = framed.next().await;
        if msg.is_none() {
            break;
        }
        let msg = msg.unwrap();
        request_count += 1;
        if request_count > MAX_REQUESTS {
            error!("Max requests per connection exceeded for {}", addr);
            break;
        }
        match msg {
            Ok(req) => {
                let env_c = env.clone();
                let otp_c = otp_db;
                let lockout_c = lockout_db;
                let ts_c = tailscale.clone();
                let base_dn_c = base_dn.clone();
                let peer = addr;
                let resp =
                    handle_request(env_c, otp_c, lockout_c, &base_dn_c, req, &ts_c, peer).await;
                for msg in resp {
                    if let Err(e) = framed.send(msg).await {
                        error!("Failed to send response: {}", e);
                        return;
                    }
                }
            }
            Err(e) => {
                error!("Error decoding message: {}", e);
                break;
            }
        }
    }
}

pub struct LdapServer {
    env: Arc<Environment>,
    otp_db: Database,
    lockout_db: Database,
    config: Config,
    tailscale: Tailscale,
    ts_net: Arc<libtailscale::Tailscale>,
    tls_acceptor: TlsAcceptor,
}

impl LdapServer {
    pub fn from_state(state: crate::state::State) -> Self {
        let cert_pair = state.certs.clone();
        let cert_chain = cert_pair.0.clone();
        let key = cert_pair.1.clone_key();

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("invalid certs");

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Self {
            env: state.env.clone(),
            otp_db: state.otp_db,
            lockout_db: state.lockout_db,
            config: state.config,
            tailscale: state.tailscale,
            ts_net: state.ts_net,
            tls_acceptor,
        }
    }
}

impl crate::http::server::Server for LdapServer {
    fn spawn(self, handle: tokio::runtime::Handle) -> anyhow::Result<()> {
        let ts = self.ts_net.clone();
        let ldaps_port = "636".to_string();
        let env_clone = self.env.clone();
        let otp_clone = self.otp_db; // copy
        let lockout_clone = self.lockout_db;
        let tailscale_clone = self.tailscale.clone();
        let base_dn = self.config.base_dn.clone();
        let tls_acceptor = self.tls_acceptor.clone();

        let env_clone = env_clone.clone();
        let otp_clone = otp_clone.clone();
        let tailscale_clone = tailscale_clone.clone();
        let base_dn = base_dn.clone();
        std::thread::spawn(move || {
            let listener = match self.ts_net.listen("tcp", &format!(":{}", ldaps_port)) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to listen on LDAPS port {}: {}", ldaps_port, e);
                    return;
                }
            };
            loop {
                match listener.accept() {
                    Ok(stream) => {
                        if let Err(e) = stream.set_nonblocking(true) {
                            error!("Failed to set nonblocking on tsnet stream: {}", e);
                            continue;
                        }

                        let peer_addr = match listener.get_remote_addr(stream.as_raw_fd()) {
                            Ok(ip) => std::net::SocketAddr::new(ip, 0),
                            Err(_) => {
                                error!("Failed to get peer address for incoming LDAPS connection");
                                continue;
                            }
                        };
                        let stream = {
                            let _guard = handle.enter();
                            match tokio::net::TcpStream::from_std(stream) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::error!("Failed to convert to tokio stream: {}", e);
                                    continue;
                                }
                            }
                        };

                        let env = env_clone.clone();
                        let otp = otp_clone;
                        let ts_api = tailscale_clone.clone();
                        let base_dn = base_dn.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        std::thread::spawn(move || {
                            let rt = match tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("Failed to build per-connection runtime: {}", e);
                                    return;
                                }
                            };

                            rt.block_on(async move {
                                let tls_stream = match tls_acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to accept TLS connection: {}", e);
                                        return;
                                    }
                                };

                                handle_client(
                                    tls_stream,
                                    peer_addr,
                                    env.clone(),
                                    otp,
                                    lockout_clone,
                                    ts_api,
                                    base_dn,
                                )
                                .await
                            });
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept LDAPS connection: {}", e);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        });

        Ok(())
    }
}
