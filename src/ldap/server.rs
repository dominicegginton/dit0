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
    state: crate::state::State,
}

impl crate::http::server::Server for LdapServer {
    fn from_state(state: crate::state::State) -> Self {
        Self { state }
    }

    fn spawn(self, handle: tokio::runtime::Handle) -> anyhow::Result<()> {
        let cert_pair = self.state.certs.clone();
        let cert_chain = cert_pair.0.clone();
        let key = cert_pair.1.clone_key();

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("invalid certs");

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let ldaps_port = "636".to_string();
        let env_clone = self.state.env.clone();
        let otp_clone = self.state.otp_db; // copy
        let lockout_clone = self.state.lockout_db;
        let tailscale_clone = self.state.tailscale.clone();
        let base_dn = self.state.config.base_dn.clone();

        std::thread::spawn(move || {
            let listener = match self.state.ts_net.listen("tcp", &format!(":{}", ldaps_port)) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to listen on LDAPS port {}: {}", ldaps_port, e);
                    return;
                }
            };

            loop {
                match listener.accept() {
                    Ok(stream) => {
                        let _ = stream
                            .set_nonblocking(true)
                            .expect("Failed to set nonblocking on tsnet stream");

                        let peer_addr = listener
                            .get_remote_addr(stream.as_raw_fd())
                            .expect("Failed to get peer address for incoming LDAPS connection");

                        let env = env_clone.clone();
                        let otp = otp_clone;
                        let ts_api = tailscale_clone.clone();
                        let base_dn = base_dn.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("Failed to build per-connection runtime");

                            rt.block_on(async move {
                                let stream = tokio::net::TcpStream::from_std(stream)
                                    .expect("Failed to convert to tokio stream");

                                let tls_stream = tls_acceptor
                                    .accept(stream)
                                    .await
                                    .expect("Failed to accept TLS connection");

                                handle_client(
                                    tls_stream,
                                    std::net::SocketAddr::new(peer_addr, 0),
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
