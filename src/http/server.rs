use super::auth::{require_allow_admin_ui, require_user};
use super::handlers::{
    admin_audit_api, admin_dashboard, credentials_reset, credentials_setup, user,
};
use super::state::AppState;
use crate::tailscale::UserClaims;
use axum::{
    http::Request,
    middleware,
    routing::{get, post},
    Router,
};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::trace::TraceLayer;

pub trait Server {
    fn from_state(state: AppState) -> Self;
    fn spawn(
        self,
        handle: tokio::runtime::Handle,
        certs: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    ) -> anyhow::Result<()>;
}

pub struct HttpsServer {
    state: AppState,
}

impl Server for HttpsServer {
    fn from_state(state: AppState) -> Self {
        HttpsServer { state }
    }
    fn spawn(
        self,
        handle: tokio::runtime::Handle,
        certs: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    ) -> anyhow::Result<()> {
        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.0, certs.1)
            .expect("Failed to create TLS config");

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let protected_routes = Router::new()
            .route("/", get(user))
            .route("/credentials/setup", post(credentials_setup))
            .route("/credentials/reset", post(credentials_reset))
            .route_layer(middleware::from_fn(require_user));

        let admin_routes = Router::new()
            .route("/admin", get(admin_dashboard))
            .route("/admin/api/audit", get(admin_audit_api))
            .route_layer(middleware::from_fn(require_allow_admin_ui));

        let app = Router::new()
            .merge(protected_routes)
            .merge(admin_routes)
            .layer(TraceLayer::new_for_http())
            .with_state(self.state.clone());

        let state = self.state.clone();

        std::thread::spawn(move || {
            let address = format!(":{}", state.config.web_port);
            let listener = state
                .ts_net
                .listen("tcp", &address)
                .expect("Failed to listen on tsnet");

            loop {
                match listener.accept() {
                    Ok(stream) => {
                        let _ = stream
                            .set_nonblocking(true)
                            .expect("Failed to set nonblocking on stream");

                        let peer_addr = match listener.get_remote_addr(stream.as_raw_fd()) {
                            Ok(addr) => addr,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to get peer address, skipping connection: {}",
                                    e
                                );
                                use std::net::Shutdown;
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                        };

                        let app = app.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let state = state.clone();

                        handle.spawn(async move {
                            let stream = tokio::net::TcpStream::from_std(stream)
                              .expect("Failed to convert to tokio stream");
                            let tls_stream = tls_acceptor.accept(stream).await.expect("Failed to accept TLS connection");

                            let io = TokioIo::new(tls_stream);
                            let service = hyper::service::service_fn(
                                move |req: Request<hyper::body::Incoming>| {
                                    let mut app = app.clone();
                                    let state = state.clone();
                                    async move {
                                        let whois = state.tailscale.whois(peer_addr).await.expect("Failed to perform whois lookup");

                                        let (parts, body) = req.into_parts();
                                        let mut req = Request::from_parts(parts, axum::body::Body::new(body));
                                        // insert state
                                        req.extensions_mut().insert(state.clone());
                                        // capture cookie (if present) and make available to handlers via Extension<String>
                                        let cookie_header_val = req.headers().get("cookie").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                                        if let Some(cookie_str) = cookie_header_val {
                                            req.extensions_mut().insert(cookie_str);
                                        } else {
                                            // ensure an empty string is available so handler signature can be static
                                            req.extensions_mut().insert(String::new());
                                        }
                                        if let Some(w) = whois.clone() {
                                            req.extensions_mut().insert(w.clone());
                                            match w.user_profile.as_ref().map(|up| up.login_name.clone()) {
                                                Some(login) if login != "tagged-devices" => {
                                                    let claims = UserClaims {
                                                        sub: w.user_profile.as_ref().and_then(|up| up.id).map(|id| id.to_string()),
                                                        email: w.user_profile.as_ref().map(|up| up.login_name.clone()),
                                                        name: w.user_profile.as_ref().map(|up| up.display_name.clone()),
                                                        picture: w.user_profile.as_ref().and_then(|up| up.profile_pic_url.clone()),
                                                        username: w.user_profile.as_ref().map(|up| up.login_name.clone()),
                                                        preferred_username: w.user_profile.as_ref().map(|up| up.login_name.clone()),
                                                        extra: w.cap_map.clone().unwrap_or_default(),
                                                    };
                                                    req.extensions_mut().insert(claims);
                                                    app.call(req).await
                                                }
                                                _ => {
                                                    let cap_map = w.cap_map.clone().unwrap_or_default();
                                                    let bindable = cap_map.get("dominicegginton.dev/cap/tsdit0").map_or(false, |val| {
                                                        if let serde_json::Value::Array(arr) = val {
                                                            arr.iter().any(|item| {
                                                                if let serde_json::Value::Object(obj) = item {
                                                                    obj.get("allow_bind").map_or(false, |v| matches!(v, serde_json::Value::Bool(true)))
                                                                } else {
                                                                    false
                                                                }
                                                            })
                                                        } else if let serde_json::Value::Object(obj) = val {
                                                            obj.get("allow_bind").map_or(false, |v| matches!(v, serde_json::Value::Bool(true)))
                                                        } else {
                                                            false
                                                        }
                                                    });
                                                    let reasons_vec: Vec<String> = if bindable {
                                                        if let Some(serde_json::Value::Array(arr)) = cap_map.get("dominicegginton.dev/cap/tsdit0") {
                                                            arr.iter().filter_map(|item| {
                                                                if let serde_json::Value::Object(obj) = item {
                                                                    let mut reason_parts = Vec::new();
                                                                    if obj.get("allow_bind").map_or(false, |v| matches!(v, serde_json::Value::Bool(true))) {
                                                                        reason_parts.push("allow_bind".to_string());
                                                                    }
                                                                    if obj.get("allow_admin_ui").map_or(false, |v| matches!(v, serde_json::Value::Bool(true))) {
                                                                        reason_parts.push("allow_admin_ui".to_string());
                                                                    }
                                                                    if let Some(serde_json::Value::Array(list)) = obj.get("tsdit_machines") {
                                                                        for entry in list.iter() {
                                                                            if let Some(s) = entry.as_str() {
                                                                                reason_parts.push(format!("tsdit_machines:{}", s));
                                                                            }
                                                                        }
                                                                    }
                                                                    if reason_parts.is_empty() {
                                                                        None
                                                                    } else { Some(reason_parts.join(", ")) }
                                                                } else { None }
                                                            }).collect()
                                                        } else {
                                                            vec!["allow_bind".to_string()]
                                                        }
                                                    } else {
                                                        Vec::new()
                                                    };

                                                    app.call(req).await
                                                }
                                            }
                                        } else {
                                            app.call(req).await
                                        }
                                    }
                                },
                            );



                            let _ = http1::Builder::new().serve_connection(io, service).await.expect("Failed to serve connection");
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        });

        Ok(())
    }
}
