//! Structured audit logging for dit0.
//!
//! Every security-relevant action (LDAP bind, search, credential change, HTTP
//! authentication, etc.) is emitted as a `tracing` event at INFO level on the
//! dedicated `audit` target **and** stored in an in-memory ring buffer so the
//! admin dashboard can render D3 charts.
//!
//! Using a named target makes it easy to route these events to a separate sink
//! (file, syslog, SIEM) via `tracing-subscriber` filter directives such as
//! `audit=info`.

use serde::Serialize;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// The `tracing` target used for all audit events.
const TARGET: &str = "audit";

/// Maximum number of events kept in the ring buffer.
const MAX_EVENTS: usize = 2000;

// ── In-memory audit store ───────────────────────────────────────────────────

/// A single stored audit event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Unix timestamp (seconds).
    pub ts: u64,
    /// Event category (e.g. `ldap_bind`, `ldap_search`, `credentials_setup`).
    pub event: String,
    /// Outcome or sub-classification (`success`, `failure`, …).
    pub result: String,
    /// Peer address or username depending on context.
    pub actor: String,
    /// Human-readable detail string.
    pub detail: String,
}

/// Thread-safe ring buffer of audit events.
#[derive(Debug, Clone)]
pub struct AuditLog {
    inner: Arc<RwLock<VecDeque<AuditEvent>>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_EVENTS))),
        }
    }

    /// Push an event, evicting the oldest if at capacity.
    pub async fn push(&self, event: AuditEvent) {
        let mut buf = self.inner.write().await;
        if buf.len() >= MAX_EVENTS {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// Snapshot all events (oldest first).
    pub async fn snapshot(&self) -> Vec<AuditEvent> {
        let buf = self.inner.read().await;
        buf.iter().cloned().collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Global audit log handle. Initialised once in `main` via `init`.
static AUDIT_LOG: std::sync::OnceLock<AuditLog> = std::sync::OnceLock::new();

/// Initialise the global audit log and return a handle for embedding in `State`.
pub fn init() -> AuditLog {
    let log = AuditLog::new();
    let _ = AUDIT_LOG.set(log.clone());
    log
}

/// Get a reference to the global log (if initialised).
fn global() -> Option<&'static AuditLog> {
    AUDIT_LOG.get()
}

/// Fire-and-forget push into the global log.
fn record(event: &str, result: &str, actor: &str, detail: &str) {
    if let Some(log) = global() {
        let ev = AuditEvent {
            ts: now_secs(),
            event: event.to_string(),
            result: result.to_string(),
            actor: actor.to_string(),
            detail: detail.to_string(),
        };
        let log = log.clone();
        tokio::spawn(async move { log.push(ev).await });
    }
}

// ── LDAP events ─────────────────────────────────────────────────────────────

/// An anonymous (unauthenticated) LDAP bind was accepted.
pub fn ldap_bind_anonymous(peer: SocketAddr) {
    tracing::info!(
        target: TARGET,
        event = "ldap_bind",
        peer = %peer,
        bind_dn = "",
        result = "success",
        method = "anonymous",
        "anonymous bind accepted"
    );
    record("ldap_bind", "success", &peer.to_string(), "anonymous bind");
}

/// An authenticated LDAP bind succeeded.
pub fn ldap_bind_success(peer: SocketAddr, bind_dn: &str, method: &str) {
    tracing::info!(
        target: TARGET,
        event = "ldap_bind",
        peer = %peer,
        bind_dn = %bind_dn,
        result = "success",
        method = %method,
        "bind succeeded"
    );
    record(
        "ldap_bind",
        "success",
        &peer.to_string(),
        &format!("{} ({})", bind_dn, method),
    );
}

/// An LDAP bind was rejected.
pub fn ldap_bind_failure(peer: SocketAddr, bind_dn: &str, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "ldap_bind",
        peer = %peer,
        bind_dn = %bind_dn,
        result = "failure",
        reason = %reason,
        "bind rejected"
    );
    record(
        "ldap_bind",
        "failure",
        &peer.to_string(),
        &format!("{}: {}", bind_dn, reason),
    );
}

/// An LDAP search was performed.
pub fn ldap_search(
    peer: SocketAddr,
    base_dn: &str,
    scope: &str,
    filter: &str,
    result_count: usize,
) {
    tracing::info!(
        target: TARGET,
        event = "ldap_search",
        peer = %peer,
        base_dn = %base_dn,
        scope = %scope,
        filter = %filter,
        result_count = result_count,
        "search completed"
    );
    record(
        "ldap_search",
        "success",
        &peer.to_string(),
        &format!("base={} scope={} results={}", base_dn, scope, result_count),
    );
}

/// An unsupported or unrecognised LDAP operation was received.
pub fn ldap_unsupported_op(peer: SocketAddr, operation: &str) {
    tracing::warn!(
        target: TARGET,
        event = "ldap_unsupported_op",
        peer = %peer,
        operation = %operation,
        "unsupported LDAP operation"
    );
    record(
        "ldap_unsupported_op",
        "failure",
        &peer.to_string(),
        operation,
    );
}

/// A client disconnected or was rate-limited.
pub fn ldap_connection_event(peer: SocketAddr, reason: &str) {
    tracing::info!(
        target: TARGET,
        event = "ldap_connection",
        peer = %peer,
        reason = %reason,
        "connection event"
    );
    record("ldap_connection", "info", &peer.to_string(), reason);
}

// ── HTTP / credential events ────────────────────────────────────────────────

/// A user accessed the web UI.
pub fn http_access(user: &str, path: &str, status: u16) {
    tracing::info!(
        target: TARGET,
        event = "http_access",
        user = %user,
        path = %path,
        status = status,
        "HTTP request"
    );
    record(
        "http_access",
        &status.to_string(),
        user,
        &format!("{} -> {}", path, status),
    );
}

/// A user configured new LDAP credentials (password + TOTP).
pub fn credentials_setup(user: &str, dn: &str) {
    tracing::info!(
        target: TARGET,
        event = "credentials_setup",
        user = %user,
        dn = %dn,
        "LDAP credentials configured"
    );
    record("credentials_setup", "success", user, dn);
}

/// A user reset (deleted) their LDAP credentials.
pub fn credentials_reset(user: &str, dn: &str) {
    tracing::info!(
        target: TARGET,
        event = "credentials_reset",
        user = %user,
        dn = %dn,
        "LDAP credentials reset"
    );
    record("credentials_reset", "success", user, dn);
}

/// Credential setup was rejected (already configured, weak password, etc.).
pub fn credentials_rejected(user: &str, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "credentials_rejected",
        user = %user,
        reason = %reason,
        "credential change rejected"
    );
    record("credentials_rejected", "failure", user, reason);
}

/// HTTP authentication / authorisation failure.
pub fn http_auth_failure(peer: &str, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "http_auth_failure",
        peer = %peer,
        reason = %reason,
        "HTTP auth failure"
    );
    record("http_auth_failure", "failure", peer, reason);
}
