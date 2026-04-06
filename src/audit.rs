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

use lmdb::{Cursor, Database, Environment, Transaction, WriteFlags};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// The `tracing` target used for all audit events.
const TARGET: &str = "audit";

/// Maximum number of events kept in the ring buffer.
const MAX_EVENTS: usize = 2000;

// ── In-memory audit store ───────────────────────────────────────────────────

/// A single stored audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Thread-safe ring buffer of audit events backed by LMDB for persistence.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditLogInner>,
}

struct AuditLogInner {
    events: RwLock<VecDeque<AuditEvent>>,
    env: Arc<Environment>,
    db: Database,
    next_key: AtomicU64,
    oldest_key: AtomicU64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish()
    }
}

impl AuditLog {
    /// Create a new audit log backed by the given LMDB environment and database,
    /// loading any previously persisted events.
    pub fn new(env: Arc<Environment>, db: Database) -> Self {
        let mut events = VecDeque::with_capacity(MAX_EVENTS);
        let mut min_key: Option<u64> = None;
        let mut max_key: u64 = 0;

        {
            let txn = env
                .begin_ro_txn()
                .expect("Failed to begin LMDB read txn for audit log");
            // lmdb 0.8's iter_start() panics on an empty database, so we
            // wrap the iteration in catch_unwind to handle first-run safely.
            let pairs: Vec<(&[u8], &[u8])> = catch_unwind(AssertUnwindSafe(|| {
                if let Ok(mut cursor) = txn.open_ro_cursor(db) {
                    cursor.iter_start().collect::<Vec<_>>()
                } else {
                    vec![]
                }
            }))
            .unwrap_or_default();

            for (key_bytes, val_bytes) in pairs {
                if key_bytes.len() == 8 {
                    let k = u64::from_be_bytes(key_bytes.try_into().expect("bad audit key len"));
                    if min_key.is_none() || k < min_key.unwrap() {
                        min_key = Some(k);
                    }
                    if k > max_key {
                        max_key = k;
                    }
                }
                if let Ok(event) = serde_json::from_slice::<AuditEvent>(val_bytes) {
                    events.push_back(event);
                }
            }
            txn.abort();
        }

        let oldest = min_key.unwrap_or(0);
        let next = if min_key.is_some() { max_key + 1 } else { 0 };

        // Trim to MAX_EVENTS if the stored log exceeded capacity.
        while events.len() > MAX_EVENTS {
            events.pop_front();
        }

        tracing::info!(
            "Loaded {} audit events from disk (keys {}..{})",
            events.len(),
            oldest,
            next.saturating_sub(1)
        );

        Self {
            inner: Arc::new(AuditLogInner {
                events: RwLock::new(events),
                env,
                db,
                next_key: AtomicU64::new(next),
                oldest_key: AtomicU64::new(oldest),
            }),
        }
    }

    /// Push an event, persisting to LMDB and evicting the oldest if at capacity.
    pub async fn push(&self, event: AuditEvent) {
        let key = self.inner.next_key.fetch_add(1, Ordering::SeqCst);
        let key_bytes = key.to_be_bytes();

        // Persist to LMDB.
        if let Ok(val) = serde_json::to_vec(&event) {
            if let Ok(mut txn) = self.inner.env.begin_rw_txn() {
                if txn
                    .put(self.inner.db, &key_bytes, &val, WriteFlags::empty())
                    .is_ok()
                {
                    // Evict oldest entry from LMDB when over capacity.
                    let oldest = self.inner.oldest_key.load(Ordering::SeqCst);
                    if key + 1 - oldest > MAX_EVENTS as u64 {
                        let old_key = self.inner.oldest_key.fetch_add(1, Ordering::SeqCst);
                        let old_bytes = old_key.to_be_bytes();
                        let _ = txn.del(self.inner.db, &old_bytes, None);
                    }
                }
                let _ = txn.commit();
            }
        }

        // Update in-memory buffer.
        let mut buf = self.inner.events.write().await;
        if buf.len() >= MAX_EVENTS {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// Snapshot all events (oldest first).
    pub async fn snapshot(&self) -> Vec<AuditEvent> {
        let buf = self.inner.events.read().await;
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
pub fn init(env: Arc<Environment>, db: Database) -> AuditLog {
    let log = AuditLog::new(env, db);
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
