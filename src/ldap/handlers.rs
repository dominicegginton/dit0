use crate::objects;
use crate::tailscale::LocalWhoIsResponse;
use crate::tailscale::Tailscale;
use base32;
use hex;
use hmac::{Hmac, Mac};
use ldap3_proto::proto::{
    LdapBindCred, LdapBindResponse, LdapExtendedResponse, LdapFilter, LdapMsg, LdapOp,
    LdapPartialAttribute, LdapResult, LdapResultCode, LdapSearchResultEntry, LdapSearchScope,
};
use lmdb::{Database, Environment, Transaction};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

#[derive(Serialize, Deserialize, Debug, Default)]
struct LockoutEntry {
    failures: u32,
    last_attempt: u64,
    locked_until: u64,
}

fn read_lockout(env: &Environment, db: Database, key: &str) -> Option<LockoutEntry> {
    if let Ok(txn) = env.begin_ro_txn() {
        if let Ok(val) = txn.get(db, &key.as_bytes()) {
            if let Ok(entry) = serde_json::from_slice::<LockoutEntry>(val) {
                return Some(entry);
            }
        }
    }
    None
}

fn write_lockout(env: &Environment, db: Database, key: &str, entry: &LockoutEntry) -> bool {
    if let Ok(mut txn) = env.begin_rw_txn() {
        if let Ok(v) = serde_json::to_vec(entry) {
            if txn
                .put(db, &key.as_bytes(), &v, lmdb::WriteFlags::empty())
                .is_ok()
            {
                return txn.commit().is_ok();
            }
        }
    }
    false
}

fn delete_lockout(env: &Environment, db: Database, key: &str) -> bool {
    if let Ok(mut txn) = env.begin_rw_txn() {
        let _ = txn.del(db, &key.as_bytes(), None);
        return txn.commit().is_ok();
    }
    false
}

fn matches_filter(filter: &LdapFilter, attrs: &HashMap<String, Vec<String>>) -> bool {
    match filter {
        LdapFilter::Equality(attr, val)
        | LdapFilter::Approx(attr, val)
        | LdapFilter::GreaterOrEqual(attr, val)
        | LdapFilter::LessOrEqual(attr, val) => {
            if let Some(values) = attrs.get(attr) {
                return values.iter().any(|v| v.eq_ignore_ascii_case(val));
            }
            false
        }
        LdapFilter::Present(attr) => attrs.contains_key(attr),
        LdapFilter::And(filters) => filters.iter().all(|f| matches_filter(f, attrs)),
        LdapFilter::Or(filters) => filters.iter().any(|f| matches_filter(f, attrs)),
        LdapFilter::Not(filter) => !matches_filter(filter, attrs),
        LdapFilter::Substring(attr, filter) => {
            if let Some(values) = attrs.get(attr) {
                return values.iter().any(|v| {
                    let v_lower = v.to_lowercase();
                    if let Some(i) = &filter.initial {
                        if !v_lower.starts_with(i.to_lowercase().as_str()) {
                            return false;
                        }
                    }
                    if let Some(f) = &filter.final_ {
                        if !v_lower.ends_with(f.to_lowercase().as_str()) {
                            return false;
                        }
                    }
                    if !filter.any.is_empty() {
                        let mut last_index: usize = 0;
                        for part in &filter.any {
                            let part_lower = part.as_str().to_lowercase();
                            if let Some(i) = v_lower[last_index..].find(part_lower.as_str()) {
                                last_index += i + part.len();
                            } else {
                                return false;
                            }
                        }
                    }
                    true
                });
            }
            false
        }
        _ => true,
    }
}

// Helper: Whois/capmap check
async fn check_whois_tagged_devices(
    tailscale: &Tailscale,
    client_addr: std::net::SocketAddr,
    msgid: i32,
) -> Result<Option<LocalWhoIsResponse>, Vec<LdapMsg>> {
    if client_addr.ip().is_unspecified() {
        return Ok(None);
    }

    match tailscale.whois(client_addr.ip()).await {
        Ok(opt) => {
            if let Some(w) = &opt {
                if let Some(name) = w
                    .user_profile
                    .as_ref()
                    .and_then(|u| Some(u.display_name.clone()))
                {
                    if name != "Tagged Devices" {
                        return Err(vec![LdapMsg {
                            msgid,
                            op: LdapOp::BindResponse(LdapBindResponse {
                                res: LdapResult {
                                    code: LdapResultCode::OperationsError,
                                    matcheddn: "".to_string(),
                                    message: "Unexpected whois response; contact administrator"
                                        .to_string(),
                                    referral: vec![],
                                },
                                saslcreds: None,
                            }),
                            ctrl: vec![],
                        }]);
                    }
                } else {
                    warn!("No display name in whois response for {}", client_addr);
                }
            }
            Ok(opt)
        }
        Err(e) => {
            warn!("LocalAPI whois request failed for {}: {}", client_addr, e);
            Err(vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::OperationsError,
                        matcheddn: "".to_string(),
                        message: "Internal error during authentication; contact administrator"
                            .to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }])
        }
    }
}

// Helper: Bind handling
async fn handle_bind(
    env: Arc<Environment>,
    otp_db: Database,
    lockout_db: Database,
    tailscale: &Tailscale,
    bind: ldap3_proto::proto::LdapBindRequest,
    msgid: i32,
    base_dn: &str,
    client_addr: std::net::SocketAddr,
) -> Vec<LdapMsg> {
    if bind.cred == LdapBindCred::Simple("".to_string()) && bind.dn == "" {
        return vec![LdapMsg {
            msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: format!("cn={},ou=machines,{}", bind.dn, base_dn),
                    message: "Anonymous bind successful".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            }),
            ctrl: vec![],
        }];
    }

    // Support both Simple binds and SASL PLAIN binds (common for GUI clients)
    let password_opt: Option<String> = match &bind.cred {
        LdapBindCred::Simple(pw) => Some(pw.clone()),
        LdapBindCred::SASL(sasl) => {
            if sasl.mechanism.eq_ignore_ascii_case("PLAIN") {
                if let Ok(s) = String::from_utf8(sasl.credentials.clone()) {
                    // PLAIN message is: [authzid]\0authcid\0password
                    let parts: Vec<&str> = s.split('\0').collect();
                    let pass = if parts.len() >= 3 {
                        parts[2]
                    } else if parts.len() == 2 {
                        parts[1]
                    } else {
                        ""
                    };
                    Some(pass.to_string())
                } else {
                    None
                }
            } else {
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::AuthMethodNotSupported,
                            matcheddn: "".to_string(),
                            message: format!("SASL mechanism {} not supported", sasl.mechanism),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        }
    };

    if let Some(password) = password_opt {
        // Rate limiting: per-DN and per-IP
        const MAX_FAILURES: u32 = 5;
        const LOCKOUT_SECS: u64 = 300; // 5 minutes

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let dn_key = format!("dn:{}", bind.dn);
        let ip_key = format!("ip:{}", client_addr.ip());

        if let Some(entry) = read_lockout(&env, lockout_db, &dn_key) {
            if entry.locked_until > now {
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::OperationsError,
                            matcheddn: "".to_string(),
                            message: "Too many failed attempts for this DN; try later".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        }
        if let Some(entry) = read_lockout(&env, lockout_db, &ip_key) {
            if entry.locked_until > now {
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::OperationsError,
                            matcheddn: "".to_string(),
                            message: "Too many failed attempts from this IP; try later".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        }
        let username = bind
            .dn
            .split(',')
            .find(|p| p.trim().to_lowercase().starts_with("uid="))
            .map(|s| s.trim().trim_start_matches("uid=").trim().to_string())
            .unwrap_or_else(|| bind.dn.clone());

        let ts_login_name = match tailscale.list_users().await {
            Ok(users) => users
                .into_iter()
                .find(|u| {
                    let uid_part = u.login_name.split('@').next().unwrap_or("");
                    uid_part.eq_ignore_ascii_case(&username)
                        || u.login_name.eq_ignore_ascii_case(&username)
                })
                .map(|u| u.login_name)
                .unwrap_or(username.clone()),
            Err(_) => username.clone(),
        };

        let policy = match tailscale.get_acl_policies().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to fetch ACL policy: {}", e);
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::OperationsError,
                            matcheddn: "".to_string(),
                            message: "Internal error during ACL check".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        };

        let acl_preview = match tailscale
            .preview_acl("-", "user", &ts_login_name, policy.clone())
            .await
        {
            Ok(json) => json,
            Err(_) => {
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::OperationsError,
                            matcheddn: "".to_string(),
                            message: "Internal error during ACL preview".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        };

        // Determine if user can bind by matching preview groups to grants with allow_bind=true
        let mut user_groups = std::collections::HashSet::new();
        if let serde_json::Value::Object(map) = &acl_preview {
            if let Some(matches_val) = map.get("matches") {
                if let serde_json::Value::Array(matches_arr) = matches_val {
                    for m in matches_arr {
                        if let serde_json::Value::Object(mobj) = m {
                            if let Some(serde_json::Value::Array(users)) = mobj.get("users") {
                                for u in users {
                                    if let Some(s) = u.as_str() {
                                        user_groups.insert(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut can_bind = false;
        if let serde_json::Value::Object(policy_obj) = &policy {
            if let Some(grants) = policy_obj.get("grants") {
                if let serde_json::Value::Array(grants_arr) = grants {
                    'outer: for grant in grants_arr {
                        if let serde_json::Value::Object(grant_obj) = grant {
                            // Check src matches any user group
                            if let Some(srcs) = grant_obj.get("src") {
                                if let serde_json::Value::Array(src_arr) = srcs {
                                    for src in src_arr {
                                        if let Some(src_str) = src.as_str() {
                                            if user_groups.contains(src_str) || src_str == "*" {
                                                // Check for app with allow_bind=true
                                                if let Some(apps) = grant_obj.get("app") {
                                                    if let serde_json::Value::Object(app_obj) = apps
                                                    {
                                                        for (_app_name, caps_val) in app_obj.iter()
                                                        {
                                                            if let serde_json::Value::Array(
                                                                caps_arr,
                                                            ) = caps_val
                                                            {
                                                                for cap in caps_arr {
                                                                    if let serde_json::Value::Object(cap_obj) = cap {
                                                                        if let Some(serde_json::Value::Bool(true)) = cap_obj.get("allow_bind") {
                                                                            can_bind = true;
                                                                            break 'outer;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !can_bind {
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InsufficentAccessRights,
                        matcheddn: bind.dn.clone(),
                        message: "Bind denied by Tailscale ACL (cap map)".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }

        let otp_clone_opt: Option<objects::OtpData> = {
            if let Ok(txn) = env.begin_ro_txn() {
                let get_result = txn.get(otp_db, &bind.dn.as_bytes());
                match get_result {
                    Ok(val) => match serde_json::from_slice::<objects::OtpData>(val) {
                        Ok(otp) => Some(otp),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            } else {
                None
            }
        };

        if let Some(otp_data) = otp_clone_opt {
            // Expect a stored password_hmac and totp_secret for TOTP verification
            if let (Some(stored_pw_hmac), Some(totp_secret)) =
                (&otp_data.password_hmac, &otp_data.totp_secret)
            {
                // split provided password into `password::TOTP`
                let mut parts = password.split("::");
                let provided_pass = parts.next().unwrap_or("");
                let provided_totp = parts.next().unwrap_or("");

                if provided_pass.is_empty() || provided_totp.is_empty() {
                    // bump counters
                    {
                        let mut e = read_lockout(&env, lockout_db, &dn_key).unwrap_or_default();
                        e.failures = e.failures.saturating_add(1);
                        e.last_attempt = now;
                        if e.failures >= MAX_FAILURES {
                            e.locked_until = now + LOCKOUT_SECS;
                            e.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &dn_key, &e);

                        let mut e2 = read_lockout(&env, lockout_db, &ip_key).unwrap_or_default();
                        e2.failures = e2.failures.saturating_add(1);
                        e2.last_attempt = now;
                        if e2.failures >= MAX_FAILURES {
                            e2.locked_until = now + LOCKOUT_SECS;
                            e2.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &ip_key, &e2);
                    }
                    return vec![LdapMsg {
                        msgid,
                        op: LdapOp::BindResponse(LdapBindResponse {
                            res: LdapResult {
                                code: LdapResultCode::InvalidCredentials,
                                matcheddn: "".to_string(),
                                message: "Invalid credentials".to_string(),
                                referral: vec![],
                            },
                            saslcreds: None,
                        }),
                        ctrl: vec![],
                    }];
                }

                // verify password HMAC
                let hmac_key = match std::env::var("OTP_HMAC_KEY") {
                    Ok(k) => k,
                    Err(_) => {
                        tracing::error!("OTP_HMAC_KEY not set; cannot verify OTP");
                        return vec![LdapMsg {
                            msgid,
                            op: LdapOp::BindResponse(LdapBindResponse {
                                res: LdapResult {
                                    code: LdapResultCode::OperationsError,
                                    matcheddn: "".to_string(),
                                    message: "Server misconfiguration".to_string(),
                                    referral: vec![],
                                },
                                saslcreds: None,
                            }),
                            ctrl: vec![],
                        }];
                    }
                };
                let mut mac_pw: Hmac<Sha256> = Hmac::new_from_slice(hmac_key.as_bytes())
                    .expect("HMAC can take key of any size");
                mac_pw.update(provided_pass.as_bytes());
                let provided_hash = hex::encode(mac_pw.finalize().into_bytes());

                if provided_hash != *stored_pw_hmac {
                    // wrong password part; bump counters
                    {
                        let mut e = read_lockout(&env, lockout_db, &dn_key).unwrap_or_default();
                        e.failures = e.failures.saturating_add(1);
                        e.last_attempt = now;
                        if e.failures >= MAX_FAILURES {
                            e.locked_until = now + LOCKOUT_SECS;
                            e.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &dn_key, &e);

                        let mut e2 = read_lockout(&env, lockout_db, &ip_key).unwrap_or_default();
                        e2.failures = e2.failures.saturating_add(1);
                        e2.last_attempt = now;
                        if e2.failures >= MAX_FAILURES {
                            e2.locked_until = now + LOCKOUT_SECS;
                            e2.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &ip_key, &e2);
                    }
                    return vec![LdapMsg {
                        msgid,
                        op: LdapOp::BindResponse(LdapBindResponse {
                            res: LdapResult {
                                code: LdapResultCode::InvalidCredentials,
                                matcheddn: "".to_string(),
                                message: "Invalid credentials".to_string(),
                                referral: vec![],
                            },
                            saslcreds: None,
                        }),
                        ctrl: vec![],
                    }];
                }

                // verify TOTP (check -1, 0, +1 steps)
                fn hotp_from_counter(secret: &[u8], counter: u64) -> u32 {
                    type HmacSha1 = Hmac<Sha1>;
                    let mut msg = [0u8; 8];
                    msg.copy_from_slice(&counter.to_be_bytes());
                    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 init");
                    mac.update(&msg);
                    let digest = mac.finalize().into_bytes();
                    let offset = (digest[19] & 0x0f) as usize;
                    let code = ((digest[offset] as u32 & 0x7f) << 24)
                        | ((digest[offset + 1] as u32) << 16)
                        | ((digest[offset + 2] as u32) << 8)
                        | (digest[offset + 3] as u32);
                    code % 1_000_000
                }

                let secret_bytes_opt = base32::decode(
                    base32::Alphabet::RFC4648 { padding: false },
                    totp_secret.as_str(),
                );
                if secret_bytes_opt.is_none() {
                    return vec![LdapMsg {
                        msgid,
                        op: LdapOp::BindResponse(LdapBindResponse {
                            res: LdapResult {
                                code: LdapResultCode::OperationsError,
                                matcheddn: "".to_string(),
                                message: "Server misconfiguration".to_string(),
                                referral: vec![],
                            },
                            saslcreds: None,
                        }),
                        ctrl: vec![],
                    }];
                }

                let secret_bytes = secret_bytes_opt.unwrap();
                let t = (now / 30) as i64;
                let mut ok = false;
                for offset in -1..=1 {
                    let counter = (t + offset) as u64;
                    let v = hotp_from_counter(&secret_bytes, counter);
                    let v_str = format!("{:06}", v);
                    if v_str == provided_totp {
                        ok = true;
                        break;
                    }
                }

                if ok {
                    // clear any attempt counters for this DN/IP on success (persistent)
                    let _ = delete_lockout(&env, lockout_db, &dn_key);
                    let _ = delete_lockout(&env, lockout_db, &ip_key);
                    return vec![LdapMsg {
                        msgid,
                        op: LdapOp::BindResponse(LdapBindResponse {
                            res: LdapResult {
                                code: LdapResultCode::Success,
                                matcheddn: bind.dn.clone(),
                                message: "Bind successful".to_string(),
                                referral: vec![],
                            },
                            saslcreds: None,
                        }),
                        ctrl: vec![],
                    }];
                } else {
                    // increment failure counters for DN and IP (persistent)
                    {
                        let mut e = read_lockout(&env, lockout_db, &dn_key).unwrap_or_default();
                        e.failures = e.failures.saturating_add(1);
                        e.last_attempt = now;
                        if e.failures >= MAX_FAILURES {
                            e.locked_until = now + LOCKOUT_SECS;
                            e.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &dn_key, &e);

                        let mut e2 = read_lockout(&env, lockout_db, &ip_key).unwrap_or_default();
                        e2.failures = e2.failures.saturating_add(1);
                        e2.last_attempt = now;
                        if e2.failures >= MAX_FAILURES {
                            e2.locked_until = now + LOCKOUT_SECS;
                            e2.failures = 0;
                        }
                        let _ = write_lockout(&env, lockout_db, &ip_key, &e2);
                    }
                    return vec![LdapMsg {
                        msgid,
                        op: LdapOp::BindResponse(LdapBindResponse {
                            res: LdapResult {
                                code: LdapResultCode::InvalidCredentials,
                                matcheddn: "".to_string(),
                                message: "Invalid credentials".to_string(),
                                referral: vec![],
                            },
                            saslcreds: None,
                        }),
                        ctrl: vec![],
                    }];
                }
            } else {
                // increment failure counters for DN and IP (persistent)
                {
                    let mut e = read_lockout(&env, lockout_db, &dn_key).unwrap_or_default();
                    e.failures = e.failures.saturating_add(1);
                    e.last_attempt = now;
                    if e.failures >= MAX_FAILURES {
                        e.locked_until = now + LOCKOUT_SECS;
                        e.failures = 0;
                    }
                    let _ = write_lockout(&env, lockout_db, &dn_key, &e);

                    let mut e2 = read_lockout(&env, lockout_db, &ip_key).unwrap_or_default();
                    e2.failures = e2.failures.saturating_add(1);
                    e2.last_attempt = now;
                    if e2.failures >= MAX_FAILURES {
                        e2.locked_until = now + LOCKOUT_SECS;
                        e2.failures = 0;
                    }
                    let _ = write_lockout(&env, lockout_db, &ip_key, &e2);
                }
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::InvalidCredentials,
                            matcheddn: "".to_string(),
                            message: "Invalid credentials".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        } else {
            // increment failure counters for DN and IP (persistent)
            {
                let mut e = read_lockout(&env, lockout_db, &dn_key).unwrap_or_default();
                e.failures = e.failures.saturating_add(1);
                e.last_attempt = now;
                if e.failures >= MAX_FAILURES {
                    e.locked_until = now + LOCKOUT_SECS;
                    e.failures = 0;
                }
                let _ = write_lockout(&env, lockout_db, &dn_key, &e);

                let mut e2 = read_lockout(&env, lockout_db, &ip_key).unwrap_or_default();
                e2.failures = e2.failures.saturating_add(1);
                e2.last_attempt = now;
                if e2.failures >= MAX_FAILURES {
                    e2.locked_until = now + LOCKOUT_SECS;
                    e2.failures = 0;
                }
                let _ = write_lockout(&env, lockout_db, &ip_key, &e2);
            }
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InvalidCredentials,
                        matcheddn: "".to_string(),
                        message: "Invalid credentials".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }
    }

    return vec![LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: LdapResult {
                code: LdapResultCode::InvalidCredentials,
                matcheddn: "".to_string(),
                message: "Only simple bind with OTP code is supported".to_string(),
                referral: vec![],
            },
            saslcreds: None,
        }),
        ctrl: vec![],
    }];
}

async fn handle_search(
    tailscale: &Tailscale,
    msgid: i32,
    base_dn: &str,
    search: ldap3_proto::proto::LdapSearchRequest,
) -> Vec<LdapMsg> {
    // Check if this is a posixGroup search
    let is_posix_group_search = {
        // Look for objectClass=posixGroup in the filter
        fn filter_has_posix_group(filter: &LdapFilter) -> bool {
            match filter {
                LdapFilter::Equality(attr, val) => {
                    attr.eq_ignore_ascii_case("objectClass")
                        && val.eq_ignore_ascii_case("posixGroup")
                }
                LdapFilter::And(filters) | LdapFilter::Or(filters) => {
                    filters.iter().any(filter_has_posix_group)
                }
                LdapFilter::Not(f) => filter_has_posix_group(f),
                _ => false,
            }
        }
        filter_has_posix_group(&search.filter)
    };

    let mut entries = Vec::new();

    if is_posix_group_search {
        // Extract username from filter if possible (for memberUid)
        fn extract_username_from_filter(filter: &LdapFilter) -> Option<String> {
            match filter {
                LdapFilter::Equality(attr, val) => {
                    if attr.eq_ignore_ascii_case("memberUid") {
                        Some(val.clone())
                    } else {
                        None
                    }
                }
                LdapFilter::And(filters) | LdapFilter::Or(filters) => {
                    filters.iter().find_map(extract_username_from_filter)
                }
                LdapFilter::Not(f) => extract_username_from_filter(f),
                _ => None,
            }
        }
        let username = extract_username_from_filter(&search.filter);

        // If username is present, lookup their posix groups using the ACL cap map logic
        if let Some(username) = username {
            // Use the Tailscale API to get the user's login name
            let ts_login_name = match tailscale.list_users().await {
                Ok(users) => users
                    .into_iter()
                    .find(|u| {
                        let uid_part = u.login_name.split('@').next().unwrap_or("");
                        uid_part.eq_ignore_ascii_case(&username)
                            || u.login_name.eq_ignore_ascii_case(&username)
                    })
                    .map(|u| u.login_name)
                    .unwrap_or(username.clone()),
                Err(_) => username.clone(),
            };

            // Get the full ACL policy
            let policy = match tailscale.get_acl_policies().await {
                Ok(p) => p,
                Err(_) => serde_json::Value::Null,
            };

            // Get the ACL preview for the user
            let acl_preview = match tailscale
                .preview_acl("-", "user", &ts_login_name, policy.clone())
                .await
            {
                Ok(json) => json,
                Err(_) => serde_json::Value::Null,
            };

            // Determine user groups from preview
            let mut user_groups = std::collections::HashSet::new();
            if let serde_json::Value::Object(map) = &acl_preview {
                if let Some(matches_val) = map.get("matches") {
                    if let serde_json::Value::Array(matches_arr) = matches_val {
                        for m in matches_arr {
                            if let serde_json::Value::Object(mobj) = m {
                                if let Some(serde_json::Value::Array(users)) = mobj.get("users") {
                                    for u in users {
                                        if let Some(s) = u.as_str() {
                                            user_groups.insert(s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Extract posix_groups from matching grants/caps in the ACL policy for this user
            // Now expects posix_groups to be an array of objects: { name: ..., gidNumber: ... }
            let mut posix_groups: Vec<(String, String)> = Vec::new();
            if let serde_json::Value::Object(policy_obj) = &policy {
                if let Some(grants) = policy_obj.get("grants") {
                    if let serde_json::Value::Array(grants_arr) = grants {
                        for grant in grants_arr {
                            if let serde_json::Value::Object(grant_obj) = grant {
                                // Check src matches any user group
                                if let Some(srcs) = grant_obj.get("src") {
                                    if let serde_json::Value::Array(src_arr) = srcs {
                                        for src in src_arr {
                                            if let Some(src_str) = src.as_str() {
                                                if user_groups.contains(src_str) || src_str == "*" {
                                                    // Check for app with posix_groups
                                                    if let Some(apps) = grant_obj.get("app") {
                                                        if let serde_json::Value::Object(app_obj) =
                                                            apps
                                                        {
                                                            for (_app_name, caps_val) in
                                                                app_obj.iter()
                                                            {
                                                                if let serde_json::Value::Array(
                                                                    caps_arr,
                                                                ) = caps_val
                                                                {
                                                                    for cap in caps_arr {
                                                                        if let serde_json::Value::Object(cap_obj) = cap {
                                                                            if let Some(serde_json::Value::Array(groups)) = cap_obj.get("posix_groups") {
                                                                                for g in groups {
                                                                                    if let serde_json::Value::Object(group_obj) = g {
                                                                                        let name = group_obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                                                        let gid = group_obj.get("gidNumber").and_then(|v| v.as_i64()).map(|n| n.to_string()).unwrap_or_else(|| "0".to_string());
                                                                                        if !name.is_empty() {
                                                                                            posix_groups.push((name, gid));
                                                                                        }
                                                                                    } else if let Some(gname) = g.as_str() {
                                                                                        // Backward compatibility: if still string, use default gid
                                                                                        posix_groups.push((gname.to_string(), "0".to_string()));
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // For each posix group, emit a posixGroup entry with memberUid=username and gidNumber
            for (group, gid_number) in posix_groups {
                let dn = format!("cn={},ou=groups,{}", group, base_dn);
                let mut attrs = HashMap::new();
                attrs.insert("objectClass".to_string(), vec!["posixGroup".to_string()]);
                attrs.insert("cn".to_string(), vec![group.clone()]);
                attrs.insert("memberUid".to_string(), vec![username.clone()]);
                attrs.insert("gidNumber".to_string(), vec![gid_number.clone()]);
                let allowed_attributes: Vec<LdapPartialAttribute> = attrs
                    .into_iter()
                    .map(|(k, v)| LdapPartialAttribute {
                        atype: k,
                        vals: v.into_iter().map(|s| s.as_bytes().to_vec()).collect(),
                    })
                    .collect();
                entries.push(LdapMsg {
                    msgid,
                    op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                        dn,
                        attributes: allowed_attributes,
                    }),
                    ctrl: vec![],
                });
            }
        }
    } else {
        // Default: return regular entries
        let entries_map = objects::get_all_entries(tailscale, base_dn).await;
        for (dn, attrs) in entries_map {
            let match_dn = match search.scope {
                LdapSearchScope::Base => dn == search.base,
                LdapSearchScope::OneLevel => {
                    dn.ends_with(&search.base)
                        && dn != search.base
                        && !dn
                            .trim_end_matches(&search.base)
                            .trim_end_matches(',')
                            .contains(',')
                }
                LdapSearchScope::Subtree => dn.ends_with(&search.base),
                _ => false,
            };

            if match_dn {
                if !matches_filter(&search.filter, &attrs) {
                    continue;
                }

                let allowed_attributes: Vec<LdapPartialAttribute> = attrs
                    .into_iter()
                    .filter_map(|(k, v)| {
                        Some(LdapPartialAttribute {
                            atype: k,
                            vals: v.into_iter().map(|s| s.as_bytes().to_vec()).collect(),
                        })
                    })
                    .collect();

                entries.push(LdapMsg {
                    msgid,
                    op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                        dn: dn.to_string(),
                        attributes: allowed_attributes,
                    }),
                    ctrl: vec![],
                });
            }
        }
    }

    entries.push(LdapMsg {
        msgid,
        op: LdapOp::SearchResultDone(LdapResult {
            code: LdapResultCode::Success,
            matcheddn: "".to_string(),
            message: "".to_string(),
            referral: vec![],
        }),
        ctrl: vec![],
    });

    entries
}

pub async fn handle_request(
    env: Arc<Environment>,
    otp_db: Database,
    lockout_db: Database,
    base_dn: &str,
    req: LdapMsg,
    tailscale: &Tailscale,
    client_addr: std::net::SocketAddr,
) -> Vec<LdapMsg> {
    let msgid = req.msgid;

    let _ = match check_whois_tagged_devices(tailscale, client_addr, msgid).await {
        Ok(val) => val,
        Err(msgs) => return msgs,
    };

    // check that the request is coming from a device with the "tagged-devices" user in whois, if whois info is available
    // TODO:

    match req.op {
        LdapOp::BindRequest(bind) => {
            handle_bind(
                env,
                otp_db,
                lockout_db,
                tailscale,
                bind,
                msgid,
                base_dn,
                client_addr,
            )
            .await
        }
        LdapOp::SearchRequest(search) => handle_search(tailscale, msgid, base_dn, search).await,
        LdapOp::CompareRequest(_) => {
            vec![LdapMsg {
                msgid,
                op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res: LdapResult {
                        code: LdapResultCode::UnwillingToPerform,
                        matcheddn: "".to_string(),
                        message: "Compare operation not supported".to_string(),
                        referral: vec![],
                    },
                    name: None,
                    value: None,
                }),
                ctrl: vec![],
            }]
        }
        LdapOp::UnbindRequest => {
            vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::Success,
                        matcheddn: "".to_string(),
                        message: "".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }]
        }
        LdapOp::ExtendedRequest(ext) => {
            // STARTTLS OID: 1.3.6.1.4.1.1466.20037
            let oid = ext.name.as_str();
            if oid == "1.3.6.1.4.1.1466.20037" {
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: LdapResult {
                            code: LdapResultCode::Success,
                            matcheddn: "".to_string(),
                            message: "".to_string(),
                            referral: vec![],
                        },
                        name: Some("1.3.6.1.4.1.1466.20037".to_string()),
                        value: None,
                    }),
                    ctrl: vec![],
                }];
            }
            vec![LdapMsg {
                msgid,
                op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res: LdapResult {
                        code: LdapResultCode::ProtocolError,
                        matcheddn: "".to_string(),
                        message: "Unknown extended operation".to_string(),
                        referral: vec![],
                    },
                    name: Some(ext.name.clone()),
                    value: None,
                }),
                ctrl: vec![],
            }]
        }
        _ => {
            vec![LdapMsg {
                msgid,
                op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res: LdapResult {
                        code: LdapResultCode::ProtocolError,
                        matcheddn: "".to_string(),
                        message: "Operation not supported".to_string(),
                        referral: vec![],
                    },
                    name: None,
                    value: None,
                }),
                ctrl: vec![],
            }]
        }
    }
}
