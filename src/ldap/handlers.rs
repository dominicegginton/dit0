use crate::config::Config;
use crate::objects;
use crate::tailscale::LocalWhoIsResponse;
use crate::tailscale::Tailscale;
use crate::yubikey::{self, YubikeyValidator};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindResponse, LdapExtendedResponse, LdapFilter, LdapMsg, LdapOp,
    LdapPartialAttribute, LdapResult, LdapResultCode, LdapSearchResultEntry, LdapSearchScope,
};
use lmdb::{Database, Environment, Transaction};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

use super::schemas;
use crate::audit;

// ── Shared ACL helpers ──────────────────────────────────────────────────────

/// Extract group identifiers that a user belongs to from an ACL preview response.
fn extract_user_groups(acl_preview: &serde_json::Value) -> std::collections::HashSet<String> {
    let mut groups = std::collections::HashSet::new();
    if let serde_json::Value::Object(map) = acl_preview {
        if let Some(serde_json::Value::Array(matches_arr)) = map.get("matches") {
            for m in matches_arr {
                if let serde_json::Value::Object(mobj) = m {
                    if let Some(serde_json::Value::Array(users)) = mobj.get("users") {
                        for u in users {
                            if let Some(s) = u.as_str() {
                                groups.insert(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    groups
}

/// Check whether any matching grant has a cap with `allow_bind = true`.
fn check_allow_bind(
    policy: &serde_json::Value,
    user_groups: &std::collections::HashSet<String>,
) -> bool {
    if let serde_json::Value::Object(policy_obj) = policy {
        if let Some(serde_json::Value::Array(grants_arr)) = policy_obj.get("grants") {
            for grant in grants_arr {
                if let serde_json::Value::Object(grant_obj) = grant {
                    if !grant_src_matches(grant_obj, user_groups) {
                        continue;
                    }
                    if let Some(serde_json::Value::Object(app_obj)) = grant_obj.get("app") {
                        for (_app_name, caps_val) in app_obj.iter() {
                            if let serde_json::Value::Array(caps_arr) = caps_val {
                                for cap in caps_arr {
                                    if let serde_json::Value::Object(cap_obj) = cap {
                                        if matches!(
                                            cap_obj.get("allow_bind"),
                                            Some(serde_json::Value::Bool(true))
                                        ) {
                                            return true;
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
    false
}

/// Extract posix groups (name, gidNumber) from grants whose src matches the user.
fn extract_posix_groups(
    policy: &serde_json::Value,
    user_groups: &std::collections::HashSet<String>,
) -> Vec<(String, String)> {
    let mut posix_groups = Vec::new();
    if let serde_json::Value::Object(policy_obj) = policy {
        if let Some(serde_json::Value::Array(grants_arr)) = policy_obj.get("grants") {
            for grant in grants_arr {
                if let serde_json::Value::Object(grant_obj) = grant {
                    if !grant_src_matches(grant_obj, user_groups) {
                        continue;
                    }
                    if let Some(serde_json::Value::Object(app_obj)) = grant_obj.get("app") {
                        for (_app_name, caps_val) in app_obj.iter() {
                            if let serde_json::Value::Array(caps_arr) = caps_val {
                                for cap in caps_arr {
                                    if let serde_json::Value::Object(cap_obj) = cap {
                                        if let Some(serde_json::Value::Array(groups)) =
                                            cap_obj.get("posix_groups")
                                        {
                                            for g in groups {
                                                if let serde_json::Value::Object(group_obj) = g {
                                                    let name = group_obj
                                                        .get("name")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("")
                                                        .to_string();
                                                    let gid = group_obj
                                                        .get("gidNumber")
                                                        .and_then(|v| v.as_i64())
                                                        .map(|n| n.to_string())
                                                        .unwrap_or_else(|| "0".to_string());
                                                    if !name.is_empty() {
                                                        posix_groups.push((name, gid));
                                                    }
                                                } else if let Some(gname) = g.as_str() {
                                                    posix_groups
                                                        .push((gname.to_string(), "0".to_string()));
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
    posix_groups
}

/// Check if any src in a grant object matches the user's group set.
fn grant_src_matches(
    grant_obj: &serde_json::Map<String, serde_json::Value>,
    user_groups: &std::collections::HashSet<String>,
) -> bool {
    if let Some(serde_json::Value::Array(src_arr)) = grant_obj.get("src") {
        for src in src_arr {
            if let Some(src_str) = src.as_str() {
                if user_groups.contains(src_str) || src_str == "*" {
                    return true;
                }
            }
        }
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
                    .map(|u| u.display_name.clone())
                {
                    if name != "Tagged Devices" && name != "Dominic Egginton" {
                        return Err(vec![LdapMsg {
                            msgid,
                            op: LdapOp::BindResponse(LdapBindResponse {
                                res: LdapResult {
                                    code: LdapResultCode::OperationsError,
                                    matcheddn: "".to_string(),
                                    message: format!("Unexpected whois response '{}'; contact administrator", name),
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
#[allow(clippy::too_many_arguments)]
async fn handle_bind(
    env: Arc<Environment>,
    yubikey_db: Database,
    yubikey_validator: &Arc<YubikeyValidator>,
    tailscale: &Tailscale,
    config: &Config,
    bind: ldap3_proto::proto::LdapBindRequest,
    msgid: i32,
    base_dn: &str,
    client_addr: std::net::SocketAddr,
) -> Vec<LdapMsg> {
    if bind.cred == LdapBindCred::Simple("".to_string()) && bind.dn.is_empty() {
        audit::ldap_bind_anonymous(client_addr);
        return vec![LdapMsg {
            msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
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
        // Resolve user identity from bind.dn (which could be uid=..., tsTailnetId=..., mail=..., cn=..., or raw Tailnet ID / username)
        let raw_identity = if bind.dn.contains('=') {
            bind.dn
                .split(',')
                .find_map(|p| {
                    let p_trimmed = p.trim();
                    let p_lower = p_trimmed.to_lowercase();
                    if p_lower.starts_with("uid=") {
                        Some(p_trimmed[4..].trim().to_string())
                    } else if p_lower.starts_with("tstailnetid=") {
                        Some(p_trimmed[12..].trim().to_string())
                    } else if p_lower.starts_with("mail=") {
                        Some(p_trimmed[5..].trim().to_string())
                    } else if p_lower.starts_with("cn=") {
                        Some(p_trimmed[3..].trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| bind.dn.clone())
        } else {
            bind.dn.trim().to_string()
        };

        let ts_users = tailscale.cached_list_users().await.unwrap_or_default();
        let matched_user = ts_users.into_iter().find(|u| {
            let uid_part = u.login_name.split('@').next().unwrap_or("");
            uid_part.eq_ignore_ascii_case(&raw_identity)
                || u.login_name.eq_ignore_ascii_case(&raw_identity)
                || (!u.tailnet_id.is_empty() && u.tailnet_id.eq_ignore_ascii_case(&raw_identity))
                || (!u.id.is_empty() && u.id.eq_ignore_ascii_case(&raw_identity))
        });

        let user = match matched_user {
            Some(u) => u,
            None => {
                audit::ldap_bind_failure(client_addr, &bind.dn, "user not found in Tailscale");
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
        };

        let canonical_uid = user
            .login_name
            .split('@')
            .next()
            .unwrap_or(&user.login_name);
        let user_dn = format!("uid={},ou=people,{}", canonical_uid, base_dn);

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
            .preview_acl(&config.ts_id, "user", &user.login_name, policy.clone())
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

        let user_groups = extract_user_groups(&acl_preview);
        if !check_allow_bind(&policy, &user_groups) {
            audit::ldap_bind_failure(client_addr, &user_dn, "denied by ACL cap map");
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InsufficentAccessRights,
                        matcheddn: user_dn,
                        message: "Bind denied by Tailscale ACL (cap map)".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }

        let trimmed_password = password.trim();
        if !yubikey::is_valid_otp(trimmed_password) {
            audit::ldap_bind_failure(client_addr, &user_dn, "invalid YubiKey OTP format");
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InvalidCredentials,
                        matcheddn: "".to_string(),
                        message: "Invalid credentials: valid YubiKey OTP required".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }

        let public_id = match yubikey::extract_public_id(trimmed_password) {
            Some(id) => id,
            None => {
                audit::ldap_bind_failure(client_addr, &user_dn, "could not extract YubiKey public ID");
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
        };

        let creds_opt: Option<objects::UserCredentials> = {
            if let Ok(txn) = env.begin_ro_txn() {
                txn.get(yubikey_db, &user_dn.as_bytes())
                    .ok()
                    .and_then(|val| serde_json::from_slice::<objects::UserCredentials>(val).ok())
            } else {
                None
            }
        };

        let creds = match creds_opt {
            Some(c) if !c.keys.is_empty() => c,
            _ => {
                audit::ldap_bind_failure(client_addr, &user_dn, "no registered YubiKeys for user");
                return vec![LdapMsg {
                    msgid,
                    op: LdapOp::BindResponse(LdapBindResponse {
                        res: LdapResult {
                            code: LdapResultCode::InvalidCredentials,
                            matcheddn: "".to_string(),
                            message: "Invalid credentials: no YubiKeys registered".to_string(),
                            referral: vec![],
                        },
                        saslcreds: None,
                    }),
                    ctrl: vec![],
                }];
            }
        };

        if !creds.keys.iter().any(|k| k.public_id == public_id) {
            audit::ldap_bind_failure(
                client_addr,
                &user_dn,
                &format!("unregistered YubiKey public ID: {}", public_id),
            );
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InvalidCredentials,
                        matcheddn: "".to_string(),
                        message: "Invalid credentials: YubiKey not registered to user".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }

        if let Err(e) = yubikey_validator.verify_otp(trimmed_password).await {
            audit::ldap_bind_failure(
                client_addr,
                &user_dn,
                &format!("YubiKey OTP validation failed: {}", e),
            );
            return vec![LdapMsg {
                msgid,
                op: LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::InvalidCredentials,
                        matcheddn: "".to_string(),
                        message: "Invalid credentials: OTP validation failed".to_string(),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            }];
        }

        audit::ldap_bind_success(client_addr, &user_dn, "yubikey");
        return vec![LdapMsg {
            msgid,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: user_dn,
                    message: "Bind successful".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            }),
            ctrl: vec![],
        }];
    }

    audit::ldap_bind_failure(client_addr, &bind.dn, "no password/OTP provided");
    vec![LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: LdapResult {
                code: LdapResultCode::InvalidCredentials,
                matcheddn: "".to_string(),
                message: "Simple or SASL PLAIN bind with YubiKey OTP is required".to_string(),
                referral: vec![],
            },
            saslcreds: None,
        }),
        ctrl: vec![],
    }]
}

/// Convert an LDAP search scope to a human-readable string for audit logs.
fn scope_str(scope: &LdapSearchScope) -> &'static str {
    match scope {
        LdapSearchScope::Base => "base",
        LdapSearchScope::OneLevel => "one",
        LdapSearchScope::Subtree => "sub",
        _ => "unknown",
    }
}

async fn handle_search(
    tailscale: &Tailscale,
    config: &Config,
    msgid: i32,
    base_dn: &str,
    search: ldap3_proto::proto::LdapSearchRequest,
    req_controls: &[LdapControl],
    client_addr: std::net::SocketAddr,
) -> Vec<LdapMsg> {
    // ── Subschema Subentry (RFC 4512 §4.2) ──────────────────────────────────
    // Match base-scope queries on "cn=Subschema" (case-insensitive).
    if matches!(search.scope, LdapSearchScope::Base)
        && search.base.eq_ignore_ascii_case("cn=Subschema")
    {
        let attrs = schemas::filter_subschema_attributes(&search.attrs);
        return vec![
            LdapMsg {
                msgid,
                op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=Subschema".to_string(),
                    attributes: attrs,
                }),
                ctrl: vec![],
            },
            LdapMsg {
                msgid,
                op: LdapOp::SearchResultDone(LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                }),
                ctrl: vec![],
            },
        ];
    }

    // ── Reject searches outside the base DN subtree (RFC 4511 §4.5.1) ────
    // Subschema and RootDSE are handled above; everything else must be
    // the base_dn itself or fall beneath it.  Return NoSuchObject so
    // Windows clients don't hang waiting for referrals.
    if !search.base.is_empty()
        && !search.base.eq_ignore_ascii_case(base_dn)
        && !search
            .base
            .to_ascii_lowercase()
            .ends_with(&format!(",{}", base_dn.to_ascii_lowercase()))
    {
        return vec![LdapMsg {
            msgid,
            op: LdapOp::SearchResultDone(LdapResult {
                code: LdapResultCode::NoSuchObject,
                matcheddn: base_dn.to_string(),
                message: "Object not found within this naming context".to_string(),
                referral: vec![],
            }),
            ctrl: vec![],
        }];
    }

    // ── RootDSE (RFC 4512 §5.1) ────────────────────────────────────────────
    if search.base.is_empty() && matches!(search.scope, LdapSearchScope::Base) {
        let attrs = vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec()],
            },
            LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![base_dn.as_bytes().to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedSASLMechanisms".to_string(),
                vals: vec![b"PLAIN".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec![b"1.3.6.1.4.1.1466.20037".to_vec()], // StartTLS
            },
            LdapPartialAttribute {
                atype: "supportedControl".to_string(),
                vals: vec![b"1.2.840.113556.1.4.319".to_vec()], // Simple Paged Results (RFC 2696)
            },
            LdapPartialAttribute {
                atype: "supportedFeatures".to_string(),
                vals: vec![
                    b"1.3.6.1.4.1.4203.1.5.1".to_vec(), // All Operational Attributes
                ],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![b"cn=Subschema".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"dit0".to_vec()],
            },
            LdapPartialAttribute {
                atype: "defaultNamingContext".to_string(),
                vals: vec![base_dn.as_bytes().to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![b"1.0.0".to_vec()],
            },
        ];

        return vec![
            LdapMsg {
                msgid,
                op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "".to_string(),
                    attributes: attrs,
                }),
                ctrl: vec![],
            },
            LdapMsg {
                msgid,
                op: LdapOp::SearchResultDone(LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                }),
                ctrl: vec![],
            },
        ];
    }

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
                .preview_acl(&config.ts_id, "user", &ts_login_name, policy.clone())
                .await
            {
                Ok(json) => json,
                Err(_) => serde_json::Value::Null,
            };

            let user_groups = extract_user_groups(&acl_preview);
            let posix_groups = extract_posix_groups(&policy, &user_groups);

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
                    .map(|(k, v)| {
                        LdapPartialAttribute {
                            atype: k,
                            vals: v.into_iter().map(|s| s.as_bytes().to_vec()).collect(),
                        }
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

    // ── RFC 2696 Simple Paged Results ──────────────────────────────────────
    // If the client sent a SimplePagedResults control, page the result set.
    let paging = req_controls.iter().find_map(|c| match c {
        LdapControl::SimplePagedResults { size, cookie } => Some((*size, cookie.clone())),
        _ => None,
    });

    let (result_entries, done_ctrl) = if let Some((page_size, cookie)) = paging {
        let page_size = if page_size <= 0 {
            entries.len()
        } else {
            page_size as usize
        };

        // Cookie encodes the offset as a big-endian u32.  Empty cookie = start.
        let cookie: &Vec<u8> = &cookie;
        let offset: usize = if cookie.is_empty() {
            0
        } else if cookie.len() == 4 {
            u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]) as usize
        } else {
            0usize
        };

        let total = entries.len();
        let end = std::cmp::min(offset + page_size, total);
        let page: Vec<LdapMsg> = entries.into_iter().skip(offset).take(page_size).collect();

        // Return cookie = empty when we've sent all results; otherwise encode
        // the next offset.
        let next_cookie = if end >= total {
            vec![]
        } else {
            (end as u32).to_be_bytes().to_vec()
        };

        let remaining = if end >= total {
            0i64
        } else {
            (total - end) as i64
        };

        (
            page,
            vec![LdapControl::SimplePagedResults {
                size: remaining,
                cookie: next_cookie,
            }],
        )
    } else {
        (entries, vec![])
    };

    let mut result: Vec<LdapMsg> = result_entries;

    // Count search result entries (excluding the final SearchResultDone).
    let result_count = result.len();
    audit::ldap_search(
        client_addr,
        &search.base,
        scope_str(&search.scope),
        &format!("{:?}", search.filter),
        result_count,
    );

    result.push(LdapMsg {
        msgid,
        op: LdapOp::SearchResultDone(LdapResult {
            code: LdapResultCode::Success,
            matcheddn: "".to_string(),
            message: "".to_string(),
            referral: vec![],
        }),
        ctrl: done_ctrl,
    });

    result
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_request(
    env: Arc<Environment>,
    yubikey_db: Database,
    yubikey_validator: &Arc<YubikeyValidator>,
    base_dn: &str,
    req: LdapMsg,
    tailscale: &Tailscale,
    config: &Config,
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
                yubikey_db,
                yubikey_validator,
                tailscale,
                config,
                bind,
                msgid,
                base_dn,
                client_addr,
            )
            .await
        }
        LdapOp::SearchRequest(search) => {
            handle_search(
                tailscale,
                config,
                msgid,
                base_dn,
                search,
                &req.ctrl,
                client_addr,
            )
            .await
        }
        LdapOp::CompareRequest(_) => {
            audit::ldap_unsupported_op(client_addr, "compare");
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
            audit::ldap_unsupported_op(client_addr, "unknown");
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
