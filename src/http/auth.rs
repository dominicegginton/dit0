use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::audit;
use crate::http::state::AppState;
use crate::tailscale::LocalWhoIsResponse;

fn has_cap(
    cap_map: &serde_json::Map<String, serde_json::Value>,
    cap_key: &str,
    required_field: &str,
) -> bool {
    if let Some(v) = cap_map.get(cap_key) {
        if let serde_json::Value::Array(arr) = v {
            for item in arr {
                if let serde_json::Value::Object(obj) = item {
                    if let Some(serde_json::Value::Bool(true)) = obj.get(required_field) {
                        return true;
                    }
                }
            }
        } else if let serde_json::Value::Object(obj) = v {
            return obj
                .get(required_field)
                .is_some_and(|vv| matches!(vv, serde_json::Value::Bool(true)));
        }
    }
    false
}

async fn check_cap_from_policy(
    state: &AppState,
    login_name: &str,
    required_field: &str,
) -> bool {
    let policy = match state.tailscale.get_acl_policies().await {
        Ok(p) => p,
        Err(_) => return false,
    };

    let acl_preview = match state
        .tailscale
        .preview_acl(&state.config.ts_id, "user", login_name, policy.clone())
        .await
    {
        Ok(json) => json,
        Err(_) => return false,
    };

    let mut user_groups = std::collections::HashSet::new();
    user_groups.insert(login_name.to_string());
    if let Some(uid_part) = login_name.split('@').next() {
        user_groups.insert(uid_part.to_string());
    }
    if let serde_json::Value::Object(map) = &acl_preview {
        if let Some(serde_json::Value::Array(matches_arr)) = map.get("matches") {
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

    if let serde_json::Value::Object(policy_obj) = &policy {
        if let Some(serde_json::Value::Array(grants_arr)) = policy_obj.get("grants") {
            for grant in grants_arr {
                if let serde_json::Value::Object(grant_obj) = grant {
                    let mut src_match = false;
                    if let Some(serde_json::Value::Array(src_arr)) = grant_obj.get("src") {
                        for src in src_arr {
                            if let Some(src_str) = src.as_str() {
                                if user_groups.contains(src_str) || src_str == "*" {
                                    src_match = true;
                                    break;
                                }
                            }
                        }
                    }
                    if !src_match {
                        continue;
                    }
                    if let Some(serde_json::Value::Object(app_obj)) = grant_obj.get("app") {
                        for (_app_name, caps_val) in app_obj.iter() {
                            if let serde_json::Value::Array(caps_arr) = caps_val {
                                for cap in caps_arr {
                                    if let serde_json::Value::Object(cap_obj) = cap {
                                        if matches!(
                                            cap_obj.get(required_field),
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

pub async fn require_user(request: Request, next: Next) -> Result<Response, StatusCode> {
    let whois = request.extensions().get::<LocalWhoIsResponse>();
    let state = request.extensions().get::<AppState>();

    let path = request.uri().path().to_string();

    let allowed = match whois {
        Some(w) => {
            if let Some(up) = &w.user_profile {
                if up.login_name == "tagged-devices" {
                    audit::http_auth_failure("tagged-devices", "tagged device denied UI access");
                    return Ok(StatusCode::FORBIDDEN.into_response());
                }
                let cap_map = w.cap_map.clone().unwrap_or_default();
                let map: serde_json::Map<String, serde_json::Value> = cap_map.into_iter().collect();
                if has_cap(&map, "dominicegginton.dev/cap/tsdit0", "allow_ui") {
                    true
                } else if let Some(st) = state {
                    check_cap_from_policy(st, &up.login_name, "allow_ui").await
                } else {
                    false
                }
            } else {
                false
            }
        }
        None => false,
    };

    if allowed {
        Ok(next.run(request).await)
    } else {
        let peer = whois
            .and_then(|w| w.user_profile.as_ref())
            .map(|up| up.login_name.as_str())
            .unwrap_or("unknown");
        audit::http_auth_failure(peer, &format!("denied access to {}", path));
        Ok(StatusCode::FORBIDDEN.into_response())
    }
}

pub async fn require_allow_admin_ui(request: Request, next: Next) -> Result<Response, StatusCode> {
    let whois = request.extensions().get::<LocalWhoIsResponse>();
    let state = request.extensions().get::<AppState>();

    let allowed = match whois {
        Some(w) => {
            if let Some(up) = &w.user_profile {
                if up.login_name == "tagged-devices" {
                    audit::http_auth_failure("tagged-devices", "tagged device denied admin UI");
                    return Ok(StatusCode::FORBIDDEN.into_response());
                }
                let cap_map = w.cap_map.clone().unwrap_or_default();
                let map: serde_json::Map<String, serde_json::Value> = cap_map.into_iter().collect();
                if has_cap(&map, "dominicegginton.dev/cap/tsdit0", "allow_admin_ui") {
                    true
                } else if let Some(st) = state {
                    check_cap_from_policy(st, &up.login_name, "allow_admin_ui").await
                } else {
                    false
                }
            } else {
                false
            }
        }
        None => false,
    };

    if allowed {
        Ok(next.run(request).await)
    } else {
        let peer = whois
            .and_then(|w| w.user_profile.as_ref())
            .map(|up| up.login_name.as_str())
            .unwrap_or("unknown");
        audit::http_auth_failure(peer, "denied access to admin UI");
        Ok(StatusCode::FORBIDDEN.into_response())
    }
}
