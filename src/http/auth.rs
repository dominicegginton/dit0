use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::audit;
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
                .map_or(false, |vv| matches!(vv, serde_json::Value::Bool(true)));
        }
    }
    false
}

pub async fn require_user(request: Request, next: Next) -> Result<Response, StatusCode> {
    let whois = request.extensions().get::<LocalWhoIsResponse>();

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
                has_cap(&map, "dominicegginton.dev/cap/tsdit0", "allow_ui")
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

    let allowed = match whois {
        Some(w) => {
            if let Some(up) = &w.user_profile {
                if up.login_name == "tagged-devices" {
                    audit::http_auth_failure("tagged-devices", "tagged device denied admin UI");
                    return Ok(StatusCode::FORBIDDEN.into_response());
                }
                let cap_map = w.cap_map.clone().unwrap_or_default();
                let map: serde_json::Map<String, serde_json::Value> = cap_map.into_iter().collect();
                has_cap(&map, "dominicegginton.dev/cap/tsdit0", "allow_admin_ui")
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
