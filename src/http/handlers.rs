use super::state::AppState;
use super::views::layout;
use crate::objects;
use crate::tailscale::{User, UserClaims};
use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse},
    Extension,
};
use base32;
use base64;
use hex;
use hmac::{Hmac, Mac};
use lmdb::Transaction;
use qrcode::render::svg;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sha2::Sha256;
use urlencoding::encode as url_encode;
use v_htmlescape::escape;

#[derive(Deserialize)]
pub struct GenerateOtpForm {
    pub csrf: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeForm {
    pub csrf: Option<String>,
    pub what: Option<String>,
}

async fn render_profile(
    state: &AppState,
    user: &User,
    _claims_opt: Option<&UserClaims>,
    csrf_token: Option<&str>,
) -> String {
    let username = user
        .login_name
        .split('@')
        .next()
        .unwrap_or(&user.login_name);

    let base_dn = &state.config.base_dn;

    let attrs_option = objects::get_user_profile(&state.tailscale, base_dn, username).await;

    let mut attrs_html = String::new();
    if let Some(attrs) = attrs_option {
        // check existing OTP/password state so we can require revoke
        let mut has_password = false;
        let mut has_totp = false;
        let mut otp_opt: Option<objects::OtpData> = None;
        let dn = format!("uid={},ou=people,{}", username, base_dn);
        if let Ok(txn) = state.env.begin_ro_txn() {
            if let Ok(bytes) = txn.get(state.otp_db, &dn.as_bytes()) {
                if let Ok(otp) = serde_json::from_slice::<objects::OtpData>(bytes) {
                    if otp.password_hmac.is_some() {
                        has_password = true;
                    }
                    if otp.totp_secret.is_some() {
                        has_totp = true;
                    }
                    otp_opt = Some(otp);
                }
            }
        }

        attrs_html.push_str(&format!(
            "<p><strong>DN:</strong> {}</p>",
            escape(&format!("uid={},ou=people,{}", username, base_dn))
        ));

        attrs_html.push_str("<h3>LDAP Attributes</h3>");

        attrs_html
            .push_str("<table><thead><tr><th>Attribute</th><th>Value</th></tr></thead><tbody>");

        let mut sorted_keys: Vec<_> = attrs.keys().collect();
        sorted_keys.sort();

        let handled_keys = vec![
            "description",
            "loginShell",
            "sshPublicKey",
            "homeDirectory",
            "uidNumber",
            "gidNumber",
            "gecos",
            "userPassword",
        ];

        // Helper to get value
        let get_val = |key: &str| -> String {
            if let Some(vals) = attrs.get(key) {
                return vals.first().map(|s| s.as_str()).unwrap_or("").to_string();
            }
            "".to_string()
        };

        // Non-admin view of editable fields (Read Only)
        attrs_html.push_str(&format!(
            "<tr><td>loginShell</td><td>{}</td></tr>",
            escape(&get_val("loginShell"))
        ));
        attrs_html.push_str(&format!(
            "<tr><td>description</td><td>{}</td></tr>",
            escape(&get_val("description"))
        ));
        attrs_html.push_str(&format!(
            "<tr><td>homeDirectory</td><td>{}</td></tr>",
            escape(&get_val("homeDirectory"))
        ));
        attrs_html.push_str(&format!(
            "<tr><td>uidNumber</td><td>{}</td></tr>",
            escape(&get_val("uidNumber"))
        ));
        attrs_html.push_str(&format!(
            "<tr><td>gidNumber</td><td>{}</td></tr>",
            escape(&get_val("gidNumber"))
        ));
        attrs_html.push_str(&format!(
            "<tr><td>gecos</td><td>{}</td></tr>",
            escape(&get_val("gecos"))
        ));

        if let Some(keys) = attrs.get("sshPublicKey") {
            for key in keys {
                attrs_html.push_str(&format!(
                    "<tr><td>sshPublicKey</td><td>{}</td></tr>",
                    escape(key)
                ));
            }
        }

        for k in sorted_keys {
            if !handled_keys.contains(&k.as_str()) {
                if let Some(vals) = attrs.get(k) {
                    for v in vals {
                        attrs_html.push_str(&format!(
                            "<tr><td><strong>{}</strong></td><td>{}</td></tr>",
                            escape(k),
                            escape(v)
                        ));
                    }
                }
            }
        }

        attrs_html.push_str("</tbody></table>");

        let password_html = if has_password {
            format!(
                r#"<div style="flex:1;"><p style="margin:0 0 0.5rem 0;">A static password is already set.</p>
                <form action="/otp/revoke" method="post" onsubmit="return confirm('Revoke static password? This will remove your saved static password.')">
                    <input type="hidden" name="csrf" value="{}">
                    <input type="hidden" name="what" value="password">
                    <button type="submit">Revoke Password</button>
                </form>
                </div>"#,
                csrf_token.unwrap_or("")
            )
        } else {
            format!(
                r#"<form action="/otp/password" method="post" style="flex:1;">
                    <input type="hidden" name="csrf" value="{}">
                    <label for="password">Set a static password (will be stored hashed):</label>
                    <input type="password" name="password" id="password" required>
                    <button type="submit">Save Password</button>
                </form>"#,
                csrf_token.unwrap_or("")
            )
        };

        let generate_html = if has_totp {
            format!(
                r#"<div style="flex:1;"><p style="margin:0 0 0.5rem 0;">TOTP is already configured.</p>
                <form action="/otp/revoke" method="post" onsubmit="return confirm('Revoke TOTP configuration? This will disable existing authenticator codes.')">
                    <input type="hidden" name="csrf" value="{}">
                    <input type="hidden" name="what" value="totp">
                    <button type="submit">Revoke TOTP</button>
                </form>
                </div>"#,
                csrf_token.unwrap_or("")
            )
        } else {
            format!(
                r#"<form action="/otp/generate" method="post" style="flex:1;">
                    <input type="hidden" name="csrf" value="{}">
                    <label for="password_generate">Password (optional):</label>
                    <input type="password" name="password" id="password_generate">
                    <button type="submit">Generate TOTP</button>
                </form>"#,
                csrf_token.unwrap_or("")
            )
        };

        let status_html = if let Some(ref otp) = otp_opt {
            let mut parts: Vec<String> = Vec::new();
            parts.push(format!(
                "<div style=\"margin-bottom:0.5rem;\"><strong>Status:</strong> {}</div>",
                escape(&otp.status)
            ));
            if otp.password_hmac.is_some() {
                parts.push("<div style=\"margin-bottom:0.25rem;\">Static password: <strong>set</strong></div>".to_string());
            } else {
                parts.push("<div style=\"margin-bottom:0.25rem;\">Static password: <strong>not set</strong></div>".to_string());
            }
            if otp.totp_secret.is_some() {
                parts.push(
                    "<div style=\"margin-bottom:0.25rem;\">TOTP: <strong>configured</strong></div>"
                        .to_string(),
                );
            } else {
                parts.push("<div style=\"margin-bottom:0.25rem;\">TOTP: <strong>not configured</strong></div>".to_string());
            }
            parts.push(format!("<div style=\"font-family: monospace; font-size: 0.9rem; margin-top:0.5rem;\">Requested at (unix): {}</div>", otp.requested_at));
            format!(
                r#"<div style="background:#f9fafb;border:1px solid #e5e7eb;padding:0.75rem;margin-bottom:0.75rem;border-radius:4px;">{}</div>"#,
                parts.join("")
            )
        } else {
            "<div style=\"background:#f9fafb;border:1px solid #e5e7eb;padding:0.75rem;margin-bottom:0.75rem;border-radius:4px;\">No OTP or static password configured.</div>".to_string()
        };

        attrs_html.push_str(&format!(
            r#"
                <h3>Password and Authentication</h3>
                {}
                <div style="display: flex; gap: 1rem; align-items: flex-end;">
                    {}
                    {}
                </div>
            "#,
            status_html, password_html, generate_html
        ));
    } else {
        attrs_html.push_str("<p>No LDAP attributes found for this user.</p>");
    }

    layout(
        &format!(
            "Profile: {}",
            escape(user.display_name.as_deref().unwrap_or(""))
        ),
        &format!(
            r#"
        <div style="max-width: 600px; margin: 2rem auto; background: white; padding: 2rem;">
            <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                <img src="{}" width="64" height="64" style="border-radius: 50%; margin-right: 1rem;">
                <h2 style="font-size: 1.5rem; font-weight: bold;">{}</h2>
            </div>
            {}
        </div>
        "#,
            escape(user.profile_pic_url.as_deref().unwrap_or("")),
            escape(user.display_name.as_deref().unwrap_or("")),
            attrs_html.to_string()
        ),
    )
}

pub async fn user(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> impl IntoResponse {
    let email = claims
        .email
        .clone()
        .or(claims.email.clone())
        .unwrap_or_default();

    // Try to find the tailscale user matching this email/username
    let ts_users = state.tailscale.list_users().await.unwrap_or_default();
    let user_obj = ts_users
        .into_iter()
        .find(|u| u.login_name == email || u.login_name.starts_with(&email)); // Simplistic matching

    // generate CSRF token and set cookie
    let csrf_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    if let Some(u) = user_obj {
        let body = render_profile(&state, &u, Some(&claims), Some(&csrf_token)).await;
        let set_cookie = format!("tsdit_csrf={}; Path=/; Secure; SameSite=Strict", csrf_token);
        let csp =
            "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'";
        let hsts = "max-age=63072000; includeSubDomains; preload";
        return (
            [
                ("Set-Cookie", set_cookie.as_str()),
                ("Content-Security-Policy", csp),
                ("Strict-Transport-Security", hsts),
            ],
            Html(body),
        )
            .into_response();
    }

    (
        [
            ("Content-Security-Policy", "default-src 'self';"),
            ("Strict-Transport-Security", "max-age=63072000"),
        ],
        Html(layout(
            "Error",
            "<h1>User profile not found in Tailscale</h1><p>Please contact your administrator.</p>",
        )),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn user_otp_set_password(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<GenerateOtpForm>,
) -> impl IntoResponse {
    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();

    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    // CSRF check (double-submit cookie)
    let cookie_str = cookie.as_str();
    if let Some(form_csrf) = form.csrf.as_ref() {
        let mut found = None;
        for part in cookie_str.split(';') {
            let kv = part.trim();
            if let Some(rest) = kv.strip_prefix("tsdit_csrf=") {
                found = Some(rest.to_string());
                break;
            }
        }
        if found.is_none() || found.unwrap() != *form_csrf {
            return Html(layout("Error", "<h1>Invalid CSRF token</h1>")).into_response();
        }
    } else {
        return Html(layout("Error", "<h1>Missing CSRF token</h1>")).into_response();
    }

    // Require a password to be provided in the form
    let password_plain = form
        .password
        .as_ref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if password_plain.is_empty() {
        return Html(layout("Error", "<h1>Password required</h1>")).into_response();
    }

    // compute HMAC of the password for storage
    let hmac_key = match &state.config.otp_hmac_key {
        Some(k) if !k.is_empty() => k.clone(),
        _ => {
            tracing::error!("OTP_HMAC_KEY not configured; refusing to store password in plaintext");
            return Html(layout(
                "Error",
                "<h1>Server misconfiguration</h1><p>OTP secret not configured.</p>",
            ))
            .into_response();
        }
    };
    let mut mac_pw: Hmac<Sha256> =
        Hmac::new_from_slice(hmac_key.as_bytes()).expect("HMAC can take key of any size");
    mac_pw.update(password_plain.as_bytes());
    let result_pw = mac_pw.finalize();
    let password_hashed = hex::encode(result_pw.into_bytes());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut item_saved = false;
    // If a password already exists, require revoke first
    if let Ok(txn_ro) = state.env.begin_ro_txn() {
        if let Ok(bytes) = txn_ro.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                if existing.password_hmac.is_some() {
                    return Html(layout(
                        "Error",
                        "<h1>Password already set</h1><p>Revoke the existing password before setting a new one.</p>",
                    ))
                    .into_response();
                }
            }
        }
    }

    if let Ok(mut txn) = state.env.begin_rw_txn() {
        // attempt to read existing
        let mut otp_data = None;
        if let Ok(bytes) = txn.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                otp_data = Some(existing);
            }
        }
        let new_data = if let Some(mut d) = otp_data {
            d.password_hmac = Some(password_hashed);
            d.requested_at = now;
            d
        } else {
            objects::OtpData {
                status: "password-only".to_string(),
                code: None,
                expiry: None,
                requested_at: now,
                device_info: None,
                totp_secret: None,
                password_hmac: Some(password_hashed),
            }
        };
        if let Ok(val) = serde_json::to_vec(&new_data) {
            if let Ok(_) = txn.put(
                state.otp_db,
                &dn.as_bytes(),
                &val,
                ::lmdb::WriteFlags::empty(),
            ) {
                if let Ok(_) = txn.commit() {
                    item_saved = true;
                }
            }
        }
    }

    if item_saved {
        Html(layout(
            "Saved",
            "<h1>Password saved</h1><p>Your static password has been updated.</p>",
        ))
        .into_response()
    } else {
        Html(layout("Error", "<h1>Failed to save password</h1>")).into_response()
    }
}

#[axum::debug_handler]
pub async fn user_otp_revoke(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<RevokeForm>,
) -> impl IntoResponse {
    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();

    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    // CSRF check
    let cookie_str = cookie.as_str();
    if let Some(form_csrf) = form.csrf.as_ref() {
        let mut found = None;
        for part in cookie_str.split(';') {
            let kv = part.trim();
            if let Some(rest) = kv.strip_prefix("tsdit_csrf=") {
                found = Some(rest.to_string());
                break;
            }
        }
        if found.is_none() || found.unwrap() != *form_csrf {
            return Html(layout("Error", "<h1>Invalid CSRF token</h1>")).into_response();
        }
    } else {
        return Html(layout("Error", "<h1>Missing CSRF token</h1>")).into_response();
    }

    let what = form.what.as_ref().map(|s| s.as_str()).unwrap_or("");

    let mut done = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if let Ok(bytes) = txn.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(mut existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                match what {
                    "password" => {
                        existing.password_hmac = None;
                        if existing.totp_secret.is_none() {
                            if let Ok(_) = txn.del(state.otp_db, &dn.as_bytes(), None) {
                                if let Ok(_) = txn.commit() {
                                    done = true;
                                }
                            }
                        } else if let Ok(val) = serde_json::to_vec(&existing) {
                            if let Ok(_) = txn.put(
                                state.otp_db,
                                &dn.as_bytes(),
                                &val,
                                ::lmdb::WriteFlags::empty(),
                            ) {
                                if let Ok(_) = txn.commit() {
                                    done = true;
                                }
                            }
                        }
                    }
                    "totp" => {
                        existing.totp_secret = None;
                        existing.status = "revoked".to_string();
                        if existing.password_hmac.is_none() {
                            if let Ok(_) = txn.del(state.otp_db, &dn.as_bytes(), None) {
                                if let Ok(_) = txn.commit() {
                                    done = true;
                                }
                            }
                        } else if let Ok(val) = serde_json::to_vec(&existing) {
                            if let Ok(_) = txn.put(
                                state.otp_db,
                                &dn.as_bytes(),
                                &val,
                                ::lmdb::WriteFlags::empty(),
                            ) {
                                if let Ok(_) = txn.commit() {
                                    done = true;
                                }
                            }
                        }
                    }
                    _ => {
                        // invalid request
                    }
                }
            }
        }
    }

    if done {
        Html(layout(
            "Revoked",
            "<h1>Revoked</h1><p>The requested credential was revoked.</p>",
        ))
        .into_response()
    } else {
        Html(layout("Error", "<h1>Failed to revoke</h1>")).into_response()
    }
}

#[axum::debug_handler]
pub async fn user_otp_generate(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<GenerateOtpForm>,
) -> impl IntoResponse {
    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();

    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // CSRF check (double-submit cookie)
    let cookie_str = cookie.as_str();
    if let Some(form_csrf) = form.csrf.as_ref() {
        let mut found = None;
        for part in cookie_str.split(';') {
            let kv = part.trim();
            if let Some(rest) = kv.strip_prefix("tsdit_csrf=") {
                found = Some(rest.to_string());
                break;
            }
        }
        if found.is_none() || found.unwrap() != *form_csrf {
            return Html(layout("Error", "<h1>Invalid CSRF token</h1>")).into_response();
        }
    } else {
        return Html(layout("Error", "<h1>Missing CSRF token</h1>")).into_response();
    }

    // If a TOTP already exists, require revoke first
    if let Ok(txn_ro) = state.env.begin_ro_txn() {
        if let Ok(bytes) = txn_ro.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                if existing.totp_secret.is_some() {
                    return Html(layout(
                        "Error",
                        "<h1>TOTP already configured</h1><p>Revoke the existing TOTP configuration before generating a new one.</p>",
                    ))
                    .into_response();
                }
            }
        }
    }

    // Per-user TOTP: no per-device binding required. Store as user-global.
    let mut device_info: Option<String> = None;

    // Password is optional for generating TOTP. If provided, compute HMAC for storage.
    let password_plain_opt = form.password.as_ref().map(|s| s.trim().to_string());
    let password_hashed_opt: Option<String> =
        if let Some(pw) = password_plain_opt.as_ref().filter(|s| !s.is_empty()) {
            // compute HMAC of the password for storage
            let hmac_key = match &state.config.otp_hmac_key {
                Some(k) if !k.is_empty() => k.clone(),
                _ => {
                    tracing::error!(
                        "OTP_HMAC_KEY not configured; refusing to store password in plaintext"
                    );
                    return Html(layout(
                        "Error",
                        "<h1>Server misconfiguration</h1><p>OTP secret not configured.</p>",
                    ))
                    .into_response();
                }
            };
            let mut mac_pw: Hmac<Sha256> =
                Hmac::new_from_slice(hmac_key.as_bytes()).expect("HMAC can take key of any size");
            mac_pw.update(pw.as_bytes());
            let result_pw = mac_pw.finalize();
            Some(hex::encode(result_pw.into_bytes()))
        } else {
            None
        };

    // generate a random 20-byte secret and encode as Base32 RFC4648 without padding
    let mut secret_bytes = [0u8; 20];
    rand::thread_rng().fill(&mut secret_bytes);
    let mut secret_b32 =
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    // Build otpauth URL for authenticator apps
    let otpauth = format!(
        "otpauth://totp/DIT:{}?secret={}&issuer=dit0&period=30&digits=6",
        username, secret_b32
    );

    let otp_data = objects::OtpData {
        status: "configured".to_string(),
        code: None,
        expiry: None,
        requested_at: now,
        device_info,
        totp_secret: Some(secret_b32.clone()),
        password_hmac: password_hashed_opt,
    };

    let val = match serde_json::to_vec(&otp_data) {
        Ok(v) => v,
        Err(_) => return Html("<h1>Error generating OTP</h1>".to_string()).into_response(),
    };

    let mut item_added = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if let Ok(_) = txn.put(
            state.otp_db,
            &dn.as_bytes(),
            &val,
            ::lmdb::WriteFlags::empty(),
        ) {
            if let Ok(_) = txn.commit() {
                item_added = true;
            }
        }
    }

    if item_added {
        // Google Chart URL (logged for debugging)
        let qr_src = format!(
            "https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl={}",
            url_encode(&otpauth)
        );

        // Also generate an embedded SVG QR and serve as data URI so the UI
        // doesn't depend on external services.
        let svg = match QrCode::new(otpauth.as_bytes()) {
            Ok(code) => code.render::<svg::Color>().min_dimensions(200, 200).build(),
            Err(e) => {
                tracing::error!("Failed to render QR SVG: {}", e);
                String::new()
            }
        };
        let data_uri = if !svg.is_empty() {
            let b64 = base64::encode(svg.as_bytes());
            format!("data:image/svg+xml;base64,{}", b64)
        } else {
            // fallback to external URL
            qr_src.clone()
        };

        Html(layout("TOTP Setup", &format!(
            r#"
            <div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <h2 style="font-size: 1.5rem; font-weight: bold; margin-bottom: 1rem;">TOTP Setup</h2>
                <p style="margin-bottom: 1rem;">Scan this QR in your authenticator app, or enter the secret manually.</p>
                <div style="text-align:center; margin-bottom: 1rem;"><img src="{}" alt="TOTP QR"></div>
                <div style="background: #f3f4f6; padding: 1rem; font-family: monospace; font-size: 1.0rem; text-align: center; border: 1px solid #e5e7eb; border-radius: 4px; margin-bottom: 1rem;">{}</div>
                <p style="color: #6b7280; font-size: 0.875rem; margin-bottom: 1.5rem;">When logging via LDAP, provide your password and the 6-digit TOTP separated by `::`, for example: <code>mypassword::123456</code></p>
                <a href="/" style="display: block; text-align: center; color: #2563eb; text-decoration: none;">Back to Profile</a>
            </div>
            "#,
            data_uri,
            secret_b32
        ))).into_response()
    } else {
        Html(layout(
            "Error",
            "<h1>Failed to save TOTP configuration</h1>",
        ))
        .into_response()
    }
}
