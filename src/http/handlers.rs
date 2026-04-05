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
use rand::Rng;
use serde::Deserialize;
use sha2::Sha256;
use v_htmlescape::escape;

#[derive(Deserialize)]
pub struct SetupForm {
    pub csrf: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub csrf: Option<String>,
}

fn verify_csrf(cookie: &str, form_csrf: Option<&String>) -> Result<(), Html<String>> {
    let form_csrf =
        form_csrf.ok_or_else(|| Html(layout("Error", "<h1>Missing CSRF token</h1>")))?;
    let cookie_csrf = cookie
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("tsdit_csrf="))
        .next();
    match cookie_csrf {
        Some(val) if val == form_csrf => Ok(()),
        _ => Err(Html(layout("Error", "<h1>Invalid CSRF token</h1>"))),
    }
}

async fn render_profile(state: &AppState, user: &User, csrf_token: Option<&str>) -> String {
    let username = user
        .login_name
        .split('@')
        .next()
        .unwrap_or(&user.login_name);

    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let otp_opt: Option<objects::OtpData> = state.env.begin_ro_txn().ok().and_then(|txn| {
        txn.get(state.otp_db, &dn.as_bytes())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<objects::OtpData>(bytes).ok())
    });

    let is_configured = otp_opt
        .as_ref()
        .map(|o| o.password_hmac.is_some() && o.totp_secret.is_some())
        .unwrap_or(false);

    let csrf = csrf_token.unwrap_or("");

    let body = if is_configured {
        format!(
            r#"<p>Your password and TOTP are configured for LDAP authentication.</p>
            <p>When logging in to LDAP-bound devices, enter your password and 6-digit TOTP code separated by <code>::</code></p>
            <p>For example: <code>mypassword::123456</code></p>
            <form action="/credentials/reset" method="post" style="margin-top: 1rem;" onsubmit="return confirm('This will remove your current password and TOTP. You will need to set them up again.')">
                <input type="hidden" name="csrf" value="{}">
                <button type="submit">Reset Credentials</button>
            </form>"#,
            csrf
        )
    } else {
        format!(
            r#"<p>Set a password to configure LDAP authentication. A TOTP secret will be generated automatically.</p>
            <form action="/credentials/setup" method="post" style="margin-top: 1rem;">
                <input type="hidden" name="csrf" value="{}">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required>
                <button type="submit">Setup Credentials</button>
            </form>"#,
            csrf
        )
    };

    layout(
        &format!(
            "Profile: {}",
            escape(user.display_name.as_deref().unwrap_or(""))
        ),
        &format!(
            r#"
            <div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                    <img src="{}" width="64" height="64" style="border-radius: 50%; margin-right: 1rem;">
                    <div>
                        <h2 style="font-size: 1.5rem; font-weight: bold;">{}</h2>
                        <p>{}</p>
                    </div>
                </div>
                <h3>LDAP Credentials</h3>
                {}
            </div>
            "#,
            escape(user.profile_pic_url.as_deref().unwrap_or("")),
            escape(user.display_name.as_deref().unwrap_or("")),
            escape(&format!("uid={},ou=people,{}", username, base_dn)),
            body
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

    let ts_users = state.tailscale.list_users().await.unwrap_or_default();
    let user_obj = ts_users
        .into_iter()
        .find(|u| u.login_name == email || u.login_name.starts_with(&email));

    let csrf_token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    if let Some(u) = user_obj {
        let body = render_profile(&state, &u, Some(&csrf_token)).await;
        let set_cookie = format!("tsdit_csrf={}; Path=/; Secure; SameSite=Strict", csrf_token);
        return (
            [
                ("Set-Cookie", set_cookie.as_str()),
                ("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'"),
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
            ],
            Html(body),
        )
            .into_response();
    }

    (
        [
            ("Content-Security-Policy", "default-src 'self';"),
            ("Strict-Transport-Security", "max-age=63072000"),
            ("Set-Cookie", ""),
        ],
        Html(layout(
            "Error",
            "<h1>User not found</h1><p>Please contact your administrator.</p>",
        )),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn credentials_setup(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<SetupForm>,
) -> impl IntoResponse {
    if let Err(e) = verify_csrf(&cookie, form.csrf.as_ref()) {
        return e.into_response();
    }

    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();
    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let password_plain = form
        .password
        .as_ref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if password_plain.is_empty() {
        return Html(layout("Error", "<h1>Password required</h1>")).into_response();
    }

    // Check if already configured
    if let Ok(txn) = state.env.begin_ro_txn() {
        if let Ok(bytes) = txn.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                if existing.password_hmac.is_some() && existing.totp_secret.is_some() {
                    return Html(layout(
                        "Error",
                        "<h1>Credentials already configured</h1><p>Reset your existing credentials first.</p>",
                    ))
                    .into_response();
                }
            }
        }
    }

    // Hash the password
    let hmac_key = match state.config.otp_hmac_key() {
        Some(k) if !k.is_empty() => k,
        _ => {
            tracing::error!("OTP_HMAC_KEY not configured");
            return Html(layout("Error", "<h1>Server misconfiguration</h1>")).into_response();
        }
    };
    let mut mac: Hmac<Sha256> =
        Hmac::new_from_slice(hmac_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(password_plain.as_bytes());
    let password_hashed = hex::encode(mac.finalize().into_bytes());

    // Generate TOTP secret
    let mut secret_bytes = [0u8; 20];
    rand::thread_rng().fill(&mut secret_bytes);
    let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let otp_data = objects::OtpData {
        status: "configured".to_string(),
        code: None,
        expiry: None,
        requested_at: now,
        device_info: None,
        totp_secret: Some(secret_b32.clone()),
        password_hmac: Some(password_hashed),
    };

    let val = match serde_json::to_vec(&otp_data) {
        Ok(v) => v,
        Err(_) => return Html(layout("Error", "<h1>Internal error</h1>")).into_response(),
    };

    let mut saved = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if txn
            .put(
                state.otp_db,
                &dn.as_bytes(),
                &val,
                ::lmdb::WriteFlags::empty(),
            )
            .is_ok()
        {
            if txn.commit().is_ok() {
                saved = true;
            }
        }
    }

    if !saved {
        return Html(layout("Error", "<h1>Failed to save credentials</h1>")).into_response();
    }

    // Build QR code
    let otpauth = format!(
        "otpauth://totp/DIT:{}?secret={}&issuer=dit0&period=30&digits=6",
        username, secret_b32
    );
    let qr_data_uri = match QrCode::new(otpauth.as_bytes()) {
        Ok(code) => {
            let svg_str = code.render::<svg::Color>().min_dimensions(200, 200).build();
            let b64 = base64::encode(svg_str.as_bytes());
            format!("data:image/svg+xml;base64,{}", b64)
        }
        Err(_) => String::new(),
    };

    let qr_html = if !qr_data_uri.is_empty() {
        format!(
            r#"<div style="text-align:center; margin: 1rem 0;"><img src="{}" alt="TOTP QR"></div>"#,
            qr_data_uri
        )
    } else {
        String::new()
    };

    Html(layout(
        "Credentials Configured",
        &format!(
            r#"
            <div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <h2>Credentials Configured</h2>
                <p>Your password has been saved and a TOTP secret has been generated.</p>
                <p>Scan this QR code in your authenticator app, or enter the secret manually:</p>
                {}
                <div style="background: var(--light-gray); padding: 1rem; font-family: monospace; font-size: 1rem; text-align: center; border: 1px solid var(--text); margin: 1rem 0;">{}</div>
                <p>When logging in via LDAP, enter your password and 6-digit TOTP separated by <code>::</code></p>
                <p>For example: <code>mypassword::123456</code></p>
                <a href="/">Back to Profile</a>
            </div>
            "#,
            qr_html, secret_b32
        ),
    ))
    .into_response()
}

#[axum::debug_handler]
pub async fn credentials_reset(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<ResetForm>,
) -> impl IntoResponse {
    if let Err(e) = verify_csrf(&cookie, form.csrf.as_ref()) {
        return e.into_response();
    }

    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();
    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let mut done = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if txn.del(state.otp_db, &dn.as_bytes(), None).is_ok() {
            if txn.commit().is_ok() {
                done = true;
            }
        }
    }

    if done {
        Html(layout(
            "Credentials Reset",
            r#"<div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <h2>Credentials Reset</h2>
                <p>Your password and TOTP have been removed. You can set up new credentials from your profile.</p>
                <a href="/">Back to Profile</a>
            </div>"#,
        ))
        .into_response()
    } else {
        Html(layout("Error", "<h1>Failed to reset credentials</h1>")).into_response()
    }
}
