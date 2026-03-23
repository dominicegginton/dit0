use crate::config::Config;
use chrono::{DateTime, Utc};
use reqwest::{header, Client, Method, Request, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error, fmt, sync::Arc};

#[derive(Debug, Clone)]
pub struct Tailscale {
    base_url: String,
    key: String,
    domain: String,
    client: Arc<Client>,
    local_api_addr: Option<String>,
    local_api_cred: Option<String>,
}

impl Tailscale {
    pub fn new(config: Config) -> Self {
        let client = Client::builder().build();
        match client {
            Ok(c) => Self {
                base_url: config.ts_api_base_url,
                key: config.ts_api_key,
                domain: config.ts_api_domain,
                client: Arc::new(c),
                local_api_addr: None,
                local_api_cred: None,
            },
            Err(e) => panic!("creating client failed: {:?}", e),
        }
    }

    pub fn set_local_api(&mut self, addr: String, cred: String) {
        self.local_api_addr = Some(addr);
        self.local_api_cred = Some(cred);
    }

    fn request<B>(
        &self,
        method: Method,
        path: &str,
        body: B,
        query: Option<Vec<(&str, String)>>,
    ) -> Request
    where
        B: Serialize,
    {
        // Build URL by concatenating base and path to avoid Url::join behavior
        // which can produce unexpected paths when base contains a path segment.
        let base_trimmed = self.base_url.trim_end_matches('/');
        let url_str = if path.starts_with('/') {
            format!("{}{}", base_trimmed, path)
        } else {
            format!("{}/{}", base_trimmed, path)
        };
        let url = Url::parse(&url_str).unwrap();

        let mut headers = header::HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );

        let mut rb = self
            .client
            .request(method.clone(), url)
            .headers(headers)
            .basic_auth(&self.key, Some(""));

        match query {
            None => (),
            Some(val) => {
                rb = rb.query(&val);
            }
        }

        if method != Method::GET && method != Method::DELETE {
            rb = rb.json(&body);
        }

        rb.build().unwrap()
    }

    fn local_request<B>(
        &self,
        method: Method,
        path: &str,
        body: B,
        query: Option<Vec<(&str, String)>>,
    ) -> Request
    where
        B: Serialize,
    {
        let addr = self
            .local_api_addr
            .as_ref()
            .expect("Local API address not configured");
        let url = format!("http://{}/localapi/v0/{}", addr, path);

        let mut headers = header::HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.append(
            header::HeaderName::from_static("sec-tailscale"),
            header::HeaderValue::from_static("localapi"),
        );

        let mut rb = self
            .client
            .request(method.clone(), &url)
            .headers(headers)
            .basic_auth("", self.local_api_cred.as_ref());

        if let Some(q) = query {
            rb = rb.query(&q);
        }

        if method != Method::GET {
            rb = rb.json(&body);
        }

        rb.build().unwrap()
    }

    pub async fn list_users(&self) -> Result<Vec<User>, APIError> {
        let request = self.request(
            Method::GET,
            &format!("tailnet/{}/users", self.domain),
            (),
            None,
        );
        let resp = self.client.execute(request).await.unwrap();

        match resp.status() {
            StatusCode::OK => (),
            s => {
                return Err(APIError {
                    status_code: s,
                    body: resp.text().await.unwrap(),
                })
            }
        };

        let r: UsersResponse = resp.json().await.unwrap();
        Ok(r.users)
    }

    pub async fn list_devices(&self) -> Result<Vec<Device>, APIError> {
        // Use the domain configured on this client and request default fields
        let resp = self.list_devices_in_tailnet(&self.domain, None).await?;

        Ok(resp.devices)
    }

    /// List devices in the given tailnet. If `fields` is Some("all") the API will return
    /// all available fields; if `fields` is Some("default") the default limited set is used.
    /// If `fields` is None, no `fields` query parameter will be sent (server default applies).
    pub async fn list_devices_in_tailnet(
        &self,
        tailnet: &str,
        fields: Option<&str>,
    ) -> Result<APIResponse, APIError> {
        let mut query: Option<Vec<(&str, String)>> = None;
        if let Some(f) = fields {
            query = Some(vec![("fields", f.to_string())]);
        }

        let request = self.request(
            Method::GET,
            &format!("tailnet/{}/devices", tailnet),
            (),
            query,
        );

        let resp = self.client.execute(request).await.unwrap();

        match resp.status() {
            StatusCode::OK => (),
            s => {
                return Err(APIError {
                    status_code: s,
                    body: resp.text().await.unwrap(),
                })
            }
        };

        let r: APIResponse = resp.json().await.unwrap();
        Ok(r)
    }

    pub async fn get_acl_policies(&self) -> Result<serde_json::Value, APIError> {
        let request = self.request(
            Method::GET,
            &format!("tailnet/{}/acl", self.domain),
            (),
            None,
        );
        let resp = self.client.execute(request).await.unwrap();

        match resp.status() {
            StatusCode::OK => (),
            s => {
                return Err(APIError {
                    status_code: s,
                    body: resp.text().await.unwrap(),
                })
            }
        };

        let text = resp.text().await.unwrap();
        let re_trailing_comma = regex::Regex::new(r",(\s*[\]}])").unwrap();
        let text_no_trailing_comma = re_trailing_comma.replace_all(&text, "$1");
        let re_comments = regex::Regex::new(r"(?m)^\s*//.*$").unwrap();
        let clean_text = re_comments.replace_all(&text_no_trailing_comma, "");
        let acl_policies: serde_json::Value = serde_json::from_str(&clean_text).unwrap();

        Ok(acl_policies)
    }

    /// Preview ACL rules against a user or ip:port without saving the policy.
    /// `preview_type` should be "user" or "ipport". `preview_for` is the
    /// username (email) or ip:port string. `policy` is a JSON object matching
    /// the body described in the Tailscale API (acls/groups/hosts).
    pub async fn preview_acl(
        &self,
        tailnet: &str,
        preview_type: &str,
        preview_for: &str,
        policy: serde_json::Value,
    ) -> Result<serde_json::Value, APIError> {
        let query = Some(vec![
            ("type", preview_type.to_string()),
            ("previewFor", preview_for.to_string()),
        ]);

        let request = self.request(
            Method::POST,
            &format!("tailnet/{}/acl/preview", tailnet),
            policy,
            query,
        );

        let resp = self.client.execute(request).await.unwrap();

        match resp.status() {
            StatusCode::OK => (),
            s => {
                return Err(APIError {
                    status_code: s,
                    body: resp.text().await.unwrap(),
                })
            }
        };

        let json: serde_json::Value = resp.json().await.unwrap();
        Ok(json)
    }

    pub async fn whois(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<LocalWhoIsResponse>, APIError> {
        let query = vec![("addr", format!("{}", ip))];
        let request = self.local_request(Method::GET, "whois", (), Some(query));
        let resp = self.client.execute(request).await;

        match resp {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(whois) = resp.json::<LocalWhoIsResponse>().await {
                        return Ok(whois.into());
                    } else {
                        tracing::error!("Failed to parse whois response");
                    }
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::error!("LocalAPI whois failed: status={}, body={}", status, body);

                    return Err(APIError {
                        status_code: status,
                        body,
                    });
                }
            }
            Err(e) => {
                tracing::error!("LocalAPI request failed: {}", e);

                return Err(APIError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    body: format!("LocalAPI request failed: {}", e),
                });
            }
        }

        Ok(None)
    }
}

pub struct APIError {
    pub status_code: StatusCode,
    pub body: String,
}

impl fmt::Display for APIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "APIError: status code -> {}, body -> {}",
            self.status_code.to_string(),
            self.body
        )
    }
}

impl fmt::Debug for APIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "APIError: status code -> {}, body -> {}",
            self.status_code.to_string(),
            self.body
        )
    }
}

impl error::Error for APIError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct APIResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
}

// Public type aliases for clarity
pub type ListDevicesResponse = APIResponse;

/// Wrapper type for ACL preview responses. The exact shape of the preview
/// response can vary; keep it as an untyped JSON value but expose a named
/// type so callers can depend on a stable return type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPreviewResponse(pub serde_json::Value);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "allowedIPs")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "extraIPs")]
    pub extra_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub derp: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "clientVersion"
    )]
    pub client_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "lastSeen")]
    pub last_seen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "machineKey"
    )]
    pub machine_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "nodeKey")]
    pub node_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "displayNodeKey"
    )]
    pub display_node_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "logID")]
    pub log_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    pub expires: DateTime<Utc>,
    #[serde(default, rename = "neverExpires")]
    pub never_expires: bool,
    #[serde(default)]
    pub authorized: bool,
    #[serde(default, rename = "isExternal")]
    pub is_external: bool,
    #[serde(default, rename = "updateAvailable")]
    pub update_available: bool,
    #[serde(default, rename = "routeAll")]
    pub route_all: bool,
    #[serde(default, rename = "hasSubnet")]
    pub has_subnet: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "loginName")]
    pub login_name: String,
    #[serde(rename = "profilePicUrl")]
    pub profile_pic_url: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "tailnetId"
    )]
    pub tailnet_id: String,
    pub created: DateTime<Utc>,
    pub role: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub username: Option<String>,
    pub preferred_username: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalWhoIsResponse {
    #[serde(rename = "UserProfile")]
    pub user_profile: Option<LocalUserProfile>,
    #[serde(rename = "Node")]
    pub node: Option<LocalNode>,
    #[serde(rename = "CapMap")]
    pub cap_map: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalUserProfile {
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    pub profile_pic_url: Option<String>,
    #[serde(rename = "ID")]
    pub id: Option<u64>,
    #[serde(rename = "Role")]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalNode {
    #[serde(rename = "ID")]
    pub id: Option<u64>,
    #[serde(rename = "StableID")]
    pub stable_id: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<u64>,
    #[serde(rename = "Key")]
    pub key: Option<String>,
    #[serde(rename = "KeyExpiry")]
    pub key_expiry: Option<String>,
    #[serde(rename = "DiscoKey")]
    pub disco_key: Option<String>,
    #[serde(rename = "Addresses")]
    pub addresses: Option<Vec<String>>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints")]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "HomeDERP")]
    pub home_derp: Option<i64>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Option<LocalHostInfo>,
    #[serde(rename = "Created")]
    pub created: Option<String>,
    #[serde(rename = "Cap")]
    pub cap: Option<i64>,
    #[serde(rename = "Online")]
    pub online: Option<bool>,
    #[serde(rename = "ComputedName")]
    pub computed_name: Option<String>,
    #[serde(rename = "ComputedNameWithHost")]
    pub computed_name_with_host: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalHostInfo {
    #[serde(rename = "OS")]
    pub os: Option<String>,
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "Services")]
    pub services: Option<Vec<LocalService>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalService {
    #[serde(rename = "Proto")]
    pub proto: Option<String>,
    #[serde(rename = "Port")]
    pub port: Option<u16>,
}
