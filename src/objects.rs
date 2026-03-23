use crate::tailscale::Tailscale;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct OtpData {
    // "pending" | "approved"
    pub status: String,
    // Present only when approved
    pub code: Option<String>,
    // Unix seconds expiry (present when approved)
    pub expiry: Option<u64>,
    // TOTP shared secret (base32)
    #[serde(default)]
    pub totp_secret: Option<String>,
    // HMAC of the user's chosen static password (stored so we can verify password::TOTP)
    #[serde(default)]
    pub password_hmac: Option<String>,
    // Request timestamp (unix seconds)
    pub requested_at: u64,
    // Optional device info / request metadata
    pub device_info: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct AclPolicy {
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
    #[serde(default)]
    acls: Vec<AclRule>,
    #[serde(default)]
    _hosts: HashMap<String, String>,
    #[serde(default)]
    _tag_owners: HashMap<String, Vec<String>>,
}

#[derive(serde::Deserialize, Debug)]
struct AclRule {
    #[serde(default)]
    action: String,
    #[serde(default)]
    src: Vec<String>,
    #[serde(default)]
    dst: Vec<String>,
}

fn stable_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
    }
    hash
}

pub async fn get_all_entries(
    tailscale: &Tailscale,
    base_dn: &str,
) -> HashMap<String, HashMap<String, Vec<String>>> {
    // Only return Tailscale users as LDAP entries, do not merge with LMDB
    let ts_users = tailscale.list_users().await.unwrap_or_default();

    // Gather devices once so we can lookup a device for a given user and
    // call the LocalAPI `whois` to retrieve `cap_map` values (e.g. shell/home).
    let ts_devices = tailscale.list_devices().await.unwrap_or_default();
    let mut devices_by_user: HashMap<String, Vec<_>> = HashMap::new();
    for dev in ts_devices {
        devices_by_user
            .entry(dev.user.clone())
            .or_default()
            .push(dev);
    }
    let mut entries_map: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for user in ts_users {
        // split login name to get uid
        let uid_str = user
            .login_name
            .split('@')
            .next()
            .unwrap_or(&user.login_name);
        // We need to keep uid_str alive or clone it
        let uid = uid_str.to_string();

        let dn = format!("uid={},ou=people,{}", uid, base_dn);

        let attrs = entries_map.entry(dn.clone()).or_default();

        // Default attributes
        attrs
            .entry("objectClass".to_string())
            .or_insert_with(Vec::new)
            .extend(vec![
                "top".to_string(),
                "person".to_string(),
                "inetOrgPerson".to_string(),
                "posixAccount".to_string(),
                "shadowAccount".to_string(),
                "tailscaleObject".to_string(),
            ]);
        // Deduplicate objectClass
        if let Some(ocs) = attrs.get_mut("objectClass") {
            ocs.sort();
            ocs.dedup();
        }

        attrs.insert("uid".to_string(), vec![uid.clone()]);
        attrs.insert("tsId".to_string(), vec![user.id.clone()]);
        attrs.insert("tsLoginName".to_string(), vec![user.login_name.clone()]);
        if let Some(dn) = &user.display_name {
            attrs.insert("tsDisplayName".to_string(), vec![dn.clone()]);
        }
        if let Some(pic) = &user.profile_pic_url {
            attrs.insert("tsProfilePicUrl".to_string(), vec![pic.clone()]);
        }
        if !user.tailnet_id.is_empty() {
            attrs.insert("tsTailnetId".to_string(), vec![user.tailnet_id.clone()]);
        }
        attrs.insert("tsRole".to_string(), vec![user.role.clone()]);
        attrs.insert("tsStatus".to_string(), vec![user.status.clone()]);

        let display_name = user
            .display_name
            .clone()
            .unwrap_or_else(|| user.login_name.clone());
        let (first_name, last_name) = match display_name.split_once(' ') {
            Some((f, l)) => (f.to_string(), l.to_string()),
            None => (display_name.clone(), display_name.clone()),
        };

        attrs
            .entry("cn".to_string())
            .or_insert_with(|| vec![display_name.clone()]);
        attrs
            .entry("sn".to_string())
            .or_insert_with(|| vec![last_name.clone()]);
        attrs
            .entry("givenName".to_string())
            .or_insert_with(|| vec![first_name.clone()]);
        attrs
            .entry("displayName".to_string())
            .or_insert_with(|| vec![display_name.clone()]);

        attrs.insert("mail".to_string(), vec![user.login_name.clone()]);

        // Deterministic UID/GID generation (2000-60000 range)
        let generated_id = 2000 + (stable_hash(&uid) % 58000);
        let id_str = generated_id.to_string();

        attrs
            .entry("uidNumber".to_string())
            .or_insert_with(|| vec![id_str.clone()]);
        attrs
            .entry("gidNumber".to_string())
            .or_insert_with(|| vec![id_str.clone()]);

        // Prefer values from the device LocalAPI `CapMap` when available.
        let mut found_shell: Option<String> = None;
        let mut found_home: Option<String> = None;

        if let Some(devs) = devices_by_user.get(&user.login_name) {
            for dev in devs {
                if let Some(addr) = dev.addresses.first() {
                    let ip_str = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if let Ok(whois_opt) = tailscale.whois(ip).await {
                            if let Some(whois) = whois_opt {
                                if let Some(cap_map) = whois.cap_map {
                                    // First prefer values inside our app capability key
                                    let app_key = "dominicegginton.dev/cap/tsdit000000000";
                                    if let Some(app_val) = cap_map.get(app_key) {
                                        // app_val may be an object or an array of objects
                                        if let Some(obj) = app_val.as_object() {
                                            if let Some(v) =
                                                obj.get("loginShell").and_then(|x| x.as_str())
                                            {
                                                found_shell = Some(v.to_string());
                                            }
                                            if let Some(v) =
                                                obj.get("homeDirectory").and_then(|x| x.as_str())
                                            {
                                                found_home = Some(v.to_string());
                                            }
                                        } else if let Some(arr) = app_val.as_array() {
                                            if let Some(first) =
                                                arr.first().and_then(|x| x.as_object())
                                            {
                                                if let Some(v) =
                                                    first.get("loginShell").and_then(|x| x.as_str())
                                                {
                                                    found_shell = Some(v.to_string());
                                                }
                                                if let Some(v) = first
                                                    .get("homeDirectory")
                                                    .and_then(|x| x.as_str())
                                                {
                                                    found_home = Some(v.to_string());
                                                }
                                            }
                                        }

                                        // If both found inside app val, we can skip top-level checks
                                        if found_shell.is_some() && found_home.is_some() {
                                            // nothing
                                        } else {
                                            // fallthrough to check common top-level keys
                                            for k in
                                                ["loginShell", "login_shell", "shell", "unix_shell"]
                                            {
                                                if found_shell.is_none() {
                                                    if let Some(v) =
                                                        cap_map.get(k).and_then(|x| x.as_str())
                                                    {
                                                        found_shell = Some(v.to_string());
                                                    }
                                                }
                                            }
                                            for k in [
                                                "homeDirectory",
                                                "home_directory",
                                                "homedir",
                                                "home",
                                            ] {
                                                if found_home.is_none() {
                                                    if let Some(v) =
                                                        cap_map.get(k).and_then(|x| x.as_str())
                                                    {
                                                        found_home = Some(v.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        // no app key; check top-level keys
                                        for k in
                                            ["loginShell", "login_shell", "shell", "unix_shell"]
                                        {
                                            if let Some(v) = cap_map.get(k).and_then(|x| x.as_str())
                                            {
                                                found_shell = Some(v.to_string());
                                                break;
                                            }
                                        }
                                        for k in
                                            ["homeDirectory", "home_directory", "homedir", "home"]
                                        {
                                            if let Some(v) = cap_map.get(k).and_then(|x| x.as_str())
                                            {
                                                found_home = Some(v.to_string());
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if found_shell.is_some() && found_home.is_some() {
                    break;
                }
            }
        }

        attrs
            .entry("homeDirectory".to_string())
            .or_insert_with(|| vec![found_home.unwrap_or_else(|| format!("/home/{}", uid))]);

        attrs.entry("loginShell".to_string()).or_insert_with(|| {
            vec![found_shell.unwrap_or_else(|| "/run/current-system/sw/bin/bash".to_string())]
        });

        // Gecso field is good practice for legacy systems
        attrs
            .entry("gecos".to_string())
            .or_insert_with(|| vec![display_name.clone()]);

        attrs
            .entry("description".to_string())
            .or_insert_with(|| vec![format!("Tailscale User (Role: {})", user.role)]);

        // LDAP Generalized Time
        let created_str = user.created.format("%Y%m%d%H%M%SZ").to_string();
        attrs
            .entry("createTimestamp".to_string())
            .or_insert_with(|| vec![created_str.clone()]);
        attrs.insert("tsCreated".to_string(), vec![created_str]);

        // Extract gid from attrs before we borrow entries_map mutably again for the group
        let user_gid = attrs.get("gidNumber").unwrap().first().unwrap().clone();

        // Ensure a matching Group object exists (User Private Group)
        // This satisfies "gids must match a group object"
        let group_dn = format!("cn={},ou=groups,{}", uid, base_dn);
        let group_attrs = entries_map.entry(group_dn).or_default();

        group_attrs
            .entry("objectClass".to_string())
            .or_insert_with(Vec::new)
            .extend(vec!["top".to_string(), "posixGroup".to_string()]);
        if let Some(ocs) = group_attrs.get_mut("objectClass") {
            ocs.sort();
            ocs.dedup();
        }

        group_attrs.insert("cn".to_string(), vec![uid.clone()]);

        // Use the same gidNumber as the user
        group_attrs.insert("gidNumber".to_string(), vec![user_gid]);

        // Add memberUid
        group_attrs
            .entry("memberUid".to_string())
            .or_insert_with(Vec::new)
            .push(uid.clone());
    }

    entries_map
}

pub async fn get_user_profile(
    tailscale: &Tailscale,
    base_dn: &str,
    username: &str,
) -> Option<HashMap<String, Vec<String>>> {
    let entries = get_all_entries(tailscale, base_dn).await;

    let expected_dn = format!("uid={},ou=people,{}", username, base_dn);
    entries.get(&expected_dn).cloned()
}
