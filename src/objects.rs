use crate::tailscale::Tailscale;
use futures::future::join_all;
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
    let ts_users = tailscale.cached_list_users().await.unwrap_or_default();

    // Gather devices once so we can lookup a device for a given user and
    // call the LocalAPI `whois` to retrieve `cap_map` values (e.g. shell/home).
    let ts_devices = tailscale.cached_list_devices().await.unwrap_or_default();
    let mut devices_by_user: HashMap<String, Vec<_>> = HashMap::new();
    for dev in &ts_devices {
        devices_by_user
            .entry(dev.user.clone())
            .or_default()
            .push(dev.clone());
    }

    // ── Pre-fetch all whois results in parallel ────────────────────────────
    // Collect unique IPs from all device addresses.
    let mut all_ips: Vec<IpAddr> = Vec::new();
    for dev in &ts_devices {
        if let Some(addr) = dev.addresses.first() {
            let ip_str = addr.split('/').next().unwrap_or(addr);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                all_ips.push(ip);
            }
        }
    }
    all_ips.sort();
    all_ips.dedup();

    let whois_futures: Vec<_> = all_ips
        .iter()
        .map(|ip| {
            let ip = *ip;
            let ts = tailscale.clone();
            async move { (ip, ts.cached_whois(ip).await) }
        })
        .collect();
    let whois_results = join_all(whois_futures).await;
    let whois_map: HashMap<IpAddr, _> = whois_results
        .into_iter()
        .filter_map(|(ip, res)| res.ok().map(|v| (ip, v)))
        .collect();
    let mut entries_map: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

    // ── Container OUs (needed for tree-browsing clients like ldp.exe) ───────
    {
        let people_dn = format!("ou=people,{}", base_dn);
        let people = entries_map.entry(people_dn).or_default();
        people.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalUnit".to_string()],
        );
        people.insert("ou".to_string(), vec!["people".to_string()]);
        people.insert(
            "description".to_string(),
            vec!["Tailscale users".to_string()],
        );
    }
    {
        let groups_dn = format!("ou=groups,{}", base_dn);
        let groups = entries_map.entry(groups_dn).or_default();
        groups.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalUnit".to_string()],
        );
        groups.insert("ou".to_string(), vec!["groups".to_string()]);
        groups.insert(
            "description".to_string(),
            vec!["Tailscale user private groups".to_string()],
        );
    }

    // ── ou=machines container OU ────────────────────────────────────────────
    {
        let machines_dn = format!("ou=machines,{}", base_dn);
        let machines = entries_map.entry(machines_dn).or_default();
        machines.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalUnit".to_string()],
        );
        machines.insert("ou".to_string(), vec!["machines".to_string()]);
        machines.insert(
            "description".to_string(),
            vec!["Tailscale devices".to_string()],
        );
    }

    // ── Device entries under ou=machines ─────────────────────────────────────
    for dev in &ts_devices {
        // Use the sanitised hostname as the cn; fall back to the Tailscale
        // name field (FQDN-like) stripped of the trailing dot.
        let raw_cn = if !dev.hostname.is_empty() {
            dev.hostname.clone()
        } else {
            dev.name.trim_end_matches('.').to_string()
        };
        if raw_cn.is_empty() {
            continue;
        }
        let cn = raw_cn.to_lowercase();

        let dn = format!("cn={},ou=machines,{}", cn, base_dn);
        let attrs = entries_map.entry(dn).or_default();

        attrs.insert(
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "device".to_string(),
                "ipHost".to_string(),
                "tailscaleObject".to_string(),
            ],
        );
        attrs.insert("cn".to_string(), vec![cn.clone()]);

        // ipHostNumber – all addresses (required by ipHost)
        let ip_addrs: Vec<String> = dev
            .addresses
            .iter()
            .map(|a| a.split('/').next().unwrap_or(a).to_string())
            .collect();
        if !ip_addrs.is_empty() {
            attrs.insert("ipHostNumber".to_string(), ip_addrs.clone());
        }

        // description
        attrs.insert(
            "description".to_string(),
            vec![format!(
                "Tailscale device {} ({})",
                dev.name.trim_end_matches('.'),
                dev.os
            )],
        );

        // ou (optional on device)
        attrs.insert("ou".to_string(), vec!["machines".to_string()]);

        // ── Tailscale custom attributes ──
        if !dev.id.is_empty() {
            attrs.insert("tsId".to_string(), vec![dev.id.clone()]);
        }
        if !dev.name.is_empty() {
            attrs.insert("tsName".to_string(), vec![dev.name.clone()]);
        }
        if !dev.hostname.is_empty() {
            attrs.insert("tsHostname".to_string(), vec![dev.hostname.clone()]);
        }
        if !dev.os.is_empty() {
            attrs.insert("tsOs".to_string(), vec![dev.os.clone()]);
        }
        if !dev.client_version.is_empty() {
            attrs.insert(
                "tsClientVersion".to_string(),
                vec![dev.client_version.clone()],
            );
        }
        if !dev.derp.is_empty() {
            attrs.insert("tsDerp".to_string(), vec![dev.derp.clone()]);
        }
        if !dev.machine_key.is_empty() {
            attrs.insert("tsMachineKey".to_string(), vec![dev.machine_key.clone()]);
        }
        if !dev.node_key.is_empty() {
            attrs.insert("tsNodeKey".to_string(), vec![dev.node_key.clone()]);
        }
        if !dev.user.is_empty() {
            attrs.insert("tsLoginName".to_string(), vec![dev.user.clone()]);
        }

        // Addresses / IPs
        for addr in &dev.addresses {
            attrs
                .entry("tsAddress".to_string())
                .or_default()
                .push(addr.clone());
        }
        for ip in &dev.allowed_ips {
            attrs
                .entry("tsAllowedIp".to_string())
                .or_default()
                .push(ip.clone());
        }
        for ip in &dev.extra_ips {
            attrs
                .entry("tsExtraIp".to_string())
                .or_default()
                .push(ip.clone());
        }
        for ep in &dev.endpoints {
            attrs
                .entry("tsEndpoint".to_string())
                .or_default()
                .push(ep.clone());
        }

        // Timestamps
        let created_str = dev.created.format("%Y%m%d%H%M%SZ").to_string();
        let last_seen_str = dev.last_seen.format("%Y%m%d%H%M%SZ").to_string();
        let expires_str = dev.expires.format("%Y%m%d%H%M%SZ").to_string();
        attrs.insert("tsCreated".to_string(), vec![created_str.clone()]);
        attrs.insert("createTimestamp".to_string(), vec![created_str]);
        attrs.insert("tsLastSeen".to_string(), vec![last_seen_str]);
        attrs.insert("tsExpires".to_string(), vec![expires_str]);

        // Booleans
        attrs.insert(
            "tsNeverExpires".to_string(),
            vec![if dev.never_expires {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );
        attrs.insert(
            "tsAuthorized".to_string(),
            vec![if dev.authorized {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );
        attrs.insert(
            "tsIsExternal".to_string(),
            vec![if dev.is_external {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );
        attrs.insert(
            "tsUpdateAvailable".to_string(),
            vec![if dev.update_available {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );
        attrs.insert(
            "tsRouteAll".to_string(),
            vec![if dev.route_all {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );
        attrs.insert(
            "tsHasSubnet".to_string(),
            vec![if dev.has_subnet {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }],
        );

        // Status – devices don't have a dedicated status field but we can
        // synthesise one from the authorized flag.
        attrs.insert(
            "tsStatus".to_string(),
            vec![if dev.authorized {
                "authorized".to_string()
            } else {
                "unauthorized".to_string()
            }],
        );
    }

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

        // Override auto-generated LDAP attributes with values from the
        // device LocalAPI `CapMap` (`dominicegginton.dev/cap/tsdit0`).
        // Any string-valued key in the capability object is applied as an
        // LDAP attribute override, so the ACL policy is the single source of
        // truth for per-user customisation (loginShell, homeDirectory,
        // uidNumber, gidNumber, gecos, description, etc.).
        let mut cap_overrides: HashMap<String, String> = HashMap::new();

        if let Some(devs) = devices_by_user.get(&user.login_name) {
            for dev in devs {
                if let Some(addr) = dev.addresses.first() {
                    let ip_str = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if let Some(Some(whois)) = whois_map.get(&ip) {
                            if let Some(ref cap_map) = whois.cap_map {
                                let app_key = "dominicegginton.dev/cap/tsdit0";
                                if let Some(app_val) = cap_map.get(app_key) {
                                    // Resolve to a single JSON object (first element if array).
                                    let obj = app_val.as_object().or_else(|| {
                                        app_val
                                            .as_array()
                                            .and_then(|a| a.first())
                                            .and_then(|v| v.as_object())
                                    });
                                    if let Some(obj) = obj {
                                        for (k, v) in obj {
                                            if let Some(s) = v.as_str() {
                                                cap_overrides.insert(k.clone(), s.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !cap_overrides.is_empty() {
                    break;
                }
            }
        }

        // Apply cap_map overrides – these win over auto-generated values.
        for (key, value) in &cap_overrides {
            attrs.insert(key.clone(), vec![value.clone()]);
        }

        // Set defaults for homeDirectory and loginShell if not overridden.
        attrs
            .entry("homeDirectory".to_string())
            .or_insert_with(|| vec![format!("/home/{}", uid)]);

        attrs
            .entry("loginShell".to_string())
            .or_insert_with(|| vec!["/run/current-system/sw/bin/bash".to_string()]);

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
