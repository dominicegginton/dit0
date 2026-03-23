pub const STYLES: &str = r#"
:root {
  --white: #ffffff;
  --black: #000000;
  --gray: #555555;
  --light-gray: #f0f0f0;
  --yellow: #f0c000;
  --background: var(--white);
  --background-secondary: var(--black);
  --text: var(--black);
  --text-secondary: var(--white);
  --link: var(--black);
  --link-hover: var(--gray);
}

html,
body {
  box-sizing: border-box;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
  font-size: 100%;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  background: var(--background);
  margin: 0;
  padding: 0;
  color: var(--text);
}

*,
*:before,
*:after {
  box-sizing: inherit;
  padding: 0;
  margin: 0;
  overflow-wrap: break-word;
}

body {
  padding: 0;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  overflow-x: hidden;
  max-width: 100vw;
}

header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 1rem;
  background-color: var(--background-secondary);
  color: var(--text-secondary);
  padding: 1rem;
  font-size: 0.8rem;
}

header a {
  color: var(--text-secondary);
  text-decoration: none;
  padding: 0.15rem 0.5rem;
  margin: 0.15rem 0;
  display: inline-block;
}

header a.active {
  color: var(--text);
  background: var(--background);
}

.main-content {
  padding: 3rem;
  width: 100%;
  margin: 0 auto;
  flex: 1;
}

h1,
h2,
h3,
h4 {
  margin: 1rem 0;
  border-bottom: solid 1px var(--text);
}

h1 {
  font-size: 3rem;
  letter-spacing: -5px;
}

h2 {
  font-size: 2.5rem;
  letter-spacing: -2px;
}

h3 {
  font-size: 1.5rem;
  letter-spacing: -1px;
  border-bottom: none;
}

p {
  font-size: 1rem;
  margin: 0.7rem 0;
}

a {
  color: var(--link);
  cursor: pointer;
}

input, textarea, select {
  width: 100%;
  padding: 0.5rem;
  background: var(--light-gray);
  color: var(--text);
  border: 1px solid var(--text);
  font-family: inherit;
  margin-bottom: 1rem;
}

button {
  padding: 0.5rem 1rem;
  background: var(--text);
  color: var(--background);
  border: none;
  font-family: inherit;
  cursor: pointer;
  font-weight: bold;
}

button:hover {
  opacity: 0.8;
}

pre {
  white-space: pre-wrap;
  word-wrap: break-word;
}

table {
  border-collapse: collapse;
  width: 100%;
  margin: 1rem 0;
  table-layout: fixed;
}

th,
td {
  border: 1px solid var(--text);
  padding: 0.5rem;
  text-align: left;
}

th {
  background-color: var(--text);
  color: var(--background);
}

img {
  max-width: 100%;
  height: auto;
}

/* D3 Graph Styles */
.links line { stroke: var(--text); stroke-opacity: 0.6; }
.nodes circle { stroke: var(--background); stroke-width: 1px; fill: var(--text); r: 5; }
text { font-family: inherit; font-size: 10px; fill: var(--text); }

.graph-container {
  border: 1px solid var(--text);
  margin: 1rem 0;
  background: var(--light-gray);
}
"#;

pub fn base_layout(title: &str, content: &str) -> String {
    format!(
        r#"
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{}</title>
        <style>{}</style>
      </head>
      <body>
        {}
      </body>
    </html>
    "#,
        title, STYLES, content
    )
}

pub fn layout(title: &str, content: &str) -> String {
    base_layout(title, content)
}

pub fn device_info_page(
    dv: &crate::tailscale::Device,
    bindable: bool,
    reasons: &[String],
    host: &str,
) -> String {
    let tags = dv.tags.join(", ");
    let bindable_str = if bindable { "Yes" } else { "No" };
    let reasons_str = if reasons.is_empty() {
        "(none)".to_string()
    } else {
        reasons.join(", ")
    };
    let device_host = if dv.hostname.is_empty() {
        dv.name.clone()
    } else {
        dv.hostname.clone()
    };
    let machine_dn = format!("cn={},ou=machines,dc=example,dc=org", device_host);

    base_layout(
        &format!("Device: {}", dv.name),
        &format!(
            r#"<div class='main-content'>
<h1>Device Info</h1>
<p><strong>Name:</strong> {name}</p>
<p><strong>ID:</strong> {id}</p>
<p><strong>OS:</strong> {os}</p>
<p><strong>Tags:</strong> {tags}</p>
<p><strong>Addresses:</strong> {addrs}</p>
<p><strong>Bindable via cap_map:</strong> {bindable} <span style='color:#6b7280;font-size:0.9rem'>({reasons})</span></p>

<section style='margin-top:1rem;background:#f8fbff;padding:1rem;border-radius:6px;border:1px solid #e6eefc;'>
  <h2 style='font-size:1.1rem;margin-top:0;'>Default (recommended): NSLCD (nslcd + libnss-ldapd)</h2>
  <p style='margin:0.25rem 0 0.75rem 0;color:#374151;'>Use <strong>nslcd</strong> as the default lightweight NSS/PAM stack to connect to this LDAP server.</p>
  <ol style='margin:0 0 0.75rem 1.2rem;color:#111827;'>
    <li>Install packages on the Linux machine.</li>
    <li>Create a minimal <code>/etc/nslcd.conf</code> and secure it.</li>
    <li>Adjust <code>/etc/nsswitch.conf</code> to use <code>passwd: files ldap</code> and enable PAM LDAP authentication modules.</li>
    <li>Start/restart <code>nslcd</code> and test with <code>getent passwd &lt;username&gt;</code>.</li>
  </ol>
  <pre style='background:#0b1220;color:#e6f0ff;padding:0.75rem;border-radius:4px;overflow:auto;font-size:0.85rem;'><code>
apt install -y nslcd libnss-ldapd ldap-utils

# /etc/nslcd.conf (minimal example)
uid nslcd
gid nslcd
uri ldap://{host}
base dc=example,dc=org
# Machine entry DN for this device (replace search base as needed):
# {machine_dn}
# optional: binddn and bindpw if your server requires a bind account
#binddn cn=reader,dc=example,dc=org
#bindpw secret

# /etc/nsswitch.conf (ensure ldap is consulted for passwd/group)
# passwd:         files ldap
# group:          files ldap

# then restart:
# systemctl restart nslcd
</code></pre>
  <p style='margin:0.5rem 0 0 0;color:#6b7280;'>Replace <code>{host}</code> and the search base with values for your deployment. Ensure <code>/etc/nslcd.conf</code> is readable only by root (chmod 600). The machine DN above is suggested for this device.</p>
</section>

<section style='margin-top:1.5rem;background:#fbfafb;padding:1rem;border-radius:6px;border:1px solid #ececec;'>
  <h2 style='font-size:1.1rem;margin-top:0;'>Alternative: Enable native Linux login (PAM/SSSD)</h2>
  <p style='margin:0.25rem 0 0.75rem 0;color:#374151;'>If you prefer SSSD, follow these steps to configure it instead.</p>
  <ol style='margin:0 0 0.75rem 1.2rem;color:#111827;'>
    <li>Install SSSD and LDAP utilities on the Linux machine.</li>
    <li>Create <code>/etc/sssd/sssd.conf</code> with the example below and set proper permissions.</li>
    <li>Enable the system to use SSSD for NSS and PAM, then start/restart <code>sssd</code>.</li>
    <li>Test with <code>getent passwd &lt;username&gt;</code> and a login.</li>
  </ol>
  <pre style='background:#111827;color:#e5e7eb;padding:0.75rem;border-radius:4px;overflow:auto;font-size:0.85rem;'><code>
apt install -y sssd libnss-sss libpam-sss ldap-utils

# /etc/sssd/sssd.conf (minimal example)
[sssd]
domains = LDAP
services = nss, pam

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldap://{host}
ldap_search_base = dc=example,dc=org
ldap_schema = rfc2307
cache_credentials = True
enumerate = False

# Machine entry DN for this device (replace search base as needed):
# {machine_dn}

# ensure permissions: chmod 600 /etc/sssd/sssd.conf
</code></pre>
  <p style='margin:0.5rem 0 0 0;color:#6b7280;'>Replace <code>{host}</code> and search base with values for your deployment. The machine DN above is suggested for this device. If using the Tailscale funnel, point <code>{host}</code> to the device name or IP shown above.</p>
</section>

<p style='margin-top:1rem;'><a href="/">Back</a></p>

"#,
            name = dv.name,
            id = dv.id,
            os = dv.client_version,
            tags = tags,
            addrs = dv.addresses.join(", "),
            bindable = bindable_str,
            reasons = reasons_str,
            host = host,
            machine_dn = machine_dn
        ),
    )
}
