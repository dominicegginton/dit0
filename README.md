# dit0

LDAP server backed by Tailscale, providing user and device directory services over your tailnet.

## Features

- LDAPS (LDAP over TLS) served via Tailscale tsnet
- User authentication with password + TOTP (`password::123456`)
- POSIX account and group attributes derived from Tailscale ACL grants
- Tailscale devices exposed as `ipHost` / `device` entries under `ou=machines` (for sssd / hostname resolution)
- Structured audit logging for bind, search, credential, and connection events (target: `audit`)
- Web UI for credential setup (password + TOTP)
- RootDSE support for LDAP client auto-discovery

## Configuration

Set `CONFIG_FILE` environment variable (defaults to `config.json`):

```json
{
  "ldap_port": 636,
  "web_port": 443,
  "ts_api_base_url": "https://api.tailscale.com/api/v2",
  "ts_api_key_file": "/run/secrets/ts_api_key",
  "ts_api_domain": "example.com",
  "base_dn": "dc=example,dc=com",
  "ts_hostname": "dit0",
  "ts_auth_key_file": "/run/secrets/ts_auth_key",
  "otp_hmac_key_file": "/run/secrets/otp_hmac_key",
  "data_dir": "/var/lib/dit0"
}
```

Secret fields (`ts_api_key_file`, `ts_auth_key_file`, `otp_hmac_key_file`) are paths to files containing the secret values.

## Tailscale ACL Configuration

dit0 uses Tailscale ACL grants to control access. Add the following to your tailnet's ACL policy file (`acl.json` / `acl.hujson`):

```jsonc
{
  // Groups — organise users however you like
  "groups": {
    "group:ldap-users": ["alice@example.com", "bob@example.com"],
    "group:ldap-admins": ["alice@example.com"]
  },

  // ACL rules — allow tagged dit0 node to reach the tailnet
  "acls": [
    { "action": "accept", "src": ["tag:dit0"], "dst": ["*:*"] }
  ],

  // Tag owners
  "tagOwners": {
    "tag:dit0": ["group:ldap-admins"]
  },

  // Grants — capabilities exposed to dit0
  "grants": [
    {
      // Allow all LDAP users to bind and access the web UI
      "src": ["group:ldap-users"],
      "dst": ["tag:dit0"],
      "app": {
        "dominicegginton.dev/cap/tsdit0": [
          {
            "allow_bind": true,
            "allow_ui": true,
            "loginShell": "/bin/bash",
            "homeDirectory": "/home/alice"
          }
        ]
      }
    },
    {
      // Admin UI access
      "src": ["group:ldap-admins"],
      "dst": ["tag:dit0"],
      "app": {
        "dominicegginton.dev/cap/tsdit0": [
          {
            "allow_bind": true,
            "allow_ui": true,
            "allow_admin_ui": true,
            // POSIX groups granted to matching users
            "posix_groups": [
              { "name": "sudo", "gidNumber": 27 },
              { "name": "docker", "gidNumber": 999 }
            ]
          }
        ]
      }
    }
  ]
}
```

### Capability key

| Key | Description |
|-----|-------------|
| `dominicegginton.dev/cap/tsdit0` | Capability key for dit0 access control and POSIX attribute overrides |

### Grant fields

| Field | Type | Description |
|-------|------|-------------|
| `allow_bind` | `bool` | Allow LDAP bind (authentication) |
| `allow_ui` | `bool` | Allow access to the web credential-management UI |
| `allow_admin_ui` | `bool` | Allow access to the admin UI |
| `posix_groups` | `array` | POSIX groups to assign (each with `name` and `gidNumber`) |
| `loginShell` | `string` | Override the user's POSIX login shell |
| `homeDirectory` | `string` | Override the user's POSIX home directory |
| `uidNumber` | `string` | Override the user's POSIX UID |
| `gidNumber` | `string` | Override the user's POSIX primary GID |
| `gecos` | `string` | Override the GECOS field |
| `description` | `string` | Override the LDAP description |
| `cn` | `string` | Override the common name |
| *any LDAP attr* | `string` | Any string-valued key is applied as an LDAP attribute override |

## Building

```sh
cargo build --release
```

## Usage

```sh
CONFIG_FILE=config.json ./target/release/dit0
```

The server joins your tailnet and listens on LDAPS (636) and HTTPS (443). Users access the web UI to set up their password and TOTP, then authenticate to LDAP-bound devices with `password::totp_code`.
