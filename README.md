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
  "ts_id": "TSK98a...",
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

## NixOS

dit0 provides a Nix flake with a NixOS module for declarative deployment.

### Flake input

```nix
{
  inputs.dit0.url = "github:dominicegginton/dit0";
}
```

### NixOS module

Add the module to your NixOS configuration and enable the service:

```nix
{ inputs, ... }:

{
  imports = [ inputs.dit0.nixosModules.default ];

  services.dit0 = {
    enable = true;
    package = inputs.dit0.packages.${pkgs.system}.default;

    baseDN = "dc=example";
    ldapPort = 636;
    webPort = 443;
    dataDir = "/var/lib/dit0";
    otpHmacKeyFile = "/run/secrets/otp-hmac-key";

    tailscale = {
      domain = "your-tailnet-name";
      hostname = "dit0";
      apiKeyFile = "/run/secrets/ts-api-key";
      # Optional — for automatic node registration:
      # authKeyFile = "/run/secrets/ts-auth-key";
    };
  };
}
```

### Module options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | `bool` | `false` | Enable the dit0 service |
| `package` | `package` | `pkgs.dit0` | The dit0 package to use |
| `ldapPort` | `port` | `636` | LDAP server listen port |
| `webPort` | `port` | `443` | HTTPS web server listen port |
| `baseDN` | `string` | — | Base distinguished name for the LDAP directory |
| `dataDir` | `path` | `/var/lib/dit0` | Persistent data directory (LMDB, Tailscale state) |
| `otpHmacKeyFile` | `path` | — | Path to OTP HMAC secret key file |
| `tailscale.apiBaseUrl` | `string` | `https://api.tailscale.com/api/v2` | Tailscale API base URL |
| `tailscale.apiKeyFile` | `path` | — | Path to Tailscale API key file |
| `tailscale.authKeyFile` | `path?` | `null` | Optional Tailscale auth key for auto-registration |
| `tailscale.domain` | `string` | — | Tailnet domain / name |
| `tailscale.hostname` | `string` | `dit0` | Hostname to register on the tailnet |

### Secrets management

Secret files are loaded via systemd `LoadCredential` — they only need to be readable by root and never appear in the Nix store.

### Systemd hardening

The NixOS module runs dit0 as a dedicated `dit0` system user with comprehensive systemd sandboxing including `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`, restricted system calls, and only the network capabilities required for Tailscale (`CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_ADMIN`).

### Building with Nix

```sh
# Build the package
nix build

# Enter a development shell
nix develop
```
