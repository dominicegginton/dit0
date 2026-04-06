# dit0

LDAP server backed by Tailscale, providing user and device directory services over your tailnet.

## Features

- LDAPS (LDAP over TLS) served via Tailscale tsnet
- User authentication with password + TOTP (`password::123456`)
- POSIX account and group attributes derived from Tailscale ACL grants
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

## Building

```sh
cargo build --release
```

## Usage

```sh
CONFIG_FILE=config.json ./target/release/dit0
```

The server joins your tailnet and listens on LDAPS (636) and HTTPS (443). Users access the web UI to set up their password and TOTP, then authenticate to LDAP-bound devices with `password::totp_code`.

## Future Scope

- Audit logging for bind and search operations
