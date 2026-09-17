# NixOS module for the dit0 sshd / LDAP client.
# This module configures NSS, PAM, and sshd to authenticate users against a dit0 directory server.
{ lib
, config
, pkgs
, ...
}:

let
  cfg = config.services.dit0.client;
in

{
  options.services.dit0.client = {
    enable = lib.mkEnableOption "dit0 SSH and NSS/PAM LDAP client integration";

    server = lib.mkOption {
      type = lib.types.str;
      example = "ldaps://dit0.example.ts.net:636";
      description = "URI of the dit0 LDAPS/LDAP server.";
    };

    base_dn = lib.mkOption {
      type = lib.types.str;
      example = "dc=example,dc=com";
      description = "Base distinguished name for the LDAP directory.";
    };

    bind_dn = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "uid=service-account,ou=people,dc=example,dc=com";
      description = "Optional DN to bind to LDAP with for searches.";
    };

    bind_password_file = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional path to a file containing the LDAP bind password.";
    };

    ssl = lib.mkOption {
      type = lib.types.enum [ "on" "off" "start_tls" ];
      default = "on";
      description = "Whether to use SSL/TLS connection.";
    };

    tls_reqcert = lib.mkOption {
      type = lib.types.enum [ "never" "allow" "try" "demand" "hard" ];
      default = "demand";
      description = "Specifies what checks to perform on server certificates.";
    };

    tls_cacertfile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional path to CA certificate bundle.";
    };

    makeHomeDir = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Automatically create user home directory upon successful SSH / PAM login.";
    };

    enableSshd = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Configure OpenSSH daemon (sshd) for PAM and keyboard-interactive LDAP authentication.";
    };

    extraConfig = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Extra configuration lines appended to nslcd.conf.";
    };
  };

  config = lib.mkIf cfg.enable {
    # NSS and PAM LDAP daemon (nslcd) configuration
    services.nslcd = {
      enable = true;
      settings = {
        uri = cfg.server;
        base = cfg.base_dn;
        ssl = cfg.ssl;
        tls_reqcert = cfg.tls_reqcert;
      }
      // lib.optionalAttrs (cfg.bind_dn != null) { binddn = cfg.bind_dn; }
      // lib.optionalAttrs (cfg.bind_password_file != null) { rootpwmoddn = cfg.bind_password_file; }
      // lib.optionalAttrs (cfg.tls_cacertfile != null) { tls_cacertfile = cfg.tls_cacertfile; };
      extraConfig = ''
        base passwd ou=people,${cfg.base_dn}
        base group ou=groups,${cfg.base_dn}
        base shadow ou=people,${cfg.base_dn}
        ${cfg.extraConfig}
      '';
    };

    # PAM LDAP integration
    security.pam.ldap = {
      enable = true;
      base = cfg.base_dn;
      server = cfg.server;
    };

    # Automatically create home directories on login via pam_mkhomedir
    security.pam.makeHomeDir.enable = lib.mkIf cfg.makeHomeDir true;
    security.pam.services.sshd.makeHomeDir = lib.mkIf cfg.makeHomeDir true;

    # OpenSSH daemon configuration hardened with secure defaults
    services.openssh = lib.mkIf cfg.enableSshd {
      enable = lib.mkDefault true;
      allowSFTP = lib.mkDefault false;
      authorizedKeysInHomedir = lib.mkDefault false;
      settings = {
        KbdInteractiveAuthentication = lib.mkDefault true;
        PasswordAuthentication = lib.mkDefault true;
        UsePAM = lib.mkDefault true;
        MaxAuthTries = lib.mkDefault 3;
        PermitEmptyPasswords = lib.mkDefault "no";
        PermitRootLogin = lib.mkDefault "no";
        LogLevel = lib.mkDefault "VERBOSE";
        Macs = lib.mkDefault [
          "hmac-sha2-512"
          "hmac-sha2-256"
        ];
        Ciphers = lib.mkDefault [
          "aes256-ctr"
          "aes192-ctr"
          "aes128-ctr"
        ];
      };
      extraConfig = lib.mkDefault ''
        AllowTcpForwarding yes
        X11Forwarding no
        AllowAgentForwarding no
        AllowStreamLocalForwarding no
        ClientAliveInterval 600
        ClientAliveCountMax 1
      '';
    };
  };
}
