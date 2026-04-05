{ lib
, config
, pkgs
, ...
}:

let
  cfg = config.services.dit0;

  # Build the jq expression for config generation.
  # Non-secret values are baked in; secret paths reference
  # $CREDENTIALS_DIRECTORY which is resolved at runtime.
  genConfigScript = pkgs.writeShellScript "dit0-gen-config" ''
    set -euo pipefail
    ${pkgs.jq}/bin/jq -n \
      --argjson ldap_port ${toString cfg.ldapPort} \
      --argjson web_port ${toString cfg.webPort} \
      --arg ts_api_base_url ${lib.escapeShellArg cfg.tailscale.apiBaseUrl} \
      --arg ts_api_key_file "$CREDENTIALS_DIRECTORY/ts-api-key" \
      --arg ts_api_domain ${lib.escapeShellArg cfg.tailscale.domain} \
      --arg base_dn ${lib.escapeShellArg cfg.baseDN} \
      --arg ts_hostname ${lib.escapeShellArg cfg.tailscale.hostname} \
      --arg otp_hmac_key_file "$CREDENTIALS_DIRECTORY/otp-hmac-key" \
      --arg data_dir ${lib.escapeShellArg cfg.dataDir} \
      ${lib.optionalString (cfg.tailscale.authKeyFile != null)
        ''--arg ts_auth_key_file "$CREDENTIALS_DIRECTORY/ts-auth-key" \''} \
      '{
        ldap_port: $ldap_port,
        web_port: $web_port,
        ts_api_base_url: $ts_api_base_url,
        ts_api_key_file: $ts_api_key_file,
        ts_api_domain: $ts_api_domain,
        base_dn: $base_dn,
        ts_hostname: $ts_hostname,
        otp_hmac_key_file: $otp_hmac_key_file,
        data_dir: $data_dir${lib.optionalString (cfg.tailscale.authKeyFile != null)
          ", ts_auth_key_file: $ts_auth_key_file"}
      }' > "$RUNTIME_DIRECTORY/config.json"
  '';
in

{
  options.services.dit0 = {
    enable = lib.mkEnableOption "dit0 — a directory information tree for your TailNet";

    package = lib.mkPackageOption pkgs "dit0" { };

    ldapPort = lib.mkOption {
      type = lib.types.port;
      default = 636;
      description = "Port for the LDAP server to listen on.";
    };

    webPort = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "Port for the HTTPS web server to listen on.";
    };

    baseDN = lib.mkOption {
      type = lib.types.str;
      example = "dc=example";
      description = "Base distinguished name for the LDAP directory.";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/dit0";
      description = "Directory for persistent data (LMDB database, Tailscale state).";
    };

    otpHmacKeyFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing the OTP HMAC secret key.
        Loaded via systemd LoadCredential — the file only needs
        to be readable by root. Works with agenix, sops-nix, or
        any secret manager that writes files.
      '';
    };

    tailscale = {
      apiBaseUrl = lib.mkOption {
        type = lib.types.str;
        default = "https://api.tailscale.com/api/v2";
        description = "Base URL for the Tailscale API.";
      };

      apiKeyFile = lib.mkOption {
        type = lib.types.path;
        description = ''
          Path to a file containing the Tailscale API key.
          Loaded via systemd LoadCredential — only needs to be
          readable by root.
        '';
      };

      authKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Optional path to a file containing a Tailscale auth key
          for automatic node registration. Loaded via systemd
          LoadCredential — only needs to be readable by root.
        '';
      };

      domain = lib.mkOption {
        type = lib.types.str;
        description = "Tailscale tailnet domain (e.g. your tailnet name).";
      };

      hostname = lib.mkOption {
        type = lib.types.str;
        default = "dit0";
        description = "Hostname to register on the tailnet.";
      };
    };
  };

  config = lib.mkIf cfg.enable {

    users.users.dit0 = {
      isSystemUser = true;
      group = "dit0";
      home = cfg.dataDir;
      description = "dit0 service user";
    };
    users.groups.dit0 = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir} 0750 dit0 dit0 -"
    ];

    systemd.services.dit0 = {
      description = "dit0 — directory information tree for your TailNet";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      # Config is generated at runtime by ExecStartPre so that
      # secret file paths reference $CREDENTIALS_DIRECTORY and
      # never appear in the Nix store.
      environment.CONFIG_FILE = "/run/dit0/config.json";

      serviceConfig = {
        ExecStartPre = [ "${genConfigScript}" ];
        ExecStart = "${cfg.package}/bin/dit0";
        Restart = "on-failure";
        RestartSec = 5;

        # --- User / Group ---
        User = "dit0";
        Group = "dit0";

        # --- Secrets via systemd credentials ---
        # Secret files are copied into a private per-service
        # directory ($CREDENTIALS_DIRECTORY) at start. The
        # originals only need to be readable by root — they are
        # never accessed by the service directly.
        LoadCredential = [
          "ts-api-key:${cfg.tailscale.apiKeyFile}"
          "otp-hmac-key:${cfg.otpHmacKeyFile}"
        ] ++ lib.optional (cfg.tailscale.authKeyFile != null)
          "ts-auth-key:${cfg.tailscale.authKeyFile}";

        # --- State & Directories ---
        WorkingDirectory = cfg.dataDir;
        StateDirectory = "dit0";
        StateDirectoryMode = "0750";
        RuntimeDirectory = "dit0";
        RuntimeDirectoryMode = "0750";
        LogsDirectory = "dit0";
        LogsDirectoryMode = "0750";

        # --- Sandboxing & Hardening ---
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        RemoveIPC = true;
        PrivateUsers = false; # needs raw network for tailscale
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        SystemCallErrorNumber = "EPERM";

        # --- Capabilities ---
        CapabilityBoundingSet = [
          "CAP_NET_BIND_SERVICE" # bind to privileged ports (443, 636)
          "CAP_NET_RAW" # tailscale networking
          "CAP_NET_ADMIN" # tailscale networking
        ];
        AmbientCapabilities = [
          "CAP_NET_BIND_SERVICE"
          "CAP_NET_RAW"
          "CAP_NET_ADMIN"
        ];

        # --- File-system access ---
        ReadWritePaths = [
          cfg.dataDir
        ];

        # --- Misc ---
        UMask = "0027";
      };
    };
  };
}
