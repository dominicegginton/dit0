{ lib
, config
, pkgs
, ...
}:

let
  cfg = config.services.dit0;

  # Generate config.json at build time using lib.writeJSON.
  configJson = lib.writeJSON "config.json" (
    let
      baseConfig = {
        ldap_port = cfg.ldap_port;
        web_port = cfg.web_port;
        ts_api_base_url = cfg.ts_api_base_url;
        ts_api_key_file = "$CREDENTIALS_DIRECTORY/ts-api-key";
        ts_id = cfg.ts_id;
        base_dn = cfg.base_dn;
        ts_hostname = cfg.ts_hostname;
        otp_hmac_key_file = "$CREDENTIALS_DIRECTORY/otp-hmac-key";
        data_dir = cfg.data_dir;
      };
    in
    if cfg.ts_auth_key_file != null then
      baseConfig // { ts_auth_key_file = "$CREDENTIALS_DIRECTORY/ts-auth-key"; }
    else
      baseConfig
  );
in

{

  options.services.dit0 = {
    enable = lib.mkEnableOption "dit0 — a directory information tree for your TailNet";

    package = lib.mkPackageOption pkgs "dit0" { };

    ldap_port = lib.mkOption {
      type = lib.types.port;
      default = 636;
      description = "Port for the LDAP server to listen on.";
    };

    web_port = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "Port for the HTTPS web server to listen on.";
    };

    base_dn = lib.mkOption {
      type = lib.types.str;
      example = "dc=example";
      description = "Base distinguished name for the LDAP directory.";
    };

    data_dir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/dit0";
      description = "Directory for persistent data (LMDB database, Tailscale state).";
    };

    otp_hmac_key_file = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing the OTP HMAC secret key.
        Loaded via systemd LoadCredential — the file only needs
        to be readable by root. Works with agenix, sops-nix, or
        any secret manager that writes files.
      '';
    };

    ts_api_base_url = lib.mkOption {
      type = lib.types.str;
      default = "https://api.tailscale.com/api/v2";
      description = "Base URL for the Tailscale API.";
    };

    ts_api_key_file = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing the Tailscale API key.
        Loaded via systemd LoadCredential — only needs to be
        readable by root.
      '';
    };

    ts_auth_key_file = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Optional path to a file containing a Tailscale auth key
        for automatic node registration. Loaded via systemd
        LoadCredential — only needs to be readable by root.
      '';
    };

    ts_id = lib.mkOption {
      type = lib.types.str;
      description = "Tailscale tailnet domain (e.g. your tailnet name).";
    };

    ts_hostname = lib.mkOption {
      type = lib.types.str;
      default = "dit0";
      description = "Hostname to register on the tailnet.";
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
