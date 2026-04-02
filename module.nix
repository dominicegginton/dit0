{ lib
, config
, pkgs
, ...
}:

{
  options.services.dit0 = {
    enable = lib.mkEnableOption "dit0";

    package = lib.mkPackageOption pkgs "dit0" { };
  };

  config = lib.mkIf config.services.dit0.enable {
    environment.systemPackages = [ config.services.dit0.package ];

    systemd.packages = [ config.services.dit0.package ];

    systemd.services.dit0 = {
      description = config.services.dit0.package.meta.description;
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${config.services.dit0.package}/bin/dit0";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
