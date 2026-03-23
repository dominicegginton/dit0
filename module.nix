{ lib
, config
, pkgs
, ...
}:

{
  options.programs.dit0 = {
    enable = lib.mkEnableOption "dit0";

    package = lib.mkPackageOption pkgs "dit0" { };
  };

  config = lib.mkIf config.programs.dit0.enable {
    environment.systemPackages = [ config.programs.dit0.package ];

    systemd.packages = [ config.programs.dit0.package ];

    systemd.services.dit0 = {
      description = config.programs.dit0.description;
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${config.programs.dit0.package}/bin/dit0";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
