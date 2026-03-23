{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:

    let
      # import nixpkgs lib
      inherit (nixpkgs) lib;

      # support all Linux systems that the nixpkgs flake exposes
      systems = lib.intersectLists lib.systems.flakeExposed lib.platforms.linux;

      # get pkgs for all systems
      forAllSystems = lib.genAttrs systems;

      # pkgs for all systems
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [ self.outputs.overlays.default ];
      });
    in

    {
      # formatter for flake
      formatter = forAllSystems (system: nixpkgsFor.${system}.nixpkgs-fmt);

      # dit0 package overlay
      overlays.default = final: _: { dit0 = final.callPackage ./default.nix { }; };

      # dit0 packages for all systems
      packages = forAllSystems (system: { default = nixpkgsFor.${system}.dit0; });

      # dit0 nixos module
      nixosModules.default = ./module.nix;
    };
}
