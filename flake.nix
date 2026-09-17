# Flake input/output specification for dit0.
# Exposes package, overlay, NixOS module, development shell, and integration tests.
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, git-hooks, ... }:

    let
      inherit (nixpkgs) lib;

      # Filter to restrict support to linux platforms (as Tailscale & LDAP sandboxing are linux-specific).
      systems = lib.intersectLists lib.systems.flakeExposed lib.platforms.linux;

      forAllSystems = lib.genAttrs systems;

      # Import nixpkgs per architecture, applying the overlay.
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [ self.outputs.overlays.default ];
      });
    in

    {
      # Code formatter for all .nix files.
      formatter = forAllSystems (system: nixpkgsFor.${system}.nixpkgs-fmt);

      # Nixpkgs overlay definition to include dit0.
      overlays.default = final: _: { dit0 = final.callPackage ./nix/default.nix { }; };

      # Packages exported by the flake.
      packages = forAllSystems (system: {
        inherit (nixpkgsFor.${system}) dit0;
        default = nixpkgsFor.${system}.dit0;
      });

      # Development shell configuration loaded via `nix develop`.
      devShells = forAllSystems (system: {
        default = nixpkgsFor.${system}.callPackage ./nix/shell.nix {
          shellHook = self.checks.${system}.pre-commit-check.shellHook;
        };
      });

      # VM Integration tests and pre-commit hooks run on `nix flake check`.
      checks = forAllSystems (system: {
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            nixpkgs-fmt.enable = true;
            rustfmt.enable = true;
            clippy = {
              enable = true;
              # Ensure package can be built in check
              packageOverrides = {
                cargo = nixpkgsFor.${system}.cargo;
                clippy = nixpkgsFor.${system}.clippy;
              };
            };
          };
        };

        dit0-test = nixpkgsFor.${system}.callPackage ./nix/test.nix {
          dit0-module = self.outputs.nixosModules.default;
          dit0-client-module = self.outputs.nixosModules.client;
          dit0-package = nixpkgsFor.${system}.dit0;
        };
      });

      # NixOS Modules to declare configurations and run services / clients.
      nixosModules = {
        default = ./nix/module.nix;
        server = ./nix/module.nix;
        client = ./nix/client.nix;
        dit0 = ./nix/module.nix;
        dit0-client = ./nix/client.nix;
      };
    };
}
