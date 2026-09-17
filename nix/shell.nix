# Nix shell configuration for development.
# This shell provides a development environment with all required tools and libraries.
{ pkgs ? import <nixpkgs> { }
, dit0 ? pkgs.callPackage ./default.nix { }
, shellHook ? ""
}:

pkgs.mkShell {
  # Inherit build inputs and environment variables from the main package derivation.
  inputsFrom = [ dit0 ];

  inherit shellHook;

  # Extra development tools and utilities.
  nativeBuildInputs = with pkgs; [
    cargo
    rustc
    rustfmt
    clippy
    go
    pkg-config
  ];

  # Extra libraries for development.
  buildInputs = with pkgs; [
    openssl
    openldap
  ];
}
