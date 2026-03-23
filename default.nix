{ lib
, rustPlatform
, rustfmt
, gcc
, go
, pkg-config
, openssl
, openldap
}:

let
  cargo = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in

rustPlatform.buildRustPackage rec {
  pname = cargo.package.name;
  version = cargo.package.version;

  src = lib.sources.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ rustfmt gcc go pkg-config ];
  buildInputs = [ openssl openldap ];

  PKGS_CONFIG_PATH = "${openssl.dev}/lib/pkgconfig";

  meta = {
    description = "A directory information tree for your TailNet.";
    homepage = "https://github.com/dominicegginton/dit0";
    platforms = lib.platforms.linux;
  };
}
