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

  # TODO: fix by vendoring go modules - not completed
  GOCACHE = "/tmp/go-build";
  GOMODCACHE = "/tmp/go-mod";
  GOFLAGS = "-mod=vendor";

  meta = {
    description = "A directory information tree for your TailNet.";
    homepage = "https://github.com/dominicegginton/dit0";
    platforms = lib.platforms.linux;
  };
}
