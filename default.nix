{ lib
, rustPlatform
, rustfmt
, clippy
, gcc
, go
, pkg-config
, openssl
, openldap
, stdenv
, cacert
}:

let
  cargo = builtins.fromTOML (builtins.readFile ./Cargo.toml);

  libtailscaleGoVendor = stdenv.mkDerivation {
    name = "libtailscale-sys-go-vendor";

    nativeBuildInputs = [ go cacert ];

    src = builtins.fetchTarball {
      url = "https://static.crates.io/crates/libtailscale-sys/libtailscale-sys-0.2.2.crate";
      sha256 = "03wxfj4sqz70a12hpxmjsq3g4ar2xap6a9dpxaylj12px86brccp";
    };

    outputHash = "sha256-mELppbs3THcGgOH5oCKdmGrzUFuTEJgeEdQN0J0A9xc=";
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";

    # may not need to set SSL_CERT_FILE
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    GOFLAGS = "-mod=mod";
    GOCACHE = "/tmp/go-build-fod";
    GOMODCACHE = "/tmp/go-mod-fod";

    buildCommand = ''
      chmod -R +w ./ 
      cd src/libtailscale
      go mod vendor
      cp -r vendor $out
    '';
  };
in

rustPlatform.buildRustPackage rec {
  pname = cargo.package.name;
  version = cargo.package.version;

  src = lib.sources.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [
    rustfmt
    clippy
    gcc
    go
    pkg-config
  ];
  buildInputs = [
    openssl
    openldap
  ];

  PKGS_CONFIG_PATH = "${openssl.dev}/lib/pkgconfig";
  GOCACHE = "/tmp/go-build";
  GOMODCACHE = "/tmp/go-mod";
  GOPATH = "/tmp/gopath";
  GOFLAGS = "-mod=vendor";

  preBuild = ''
    # Ensure libtailscale-sys always builds with a complete vendored tree.
    patched=0
    for root in "$CARGO_HOME" "$NIX_BUILD_TOP"; do
      if [ -d "$root" ]; then
        for dir in $(find "$root" -path "*/libtailscale-sys-*/libtailscale" -type d 2>/dev/null); do
          rm -rf "$dir/vendor"
          cp -r ${libtailscaleGoVendor} "$dir/vendor"
          chmod -R +w "$dir/vendor"
          patched=1
        done
      fi
    done

    if [ "$patched" -eq 0 ]; then
      echo "warning: did not find libtailscale-sys source to patch vendor directory"
    fi
  '';

  meta = {
    description = "A directory information tree for your TailNet.";
    homepage = "https://github.com/dominicegginton/dit0";
    platforms = lib.platforms.linux;
  };
}
