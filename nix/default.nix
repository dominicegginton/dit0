# Nix package derivation for dit0.
# This builds the Rust project while correctly handling its embedded Go dependency.
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
  # Read Cargo.toml to extract project name and version metadata.
  cargo = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  # Fixed-Output Derivation (FOD) to vendor Go dependencies for libtailscale-sys.
  # Since the build is sandboxed in Nix, we must pre-download the dependencies.
  libtailscaleGoVendor = stdenv.mkDerivation {
    name = "libtailscale-sys-go-vendor";

    # Include go and CA certificates for SSL verification during downloads.
    nativeBuildInputs = [ go cacert ];

    # Fetch the source of the libtailscale-sys crate from crates.io.
    src = builtins.fetchTarball {
      url = "https://static.crates.io/crates/libtailscale-sys/libtailscale-sys-0.2.2.crate";
      sha256 = "03wxfj4sqz70a12hpxmjsq3g4ar2xap6a9dpxaylj12px86brccp";
    };

    # The output hash allows internet access inside this specific sandbox.
    outputHash = "sha256-mELppbs3THcGgOH5oCKdmGrzUFuTEJgeEdQN0J0A9xc=";
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";

    # Go environment variables for resolving dependencies offline in the builder.
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    GOFLAGS = "-mod=mod";
    GOCACHE = "/tmp/go-build-fod";
    GOMODCACHE = "/tmp/go-mod-fod";

    # Vendor the dependencies and output only the vendor folder.
    buildCommand = ''
      chmod -R +w ./ 
      cd ./libtailscale
      go mod vendor
      cp -r vendor $out
    '';
  };
in

rustPlatform.buildRustPackage rec {
  pname = cargo.package.name;
  version = cargo.package.version;

  # Clean source to exclude untracked or unnecessary files from the build context.
  src = lib.sources.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  # Tools required to build the package.
  nativeBuildInputs = [
    rustfmt
    clippy
    gcc
    go
    pkg-config
  ];

  # Libraries required by the binary at runtime or dynamically linked.
  buildInputs = [
    openssl
    openldap
  ];

  # Set paths and build-time options.
  PKG_CONFIG_PATH = "${openssl.dev}/lib/pkgconfig";
  CGO_ENABLED = "1";
  GOFLAGS = "-mod=vendor";

  # Patch the libtailscale-sys source to use our pre-vendored Go dependencies.
  preBuild = ''
    export GOCACHE=$(mktemp -d)
    export GOMODCACHE=$(mktemp -d)
    export GOPATH=$(mktemp -d)

    # Ensure libtailscale-sys always builds with a complete vendored tree.
    patched=0
    for root in "$CARGO_HOME" "$NIX_BUILD_TOP" . ..; do
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
