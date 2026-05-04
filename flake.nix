{
  description = "mini-pkcs11-rand — PKCS#11 module exposing a pool of hardware TRNGs (ISO7816 GET CHALLENGE smartcards + Infinite Noise USB) as C_GenerateRandom";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Build one PKCS#11 module variant. `n` and `m` are the build-time
        # iso7816 / infnoise counts; switching either is a rebuild.
        # `iso_in` / `inf_in` control per-source per-round byte counts;
        # values >32 enable oversampling and force the SHA3-256 chain on
        # even at n+m=1.
        mkP11Rand = { n, m, iso_in ? 32, inf_in ? 32, pname-suffix }:
          pkgs.rustPlatform.buildRustPackage {
            pname  = "mini-pkcs11-rand-${pname-suffix}";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs       = [ pkgs.pcsclite ];

            # Compile-time pool config. The `p11rand` crate's build.rs
            # reads these env vars and bakes them into the cdylib.
            P11RAND_ISO7816_CARDS       = toString n;
            P11RAND_INFNOISE_DEVICES    = toString m;
            P11RAND_ISO7816_INPUT_BYTES = toString iso_in;
            P11RAND_INFNOISE_INPUT_BYTES = toString inf_in;

            postInstall = ''
              # Cargo names the cdylib `libp11rand.so`. We want the
              # versioned soname mirror that the original meson build
              # produced, so /etc/p11/modules consumers can keep their
              # existing config file.
              if [ -f $out/lib/libp11rand.so ]; then
                ln -sf libp11rand.so $out/lib/libp11rand.so.0
              fi
            '';

            meta = with pkgs.lib; {
              description = "PKCS#11 RNG pool (n=${toString n} smartcards, m=${toString m} infnoise)";
              license     = licenses.mit;
              platforms   = platforms.linux;
            };
          };
      in {
        packages = {
          # Default: single smartcard, raw GET CHALLENGE, no SHA3 chain.
          default  = mkP11Rand { n = 1; m = 0; pname-suffix = "iso7816"; };
          iso7816  = mkP11Rand { n = 1; m = 0; pname-suffix = "iso7816"; };

          # Single Infinite Noise TRNG.
          infnoise = mkP11Rand { n = 0; m = 1; pname-suffix = "infnoise"; };

          # Combined pool: 1 smartcard + 1 infnoise, mixed via SHA3-256 chain.
          combined        = mkP11Rand { n = 1; m = 1; pname-suffix = "combined"; };
          combined-double = mkP11Rand { n = 3; m = 2; pname-suffix = "combined-double"; };

          # 2 smartcards in a pool, mixed via SHA3-256 chain.
          iso7816-pool  = mkP11Rand { n = 2; m = 0; pname-suffix = "iso7816-pool"; };

          # 2 Infinite Noise dongles in a pool, mixed via SHA3-256 chain.
          infnoise-pool = mkP11Rand { n = 0; m = 2; pname-suffix = "infnoise-pool"; };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo rustc rustfmt clippy rust-analyzer
            pkg-config
            pcsclite           # iso7816 backend
            opensc             # pkcs11-tool
            pcsc-tools         # pcsc_scan
          ];
          shellHook = ''
            echo "mini-pkcs11-rand dev shell — examples:"
            echo "  cargo build --release                          # default: iso7816=1"
            echo "  P11RAND_ISO7816_CARDS=2 cargo build --release  # 2-card pool"
            echo "  P11RAND_INFNOISE_DEVICES=1 P11RAND_ISO7816_CARDS=0 cargo build --release  # infnoise-only"
            echo "  P11RAND_ISO7816_CARDS=1 P11RAND_INFNOISE_DEVICES=1 cargo build --release  # combined"
          '';
        };

        checks = {
          build-iso7816   = self.packages.${system}.iso7816;
          build-infnoise  = self.packages.${system}.infnoise;
          build-combined  = self.packages.${system}.combined;
          build-pool      = self.packages.${system}.iso7816-pool;
          build-inf-pool  = self.packages.${system}.infnoise-pool;
        };
      });
}
