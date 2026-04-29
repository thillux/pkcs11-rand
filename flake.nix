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

        # Build one PKCS#11 module variant. `n` and `m` are the compile-time
        # iso7816 / infnoise counts; switching either is a rebuild.
        mkP11Rand = { n, m, pname-suffix }: pkgs.stdenv.mkDerivation {
          pname  = "mini-pkcs11-rand-${pname-suffix}";
          version = "0.1.0";
          src = self;

          nativeBuildInputs = with pkgs; [ meson ninja pkg-config ];
          buildInputs =
            pkgs.lib.optionals (n > 0) [ pkgs.pcsclite ]
            # libcrypto: needed only by the pool's SHA3-256 chain when n+m>1.
            ++ pkgs.lib.optionals ((n + m) > 1) [ pkgs.openssl ];

          mesonFlags = [
            "-Diso7816_cards=${toString n}"
            "-Dinfnoise_devices=${toString m}"
          ];

          meta = with pkgs.lib; {
            description = "PKCS#11 RNG pool (n=${toString n} smartcards, m=${toString m} infnoise)";
            license     = licenses.mit;
            platforms   = platforms.linux;
          };
        };
      in {
        packages = {
          # Default: single smartcard, raw GET CHALLENGE, no openssl dep.
          default  = mkP11Rand { n = 1; m = 0; pname-suffix = "iso7816"; };
          iso7816  = mkP11Rand { n = 1; m = 0; pname-suffix = "iso7816"; };

          # Single Infinite Noise TRNG.
          infnoise = mkP11Rand { n = 0; m = 1; pname-suffix = "infnoise"; };

          # Combined pool: 1 smartcard + 1 infnoise, mixed via SHA3-256 chain.
          combined = mkP11Rand { n = 1; m = 1; pname-suffix = "combined"; };
          combined-double = mkP11Rand { n = 3; m = 2; pname-suffix = "combined"; };

          # 2 smartcards in a pool, mixed via SHA3-256 chain.
          iso7816-pool = mkP11Rand { n = 2; m = 0; pname-suffix = "iso7816-pool"; };

          # 2 Infinite Noise dongles in a pool, mixed via SHA3-256 chain.
          infnoise-pool = mkP11Rand { n = 0; m = 2; pname-suffix = "infnoise-pool"; };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            meson ninja pkg-config gcc
            pcsclite          # iso7816
            openssl           # SHA3 (pool chain or infnoise postprocess)
            opensc            # pkcs11-tool
            pcsc-tools        # pcsc_scan
          ];
          shellHook = ''
            echo "mini-pkcs11-rand dev shell — examples:"
            echo "  meson setup build      -Diso7816_cards=1 -Dinfnoise_devices=0   # default"
            echo "  meson setup build-pool -Diso7816_cards=2                         # 2-card pool"
            echo "  meson setup build-mix  -Diso7816_cards=1 -Dinfnoise_devices=1   # combined"
            echo "  meson setup build-inf  -Diso7816_cards=0 -Dinfnoise_devices=1   # infnoise only"
          '';
        };

        checks = {
          build-iso7816  = self.packages.${system}.iso7816;
          build-infnoise = self.packages.${system}.infnoise;
          build-combined = self.packages.${system}.combined;
          build-pool     = self.packages.${system}.iso7816-pool;
          build-inf-pool = self.packages.${system}.infnoise-pool;
        };
      });
}
