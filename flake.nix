{
  description = "multisig-sig — multi-user bitcoin multisig custody coordination";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {inherit system overlays;};

      # Toolchain pinned by rust-toolchain.toml (channel stable, profile
      # default — which already includes clippy and rustfmt); rust-src and
      # rust-analyzer added for IDE support.
      rustToolchain =
        (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = ["rust-src" "rust-analyzer"];
        };
    in
      with pkgs; {
        devShells.default = mkShell {
          nativeBuildInputs = [
            rustToolchain
            sqlx-cli
            cargo-nextest
            cargo-watch
            postgresql_18
            jq
            alejandra
          ];

          shellHook = ''
            # Scoped to this directory by direnv — overrides any DATABASE_URL
            # leaked from other projects' shells.
            export DATABASE_URL="postgres://user:password@127.0.0.1:5441/kota"
          '';
        };

        formatter = alejandra;
      });
}
