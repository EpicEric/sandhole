{
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding.";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        inherit (pkgs) lib;

        inherit (pkgs.rustPackages) rustPlatform;

        craneLib = crane.mkLib pkgs;

        unfilteredRoot = ./.;
        src = lib.fileset.toSource {
          root = unfilteredRoot;
          fileset = lib.fileset.unions [
            (craneLib.fileset.commonCargoSources unfilteredRoot)
            (lib.fileset.fileFilter (file: file.hasExt "md") unfilteredRoot)
            ./tests/data
          ];
        };

        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = with pkgs; [
            cmake
            gnumake
          ];

          nativeBuildInputs = with pkgs; [
            perl
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        mdbook = rustPlatform.buildRustPackage rec {
          pname = "mdbook";
          version = "0.5.2";

          src = pkgs.fetchFromGitHub {
            owner = "rust-lang";
            repo = "mdBook";
            tag = "v${version}";
            hash = "sha256-gyjD47ZR9o2lIxipzesyJ6mxb9J9W+WS77TNWhKHP6U=";
          };

          cargoHash = "sha256-230KljOUSrDy8QCQki7jvJvdAsjVlUEjKDNVyTF4tWs=";
        };

        mdbook-mermaid = rustPlatform.buildRustPackage rec {
          pname = "mdbook-mermaid";
          version = "0.17.0";

          src = pkgs.fetchFromGitHub {
            owner = "badboy";
            repo = "mdbook-mermaid";
            tag = "v${version}";
            hash = "sha256-9aiu3mQaRgVVhtX/v2hMPzclnVQIhUz4gVy0Xc84zO8=";
          };

          cargoHash = "sha256-MDtXgNiN4tVgP/98fbcL9WQXAJire+c3lmnc12KhQ50=";
        };

        sandhole = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false;
          }
        );
      in
      {
        packages.default = sandhole;

        apps.default = flake-utils.lib.mkApp {
          drv = sandhole;
        };

        checks = {
          inherit sandhole;

          sandhole-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );

          sandhole-doc = craneLib.cargoDoc (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );

          sandhole-fmt = craneLib.cargoFmt {
            inherit src;
          };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          inputsFrom = [ sandhole ];

          packages = [
            pkgs.cargo-flamegraph
            pkgs.just
            mdbook
            mdbook-mermaid
            pkgs.to-html
          ];
        };
      }
    );
}
