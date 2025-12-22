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

        craneLib = crane.mkLib pkgs;

        mdbook = craneLib.buildPackage rec {
          pname = "mdbook";
          version = "0.5.2";
          src = pkgs.fetchFromGitHub {
            owner = "rust-lang";
            repo = "mdBook";
            tag = "v${version}";
            hash = "sha256-gyjD47ZR9o2lIxipzesyJ6mxb9J9W+WS77TNWhKHP6U=";
          };
          doCheck = false;
        };

        mdbook-mermaid = craneLib.buildPackage rec {
          pname = "mdbook-mermaid";
          version = "0.17.0";
          src = pkgs.fetchFromGitHub {
            owner = "badboy";
            repo = "mdbook-mermaid";
            tag = "v${version}";
            hash = "sha256-9aiu3mQaRgVVhtX/v2hMPzclnVQIhUz4gVy0Xc84zO8=";
          };
          doCheck = false;
        };

        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            (craneLib.fileset.commonCargoSources ./.)
            ./README.md
            ./.config/nextest.toml
            ./tests/data
          ];
        };

        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = with pkgs; [ cmake ];
          nativeBuildInputs = with pkgs; [ perl ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

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

        apps.default =
          (flake-utils.lib.mkApp {
            drv = sandhole;
          })
          // {
            meta = {
              description = "Expose HTTP/SSH/TCP services through SSH port forwarding";
              homepage = "https://sandhole.com.br";
              license = lib.licenses.mit;
              mainProgram = "sandhole";
              platforms = lib.platforms.linux ++ lib.platforms.darwin;
            };
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

          sandhole-test = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoNextestExtraArgs = "-P nix";
            }
          );
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
