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

          packages = with pkgs; [
            cargo-flamegraph
            just
            mdbook
            mdbook-mermaid
            to-html
          ];
        };
      }
    );
}
