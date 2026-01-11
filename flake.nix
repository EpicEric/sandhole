{
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      ...
    }:
    {
      nixosModules = {
        default = self.nixosModules.sandhole;
        sandhole =
          {
            pkgs,
            lib,
            ...
          }:
          {
            imports = [ ./nixos/module.nix ];
            services.sandhole.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
      };
      overlays = {
        default = self.overlays.sandhole;
        sandhole = final: prev: {
          sandhole = self.packages.${prev.stdenv.hostPlatform.system}.default;
        };
      };
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        rustChannel = "stable";
        rustVersion = "latest";

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        inherit (pkgs) lib;

        craneLib = (crane.mkLib pkgs).overrideToolchain (
          pkgs: pkgs.rust-bin.${rustChannel}.${rustVersion}.default
        );

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

          nativeBuildInputs = [
            pkgs.cmake
            pkgs.perl
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        sandhole =
          (craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
            }
          ))
          // {
            meta.mainProgram = "sandhole";
          };

        evalOptions = lib.evalModules {
          modules = [
            (
              { config, ... }:
              {
                options =
                  (import ./nixos/module.nix {
                    inherit pkgs lib;
                    config = config;
                  }).options;
              }
            )
          ];
        };

        optionsDoc = pkgs.nixosOptionsDoc {
          options = removeAttrs evalOptions.options [ "_module" ];
        };

        sandhole-cli = pkgs.stdenv.mkDerivation {
          name = "sandhole-cli";
          buildInputs = [
            pkgs.which
            pkgs.unixtools.script
          ];
          buildCommand = ''
            mkdir $out
            ${pkgs.to-html}/bin/to-html --no-prompt "${sandhole}/bin/sandhole --help" > $out/cli.html
          '';
        };

        sandhole-book = pkgs.stdenv.mkDerivation {
          name = "sandhole-book";
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              (lib.fileset.fileFilter (file: file.hasExt "js") ./book)
              ./book/book.toml
              ./book/src
              ./book/theme
            ];
          };
          buildInputs = [
            pkgs.mdbook-mermaid
          ];
          buildPhase = ''
            ${pkgs.mdbook}/bin/mdbook build book --dest-dir $out
          '';
        };
      in
      {
        packages = {
          inherit sandhole;
          default = sandhole;
          _book = sandhole-book;
          _cli = sandhole-cli;
          _docs = optionsDoc.optionsCommonMark;
        };

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
            pkgs.mdbook
            pkgs.mdbook-mermaid
            pkgs.minica
            pkgs.to-html
          ];
        };
      }
    );
}
