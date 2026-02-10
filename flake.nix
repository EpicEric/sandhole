{
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
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
      rust-overlay,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      eachSystem =
        f:
        (builtins.foldl' (
          acc: system:
          let
            fSystem = f system;
          in
          builtins.foldl' (
            acc': attr:
            acc'
            // {
              ${attr} = (acc'.${attr} or { }) // fSystem.${attr};
            }
          ) acc (builtins.attrNames fSystem)
        ) { } systems);
    in
    {
      nixosModules = {
        default = self.nixosModules.sandhole;
        sandhole =
          { lib, pkgs, ... }:
          {
            imports = [ ./nixos/module.nix ];
            services.sandhole.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
        sandhole-websites =
          { ... }:
          {
            imports = [ ./nixos/sandhole-websites.nix ];
          };
      };

      overlays = {
        default = self.overlays.sandhole;
        sandhole = _: prev: {
          sandhole = self.packages.${prev.stdenv.hostPlatform.system}.default;
        };
      };
    }
    // eachSystem (
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
          nativeBuildInputs = [ pkgs.to-html ];
          buildCommand = ''
            mkdir $out
            to-html --no-prompt "${lib.getExe sandhole} --help" > $out/cli.html
          '';
        };

        sandhole-book = pkgs.stdenv.mkDerivation {
          name = "sandhole-book";
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./book/book.toml
              ./book/src
              ./book/theme
            ];
          };
          nativeBuildInputs = [ pkgs.mdbook ];
          buildPhase = ''
            mdbook build book --dest-dir $out
          '';
        };
      in
      {
        packages.${system} = {
          inherit sandhole;
          default = sandhole;
          _book = sandhole-book;
          _cli = sandhole-cli;
          _docs = optionsDoc.optionsCommonMark;
        };

        apps.${system}.default = {
          type = "app";
          program = lib.getExe sandhole;
          meta = {
            name = "sandhole";
            description = "Expose HTTP/SSH/TCP services through SSH port forwarding";
            homepage = "https://sandhole.com.br";
            license = lib.licenses.mit;
            mainProgram = "sandhole";
            platforms = lib.platforms.linux ++ lib.platforms.darwin;
          };
        };

        checks.${system} = {
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

          sandhole-test =
            let
              sandhole-nextest-archive = craneLib.mkCargoDerivation (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  pname = "sandhole-nextest-archive";
                  doCheck = false;
                  nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-nextest ];
                  buildPhaseCargoCommand = ''
                    cargo nextest archive --archive-format tar-zst --archive-file archive.tar.zst
                  '';
                  installPhaseCommand = ''
                    mkdir -p $out
                    cp archive.tar.zst $out
                  '';
                }
              );
            in
            pkgs.testers.runNixOSTest {
              name = "sandhole-nextest";
              nodes = {
                machine =
                  { ... }:
                  {
                    virtualisation.diskSize = 4096;
                    environment.defaultPackages = [
                      pkgs.cargo
                      pkgs.rustc
                    ];
                    systemd.services.sandhole-nextest = {
                      description = "Sandhole tests";
                      wantedBy = [ "multi-user.target" ];
                      after = [ "network-online.target" ];
                      wants = [ "network-online.target" ];
                      script = ''
                        cp -r ${src}/* .
                        ${pkgs.cargo-nextest}/bin/cargo-nextest nextest run \
                          --archive-file ${sandhole-nextest-archive}/archive.tar.zst \
                          --workspace-remap .
                      '';
                      serviceConfig = {
                        StateDirectory = "sandhole-nextest";
                        StateDirectoryMode = "0750";
                        WorkingDirectory = "/var/lib/sandhole-nextest";
                        Type = "oneshot";
                        RemainAfterExit = "yes";
                        Restart = "no";
                      };
                    };
                  };
              };
              testScript = ''
                machine.start()
                machine.wait_for_unit("sandhole-nextest.service")
              '';
            };
        };

        devShells.${system}.default = craneLib.devShell {
          checks = self.checks.${system};

          inputsFrom = [ sandhole ];

          packages = [
            pkgs.cargo-flamegraph
            pkgs.cargo-nextest
            pkgs.just
            pkgs.mdbook
            pkgs.minica
            pkgs.to-html
          ];
        };
      }
    );
}
