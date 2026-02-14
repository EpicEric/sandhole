{
  system ? builtins.currentSystem,
  rustChannel ? "stable",
  rustVersion ? "latest",
}:
let
  sources = import ./npins;

  pkgs = import sources.nixpkgs {
    inherit system;
    overlays = [ (import sources.rust-overlay) ];
  };

  inherit (pkgs) lib;

  craneLib = (import sources.crane { inherit pkgs; }).overrideToolchain (
    p: p.rust-bin.${rustChannel}.${rustVersion}.default
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

  sandhole = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      doCheck = false;
      meta.mainProgram = "sandhole";
    }
  );

  evalOptions = lib.evalModules {
    modules = [
      (
        { config, ... }:
        {
          options =
            (import ./nix/modules/sandhole.nix {
              inherit pkgs lib;
              config = config;
            }).options;
        }
      )
    ];
  };
in
{
  inherit
    pkgs
    lib
    craneLib
    commonArgs
    cargoArtifacts
    sandhole
    ;

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

    sandhole-test =
      let
        sandhole-nextest-archive = craneLib.mkCargoDerivation (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "sandhole-nextest-archive";
            doCheck = false;
            nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ]) ++ [ pkgs.cargo-nextest ];
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
            { pkgs, ... }:
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
                path = [
                  pkgs.cargo
                  pkgs.cargo-nextest
                ];
                script = ''
                  cp -r ${src}/* .
                  cargo nextest run \
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
}
