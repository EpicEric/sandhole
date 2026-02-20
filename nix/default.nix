{
  system ? builtins.currentSystem,
  rustChannel ? "stable",
  rustVersion ? "latest",
}:
let
  sources = import ../npins;

  pkgs = import sources.nixpkgs {
    inherit system;
    overlays = [ (import sources.rust-overlay) ];
  };

  inherit (pkgs) lib;

  craneLib = (import sources.crane { inherit pkgs; }).overrideToolchain (
    p: p.rust-bin.${rustChannel}.${rustVersion}.default
  );

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (craneLib.fileset.commonCargoSources ../.)
      ../README.md
      ../.config/nextest.toml
      ../tests/data
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
in
{
  inherit pkgs sandhole;

  packages = import ./packages.nix {
    inherit sandhole;
    inherit (pkgs)
      lib
      mdbook
      nixosOptionsDoc
      stdenv
      to-html
      ;
  };

  checks = import ./checks.nix {
    inherit
      cargoArtifacts
      commonArgs
      craneLib
      sandhole
      src
      ;
    inherit (pkgs)
      cargo-nextest
      testers
      ;
  };

  shell = craneLib.devShell {
    packages = [
      # General dependencies
      pkgs.just

      # Book dependencies
      pkgs.mdbook
      pkgs.to-html

      # Profiling dependencies
      pkgs.cargo-flamegraph

      # Test dependencies
      pkgs.cargo-nextest
      pkgs.minica
    ];
  };
}
