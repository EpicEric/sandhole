{
  system ? builtins.currentSystem,
  sources ? import ../npins,
  pkgs ? import sources.nixpkgs {
    inherit system;
    overlays = [ (import sources.rust-overlay) ];
  },
  craneLib ? (import sources.crane { inherit pkgs; }).overrideToolchain (
    p: p.rust-bin.stable.latest.default
  ),
}:
let
  inherit (pkgs) lib;

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
    ]
    ++ lib.optionals (system == "x86_64-darwin" || system == "aarch64-darwin") [ pkgs.lld ];
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
    inherit
      pkgs
      sandhole
      ;
  };

  checks = import ./checks.nix {
    inherit
      cargoArtifacts
      commonArgs
      craneLib
      pkgs
      sandhole
      src
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
