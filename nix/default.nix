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
      pkgs.installShellFiles
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
      postInstall = lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
        $out/bin/sandhole --completions bash
        installShellCompletion --cmd sandhole \
          --bash <($out/bin/sandhole --completions bash) \
          --fish <($out/bin/sandhole --completions fish) \
          --zsh <($out/bin/sandhole --completions zsh)
      '';
      meta = {
        name = "sandhole";
        description = "Expose HTTP/SSH/TCP services through SSH port forwarding";
        homepage = "https://sandhole.com.br";
        license = lib.licenses.mit;
        mainProgram = "sandhole";
        platforms = lib.platforms.linux ++ lib.platforms.darwin;
      };
    }
  );

  sandhole-no-default-features = sandhole.overrideAttrs {
    cargoExtraArgs = "--locked --no-default-features";
  };
in
{
  inherit sandhole sandhole-no-default-features;

  packages = import ./packages.nix {
    inherit
      pkgs
      sandhole
      sandhole-no-default-features
      ;
  };

  checks = import ./checks.nix {
    inherit
      cargoArtifacts
      commonArgs
      craneLib
      pkgs
      sandhole
      sandhole-no-default-features
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
