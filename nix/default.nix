{
  system ? builtins.currentSystem,
  inputs ? import ../.tack,
  pkgs ? import inputs.nixpkgs {
    inherit system;
    overlays = [ (import inputs.rust-overlay) ];
  },
  craneLib ? (import inputs.crane { inherit pkgs; }).overrideToolchain (
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

  sandhole-no_default_features = sandhole.overrideAttrs {
    cargoExtraArgs = "--locked --no-default-features";
  };

  udp_over_tcp = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      inherit (craneLib.crateNameFromCargoToml { cargoToml = ../udp_over_tcp/Cargo.toml; })
        pname
        version
        ;
      doCheck = false;
      cargoExtraArgs = "-p sandhole_udp_over_tcp";
      meta = {
        name = "sandhole_udp_over_tcp";
        description = "Proxy UDP traffic for Sandhole via SSH";
        homepage = "https://sandhole.com.br";
        license = lib.licenses.mit;
        mainProgram = "sandhole_udp_over_tcp";
        platforms = lib.platforms.linux ++ lib.platforms.darwin;
      };
    }
  );
in
{
  inherit sandhole sandhole-no_default_features;

  packages = import ./packages.nix {
    inherit
      pkgs
      sandhole
      sandhole-no_default_features
      udp_over_tcp
      ;
  };

  checks = import ./checks.nix {
    inherit
      cargoArtifacts
      commonArgs
      craneLib
      pkgs
      sandhole
      sandhole-no_default_features
      udp_over_tcp
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
