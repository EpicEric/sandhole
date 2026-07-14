# sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
# Copyright (C) 2024-2026 Eric Rodrigues Pires
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
# more details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

{
  system ? builtins.currentSystem,
  inputs ? import ../.tack,
  pkgs ? import inputs.nixpkgs {
    inherit system;
    overlays = [ (import inputs.rust-overlay) ];
  },
}:
let
  inherit (pkgs) pkgsStatic lib;

  rustPlatform = pkgsStatic.makeRustPlatform {
    cargo = pkgsStatic.rust-bin.stable.latest.default;
    rustc = pkgsStatic.rust-bin.stable.latest.default;
  };

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../README.md
      ../.cargo
      ../.config/nextest.toml
      ../sandhole_socket
      ../src
      ../udp_over_tcp
      ../tests
    ];
  };

  commonArgs = {
    inherit src;
    __structuredAttrs = true;
    strictDeps = true;
    cargoLock.lockFile = ../Cargo.lock;

    nativeBuildInputs = [
      pkgsStatic.cmake
      pkgsStatic.installShellFiles
      pkgsStatic.perl
    ]
    ++ lib.optionals (system == "x86_64-darwin" || system == "aarch64-darwin") [ pkgsStatic.lld ];
  };

  sandhole = rustPlatform.buildRustPackage (
    commonArgs
    // {
      pname = (lib.importTOML ../Cargo.toml).package.name;
      version = (lib.importTOML ../Cargo.toml).package.version;
      doCheck = false;
      postInstall = lib.optionalString (pkgsStatic.stdenv.buildPlatform.canExecute pkgsStatic.stdenv.hostPlatform) ''
        installShellCompletion --cmd sandhole \
          --bash <($out/bin/sandhole --completions bash) \
          --fish <($out/bin/sandhole --completions fish) \
          --zsh <($out/bin/sandhole --completions zsh)
      '';
      meta = {
        name = "sandhole";
        description = "Expose HTTP/SSH/TCP services through SSH port forwarding";
        homepage = "https://sandhole.com.br";
        license = lib.licenses.agpl3Plus;
        mainProgram = "sandhole";
        platforms = lib.platforms.linux ++ lib.platforms.darwin;
      };
    }
  );

  sandhole-no_default_features = sandhole.overrideAttrs { buildNoDefaultFeatures = true; };

  udp_over_tcp = rustPlatform.buildRustPackage (
    commonArgs
    // {
      pname = (lib.importTOML ../udp_over_tcp/Cargo.toml).package.name;
      version = (lib.importTOML ../udp_over_tcp/Cargo.toml).package.version;
      buildAndTestSubdir = "udp_over_tcp";
      doCheck = false;
      meta = {
        name = "sandhole_udp_over_tcp";
        description = "Proxy UDP traffic for Sandhole via SSH";
        homepage = "https://sandhole.com.br";
        license = lib.licenses.agpl3Plus;
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
      pkgs
      sandhole
      ;
  };

  shell = pkgs.mkShell {
    packages = [
      # General dependencies
      pkgs.rust-bin.stable.latest.default
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
