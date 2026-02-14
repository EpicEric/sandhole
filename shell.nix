{
  system ? builtins.currentSystem,
}:
let
  inherit (import ./lib.nix { inherit system; }) pkgs craneLib;
in
craneLib.devShell {
  packages = [
    pkgs.cargo-flamegraph
    pkgs.cargo-nextest
    pkgs.just
    pkgs.mdbook
    pkgs.minica
    pkgs.to-html
  ];
}
