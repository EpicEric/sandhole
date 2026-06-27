{
  system ? builtins.currentSystem,
  inputs ? import ./.tack,
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
in
{
  imports = [ ./nix/modules/sandhole.nix ];
  services.sandhole.package =
    lib.mkDefault
      (import ./nix {
        inherit
          system
          inputs
          pkgs
          craneLib
          ;
      }).sandhole;
}
