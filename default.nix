{
  system ? builtins.currentSystem,
}:
(import ./lib.nix { inherit system; }).sandhole
