{
  system ? builtins.currentSystem,
}:
(import ./nix/lib.nix { inherit system; }).sandhole
