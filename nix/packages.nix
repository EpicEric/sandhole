{
  pkgs,
  sandhole,
  ...
}:
let
  inherit (pkgs) lib;
  evalOptions = lib.evalModules {
    modules = [
      (
        { config, pkgs, ... }:
        {
          options =
            (import ./modules/sandhole.nix {
              inherit
                pkgs
                config
                ;
              inherit (pkgs) lib;
            }).options;
        }
      )
    ];
    specialArgs = { inherit pkgs; };
  };
in
{
  inherit sandhole;
  default = sandhole;

  _docs =
    (pkgs.nixosOptionsDoc {
      options = removeAttrs evalOptions.options [ "_module" ];
    }).optionsCommonMark;

  _cli = pkgs.stdenv.mkDerivation {
    name = "sandhole-cli.html";
    nativeBuildInputs = [ pkgs.to-html ];
    buildCommand = ''
      to-html --no-prompt "${lib.getExe sandhole} --help" > $out
    '';
  };

  _book = pkgs.stdenv.mkDerivation {
    name = "sandhole-book";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../book/book.toml
        ../book/src
        ../book/theme
      ];
    };
    nativeBuildInputs = [ pkgs.mdbook ];
    buildPhase = ''
      mdbook build book --dest-dir $out
    '';
  };
}
