{
  lib,
  mdbook,
  nixosOptionsDoc,
  sandhole,
  stdenv,
  to-html,
}:
let
  evalOptions = lib.evalModules {
    modules = [
      (
        { config, pkgs, ... }:
        {
          options =
            (import ./modules/sandhole.nix {
              inherit
                pkgs
                lib
                config
                ;
            }).options;
        }
      )
    ];
  };
in
{
  inherit sandhole;
  default = sandhole;

  _docs =
    (nixosOptionsDoc {
      options = removeAttrs evalOptions.options [ "_module" ];
    }).optionsCommonMark;

  _cli = stdenv.mkDerivation {
    name = "sandhole-cli.html";
    nativeBuildInputs = [ to-html ];
    buildCommand = ''
      to-html --no-prompt "${lib.getExe sandhole} --help" > $out
    '';
  };

  _book = stdenv.mkDerivation {
    name = "sandhole-book";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../book/book.toml
        ../book/src
        ../book/theme
      ];
    };
    nativeBuildInputs = [ mdbook ];
    buildPhase = ''
      mdbook build book --dest-dir $out
    '';
  };
}
