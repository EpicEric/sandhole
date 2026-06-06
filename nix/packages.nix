{
  pkgs,
  sandhole,
  sandhole-no-default-features,
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
  inherit sandhole sandhole-no-default-features;
  default = sandhole;

  _docs =
    (pkgs.nixosOptionsDoc {
      options = removeAttrs evalOptions.options [ "_module" ];
    }).optionsCommonMark;

  _cli =
    pkgs.runCommand "sandhole-cli.html"
      {
        nativeBuildInputs = [
          pkgs.to-html
          sandhole
        ];
      }
      ''
        mkdir $out
        to-html --no-prompt "sandhole --help" > $out/cli.html
      '';

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
