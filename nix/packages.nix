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
  pkgs,
  sandhole,
  sandhole-no_default_features,
  udp_over_tcp,
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
  inherit sandhole sandhole-no_default_features udp_over_tcp;
  default = sandhole;

  docker = pkgs.dockerTools.buildImage {
    name = "sandhole";
    tag = "musl";
    config.Entrypoint = [ (lib.getExe sandhole) ];
  };

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
