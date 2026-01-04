flake:
let
  lib = flake.lib;
  pkgs = flake.self.nixosConfigurations.basic.pkgs;

  evalOptions = (
    lib.evalModules {
      modules = [
        (import ./module.nix flake)
      ];
    }
  );

  optionsDoc = (
    pkgs.nixosOptionsDoc {
      options = removeAttrs evalOptions.options [ "_module" ];
    }
  );
in
optionsDoc.optionsCommonMark
