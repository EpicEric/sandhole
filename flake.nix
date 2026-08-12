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
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding";

  outputs =
    { self, ... }@args:
    let
      inputs = (import ./.tack) {
        overrides = args.tackOverrides or { };
      };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      eachSystem =
        f:
        (builtins.foldl' (
          acc: system:
          let
            fSystem = f system;
          in
          builtins.foldl' (
            acc': attr:
            acc'
            // {
              ${attr} = (acc'.${attr} or { }) // fSystem.${attr};
            }
          ) acc (builtins.attrNames fSystem)
        ) { } systems);
    in
    {
      nixosModules = {
        default = self.nixosModules.sandhole;
        sandhole =
          { lib, pkgs, ... }:
          {
            imports = [ ./nix/modules/sandhole.nix ];
            services.sandhole.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
        sandhole-websites =
          { ... }:
          {
            imports = [ ./nix/modules/sandhole-websites.nix ];
          };
      };

      overlays = {
        default = self.overlays.sandhole;
        sandhole = _: prev: {
          sandhole = self.packages.${prev.stdenv.hostPlatform.system}.default;
        };
      };
    }
    // eachSystem (
      system:
      let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ (import inputs.rust-overlay) ];
        };

        inherit
          (import ./nix {
            inherit
              system
              pkgs
              ;
          })
          packages
          checks
          shell
          ;

        inherit (pkgs) lib;
      in
      {
        packages.${system} = packages;

        apps.${system}.default =
          let
            sandhole = self.packages.${system}.default;
          in
          {
            type = "app";
            program = lib.getExe sandhole;
            inherit (sandhole) meta;
          };

        checks.${system} = checks;

        devShells.${system}.default = shell;
      }
    );
}
