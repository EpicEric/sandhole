{
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding";

  inputs = {
    crane = {
      url = "github:EpicEric/dummy.nix/main";
      flake = false;
    };
    nixpkgs = {
      url = "github:EpicEric/dummy.nix/main";
      flake = false;
    };
    rust-overlay = {
      url = "github:EpicEric/dummy.nix/main";
      flake = false;
    };
  };

  outputs =
    { self, ... }@inputs:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
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
        sources = import ./npins;
        importInput =
          attr:
          if import inputs.${attr} ? __isDummyInput then import sources.${attr} else import inputs.${attr};
        pkgs = importInput "nixpkgs" {
          inherit system;
          overlays = [ (importInput "rust-overlay") ];
        };
        craneLib = (importInput "crane" { inherit pkgs; }).overrideToolchain (
          p: p.rust-bin.stable.latest.default
        );

        inherit
          (import ./nix {
            inherit
              system
              pkgs
              craneLib
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
