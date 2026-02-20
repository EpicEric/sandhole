{
  description = "Expose HTTP/SSH/TCP services through SSH port forwarding";

  inputs = { };

  outputs =
    { self, ... }:
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
        inherit (import ./nix/lib.nix { inherit system; })
          sandhole
          sandhole-book
          sandhole-cli
          optionsDoc
          lib
          checks
          ;
      in
      {
        packages.${system} = {
          inherit sandhole;
          default = sandhole;
          _book = sandhole-book;
          _cli = sandhole-cli;
          _docs = optionsDoc.optionsCommonMark;
        };

        apps.${system}.default = {
          type = "app";
          program = lib.getExe sandhole;
          meta = {
            name = "sandhole";
            description = "Expose HTTP/SSH/TCP services through SSH port forwarding";
            homepage = "https://sandhole.com.br";
            license = lib.licenses.mit;
            mainProgram = "sandhole";
            platforms = lib.platforms.linux ++ lib.platforms.darwin;
          };
        };

        checks.${system} = checks;

        devShells.${system}.default = import ./shell.nix { inherit system; };
      }
    );
}
