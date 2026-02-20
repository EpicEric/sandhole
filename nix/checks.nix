{
  cargo-nextest,
  cargoArtifacts,
  commonArgs,
  craneLib,
  sandhole,
  src,
  testers,
}:
{
  inherit sandhole;

  sandhole-clippy = craneLib.cargoClippy (
    commonArgs
    // {
      inherit cargoArtifacts;
    }
  );

  sandhole-doc = craneLib.cargoDoc (
    commonArgs
    // {
      inherit cargoArtifacts;
    }
  );

  sandhole-fmt = craneLib.cargoFmt {
    inherit src;
  };

  sandhole-test =
    let
      sandhole-nextest-archive = craneLib.mkCargoDerivation (
        commonArgs
        // {
          inherit cargoArtifacts;
          pname = "sandhole-nextest-archive";
          doCheck = false;
          nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ]) ++ [ cargo-nextest ];
          buildPhaseCargoCommand = ''
            cargo nextest archive --archive-format tar-zst --archive-file archive.tar.zst
          '';
          installPhaseCommand = ''
            mkdir -p $out
            cp archive.tar.zst $out
          '';
        }
      );
    in
    testers.runNixOSTest {
      name = "sandhole-nextest";
      nodes = {
        machine =
          { pkgs, ... }:
          {
            virtualisation.diskSize = 4096;
            environment.defaultPackages = [
              pkgs.cargo
              pkgs.rustc
            ];
            systemd.services.sandhole-nextest = {
              description = "Sandhole tests";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              path = [
                pkgs.cargo
                pkgs.cargo-nextest
              ];
              script = ''
                cp -r ${src}/* .
                cargo nextest run \
                  --archive-file ${sandhole-nextest-archive}/archive.tar.zst \
                  --workspace-remap .
              '';
              serviceConfig = {
                StateDirectory = "sandhole-nextest";
                StateDirectoryMode = "0750";
                WorkingDirectory = "/var/lib/sandhole-nextest";
                Type = "oneshot";
                RemainAfterExit = "yes";
                Restart = "no";
              };
            };
          };
      };
      testScript = ''
        machine.start()
        machine.wait_for_unit("sandhole-nextest.service")
      '';
    };
}
