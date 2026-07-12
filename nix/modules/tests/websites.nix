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

# Set up a Sandhole server with HTTPS certificates,
# and connect to it from a different host with the custom
# sandhole-websites module.

{ pkgs, sandhole, ... }:

let
  pubKeys = "${../../../tests/data/user_keys}";
  privKey = "${../../../tests/data/private_keys/key1}";
  adminKey = "${../../../tests/data/private_keys/admin}";

  sandholeCerts = import ./generate-certs.nix {
    inherit pkgs;
    domain = "sandhole.nix";
  };
in

{
  name = "sandhole-module-test-websites";

  nodes = {
    # The reverse proxy running Sandhole.
    sandhole =
      { lib, ... }:
      {
        imports = [ ../sandhole.nix ];
        virtualisation.vlans = [ 10 ];
        networking = {
          useDHCP = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4 = {
              addresses = [
                {
                  address = "192.168.10.10";
                  prefixLength = 24;
                }
              ];
              routes = lib.mkForce [
                {
                  address = "0.0.0.0";
                  prefixLength = 0;
                  via = "192.168.10.1";
                }
              ];
            };
          };
          nameservers = [
            "8.8.8.8"
            "8.8.4.4"
          ];
        };

        environment.etc.admin_key = {
          source = adminKey;
          mode = "0400";
        };

        services.sandhole = {
          enable = true;
          package = sandhole;
          openFirewall = true;
          settings = {
            no-domain = true;
            user-keys-directory = pubKeys;
            certificates-directory = sandholeCerts;
            bind-hostnames = "all";
            force-https = true;
          };
        };
      };

    # The server that will be proxied via SSH.
    server =
      { lib, ... }:
      {
        imports = [ ../sandhole-websites.nix ];
        virtualisation.vlans = [ 10 ];
        networking = {
          useDHCP = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4 = {
              addresses = [
                {
                  address = "192.168.10.20";
                  prefixLength = 24;
                }
              ];
              routes = lib.mkForce [
                {
                  address = "0.0.0.0";
                  prefixLength = 0;
                  via = "192.168.10.1";
                }
              ];
            };
          };
        };

        services.openssh.enable = true;

        environment.etc.ssh_key = {
          source = privKey;
          mode = "0400";
        };

        sandhole.websites.example-website = {
          authorizedKeys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpmDGLbC68yM87r+fD/aoEimDdnzZtmnZXCnxkIGHMq admin"
          ];
          domains = [ "example.sandhole.nix" ];
          enableHttp2 = true;
          hostAddress6 = "fc00::2:1";
          localAddress6 = "fc00::2:2";
          autosshExtraArguments = "-o ServerAliveInterval=30 -c aes256-gcm@openssh.com";
          sandholeHost = "192.168.10.10";
          sandholePort = 2222;
          sandholeKeyPath = "/etc/ssh_key";
          sandholeExecArguments = "http2";
        };
      };
  };

  testScript = ''
    sandhole.start()
    sandhole.wait_for_unit("sandhole.service")
    sandhole.wait_for_open_port(2222)

    with subtest("add index.html to server"):
      server.start()
      server.wait_for_open_port(22)
      sandhole.succeed(
        "${pkgs.openssh}/bin/ssh"
        "  -i /etc/admin_key"
        "  -o StrictHostKeyChecking=accept-new"
        "  example-website@192.168.10.20"
        "  'echo \"Hello from NGINX!\" > /home/example-website/www/index.html'"
      )

    with subtest("connect to Sandhole"):
      server.wait_for_unit("autossh-example-website.service")
      server.wait_until_succeeds(
        "${pkgs.curl}/bin/curl --fail"
        "  --resolve example.sandhole.nix:443:192.168.10.10"
        "  --cacert ${sandholeCerts}/ca.cert.pem"
        "  https://example.sandhole.nix"
        "  | grep 'Hello from NGINX!'",
        timeout=30,
      )
  '';
}
