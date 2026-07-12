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
# a proxied service in a different machine, and a
# client who's blacklisted by Sandhole.

{ pkgs, sandhole, ... }:

let
  pubKeys = "${../../../tests/data/user_keys}";
  privKey = "${../../../tests/data/private_keys/key1}";

  sandholeCerts = import ./generate-certs.nix {
    inherit pkgs;
    domain = "sandhole.nix";
  };
in

{
  name = "sandhole-module-test-blacklist";

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

        services.sandhole = {
          enable = true;
          package = sandhole;
          openFirewall = true;
          settings = {
            domain = "sandhole.nix";
            user-keys-directory = pubKeys;
            certificates-directory = sandholeCerts;
            bind-hostnames = "all";
            ip-blocklist = "192.168.10.30/32";
            force-https = true;
          };
        };
      };

    # The server that will be proxied via SSH.
    server =
      { lib, ... }:
      {
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
          firewall.allowedTCPPorts = [ 80 ];
        };

        users.users.autossh = {
          isNormalUser = true;
        };
        users.groups.autossh = { };

        services.nginx = {
          enable = true;
          virtualHosts.localhost = {
            locations."/" = {
              return = "200 '<html><body>Hello, NixOS!</body></html>'";
              extraConfig = ''
                default_type text/html;
              '';
            };
          };
        };

        services.autossh.sessions = [
          {
            name = "sandhole";
            user = "autossh";
            extraArguments = ''
              -i ${privKey} \
              -o StrictHostKeyChecking=accept-new \
              -o ServerAliveInterval=30 \
              -R hello.sandhole.nix:443:localhost:80 \
              -p 2222 \
              192.168.10.10
            '';
          }
        ];
      };

    # The client that will be blocked from accessing Sandhole.
    blocked =
      { lib, ... }:
      {
        virtualisation.vlans = [ 10 ];
        networking = {
          useDHCP = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4 = {
              addresses = [
                {
                  address = "192.168.10.30";
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
      };
  };

  testScript = ''
    sandhole.start()
    sandhole.wait_for_unit("sandhole.service")
    sandhole.wait_for_open_port(2222)

    with subtest("connect to Sandhole"):
      server.start()
      server.wait_for_unit("autossh-sandhole.service")
      server.wait_until_succeeds(
        "${pkgs.curl}/bin/curl --fail"
        "  --resolve hello.sandhole.nix:443:192.168.10.10"
        "  --cacert ${sandholeCerts}/ca.cert.pem"
        "  https://hello.sandhole.nix"
        "  | grep 'Hello, NixOS!'",
        timeout=30,
      )

    with subtest("get blocklisted by Sandhole"):
      blocked.start()
      blocked.wait_for_unit("network.target")
      blocked.wait_until_succeeds(
        "${pkgs.curl}/bin/curl --fail"
        "  http://192.168.10.20"
        "  | grep 'Hello, NixOS!'",
        timeout=30,
      )
      blocked.fail(
        "${pkgs.curl}/bin/curl --fail"
        "  --resolve hello.sandhole.nix:443:192.168.10.10"
        "  --cacert ${sandholeCerts}/ca.cert.pem"
        "  https://hello.sandhole.nix"
      )
  '';
}
