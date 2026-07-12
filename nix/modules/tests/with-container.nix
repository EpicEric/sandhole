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

# Set up a Sandhole server without any privileged ports,
# and a container on the same machine running httpd,
# which will be proxied via Sandhole.

{ pkgs, sandhole, ... }:

let
  pubKeys = "${../../../tests/data/user_keys}";
  privKey = "${../../../tests/data/private_keys/key1}";
in

{
  name = "sandhole-module-test-with-container";

  nodes.machine =
    { ... }:
    {
      imports = [ ../sandhole.nix ];
      virtualisation.vlans = [ 10 ];
      networking = {
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
          bind-hostnames = "all";
          disable-https = true;
          http-port = 8080;
        };
      };

      containers.httpd = {
        autoStart = true;
        privateNetwork = true;
        hostAddress = "172.16.0.1";
        localAddress = "172.16.0.2";
        config = {
          services.httpd = {
            enable = true;
            adminAddr = "foo@example.org";
          };
          networking.firewall.allowedTCPPorts = [ 80 ];
          system.stateVersion = "25.11";
        };
      };

      users.users.autossh = {
        isNormalUser = true;
      };
      users.groups.autossh = { };
      services.autossh.sessions = [
        {
          name = "httpd";
          user = "autossh";
          extraArguments = ''
            -i ${privKey} \
            -o StrictHostKeyChecking=accept-new \
            -o ServerAliveInterval=30 \
            -R httpd.sandhole.nix:80:172.16.0.2:80 \
            -p 2222 \
            127.0.0.1
          '';
        }
      ];
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("sandhole.service")
    machine.wait_for_open_port(2222)
    machine.wait_for_unit("autossh-httpd.service")
    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds(
      "${pkgs.curl}/bin/curl --fail"
      "  --resolve httpd.sandhole.nix:8080:127.0.0.1"
      "  http://httpd.sandhole.nix:8080"
      "  | grep 'It works!'",
      timeout=30,
    )
  '';
}
