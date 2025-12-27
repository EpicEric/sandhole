# NixOS

Sandhole is available in the `unstable` channel as [a Nix package](https://search.nixos.org/packages?channel=unstable&query=sandhole), as well as [a NixOS service](https://search.nixos.org/options?channel=unstable&query=services.sandhole).

Here's an example `configuration.nix` with Sandhole and Agnos:

```nix
{
  pkgs,
  ...
}:

let
  # ...

  # Add admin keys to this directory
  adminKeysDirectory = pkgs.symlinkJoin {
    name = "sandhole-admin-keys";
    paths = [
      (pkgs.writeText "example-admin.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH3e5SFdwLOuleypjfgauqEUAmgpm9r8lqfvc6G1o1D example-admin
      '')
    ];
  };

  # Add user keys to this directory
  userKeysDirectory = pkgs.symlinkJoin {
    name = "sandhole-user-keys";
    paths = [
      (pkgs.writeText "example-user.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtH7kS+q8/8TXWAp4OJvRh/7GNkQ6FR/QBOhGJuEwEC example-user
      '')
    ];
  };

  certificatesDirectory = "/var/lib/sandhole/certificates";
in

{
  # ...

  services.sandhole = {
    # Install the Sandhole package and enable the systemd service
    enable = true;
    # Let Sandhole manage the firewall and open ports from its configuration.
    # Note: If `disableTcp` is `false` (default), it will open all ports >= 1024
    openFirewall = true;
    # See: https://search.nixos.org/options?channel=unstable&query=services.sandhole.settings
    # Make sure to change at least `domain` and `acmeContactEmail` below
    settings = {
      domain = "sandhole.com.br";
      acmeContactEmail = "admin@sandhole.com.br";
      disableTcp = true;
      forceHttps = true;
      inherit
        adminKeysDirectory
        userKeysDirectory
        certificatesDirectory
        ;
    };
  };

  security.agnos = {
    enable = true;
    temporarilyOpenFirewall = true;
    user = "sandhole";
    generateKeys.enable = true;
    settings =
      {
        dns_listen_addr = "[::]:53";
        accounts =
          [
            {
              # Change this to your e-mail address
              email = "admin@sandhole.com.br";
              private_key_path = "./letsencrypt_key.pem";
              certificates =
                [
                  {
                    # Change these from `sandhole.com.br` to your domain
                    domains = [ "sandhole.com.br" "*.sandhole.com.br" ];
                    fullchain_output_file = "${certificatesDirectory}/sandhole.com.br/fullchain.pem";
                    key_output_file = "${certificatesDirectory}/sandhole.com.br/privkey.pem";
                  }
                ];
            }
          ];
      };
  };
}
```

You can then connect services with the provided keys. For example, to use a SearXNG NixOS container in the same machine:

```nix
{
  lib,
  ...
}:

{
  # ...

  networking.nat = {
    enable = true;
    internalInterfaces = ["ve-+"];
    externalInterface = "eno0"; # Change to the appropriate interface
    enableIPv6 = true;
  };

  # Example: Setting up SearXNG
  containers.searxng = {
    autoStart = true;
    privateNetwork = true;
    hostAddress = "192.168.100.2";
    localAddress = "192.168.100.11";
    hostAddress6 = "fc00::1";
    localAddress6 = "fc00::2";
    extraFlags = [ "-U" ];
    config = { lib, ... }: {
      services.searx.enable = true;
  
      networking = {
        firewall.allowedTCPPorts = [ 8888 ];
        useHostResolvConf = lib.mkForce false;
      };
      
      services.resolved.enable = true;
  
      system.stateVersion = "25.11";
    };
  };

  # Proxy SearXNG to the local Sandhole instance
  services.autossh.sessions = [
    {
      name = "searxng";
      # Change the arguments as necessary
      extraArguments = ''
        -i /path/to/ssh/key/example-user \
        -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=30 \
        -R searxng.sandhole.com.br:80:192.168.100.11:8888 \
        -p 2222 \
        127.0.0.1
      '';
    }
  ];
}
```
