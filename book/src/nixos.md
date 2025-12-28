# NixOS

Sandhole is available as a flake, containing an overlay and a NixOS service.

## Setup

If you're using Nix Flakes for your system, you can install the NixOS service like so:

```nix
{
  description = "My NixOS config";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    # ...
    sandhole.url = "github:EpicEric/sandhole";
  };

  outputs =
    {
      nixpkgs,
      sandhole,
      ...
    }@inputs:
    {
      nixosConfigurations."your-hostname" = nixpkgs.lib.nixosSystem {
        specialArgs = { inherit inputs; };
        modules = [
          ./configuration.nix
          # ...
          sandhole.nixosModules.sandhole
        ];
      };
    };
}
```

Here's an example `configuration.nix` with Sandhole and Agnos. You can find full options in [the NixOS module options page](./nixos_options.md):

```nix
{
  pkgs,
  ...
}:

let
  # ...

  # Add admin keys to this directory
  adminKeysDirectory = pkgs.linkFarm "sandhole-admin-keys" [
    {
      name = "example-admin.pub";
      path = pkgs.writeText "example-admin.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH3e5SFdwLOuleypjfgauqEUAmgpm9r8lqfvc6G1o1D example-admin
      '';
    }
  ];

  # Add user keys to this directory
  userKeysDirectory = pkgs.linkFarm "sandhole-user-keys" [
    {
      name = "example-user.pub";
      path = pkgs.writeText "example-user.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtH7kS+q8/8TXWAp4OJvRh/7GNkQ6FR/QBOhGJuEwEC example-user
      '';
    }
  ];

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
    # These are the same CLI options from Sandhole, except in camelCase.
    # See: http://sandhole.com.br/nixos_options.html
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

## Binary caching

In order to avoid re-building Sandhole for each update, you can use the Sandhole binary cache. In `configuration.nix`:

```nix
  nix.settings = {
    substituters = [
      "https://nix-community.cachix.org"
      "https://sandhole.cachix.org"
    ];
    trusted-public-keys = [
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      "sandhole.cachix.org-1:cZadr6kgjQcRvsr++Nv9kgtMOrbLahiZBpuI9WpIXvA="
    ];
  };
```
