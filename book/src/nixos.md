# NixOS

Sandhole is available in the `unstable` channel as [a Nix package](https://search.nixos.org/packages?channel=unstable&query=sandhole), as well as [a NixOS service](https://search.nixos.org/options?channel=unstable&query=services.sandhole). It's also available as a flake in the Sandhole repository.

## Setup

Here's an example `configuration.nix` with Sandhole and Agnos:

```nix
{
  pkgs,
  ...
}:

let
  # ...

  # Add admin keys to this directory
  adminKeys = pkgs.linkFarm "sandhole-admin-keys" [
    {
      name = "example-admin.pub";
      path = pkgs.writeText "example-admin.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH3e5SFdwLOuleypjfgauqEUAmgpm9r8lqfvc6G1o1D example-admin
      '';
    }
  ];

  # Add user keys to this directory
  userKeys = pkgs.linkFarm "sandhole-user-keys" [
    {
      name = "example-user.pub";
      path = pkgs.writeText "example-user.pub" ''
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtH7kS+q8/8TXWAp4OJvRh/7GNkQ6FR/QBOhGJuEwEC example-user
      '';
    }
  ];

  admin-keys-directory = "/etc/sandhole/admin-keys";
  user-keys-directory = "/etc/sandhole/user-keys";
  certificates-directory = "/var/lib/sandhole/certificates";
in

{
  # ...

  # By symlinking to /etc, Sandhole doesn't have to restart when modifying keys
  environment.etc = {
    "sandhole/admin-keys".source = adminKeys;
    "sandhole/user-keys".source = userKeys;
  };

  # Configurations for Sandhole
  services.sandhole = {
    # Install the Sandhole package and enable the systemd service
    enable = true;
    # Let Sandhole manage the firewall and open ports from its configuration.
    # Note: If `disable-tcp` is `false` (default), it will open all ports >= 1024
    openFirewall = true;
    # These are the same CLI options from Sandhole, except without leading hyphens.
    # See: http://sandhole.com.br/cli.html
    # Make sure to change at least `domain` and `acme-contact-email` below
    settings = {
      domain = "sandhole.com.br";
      acme-contact-email = "admin@sandhole.com.br";
      disable-tcp = true;
      force-https = true;
      inherit
        admin-keys-directory
        user-keys-directory
        certificates-directory
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
                    fullchain_output_file = "${certificates-directory}/sandhole.com.br/fullchain.pem";
                    key_output_file = "${certificates-directory}/sandhole.com.br/privkey.pem";
                  }
                ];
            }
          ];
      };
  };
}
```

### Setup with Flake

If you're using Nix Flakes for your system, you can optionally install the bleeding-edge NixOS package with an overlay:

```nix
{
  description = "My NixOS config";

  inputs = {
    # ...
    sandhole.url = "github:EpicEric/sandhole";
  };

  outputs =
    {
      nixpkgs,
      # ...
      sandhole,
      ...
    }@inputs:
    {
      nixosConfigurations."your-hostname" = nixpkgs.lib.nixosSystem {
        specialArgs = { inherit inputs; };
        modules = [
          # ...
          sandhole.overlays.sandhole
        ];
      };
    };
}
```

In order to avoid building Sandhole, you can use either of the Sandhole binary caches. In `configuration.nix`:

```nix
nix.settings = {
  substituters = [
    "https://sandhole.cachix.org"
    "https://cache.garnix.io"
  ];
  trusted-public-keys = [
    "sandhole.cachix.org-1:cZadr6kgjQcRvsr++Nv9kgtMOrbLahiZBpuI9WpIXvA="
    "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
  ];
};
```

## Connecting to Sandhole

You can connect services with the keys provided to `user-keys-directory`. For example, to use a Vaultwarden NixOS container in the same machine:

```nix
{
  lib,
  ...
}:

{
  # ...

  # Set up NAT for NixOS containers
  networking.nat = {
    enable = true;
    internalInterfaces = ["ve-+"];
    externalInterface = "eno0"; # Change to the appropriate interface
    enableIPv6 = true;
  };

  # Example: Setting up Vaultwarden
  containers.vaultwarden = {
    autoStart = true;
    privateNetwork = true;
    hostAddress = "192.168.102.1";
    localAddress = "192.168.102.2";
    hostAddress6 = "fc00::2:1";
    localAddress6 = "fc00::2:2";
    extraFlags = [ "-U" ];
    config =
      { lib, ... }:
      {
      services.vaultwarden = {
        enable = true;
        config = {
          DOMAIN = "https://vaultwarden.sandhole.com.br";
          SIGNUPS_ALLOWED = false;
          ROCKET_ADDRESS = "::";
          ROCKET_PORT = 8222;
          ROCKET_LOG = "warning";
        };
      };

      networking = {
        firewall.allowedTCPPorts = [ 8222 ];
        useHostResolvConf = lib.mkForce false;
      };

      services.resolved.enable = true;

      system.stateVersion = "25.11";
    };
  };

  # Proxy Vaultwarden to the local Sandhole instance
  services.autossh.sessions = [
    {
      name = "vaultwarden";
      user = "root";
      # Change the arguments as necessary
      extraArguments = ''
        -i /path/to/ssh/key/example-user \
        -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=30 \
        -R vaultwarden.sandhole.com.br:80:192.168.102.2:8222 \
        -p 2222 \
        127.0.0.1
      '';
    }
  ];
}
```
