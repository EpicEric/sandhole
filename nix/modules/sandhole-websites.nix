{
  config,
  lib,
  ...
}:
let
  cfg = config.sandhole.websites;

  sandholeSshPort = config.services.sandhole.settings.ssh-port or 2222;

  inherit (lib) types;
in
{
  options = {
    sandhole.websites = lib.mkOption {
      default = { };
      type = types.attrsOf (
        types.submodule (
          {
            name,
            config,
            ...
          }:
          {
            options = {
              user = lib.mkOption {
                type = types.str;
                default = name;
                description = ''
                  Username to mount the website on. Defaults to the key of the submodule.
                '';
                example = "my-website";
              };

              authorizedKeys = lib.mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = ''
                  SSH keys authorized to log in to the user, in order to rsync the website files.
                '';
                example = [
                  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2S+gve6ueYFih3Ad5KJ+IQGhhnA9LK1ieiU7cg2fXB my-website"
                ];
              };

              path = lib.mkOption {
                type = types.path;
                default = "/home/${config.user}/www";
                description = ''
                  Path containing the static files for the website.
                '';
                example = "/home/my-website/www";
              };

              domains = lib.mkOption {
                type = types.listOf types.str;
                description = ''
                  Domains to host the website in Sandhole.
                '';
                example = [
                  "my-website.com"
                  "www.my-website.com"
                ];
              };

              hostAddress6 = lib.mkOption {
                type = types.str;
                description = ''
                  The IPv6 address assigned to the host interface.
                '';
                example = "fc00:22::1:1";
              };

              localAddress6 = lib.mkOption {
                type = types.str;
                description = ''
                  The IPv6 address assigned to the interface in the container. The default netmask is /128 and routing is set up from localAddress6 to hostAddress6 and back.
                '';
                example = "fc00:22::1:2";
              };

              autosshExtraArguments = lib.mkOption {
                type = types.str;
                default = "";
                description = ''
                  These lines go to the end of the Autossh arguments verbatim before the SSH exec options.
                '';
                example = "-o ServerAliveInterval=30 -c aes256-gcm@openssh.com";
              };

              nginxExtraConfig = lib.mkOption {
                type = types.str;
                default = "";
                description = ''
                  These lines go to the end of the NGINX vhost verbatim.
                '';
                example = ''
                  http2 on;
                  rewrite ^/github https://github.com/EpicEric permanent;
                '';
              };

              sandholeKeyPath = lib.mkOption {
                type = types.path;
                description = ''
                  Path to the private key to connect to Sandhole.
                '';
                example = "/root/secrets/id_ed25519";
              };

              sandholeHost = lib.mkOption {
                type = types.str;
                default = "127.0.0.1";
                description = ''
                  Sandhole host to connect to. Defaults to localhost.
                '';
                example = "my-sandhole.com";
              };

              sandholePort = lib.mkOption {
                type = types.port;
                default = sandholeSshPort;
                description = ''
                  Sandhole port to connect to. Defaults to `services.sandhole.settings.ssh-port`.
                '';
                example = 22;
              };

              sandholeExecArguments = lib.mkOption {
                type = types.str;
                default = "";
                description = ''
                  These lines go to the end of the Autossh arguments verbatim, for use with Sandhole.
                '';
                example = "http2";
              };
            };
          }
        )
      );
    };
  };

  config = {
    users.users = lib.mapAttrs' (_: value: {
      name = value.user;
      value = {
        openssh.authorizedKeys.keys = value.authorizedKeys;
        isNormalUser = true;
      };
    }) cfg;

    systemd.tmpfiles.rules = map (value: "d ${value.path} - ${value.user} users -") (
      builtins.attrValues cfg
    );

    containers = lib.mapAttrs' (name: value: {
      inherit name;
      value = {
        autoStart = true;
        privateNetwork = true;
        inherit (value) hostAddress6 localAddress6;
        extraFlags = [ "-U" ];
        bindMounts."/static" = {
          hostPath = value.path;
          isReadOnly = true;
        };
        config =
          { lib, ... }:
          {
            services.nginx = {
              enable = true;
              virtualHosts.${value.localAddress6} = {
                locations."/" = {
                  index = "index.html index.htm";
                  root = "/static";
                };
                extraConfig = value.nginxExtraConfig;
              };
            };
            networking = {
              firewall.allowedTCPPorts = [ 80 ];
              useHostResolvConf = lib.mkForce false;
            };
            services.resolved.enable = true;
            system.stateVersion = "25.11";
          };
      };
    }) cfg;

    services.autossh.sessions = lib.mapAttrsToList (name: value: {
      inherit name;
      user = "root";
      extraArguments = ''
        -i ${value.sandholeKeyPath} \
        -o StrictHostKeyChecking=accept-new \
        ${
          builtins.concatStringsSep " " (
            map (domain: "-R ${domain}:80:[${value.localAddress6}]:80") value.domains
          )
        } \
        -p ${toString value.sandholePort} \
        ${value.autosshExtraArguments} ${value.sandholeHost} ${value.sandholeExecArguments}
      '';
    }) cfg;
  };
}
