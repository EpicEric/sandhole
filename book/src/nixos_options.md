# NixOS module options

## services\.sandhole\.enable

Whether to enable Sandhole, a reverse proxy that lets you expose HTTP/SSH/TCP services through SSH port forwarding\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.package



The sandhole package to use\.



*Type:*
package



*Default:*
` pkgs.sandhole `



## services\.sandhole\.group



Group to run Sandhole as\.



*Type:*
string



*Default:*
` "sandhole" `



## services\.sandhole\.openFirewall



Whether to automatically open the necessary ports in the firewall\.

**Warning:** If this option is true and ` services.sandhole.settings.disable-tcp ` is false or unset,
all unprivileged TCP ports (i\.e\. >= 1024) will be opened\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings



Attribute set of command line options for Sandhole, without the leading hyphens\.

If Sandhole is enabled, then ` services.sandhole.settings.domain ` must be set\.

**Note:** For all available settings, see [the Sandhole documentation](https://sandhole\.com\.br/cli\.html)\.



*Type:*
attribute set of (null or boolean or (unsigned integer, meaning >=0) or absolute path or string)



*Default:*

```
{
  disable-http = false;
  disable-https = false;
  disable-tcp = false;
  domain = null;
  http-port = 80;
  https-port = 443;
  ssh-port = 2222;
}
```



*Example:*

```
{
  domain = "sandhole.com.br";
  acme-contact-email = "admin@sandhole.com.br";
  ssh-port = 22;
  user-keys-directory = ./sandhole-user-keys;
  connect-ssh-on-https-port = true;
  load-balancing = "replace";
  allow-requested-subdomains = true;
  disable-tcp = true;
  ip-allowlist = "192.168.0.1,2001:db1::/32";
  idle-connection-timeout = "10s";
}

```



## services\.sandhole\.user



User to run Sandhole as\.



*Type:*
string



*Default:*
` "sandhole" `


