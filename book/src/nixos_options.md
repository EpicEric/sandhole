# NixOS module options

## services\.sandhole\.enable

Whether to enable Sandhole, a reverse proxy that lets you expose HTTP/SSH/TCP services through SSH port forwarding\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.package



The sandhole package to use\.



*Type:*
package



*Default:*

```nix
pkgs.sandhole
```



## services\.sandhole\.group



Group to run Sandhole as\.



*Type:*
string



*Default:*

```nix
"sandhole"
```



## services\.sandhole\.openFirewall



Whether to automatically open the necessary ports in the firewall\.

**Warning:** If this option is true and ` services.sandhole.settings.disable-tcp ` is false or unset,
all unprivileged TCP ports (i\.e\. >= 1024) will be opened\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.settings



Attribute set of command line options for Sandhole, without the leading hyphens\.

If Sandhole is enabled, then either ` services.sandhole.settings.domain ` or ` services.sandhole.settings.no-domain ` must be set\.

**Note:** For all available settings, see [the Sandhole documentation](https://sandhole\.com\.br/cli\.html)\.



*Type:*
open submodule of attribute set of (null or boolean or (unsigned integer, meaning >=0) or absolute path or string)



*Default:*

```nix
{ }
```



*Example:*

```nix
{
  domain = "sandhole.com.br";
  acme-contact-email = "admin@sandhole.com.br";
  connect-ssh-on-https-port = true;
  load-balancing = "replace";
  allow-requested-subdomains = true;
  allow-requested-ports = true;
  random-subdomain-filter-profanities = true;
  force-https = true;
  directory-poll-interval = "10s";
  pool-size = 1024;
  pool-timeout = "10s";
}

```



## services\.sandhole\.settings\.disable-http



Disable all HTTP tunneling\. By default, this is enabled globally\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.settings\.disable-https



Disable all HTTPS tunneling\. By default, this is enabled globally\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.settings\.disable-tcp



Disable all TCP port tunneling except HTTP\. By default, this is enabled globally\.

**Warning:** If this option is false or unset and ` services.sandhole.openFirewall ` is true,
all unprivileged TCP ports (i\.e\. >= 1024) will be opened\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.settings\.domain



The root domain of the application\.



*Type:*
null or string



*Default:*

```nix
null
```



*Example:*

```nix
"nixos.org"
```



## services\.sandhole\.settings\.http-port



Port to listen for HTTP connections\.



*Type:*
16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*

```nix
80
```



## services\.sandhole\.settings\.https-port



Port to listen for HTTPS connections\.



*Type:*
16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*

```nix
443
```



## services\.sandhole\.settings\.no-domain



Whether to run Sandhole without a root domain\.

This option disables subdomains\.



*Type:*
boolean



*Default:*

```nix
false
```



*Example:*

```nix
true
```



## services\.sandhole\.settings\.ssh-port



Port to listen for SSH connections\.



*Type:*
16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*

```nix
2222
```



*Example:*

```nix
22
```



## services\.sandhole\.user



User to run Sandhole as\.



*Type:*
string



*Default:*

```nix
"sandhole"
```


