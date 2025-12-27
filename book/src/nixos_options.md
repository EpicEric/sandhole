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



## services\.sandhole\.openFirewall



Whether to automatically open the necessary ports in the firewall\.

Warning: If this option is true and ` services.sandhole.settings.disableTcp ` is false (by default),
all unprivileged ports (i\.e\. >= 1024) will be opened\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.acmeCacheDirectory



Directory to use as a cache for Let’s Encrypt’s account and certificates\.
This will automatically be created for you\.

Note that this setting ignores the ` disableDirectoryCreation ` flag\.



*Type:*
absolute path



*Default:*
` "/var/lib/sandhole/acme_cache" `



*Example:*
` ./deploy/acme_cache/ `



## services\.sandhole\.settings\.acmeContactEmail



Contact e-mail to use with Let’s Encrypt\.
If set, enables ACME for HTTPS certificates\.

By providing your e-mail, you agree to the Let’s Encrypt Subscriber Agreement\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "your-email@domain.com" `



## services\.sandhole\.settings\.acmeUseStaging



Controls whether to use the staging directory for Let’s Encrypt certificates (default is production)\.
Only set this option for testing\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.adminKeysDirectory



Directory containing public keys of admin users\.
Each file must contain at least one key\.



*Type:*
absolute path



*Default:*
` "/var/lib/sandhole/admin_keys" `



*Example:*
` ./deploy/admin_keys/ `



## services\.sandhole\.settings\.allowRequestedPorts



Allow user-requested subdomains\.
By default, subdomains are always random\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.allowRequestedSubdomains



Allow user-requested subdomains\.
By default, subdomains are always random\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.authenticationRequestTimeout



Time until a user+password authentication request is canceled\.
Any timed out requests will not authenticate the user\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "5s" `



## services\.sandhole\.settings\.bindHostnames



Policy on whether to allow binding specific hostnames\.

Beware that this can lead to domain takeovers if misused!

Possible values:

 - all: Allow any hostnames unconditionally, including the main domain\.
 - cname: Allow any hostnames with a CNAME record pointing to the main domain\.
 - txt (default): Allow any hostnames with a TXT record containing a fingerprint, including the main domain\.
 - none: Don’t allow user-provided hostnames, enforce subdomains\.



*Type:*
null or one of “all”, “cname”, “txt”, “none”



*Default:*
` null `



*Example:*
` "txt" `



## services\.sandhole\.settings\.bufferSize



Size to use for bidirectional buffers, in bytes\.

A higher value will lead to higher memory consumption\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "32768B" `



## services\.sandhole\.settings\.certificatesDirectory



Directory containing SSL certificates and keys\.
Each sub-directory inside of this one must contain a certificate chain
in a fullchain\.pem file and its private key in a privkey\.pem file\.



*Type:*
absolute path



*Default:*
` "/var/lib/sandhole/certificates" `



*Example:*
` ./deploy/certificates/ `



## services\.sandhole\.settings\.connectSshOnHttpsPort



Allow connecting to SSH via the HTTPS port as well\.
This can be useful in networks that block binding to other ports\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableAliasing



Disable all aliasing (i\.e\. local forwarding)\.
By default, this is enabled globally\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableDirectoryCreation



If set, disables automatic creation of the directories expected by the application\.
This may result in application errors if the directories are missing\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableHttp



Disable all HTTP tunneling\.
By default, this is enabled globally\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableHttpLogs



Disable sending HTTP logs to clients\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableHttps



Disable all HTTPS tunneling\.
By default, this is enabled globally\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disablePrometheus



Disable the admin-only alias for the Prometheus exporter\.
By default, it is enabled\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableSni



Disable SNI proxy tunneling\.
By default, this is enabled globally\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableTcp



Disable all TCP port tunneling except HTTP\.
By default, this is enabled globally\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.disableTcpLogs



Disable sending TCP/proxy logs to clients\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.domain



The root domain of the application\.



*Type:*
string



*Example:*
` "sandhole.com.br" `



## services\.sandhole\.settings\.domainRedirect



Where to redirect requests to the root domain\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "https://github.com/EpicEric/sandhole" `



## services\.sandhole\.settings\.forceHttps



Always redirect HTTP requests to HTTPS\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.httpPort



Port to listen for HTTP connections\.



*Type:*
null or 16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*
` null `



*Example:*
` 80 `



## services\.sandhole\.settings\.httpRequestTimeout



Time until an outgoing HTTP request is automatically canceled\.

By default, outgoing requests are not terminated by Sandhole\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "60s" `



## services\.sandhole\.settings\.httpsPort



Port to listen for HTTPS connections\.



*Type:*
null or 16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*
` null `



*Example:*
` 443 `



## services\.sandhole\.settings\.idleConnectionTimeout



Grace period for dangling/unauthenticated connections before they are forcefully disconnected…

A low value may cause valid connections to be erroneously removed\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "2s" `



## services\.sandhole\.settings\.ipAllowlist



List of IP networks to allow\.
Setting this will block unknown IPs from connecting\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "192.168.0.1"
  "2001:db1::/32"
]
```



## services\.sandhole\.settings\.ipBlocklist



List of IP networks to block\.
Setting this will allow unspecified IPs to connect, unless ` ipAllowlist ` is set\.



*Type:*
list of string



*Default:*
` [ ] `



*Example:*

```
[
  "192.168.0.1"
  "2001:db1::/32"
]
```



## services\.sandhole\.settings\.listenAddress



Address to listen for all client connections\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "::" `



## services\.sandhole\.settings\.loadBalancing



Strategy for load-balancing when multiple services request the same hostname/port\.

By default, traffic towards matching hostnames/ports will be load-balanced\.

Possible values:

 - allow (default): Load-balance with all available handlers\.
 - replace: Don’t load-balance; When adding a new handler, replace the existing one\.
 - deny: Don’t load-balance; Deny the new handler if there’s an existing one\.



*Type:*
null or one of “allow”, “replace”, “deny”



*Default:*
` null `



*Example:*
` "allow" `



## services\.sandhole\.settings\.loadBalancingAlgorithm



Algorithm to use for service selection when load-balancing\.

By default, traffic will be randomly distributed between services\.

Possible values:

 - random (default): Choose randomly\.
 - round-robin: Round robin\.
 - ip-hash: Choose based on IP hash\.



*Type:*
null or one of “random”, “round-robin”, “ip-hash”



*Default:*
` null `



*Example:*
` "random" `



## services\.sandhole\.settings\.passwordAuthenticationUrl



If set, defines a URL which password authentication requests will be validated against\.
This is done by sending the following JSON payload via a POST request:

` {"user": "...", "password": "...", "remote_address": "..."} `

Any 2xx response indicates that the credentials are authorized\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "https://login-service.com/authenticate" `



## services\.sandhole\.settings\.privateKeyFile



File path to the server’s secret key\.
If missing, it will be created for you\.



*Type:*
absolute path



*Default:*
` "/var/lib/sandhole/server_keys/ssh" `



*Example:*
` ./deploy/server_keys/ssh `



## services\.sandhole\.settings\.quotaPerUser



How many services can be exposed for a single user at once\.
Doesn’t apply to admin users\.

Each user is distinguished by their key fingerprint or, in the case of API logins, by their username\.

By default, no limit is set\.



*Type:*
null or (positive integer, meaning >0)



*Default:*
` null `



*Example:*
` 2 `



## services\.sandhole\.settings\.randomSubdomainFilterProfanities



Prevents random subdomains from containing profanities\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.randomSubdomainLength



The length of the string appended to the start of random subdomains\.



*Type:*
null or (positive integer, meaning >0)



*Default:*
` null `



*Example:*
` 6 `



## services\.sandhole\.settings\.randomSubdomainSeed



Which value to seed with when generating random subdomains, for determinism\.
This allows binding to the same random address until Sandhole is restarted\.

Beware that this can lead to collisions if misused!

If unset, defaults to a random seed\.

Possible values:

 - ip-and-user: From IP address, SSH user, and requested address\. Recommended if unsure\.
 - user: From SSH user and requested address\.
 - fingerprint: From SSH user, key fingerprint, and requested address\.
 - address: From SSH connection socket (address + port) and requested address\.



*Type:*
null or one of “ip-and-user”, “user”, “fingerprint”, “address”



*Default:*
` null `



*Example:*
` "ip-and-user" `



## services\.sandhole\.settings\.randomSubdomainValue



Set a value for random subdomains for use in conjunction with ` randomSubdomainSeed `
to allow binding to the same random address between Sandhole restarts\.

Beware that this can lead to collisions if misused!

If unset, defaults to a random value\.



*Type:*
null or (positive integer, meaning >0)



*Default:*
` null `



*Example:*
` 42 `



## services\.sandhole\.settings\.rateLimitPerUser



How many bytes per second a single user’s services can transmit at once\.
Doesn’t apply to admin users\.

Each user is distinguished by their key fingerprint or, in the case of API logins, by their username\.

By default, no rate limit is set\. For better results, this should be a multiple of ` bufferSize `\.



*Type:*
null or (positive integer, meaning >0)



*Default:*
` null `



*Example:*
` 10000000 `



## services\.sandhole\.settings\.requestedDomainFilterProfanities



Prevents user-requested domains from containing profanities\.

Beware that this can lead to false positives being blocked!



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.requestedSubdomainFilterProfanities



Prevents user-requested subdomains from containing profanities\.

Beware that this can lead to false positives being blocked!



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## services\.sandhole\.settings\.sshKeepaliveInterval



How long to wait between each keepalive message that is sent to an unresponsive SSH connection\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "15s" `



## services\.sandhole\.settings\.sshKeepaliveMax



How many keepalive messages are sent to an unresponsive SSH connection before it is dropped\.

A value of zero disables timeouts\.

The timeout is equal to this value plus one, times ` sshKeepaliveInterval `\.



*Type:*
null or (unsigned integer, meaning >=0)



*Default:*
` null `



*Example:*
` 3 `



## services\.sandhole\.settings\.sshPort



Port to listen for SSH connections\.



*Type:*
null or 16 bit unsigned integer; between 0 and 65535 (both inclusive)



*Default:*
` null `



*Example:*
` 2222 `



## services\.sandhole\.settings\.tcpConnectionTimeout



How long until TCP connections (including Websockets and
local forwardings) are automatically garbage-collected\.

By default, these connections are not terminated by Sandhole\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "60s" `



## services\.sandhole\.settings\.txtRecordPrefix



Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain\.

In other words, valid records will be of the form:

` TXT <PREFIX>.<DOMAIN> SHA256:... `



*Type:*
null or string



*Default:*
` null `



*Example:*
` "_sandhole" `



## services\.sandhole\.settings\.unproxiedConnectionTimeout



Grace period for unauthenticated SSH connections after closing
the last proxy tunnel before they are forcefully disconnected\.

A low value may cause valid proxy/tunnel connections to be erroneously removed\.

If unset, this defaults to the value set by ` idleConnectionTimeout `\.



*Type:*
null or string



*Default:*
` null `



*Example:*
` "2s" `



## services\.sandhole\.settings\.userKeysDirectory



Directory containing public keys of authorized users\.
Each file must contain at least one key\.



*Type:*
absolute path



*Default:*
` "/var/lib/sandhole/user_keys" `



*Example:*
` ./deploy/user_keys/ `


