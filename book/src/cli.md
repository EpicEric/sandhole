# Command-line interface options

Sandhole exposes several options, which you can see by running `sandhole --help`.

---

<pre class="terminal">
Expose HTTP/SSH/TCP services through SSH port forwarding.

<b><u>Usage:</u></b> <b>sandhole</b> [OPTIONS] &lt;--domain &lt;DOMAIN&gt;|--no-domain&gt;

<b><u>Options:</u></b>
      <b>--domain</b> &lt;DOMAIN&gt;
          The root domain of the application

      <b>--no-domain</b>
          Whether to run Sandhole without a root domain.

          This option disables subdomains.

      <b>--domain-redirect</b> &lt;URL&gt;
          Where to redirect requests to the root domain

          [default: https://github.com/EpicEric/sandhole]

      <b>--user-keys-directory</b> &lt;DIRECTORY&gt;
          Directory containing public keys of authorized users. Each file must
          contain at least one key

          [default: ./deploy/user_keys/]

      <b>--admin-keys-directory</b> &lt;DIRECTORY&gt;
          Directory containing public keys of admin users. Each file must
          contain at least one key

          [default: ./deploy/admin_keys/]

      <b>--certificates-directory</b> &lt;DIRECTORY&gt;
          Directory containing SSL certificates and keys. Each sub-directory
          inside of this one must contain a certificate chain in a fullchain.pem
          file and its private key in a privkey.pem file

          [default: ./deploy/certificates/]

      <b>--acme-cache-directory</b> &lt;DIRECTORY&gt;
          Directory to use as a cache for Let&#39;s Encrypt&#39;s account and
          certificates. This will automatically be created for you.

          Note that this setting ignores the --disable-directory-creation flag.

          [default: ./deploy/acme_cache/]

      <b>--private-key-file</b> &lt;FILE&gt;
          File path to the server&#39;s secret key. If missing, it will be
          created for you

          [default: ./deploy/server_keys/ssh]

      <b>--disable-directory-creation</b>
          If set, disables automatic creation of the directories expected by the
          application. This may result in application errors if the directories
          are missing

      <b>--listen-address</b> &lt;ADDRESS&gt;
          Address to listen for all client connections

          [default: ::]

      <b>--ssh-port</b> &lt;PORT&gt;
          Port to listen for SSH connections

          [default: 2222]

      <b>--http-port</b> &lt;PORT&gt;
          Port to listen for HTTP connections

          [default: 80]

      <b>--https-port</b> &lt;PORT&gt;
          Port to listen for HTTPS connections

          [default: 443]

      <b>--connect-ssh-on-https-port</b>
          Allow connecting to SSH via the HTTPS port as well. This can be useful
          in networks that block binding to other ports

      <b>--force-https</b>
          Always redirect HTTP requests to HTTPS

      <b>--disable-http-logs</b>
          Disable sending HTTP logs to clients

      <b>--disable-tcp-logs</b>
          Disable sending TCP/proxy logs to clients

      <b>--acme-contact-email</b> &lt;EMAIL&gt;
          Contact e-mail to use with Let&#39;s Encrypt. If set, enables ACME for
          HTTPS certificates.

          By providing your e-mail, you agree to the Let&#39;s Encrypt Subscriber
          Agreement.

      <b>--acme-use-staging</b>
          Controls whether to use the staging directory for Let&#39;s Encrypt
          certificates (default is production). Only set this option for testing

      <b>--password-authentication-url</b> &lt;URL&gt;
          If set, defines a URL which password authentication requests will be
          validated against. This is done by sending the following JSON payload
          via a POST request:

          {&quot;user&quot;: &quot;...&quot;, &quot;password&quot;: &quot;...&quot;, &quot;remote_address&quot;: &quot;...&quot;}

          Any 2xx response indicates that the credentials are authorized.

      <b>--bind-hostnames</b> &lt;POLICY&gt;
          Policy on whether to allow binding specific hostnames.

          Beware that this can lead to domain takeovers if misused!

          [default: txt]

          Possible values:
          - <b>all</b>:   Allow any hostnames unconditionally, including the
                   main domain
          - <b>cname</b>: Allow any hostnames with a CNAME record pointing to
                   the main domain
          - <b>txt</b>:   Allow any hostnames with a TXT record containing a
                   fingerprint, including the main domain
          - <b>none</b>:  Don&#39;t allow user-provided hostnames, enforce
                   subdomains

      <b>--load-balancing</b> &lt;STRATEGY&gt;
          Strategy for load-balancing when multiple services request the same
          hostname/port.

          By default, traffic towards matching hostnames/ports will be
          load-balanced.

          [default: allow]

          Possible values:
          - <b>allow</b>:   Load-balance with all available handlers
          - <b>replace</b>: Don&#39;t load-balance; When adding a new handler,
                     replace the existing one
          - <b>deny</b>:    Don&#39;t load-balance; Deny the new handler if
                     there&#39;s an existing one

      <b>--load-balancing-algorithm</b> &lt;ALGORITHM&gt;
          Algorithm to use for service selection when load-balancing.

          By default, traffic will be randomly distributed between services.

          [default: random]

          Possible values:
          - <b>random</b>:      Choose randomly
          - <b>round-robin</b>: Round robin
          - <b>ip-hash</b>:     Choose based on IP hash

      <b>--txt-record-prefix</b> &lt;PREFIX&gt;
          Prefix for TXT DNS records containing key fingerprints, for
          authorization to bind under a specific domain.

          In other words, valid records will be of the form:

          TXT &lt;PREFIX&gt;.&lt;DOMAIN&gt; SHA256:...

          [default: _sandhole]

      <b>--allow-requested-subdomains</b>
          Allow user-requested subdomains. By default, subdomains are always
          random

      <b>--allow-requested-ports</b>
          Allow user-requested ports. By default, ports are always random

      <b>--disable-http</b>
          Disable all HTTP tunneling. By default, this is enabled globally

      <b>--disable-https</b>
          Disable all HTTPS tunneling. By default, this is enabled globally

      <b>--disable-sni</b>
          Disable SNI proxy tunneling. By default, this is enabled globally

      <b>--disable-tcp</b>
          Disable all TCP port tunneling except HTTP. By default, this is
          enabled globally

      <b>--disable-aliasing</b>
          Disable all aliasing (i.e. local forwarding). By default, this is
          enabled globally

      <b>--disable-prometheus</b>
          Disable the admin-only alias for the Prometheus exporter. By default,
          it is enabled

      <b>--quota-per-user</b> &lt;MAX&gt;
          How many services can be exposed for a single user at once. Doesn&#39;t
          apply to admin users.

          Each user is distinguished by their key fingerprint or, in the case of
          API logins, by their username.

          By default, no limit is set.

      <b>--rate-limit-per-user</b> &lt;RATE&gt;
          How many bytes per second a single user&#39;s services can transmit at
          once. Doesn&#39;t apply to admin users.

          Each user is distinguished by their key fingerprint or, in the case of
          API logins, by their username.

          By default, no rate limit is set. For better results, this should be a
          multiple of `--buffer-size`.

      <b>--random-subdomain-value</b> &lt;VALUE&gt;
          Set a U64 value for random subdomains for use in conjunction with
          `--random-subdomain-seed` to allow binding to the same random address
          between Sandhole restarts.

          Beware that this can lead to collisions if misused!

          If this and `--random-subdomain-value-file` are unset, defaults to a
          random value.

      <b>--random-subdomain-value-file</b> &lt;FILE&gt;
          Set a file containing a U64 value for random subdomains for use in
          conjunction with `--random-subdomain-seed` to allow binding to the same
          random address between Sandhole restarts.

          Beware that this can lead to collisions if misused!

          If this and `--random-subdomain-value` are unset, defaults to a random
          value.

          This option takes priority over `--random-subdomain-value`.

      <b>--random-subdomain-seed</b> &lt;SEED&gt;
          Which value to seed with when generating random subdomains, for
          determinism. This allows binding to the same random address until
          Sandhole is restarted.

          Beware that this can lead to collisions if misused!

          If unset, defaults to a random seed.

          Possible values:
          - <b>ip-and-user</b>: From IP address, SSH user, and requested address.
                         Recommended if unsure
          - <b>user</b>:        From SSH user and requested address
          - <b>fingerprint</b>: From SSH user, key fingerprint, and requested address
          - <b>address</b>:     From SSH connection socket (address + port) and
                         requested address

      <b>--random-subdomain-length</b> &lt;LENGTH&gt;
          The length of the string appended to the start of random subdomains

          [default: 6]

      <b>--random-subdomain-filter-profanities</b>
          Prevents random subdomains from containing profanities

      <b>--requested-domain-filter-profanities</b>
          Prevents user-requested domains from containing profanities.

          Beware that this can lead to false positives being blocked!

      <b>--requested-subdomain-filter-profanities</b>
          Prevents user-requested subdomains from containing profanities.

          Beware that this can lead to false positives being blocked!

      <b>--ip-allowlist</b> &lt;CIDR&gt;
          Comma-separated list of IP networks to allow. Setting this will block
          unknown IPs from connecting

      <b>--ip-blocklist</b> &lt;CIDR&gt;
          Comma-separated list of IP networks to block. Setting this will allow
          unknown IPs to connect, unless --ip-allowlist is set

      <b>--buffer-size</b> &lt;SIZE&gt;
          Size to use for bidirectional buffers, in bytes.

          A higher value will lead to higher memory consumption.

          [default: 32768B]

      <b>--pool-size</b> &lt;SIZE&gt;
          Maximum pool size for simultaneous connections per proxied service.
          The maximum is 1024.

          A higher value will lead to higher memory consumption, and may cause
          disruption on services.

          [default: 128]

      <b>--pool-timeout</b> &lt;DURATION&gt;
          How long to wait for a connection to be available in the pool
          before being timed out.

          By default, connections are immediately timed out when the pool is
          exhausted.

      <b>--ssh-keepalive-interval</b> &lt;DURATION&gt;
          How long to wait between each keepalive message that is sent to an
          unresponsive SSH connection

          [default: 15s]

      <b>--ssh-keepalive-max</b> &lt;VALUE&gt;
          How many keepalive messages are sent to an unresponsive SSH connection
          before it is dropped.

          A value of zero disables timeouts.

          The timeout is equal to this value plus one,
          times `--ssh-keepalive-interval`.

          [default: 3]

      <b>--directory-poll-interval</b> &lt;DURATION&gt;
          How long to poll certificates and keys directories for new changes.

          A low value may consume too many resources on large file trees.

          [default: 15s]

      <b>--idle-connection-timeout</b> &lt;DURATION&gt;
          Grace period for dangling/unauthenticated connections before they are
          forcefully disconnected.

          A low value may cause valid connections to be erroneously removed.

          [default: 2s]

      <b>--unproxied-connection-timeout</b> &lt;DURATION&gt;
          Grace period for unauthenticated SSH connections after closing the
          last proxy tunnel before they are forcefully disconnected.

          A low value may cause valid proxy/tunnel connections to be erroneously
          removed.

          If unset, this defaults to the value set by --idle-connection-timeout

      <b>--authentication-request-timeout</b> &lt;DURATION&gt;
          Time until a user+password authentication request is canceled. Any
          timed out requests will not authenticate the user

          [default: 5s]

      <b>--http-request-timeout</b> &lt;DURATION&gt;
          Time until an outgoing HTTP request is automatically canceled.

          By default, outgoing requests are not terminated by Sandhole.

      <b>--tcp-connection-timeout</b> &lt;DURATION&gt;
          How long until TCP connections (including Websockets and local
          forwardings) are automatically garbage-collected.

          By default, these connections are not terminated by Sandhole.

  <b>-h</b>, <b>--help</b>
          Print help (see a summary with &#39;-h&#39;)

  <b>-V</b>, <b>--version</b>
          Print version
</pre>
