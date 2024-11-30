# Command-line interface options

Sandhole exposes several options, which you can see by running `sandhole --help`.

```
Expose HTTP/SSH/TCP services through SSH port forwarding.

Usage: sandhole [OPTIONS] --domain <DOMAIN>

Options:
      --domain <DOMAIN>
          The root domain of the application

      --domain-redirect <URL>
          Where to redirect requests to the root domain

          [default: https://github.com/EpicEric/sandhole]

      --user-keys-directory <DIRECTORY>
          Directory containing public keys of authorized users. Each file must
          contain at least one key

          [default: ./deploy/user_keys/]

      --admin-keys-directory <DIRECTORY>
          Directory containing public keys of admin users. Each file must
          contain at least one key

          [default: ./deploy/admin_keys/]

      --certificates-directory <DIRECTORY>
          Directory containing SSL certificates and keys. Each sub-directory
          inside of this one must contain a certificate chain in a
          `fullchain.pem` file and its private key in a `privkey.pem` file

          [default: ./deploy/certificates/]

      --acme-cache-directory <DIRECTORY>
          Directory to use as a cache for Let's Encrypt's account and
          certificates. This will automatically be created for you.

          Note that this setting ignores the --disable-directory-creation flag.

          [default: ./deploy/acme_cache]

      --private-key-file <FILE>
          File path to the server's secret key. If missing, it will be created
          for you

          [default: ./deploy/server_keys/ssh]

      --disable-directory-creation
          If set, disables automatic creation of the directories expected by the
          application. This may result in application errors if the directories
          are missing

      --listen-address <ADDRESS>
          Address to listen for all client connections

          [default: ::]

      --ssh-port <PORT>
          Port to listen for SSH connections

          [default: 2222]

      --http-port <PORT>
          Port to listen for HTTP connections

          [default: 80]

      --https-port <PORT>
          Port to listen for HTTPS connections

          [default: 443]

      --force-https
          Always redirect HTTP requests to HTTPS

      --disable-http-logs
          Disable sending HTTP logs to clients

      --disable-tcp-logs
          Disable sending TCP/proxy logs to clients

      --acme-contact-email <EMAIL>
          Contact e-mail to use with Let's Encrypt. If set, enables ACME for
          HTTPS certificates.

          By providing your e-mail, you agree to the Let's Encrypt Subscriber
          Agreement.

      --acme-use-staging
          Controls whether to use the staging directory for Let's Encrypt
          certificates (default is production). Only set this option for testing

      --password-authentication-url <URL>
          If set, defines a URL against which password authentication requests
          will be validated. This is done by sending the following JSON payload:

          `{"user": "...", "password": "..."}`

          Any 2xx response indicates that the credentials are authorized.

      --bind-hostnames <POLICY>
          Policy on whether to allow binding specific hostnames.

          Beware that this can lead to domain takeovers if misused!

          [default: txt]

          Possible values:
          - all:   Allow any hostnames unconditionally, including the main
                   domain
          - cname: Allow any hostnames with a CNAME record pointing to the main
                   domain
          - txt:   Allow any hostnames with a TXT record containing a
                   fingerprint, including the main domain
          - none:  Don't allow user-provided hostnames, enforce subdomains

      --load-balancing <STRATEGY>
          Strategy for load-balancing when multiple services request the same
          hostname/port.

          By default, traffic towards matching hostnames/ports will be
          load-balanced.

          [default: allow]

          Possible values:
          - allow:   Load-balance with all available handlers
          - replace: Don't load-balance; When adding a new handler, replace the
                     existing one
          - deny:    Don't load-balance; Deny the new handler if there's an
                     existing one

      --txt-record-prefix <PREFIX>
          Prefix for TXT DNS records containing key fingerprints, for
          authorization to bind under a specific domain.

          In other words, valid records will be of the form:
          `TXT prefix.custom-domain SHA256:...`

          [default: _sandhole]

      --allow-provided-subdomains
          Allow user-provided subdomains. By default, subdomains are always
          random

      --allow-requested-ports
          Allow user-requested ports. By default, ports are always random

      --random-subdomain-seed <SEED>
          Which value to seed with when generating random subdomains, for
          determinism. This allows binding to the same random address until
          Sandhole is restarted.

          Beware that this can lead to collisions if misused!

          If unset, defaults to a random seed.

          Possible values:
          - ip-and-user: From IP address, SSH user, and requested address.
                         Recommended if unsure
          - user:        From SSH user and requested address
          - fingerprint: From SSH key fingerprint and requested address
          - address:     From SSH connection socket (address + port) and
                         requested address

      --idle-connection-timeout <DURATION>
          Grace period for dangling/unauthenticated SSH connections before they
          are forcefully disconnected.

          A low value may cause valid proxy/tunnel connections to be erroneously
          removed.

          [default: 2s]

      --authentication-request-timeout <DURATION>
          Time until a user+password authentication request is canceled. Any
          timed out requests will not authenticate the user

          [default: 5s]

      --http-request-timeout <DURATION>
          Time until an outgoing HTTP request is automatically canceled

          [default: 10s]

      --tcp-connection-timeout <DURATION>
          How long until TCP connections (including Websockets) are
          automatically garbage-collected.

          By default, these connections are not terminated by Sandhole.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
