# Features

This is a comprehensive list of all features offered by Sandhole.

## Tunneling (remote forwarding)

Features related to Sandhole's remote forwarding and reverse proxy capabilities.

### HTTP/HTTPS

- HTTP tunneling via SSH remote forwarding.
  - Option to force HTTP redirects to HTTPS. (SSH exec: `force-https`; CLI: `--force-https`)
- HTTPS tunneling via SSH remote forwarding, with automatic TLS certificates.
  - Option to connect SSH clients via the HTTPS port. (CLI: `--connect-ssh-on-https-port`)
  - Support for Server Name Indication (SNI) proxying. (SSH exec: `sni-proxy`)
  - Support for HTTP/2 proxying. (SSH exec: `http2`)
- Support for automatic `X-Forwarded` headers.
- Random subdomain generation by default.
  - Option to set the seed for random subdomain generation. (CLI: `--random-subdomain-seed`)
  - Option to set the length for random subdomains. (CLI: `--random-subdomain-length`)
  - Option to skip subdomains containing profanities. (CLI: `--random-subdomain-filter-profanities`)
- Option to allow requested subdomains instead of random generation by default. (CLI: `--allow-requested-subdomains`)

### TCP

- TCP tunneling via SSH remote forwarding, with random port selection.
  - Option to allow requested ports instead of random selection by default. (CLI: `--allow-requested-ports`)

### Aliasing (local forwarding)

- TCP/HTTP/SNI aliasing via SSH remote forwarding.
  - Alias-only forwardings. (SSH exec: `tcp-alias`)
- ProxyJump SSH hosts via SSH remote forwarding.
- Generic aliases via SSH remote forwarding.
- Option to restrict fingerprints for local aliasing forwardings. (SSH exec: `allowed-fingerprints`)

### Authentication

- SSH public key-based authentication for users and admins.
  - SSH public key-restricted connection for local forwarding users.
- Option for password-based authentication for users. (CLI: `--password-authentication-url`)
  - Configurable authentication request timeout. (CLI: `--authentication-request-timeout`)

### Authorization

- Control over how external hostnames are allowed to be bound. (CLI: `--bind-hostnames`)
- Control over the prefix for TXT external hostname authorization for binding. (CLI: `--txt-record-prefix`)
- Option to disable domains containing profanities from binding. (CLI: `--requested-domain-filter-profanities`)

### Reverse proxy

- Access logs for HTTP, TCP, and aliases.
- Control over if and how services are load-balanced. (CLI: `--load-balancing`, `--load-balancing-algorithm`)
- Control over allowed incoming connections by IP address CIDRs. (SSH exec: `ip-allowlist`, CLI: `--ip-allowlist`)
- Control over blocked incoming connections by IP address CIDRs. (SSH exec: `ip-blocklist`, CLI: `--ip-blocklist`)
- Option to restrict maximum services exposed by users. (CLI: `--quota-per-user`)
- Option to restrict maximum transfer rate by the users' services. (CLI: `--rate-limit-per-user`)

### ACME

- Option to use Let's Encrypt's ACME server for dynamic certificates. (CLI: `--acme-contact-email`)
- Option for using Let's Encrypt's staging server for ACME debug mode. (CLI: `--acme-use-staging`)

## Admin access

Features related to the admin permissioning system.

### Admin interface

- Terminal-based interface accessible via admin key authentication.
- Real-time system metrics (CPU, memory, network usage).
- View all active connections (SSH, HTTP, SNI, TCP, and alias).
  - Real-time connection statistics.
- View user details for connections.
  - Display key algorithm and comments.
  - Remove user connections and keys.

### Admin-only aliases

- Access to special aliases that can only be local forwarded to by users with admin credentials.
  - Endpoint for exposing Prometheus metrics. (Alias: `prometheus.sandhole:10`)

## Configuration

Features related to system-wide configuration options.

### Networking

- Option to configure address for network interfaces. (CLI: `--listen-address`)
- Option to change SSH port from the default 2222. (CLI: `--ssh-port`)
- Option to change HTTP port from the default 80. (CLI: `--http-port`)
- Option to change HTTPS port from the default 443. (CLI: `--https-port`)
- Option to configure the redirect page for the root domain. (CLI: `--domain-redirect`)

### Resources

- Configurable buffer size for bidirectional proxying. (CLI: `--buffer-size`)
- Automatic cleanup of idle connections via timeout. (CLI: `--idle-connection-timeout`)
- Automatic cleanup of unproxied connections via timeout. (CLI: `--unproxied-connection-timeout`)
- Option to configure a timeout for HTTP/HTTPS requests. (CLI: `--http-request-timeout`)
- Option to configure a timeout for TCP/WebSocket/aliasing connections. (CLI: `--tcp-connection-timeout`)

### File system

- Directory-based configuration.
  - Configuration of directory for SSH user keys. (CLI: `--user-keys-directory`)
  - Configuration of directory for SSH admin keys. (CLI: `--admin-keys-directory`)
  - Configuration of directory for TLS certificates chains and private keys. (CLI: `--certificates-directory`)
  - Configuration of directory for ACME cache. (CLI: `--acme-cache-directory`)
  - Configuration of file for server private key. (CLI: `--private-key-file`)
- Disabling automatic directory creation for missing paths. (CLI: `--disable-directory-creation`)

### Logs

- [`tracing`-based log filtering](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
- Option to disable HTTP access logs. (CLI: `--disable-http-logs`)
- Option to disable TCP access logs. (CLI: `--disable-tcp-logs`)

### Modules

- Disabling HTTP, along with HTTPS and SNI proxying. (CLI: `--disable-http`)
- Disabling HTTPS, along with SNI proxying. (CLI: `--disable-https`)
- Disabling SNI proxying. (CLI: `--disable-sni`)
- Disabling TCP port binding. (CLI: `--disable-tcp`)
- Disabling generic aliases, along with SSH ProxyJump. (CLI: `--disable-aliasing`)
  - Disabling Prometheus metrics collection and admin-only alias. (CLI: `--disable-prometheus`)
