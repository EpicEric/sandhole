# sandhole

Experimental SSH hole-punching tunnel for exposing HTTP services.

## Status

This is not in a usable state, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- Figure out way to allow proxy jump without valid fingerprint, while avoiding security concerns
- Use env_logger
- Option to garbage-collect TCP/WebSocket connections
- Admin interface through SSH
- API-based password authentication
- Documentation
- Improve technical debts
  - TO-DOs
  - Allow user-provided key fingerprints for tunnel authentication
- And more

## Features

- HTTP/SSH/TCP port forwarding through SSH.
- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Automatic subdomain assignment by default, with options for deterministic assignment.
- Authenticate proxy tunnels through DNS, via a TXT record containing the authorized key's fingerprint.
- Written in Rust, with comprehensive testing of most features.
