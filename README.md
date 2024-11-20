# sandhole

Experimental SSH hole-punching tunnel for exposing HTTP services.

## Status

This is not in a usable state, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- Generic TCP forwarding
- Temporarily allow unknown keys for SSH local port forwarding
- Allow user-provided key fingerprints for a tunnel
- Option to garbage-collect TCP/WebSocket connections
- Use env_logger
- API-based password authentication
- Admin interface through SSH
- Documentation
- Improve technical debts
- And more

## Features

- HTTP port forwarding through SSH.
- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Automatic subdomain assignment (by default), with options for deterministic assignment.
- Authenticate proxy tunnels through DNS, via a TXT record containing the authorized key's fingerprint.
- Written in Rust, with comprehensive testing of most features.
