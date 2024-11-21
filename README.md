# sandhole

Expose HTTP/SSH/TCP services through SSH port forwarding.

## Status

This is still in early development, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- Option to garbage-collect TCP/WebSocket connections
- Option to disable load-balancing
- Admin interface through SSH
- Documentation
- Create issues for technical debts
  - TO-DOs
  - Allow user-provided key fingerprints for tunnel authentication
- And more

## Features

- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Automatic subdomain assignment by default, with options for deterministic assignment.
- Authenticate proxy tunnels through DNS, via a TXT record containing the authorized key's fingerprint.
- Written in Rust, with comprehensive testing of most features.
