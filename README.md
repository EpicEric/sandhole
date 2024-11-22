# sandhole

Expose HTTP/SSH/TCP services through SSH port forwarding.

## Status

This is still in early development, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- Admin interface through SSH
- Documentation
- Create issues for technical debts
  - Option to garbage-collect TCP/WebSocket connections
  - Option to disable load-balancing
  - Allow user-provided key fingerprints for tunnel authentication
  - Check viability of verifying whole subdomain chain for a matching fingerprint
  - Support loading multiple pubkeys from a single file
  - Option to not log back requests to the client
  - Try to optimize ServerHandler's memory usage

## Features

- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Automatic subdomain assignment by default, with options for deterministic assignment.
- Authenticate proxy tunnels through DNS, via a TXT record containing the authorized key's fingerprint.
- Written in Rust, with comprehensive testing of most features.
