# sandhole

Experimental SSH hole-punching tunnel for exposing HTTP services.

## Status

This is not in a usable state, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- HTTPS redirection
- API-based password authentication
- ACME for certificates
- Admin interface through SSH
- Generic TCP forwarding
- Local port forwarding
- Use env_logger
- Documentation
- Improve technical debts
- And more

## Features

- Written in Rust.
- HTTP port forwarding through SSH.
- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert)).
- Automatic subdomain assignment (by default), with options for deterministic assignment.
- Authenticate proxy tunnels through DNS, via a TXT record containing the authorized key's fingerprint.
- Comprehensive testing of features.
