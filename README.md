# sandhole

Expose HTTP/SSH/TCP services through SSH port forwarding.

[Check out the Sandhole book.](https://epiceric.github.io/sandhole/)

## Features

- Reverse proxy that only requires your services to have a regular SSH client.
- Automatic HTTPS support (with a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Random subdomain assignment by default, with options for deterministic assignment.
- Easily balance load by pointing multiple services to the same domain/port.
- Authorize keys for custom domains with DNS, via TXT records.
- A terminal-based admin interface to view current connections.
- Written in Rust, with comprehensive testing of most features.

## Status

This is still in early development, and mostly serves as an experiment. Contributions are welcome, but try it in production at your own risk.

## Alternatives

- [sish](https://github.com/antoniomika/sish/) - My favorite one. Written in Golang.
- [rlt](https://github.com/kaichaosun/rlt) - Uses own protocol instead of SSH. Written in Rust.
- [localhost.run](https://localhost.run/) - Free but closed-source, no self-hosting option.
- [Serveo](https://serveo.net) - Free but closed-source, no self-hosting option. Frequently goes offline.

Beware that not self-hosting your reverse proxy allows others to spy on your traffic!
