# sandhole

[![GitHub Actions workflow status](https://img.shields.io/github/actions/workflow/status/EpicEric/sandhole/validate.yml?label=tests)](https://github.com/EpicEric/sandhole/actions/workflows/validate.yml)
[![crates.io version](https://img.shields.io/crates/v/sandhole)](https://crates.io/crates/sandhole)
[![GitHub license](https://img.shields.io/github/license/EpicEric/sandhole)](https://github.com/EpicEric/sandhole/blob/main/LICENSE)

Expose HTTP/SSH/TCP services through SSH port forwarding. A self-hosted [ngrok](https://ngrok.com/)/[Cloudflare Tunnels](https://www.cloudflare.com/products/tunnel/)/[localhost.run](https://localhost.run/)/etc. alternative.

[Check out the Sandhole book.](https://sandhole.eric.dev.br)

## Features

- Reverse proxy that just works with an OpenSSH client. No extra software required!
- Automatic HTTPS support (with [dnsrobocert](https://github.com/adferrand/dnsrobocert) and/or ACME).
- Easily load-balance by pointing multiple services to the same domain/port.
- Bring your own custom domains and authorize them via DNS records.
- Random subdomain assignment by default, with options for deterministic assignment.
- Option to connect with SSH via the HTTPS port, if your network blocks outbound connections to SSH ports.
- A terminal-based admin interface to view current connections.
- Written in Rust, with comprehensive testing of most features.

## Status

Sandhole is in active development. Contributions are welcome, but try it in production at your own risk.

## Alternatives

- [sish](https://github.com/antoniomika/sish/) - My favorite one. Written in Golang.
- [rlt](https://github.com/kaichaosun/rlt) - Uses own protocol instead of SSH. Written in Rust.
- [sshuttle](https://github.com/sshuttle/sshuttle) - A smarter proxy service, also based on SSH. Written in Python.
