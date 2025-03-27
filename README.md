# Sandhole

[![GitHub Actions workflow status](https://img.shields.io/github/actions/workflow/status/EpicEric/sandhole/validate.yml?label=tests)](https://github.com/EpicEric/sandhole/actions/workflows/validate.yml)
[![Codecov](https://img.shields.io/codecov/c/github/EpicEric/sandhole)](https://app.codecov.io/github/EpicEric/sandhole)
[![crates.io version](https://img.shields.io/crates/v/sandhole)](https://crates.io/crates/sandhole)
[![GitHub license](https://img.shields.io/github/license/EpicEric/sandhole)](https://github.com/EpicEric/sandhole/blob/main/LICENSE)

![The Sandhole logo, with a crab partially inside a sand mound and the name "Sandhole" written in cursive beside them.](https://sandhole.com.br/logo.png)

Expose HTTP/SSH/TCP services through SSH port forwarding. A self-hosted ngrok / Cloudflare Tunnels / localhost.run alternative.

[Check out the Sandhole book](https://sandhole.com.br) for a full guide.

## Features

- Reverse proxy that just works with an OpenSSH client. No extra software required!
- Automatic HTTPS support (with [Agnos](https://github.com/krtab/agnos) and ACME), including HTTP/2 support.
- Easily load-balance by pointing multiple services to the same domain/port.
- Bring your own custom domains and authorize them via DNS records.
- Random subdomain assignment by default, with options for deterministic assignment.
- Option to connect with SSH via the HTTPS port, if your network blocks outbound connections to SSH ports.
- A terminal-based admin interface to view and manage current connections.
- Written in Rust, with comprehensive testing of most features.

## Status

Sandhole is in active development. Contributions are welcome, but try it in production at your own risk.

## Some alternatives

- [sish](https://github.com/antoniomika/sish) - Main inspiration for this project. Written in Golang.
- [rlt](https://github.com/kaichaosun/rlt) - Uses localtunnel's protocol instead of SSH. Written in Rust.
- [rathole](https://github.com/rapiz1/rathole) - A highly configurable reverse proxy with NAT traversal and a great name. Written in Rust.
- [sshuttle](https://github.com/sshuttle/sshuttle) - A smarter proxy service, also based on SSH. Written in Python.
