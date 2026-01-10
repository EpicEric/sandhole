# Docker Compose examples

This directory contains:

- [`sandhole`](./sandhole/) - The default way of installing Sandhole, with [Agnos](https://github.com/krtab/agnos) as the ACME DNS certification tool.
- [`sandhole-dnsrobocert`](./sandhole-dnsrobocert/) - An alternative way of installing Sandhole, with [dnsrobocert](https://adferrand.github.io/dnsrobocert/) as the ACME DNS certification tool (using an external DNS service).
- [`client`](./client/) - An example of running a client service with Nginx through Sandhole.
- [`localhost-testing`](./localhost-testing/) - A configuration for running a test instance of Sandhole that resolves to localhost.
