# Technical overview

This page goes over the technical details about Sandhole's inner workings. Feel free to skip this page if you are only interested in using Sandhole.

## Secure Shell

[SSH](https://en.wikipedia.org/wiki/Secure_Shell) is a powerful protocol, with built-in features such as encryption and authentication. It's widely used to access remote servers, in order to get access to a shell or transfer Git repositories, for example.

One of its less known features is the ability to forward ports between the client and the server. With an OpenSSH server, it's possible to do:

- Local port forwarding: Accessing a port from the server, as if it were a local service on your machine.
- Remote port forwarding: Exposing a port from a local service to the server, as if it were a remote service running on the server.

See [this post on SSH tunneling](https://web.archive.org/web/20250221173009/https://goteleport.com/blog/ssh-tunneling-explained/) for more information.

Sandhole is capable of handling both, albeit in a different way than a regular OpenSSH server.

## Reverse proxy

A reverse proxy is an intermediary server that receives and forwards requests to a backend service. They are commonly used to secure traffic, or expose servers behind a firewall/private network.

Sandhole is essentially a reverse proxy. It leverages SSH for authentication and tunneling of services, while transparently handling client requests.

![A diagram displaying Sandhole's usage as a reverse proxy. It's deployed to a public server, where a local service connects to its SSH port. A remote service in a private server also connects to the SSH port over the Internet. Meanwhile, a client's web browser connects to the HTTPS port of Sandhole over the Internet.](./how_it_works.svg)

As such, it's possible to expose services publicly without needing a VPN, even behind NAT or firewalls.
